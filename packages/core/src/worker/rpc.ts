// Typed postMessage RPC between the main thread and the Sidecar Worker.
//
// The wire format is small and protocol-agnostic:
//
//   Request:   { kind: 'req', id, method, args }
//   Response:  { kind: 'res', id, result }   or   { kind: 'res', id, error }
//   Event:     { kind: 'evt', name, data }   (worker → main, push-only)
//
// Requests are correlated by monotonic numeric id. Events are used by the
// worker to push async state changes (e.g. "task errored") without the main
// thread having to poll.

export interface RpcRequest {
  kind: 'req';
  id: number;
  method: string;
  args: unknown;
}

export interface RpcResponse {
  kind: 'res';
  id: number;
  result?: unknown;
  error?: string;
}

export interface RpcEvent<T = unknown> {
  kind: 'evt';
  name: string;
  data: T;
}

export type RpcMessage = RpcRequest | RpcResponse | RpcEvent;

/** Anything that can send/receive RPC messages — a Worker or a DedicatedWorkerGlobalScope. */
export interface RpcEndpoint {
  postMessage(msg: RpcMessage): void;
  addEventListener(
    type: 'message',
    listener: (ev: { data: RpcMessage }) => void,
  ): void;
  removeEventListener?(
    type: 'message',
    listener: (ev: { data: RpcMessage }) => void,
  ): void;
}

/** Main-thread side: sends requests, waits for responses, dispatches events. */
export class RpcClient {
  private nextId = 1;
  private readonly pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (err: Error) => void }
  >();
  private readonly listeners = new Map<string, Set<(data: unknown) => void>>();

  constructor(private readonly endpoint: RpcEndpoint) {
    endpoint.addEventListener('message', (ev) => this.handleMessage(ev.data));
  }

  /** Send an RPC call and await the response. */
  call<T = unknown>(method: string, args: unknown = {}): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (v) => resolve(v as T),
        reject,
      });
      const req: RpcRequest = { kind: 'req', id, method, args };
      this.endpoint.postMessage(req);
    });
  }

  /** Subscribe to a worker-pushed event. */
  on<T = unknown>(name: string, handler: (data: T) => void): () => void {
    let set = this.listeners.get(name);
    if (!set) {
      set = new Set();
      this.listeners.set(name, set);
    }
    set.add(handler as (data: unknown) => void);
    return () => {
      set?.delete(handler as (data: unknown) => void);
    };
  }

  private handleMessage(msg: RpcMessage): void {
    if (!msg || typeof msg !== 'object') return;
    if (msg.kind === 'res') {
      const pending = this.pending.get(msg.id);
      if (!pending) return;
      this.pending.delete(msg.id);
      if (msg.error != null) {
        pending.reject(new Error(msg.error));
      } else {
        pending.resolve(msg.result);
      }
    } else if (msg.kind === 'evt') {
      const handlers = this.listeners.get(msg.name);
      if (!handlers) return;
      for (const h of handlers) {
        try {
          h(msg.data);
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(`[qkms-sdk rpc] event handler for ${msg.name} threw:`, err);
        }
      }
    }
  }
}

/** Worker-side: receives requests, dispatches to handlers, pushes events. */
export class RpcServer {
  private readonly handlers = new Map<string, (args: unknown) => unknown | Promise<unknown>>();

  constructor(private readonly endpoint: RpcEndpoint) {
    endpoint.addEventListener('message', (ev) => {
      void this.handleMessage(ev.data);
    });
  }

  /** Register a method handler. */
  on(method: string, handler: (args: unknown) => unknown | Promise<unknown>): void {
    this.handlers.set(method, handler);
  }

  /** Push an event to the main thread. */
  emit<T = unknown>(name: string, data: T): void {
    const evt: RpcEvent<T> = { kind: 'evt', name, data };
    this.endpoint.postMessage(evt as unknown as RpcMessage);
  }

  private async handleMessage(msg: RpcMessage): Promise<void> {
    if (!msg || typeof msg !== 'object' || msg.kind !== 'req') return;
    const handler = this.handlers.get(msg.method);
    const id = msg.id;

    if (!handler) {
      const res: RpcResponse = {
        kind: 'res',
        id,
        error: `unknown RPC method: ${msg.method}`,
      };
      this.endpoint.postMessage(res);
      return;
    }

    try {
      const result = await handler(msg.args);
      const res: RpcResponse = { kind: 'res', id, result };
      this.endpoint.postMessage(res);
    } catch (err) {
      const res: RpcResponse = {
        kind: 'res',
        id,
        error: err instanceof Error ? err.message : String(err),
      };
      this.endpoint.postMessage(res);
    }
  }
}
