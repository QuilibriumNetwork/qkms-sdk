// Task dispatcher — routes a QKMS task to the right protocol session.
//
// Mirrors processTask() in qkms/cmd/mpc-sidecar/main.go (~lines 774-988).
// The Go version is monolithic; here we keep the routing table small and
// delegate to one session module per protocol. Each protocol session
// (DKLs23, BLS, FROST, Decaf448, RSA-2PC) registers itself on the dispatcher.
//
// Idempotency: the Go sidecar maintains a `submittedRounds` cache keyed by
// `taskId:partyKey:round` to avoid re-computing contributions on re-poll.
// We mirror that here to avoid corrupting protocol state when the server
// re-issues the same task round.

import type { QkmsRpcClient } from '../client.js';
import type { QkmsTask, SidecarIdentity } from '../types.js';
import type { PeerChannel } from './peer-channel.js';

/** A protocol session — implementations are in ./sessions/. */
export interface ProtocolSession {
  /** Returns true if this session can handle the given task. */
  canHandle(task: QkmsTask): boolean;
  /** Process one round of the task and (optionally) submit results to the server. */
  process(task: QkmsTask, ctx: SessionContext): Promise<void>;
}

/** Context passed to each session call. */
export interface SessionContext {
  client: QkmsRpcClient;
  identity: SidecarIdentity;
  /** Hex-encoded sidecar id (matches `identity.sidecarId`). */
  sidecarId: string;
  /** E2EE peer channel for sidecar-to-sidecar messaging. */
  peerChannel?: PeerChannel;
}

export class TaskDispatcher {
  private readonly sessions: ProtocolSession[] = [];
  /** Cache: `${taskId}:${round}` → submitted, prevents reprocessing on re-poll. */
  private readonly submittedRounds = new Set<string>();
  /** Tasks we've already claimed (2-of-2 mode). */
  private readonly claimedTasks = new Set<string>();

  register(session: ProtocolSession): void {
    this.sessions.push(session);
  }

  /** Dispatch one task. Returns true if a session handled it. */
  async dispatch(task: QkmsTask, ctx: SessionContext): Promise<boolean> {
    const cacheKey = `${task.TaskId}:${task.Round}`;
    if (this.submittedRounds.has(cacheKey)) {
      // Already processed this round — task hasn't advanced yet
      return true;
    }
    for (const session of this.sessions) {
      if (session.canHandle(task)) {
        await session.process(task, ctx);
        this.submittedRounds.add(cacheKey);
        return true;
      }
    }
    return false;
  }

  /** Drop cache entries for a completed task to bound memory growth. */
  forgetTask(taskId: string): void {
    for (const k of this.submittedRounds) {
      if (k.startsWith(`${taskId}:`)) this.submittedRounds.delete(k);
    }
  }
}
