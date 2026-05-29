// Polling loop — fetches pending tasks from QKMS and dispatches them.
//
// Mirrors pollAndProcess() in qkms/cmd/mpc-sidecar/main.go (~lines 657-672).

import type { QkmsRpcClient } from '../client.js';
import type { QkmsTask, SidecarIdentity } from '../types.js';
import type { TaskDispatcher } from './dispatch.js';
import { PeerChannel, type PartyMessage } from './peer-channel.js';

export interface PollLoopConfig {
  client: QkmsRpcClient;
  dispatcher: TaskDispatcher;
  identity: SidecarIdentity;
  peerChannel?: PeerChannel;
  pollIntervalMs: number;
  /** If true, use ListTasksForSidecar (t-of-n). Else use ListTasks (2-of-2). */
  useTofN: boolean;
  /** Optional callback fired on each task dispatch error. */
  onError?: (err: unknown, task?: QkmsTask) => void;
}

export class PollLoop {
  private running = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly cfg: PollLoopConfig;

  constructor(cfg: PollLoopConfig) {
    this.cfg = cfg;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.scheduleNext(0);
  }

  stop(): void {
    this.running = false;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  private scheduleNext(delayMs: number): void {
    if (!this.running) return;
    this.timer = setTimeout(() => {
      void this.tick();
    }, delayMs);
  }

  private async tick(): Promise<void> {
    if (!this.running) return;
    try {
      const { Tasks } = this.cfg.useTofN
        ? await this.cfg.client.listTasksForSidecar({ SidecarId: this.cfg.identity.sidecarId })
        : await this.cfg.client.listTasks({});

      for (const task of Tasks) {
        if (task.Status !== 'AWAITING_CLIENT') continue;

        // For multi-party tasks, perform E2EE handshakes with peer sidecars
        // before dispatching to the protocol session.
        const hasOthers = this.hasOtherSidecars(task);
        if (this.cfg.peerChannel && hasOthers) {
          const ready = await this.ensureE2EESessions(task);
          if (!ready) continue; // Handshake in progress, will retry next poll
        }

        try {
          await this.cfg.dispatcher.dispatch(task, {
            client: this.cfg.client,
            identity: this.cfg.identity,
            sidecarId: this.cfg.identity.sidecarId,
            peerChannel: this.cfg.peerChannel,
          });
        } catch (err) {
          console.error('[qkms-sdk] dispatch error:', task.TaskId, err);
          this.cfg.onError?.(err, task);
        }
      }
    } catch (err) {
      console.error('[qkms-sdk] poll error:', err);
      this.cfg.onError?.(err);
    } finally {
      this.scheduleNext(this.cfg.pollIntervalMs);
    }
  }

  /** Check if a task has other sidecars we need E2EE sessions with. */
  private hasOtherSidecars(task: QkmsTask): boolean {
    const participants = task.Participants;
    if (!participants || participants.length <= 1) return false;
    // Check if any participant is a sidecar other than us
    for (const p of participants) {
      if (p !== this.cfg.identity.sidecarId && p !== 'service') {
        return true;
      }
    }
    return false;
  }

  /**
   * Ensure E2EE sessions are established with all peer sidecars in the task.
   * Returns true when *every* peer session is ready.
   *
   * Two crucial constraints from how QKMS GetPartyMessages works:
   *   1. It DELETES messages on read (consume-on-retrieval). So we can't call
   *      it once per peer — that would consume messages destined for other
   *      peers and silently throw them away.
   *   2. Each peer's session has its own ratchet state; decrypting a msg from
   *      peer X with peer Y's key both throws AND corrupts Y's ratchet.
   *
   * Strategy: pre-fetch ALL hellos and ALL acks for this round once per tick,
   * partition by `fromParty`, then hand each peer its own slice via
   * `performHandshakeWithMessages`. Never bail on the first non-ready peer —
   * that causes a circular deadlock in t-of-n with n>2.
   */
  private async ensureE2EESessions(task: QkmsTask): Promise<boolean> {
    const pc = this.cfg.peerChannel!;
    const partyIdMap = task.PartyIdMap ?? {};
    const myPartyId = partyIdMap[this.cfg.identity.sidecarId] ?? 2;

    // Build the peer list (sidecar id + party id) and fetch identities first.
    interface Peer { sidecarId: string; partyId: number; identity?: import('./peer-channel.js').PeerIdentity }
    const peers: Peer[] = [];
    for (const [peerId, peerPartyId] of Object.entries(partyIdMap)) {
      if (peerId === this.cfg.identity.sidecarId) continue;
      if (peerId === 'service') continue;
      peers.push({ sidecarId: peerId, partyId: peerPartyId });
    }

    for (const peer of peers) {
      try {
        peer.identity = await PeerChannel.fetchPeerIdentity(this.cfg.client, peer.sidecarId);
      } catch (err) {
        console.warn('[qkms-sdk] fetch peer identity failed for', peer.sidecarId, err);
        return false;
      }
    }

    // Batch-fetch hellos (round 0) and acks (round 1) once per tick.
    const helloByParty = new Map<number, PartyMessage[]>();
    const ackByParty = new Map<number, PartyMessage[]>();
    try {
      const helloResp = await this.cfg.client.call<Record<string, unknown>, { Messages: PartyMessage[] }>(
        'GetPartyMessages',
        { TaskId: task.TaskId, SidecarId: this.cfg.identity.sidecarId, ForParty: myPartyId, Round: 0 },
      );
      for (const msg of helloResp.Messages ?? []) {
        const list = helloByParty.get(msg.fromParty) ?? [];
        list.push(msg);
        helloByParty.set(msg.fromParty, list);
      }
    } catch {
      // Treat as empty for this tick.
    }
    try {
      const ackResp = await this.cfg.client.call<Record<string, unknown>, { Messages: PartyMessage[] }>(
        'GetPartyMessages',
        { TaskId: task.TaskId, SidecarId: this.cfg.identity.sidecarId, ForParty: myPartyId, Round: 1 },
      );
      for (const msg of ackResp.Messages ?? []) {
        const list = ackByParty.get(msg.fromParty) ?? [];
        list.push(msg);
        ackByParty.set(msg.fromParty, list);
      }
    } catch {
      // Treat as empty.
    }

    // Drive each peer's handshake with its pre-filtered message slice.
    let allReady = true;
    for (const peer of peers) {
      if (!peer.identity) { allReady = false; continue; }
      try {
        const ready = await pc.performHandshakeWithMessages(
          this.cfg.client,
          task.TaskId,
          this.cfg.identity.sidecarId,
          myPartyId,
          peer.sidecarId,
          peer.partyId,
          peer.identity,
          helloByParty.get(peer.partyId) ?? [],
          ackByParty.get(peer.partyId) ?? [],
        );
        if (!ready) allReady = false;
      } catch (err) {
        console.warn('[qkms-sdk] E2EE handshake with', peer.sidecarId, 'failed:', err);
        allReady = false;
      }
    }

    return allReady;
  }
}
