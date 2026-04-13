// Polling loop — fetches pending tasks from QKMS and dispatches them.
//
// Mirrors pollAndProcess() in qkms/cmd/mpc-sidecar/main.go (~lines 657-672).

import type { QkmsRpcClient } from '../client.js';
import type { QkmsTask, SidecarIdentity } from '../types.js';
import type { TaskDispatcher } from './dispatch.js';
import { PeerChannel } from './peer-channel.js';

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
   * Returns true when all sessions are ready.
   */
  private async ensureE2EESessions(task: QkmsTask): Promise<boolean> {
    const pc = this.cfg.peerChannel!;
    const partyIdMap = task.PartyIdMap ?? {};
    const myPartyId = partyIdMap[this.cfg.identity.sidecarId] ?? 2;

    for (const [peerId, peerPartyId] of Object.entries(partyIdMap)) {
      if (peerId === this.cfg.identity.sidecarId) continue;
      if (peerId === 'service') continue;

      // Don't short-circuit — sessions are per-task, isReady is global

      try {
        const peerIdentity = await PeerChannel.fetchPeerIdentity(this.cfg.client, peerId);
        const ready = await pc.performHandshake(
          this.cfg.client,
          task.TaskId,
          this.cfg.identity.sidecarId,
          myPartyId,
          peerId,
          peerPartyId,
          peerIdentity,
        );
        if (!ready) return false;
      } catch (err) {
        console.warn('[qkms-sdk] E2EE handshake with', peerId, 'failed:', err);
        return false;
      }
    }

    return true;
  }
}
