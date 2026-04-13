// E2EE peer channel — X3DH + double ratchet for sidecar-to-sidecar messaging.
//
// Port of qkms/src/e2ee/channel_manager.go + the handshake protocol from
// qkms/cmd/mpc-sidecar/main.go (ensureE2EESession, performSenderHandshake,
// checkAndRespondToHandshake).
//
// Uses channel-wasm primitives:
//   js_sender_x3dh / js_receiver_x3dh  → X3DH key agreement
//   js_new_double_ratchet               → create ratchet from session key
//   js_double_ratchet_encrypt/decrypt   → message encryption
//
// Wire format: messages are exchanged via TrentService.SendPartyMessage /
// GetPartyMessages. E2EE handshake uses negative round numbers:
//   Round 0 = hello (sender → receiver)
//   Round 1 = ack   (receiver → sender)
//   Round 2+ = protocol data (offset by E2EE_ROUND_PROTOCOL_START)

import * as channelwasm from 'channelwasm';
import type { QkmsRpcClient } from '../client.js';
import type { SidecarIdentity } from '../types.js';

// ---- Constants (match Go sidecar) ----

const E2EE_ROUND_HELLO = 0;
const E2EE_ROUND_ACK = 1;
export const E2EE_ROUND_PROTOCOL_START = 2;

// ---- Encoding helpers ----

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---- Peer identity ----

interface PeerIdentity {
  identityKey: Uint8Array;   // X448 public key (57 bytes Edwards compressed)
  signedPreKey: Uint8Array;  // X448 signed pre-key public key (57 bytes)
}

// ---- Channel Manager ----

export class PeerChannel {
  private readonly identityPrivateX448: Uint8Array;
  private readonly signedPreKeyPrivateX448: Uint8Array;
  private readonly sessions = new Map<string, string>(); // peerId → ratchet state
  private readonly sessionReady = new Set<string>();
  private readonly helloSent = new Set<string>(); // taskId:peerId:hello

  constructor(identity: SidecarIdentity) {
    this.identityPrivateX448 = hexToBytes(identity.identityPrivateX448);
    this.signedPreKeyPrivateX448 = hexToBytes(identity.signedPreKeyPrivateX448);
  }

  // Sessions are per-task (fresh handshake each time) so no persistence.

  get sidecarId(): string {
    // We don't store it directly, but the caller always has it
    return '';
  }

  isReady(peerId: string): boolean {
    return this.sessionReady.has(peerId);
  }

  hasSession(peerId: string): boolean {
    return this.sessions.has(peerId);
  }

  // ---- Session establishment (X3DH) ----

  establishSession(peerId: string, isSender: boolean, peerIdentityKey: Uint8Array, peerSignedPreKey: Uint8Array): void {
    if (this.sessions.has(peerId)) return;

    // X3DH key agreement → 96-byte session key
    let sessionKeyB64: string;
    if (isSender) {
      const result = channelwasm.js_sender_x3dh(JSON.stringify({
        sending_identity_private_key: Array.from(this.identityPrivateX448),
        sending_ephemeral_private_key: Array.from(this.signedPreKeyPrivateX448),
        receiving_identity_key: Array.from(peerIdentityKey),
        receiving_signed_pre_key: Array.from(peerSignedPreKey),
        session_key_length: 96,
      }));
      sessionKeyB64 = JSON.parse(result) as string;
    } else {
      const result = channelwasm.js_receiver_x3dh(JSON.stringify({
        sending_identity_private_key: Array.from(this.identityPrivateX448),
        sending_signed_private_key: Array.from(this.signedPreKeyPrivateX448),
        receiving_identity_key: Array.from(peerIdentityKey),
        receiving_ephemeral_key: Array.from(peerSignedPreKey),
        session_key_length: 96,
      }));
      sessionKeyB64 = JSON.parse(result) as string;
    }

    const sessionKey = base64ToBytes(sessionKeyB64);

    // Create double ratchet from session key
    const state = channelwasm.js_new_double_ratchet(JSON.stringify({
      session_key: Array.from(sessionKey.subarray(0, 32)),
      sending_header_key: Array.from(sessionKey.subarray(32, 64)),
      next_receiving_header_key: Array.from(sessionKey.subarray(64, 96)),
      is_sender: isSender,
      sending_ephemeral_private_key: Array.from(this.signedPreKeyPrivateX448),
      receiving_ephemeral_key: Array.from(peerSignedPreKey),
    }));

    this.sessions.set(peerId, state);
  }

  // ---- Encrypt / Decrypt ----

  encrypt(peerId: string, plaintext: Uint8Array): string {
    const state = this.sessions.get(peerId);
    if (!state) throw new Error(`No E2EE session with ${peerId}`);

    const result = JSON.parse(channelwasm.js_double_ratchet_encrypt(JSON.stringify({
      ratchet_state: state,
      message: Array.from(plaintext),
    }))) as { ratchet_state: string; envelope: string };

    this.sessions.set(peerId, result.ratchet_state);

    return result.envelope; // JSON string of P2PChannelEnvelope
  }

  decrypt(peerId: string, envelopeJson: string): Uint8Array {
    const state = this.sessions.get(peerId);
    if (!state) throw new Error(`No E2EE session with ${peerId}`);

    const result = JSON.parse(channelwasm.js_double_ratchet_decrypt(JSON.stringify({
      ratchet_state: state,
      envelope: envelopeJson,
    }))) as { ratchet_state: string; message: number[] };

    this.sessions.set(peerId, result.ratchet_state);

    return Uint8Array.from(result.message);
  }

  // ---- Handshake protocol ----

  /**
   * Perform the E2EE handshake with a peer sidecar. This mirrors
   * ensureE2EESession in the Go sidecar.
   *
   * - The sender (lexicographically lower sidecar ID) initiates X3DH,
   *   sends an encrypted "hello" via SendPartyMessage (round 0).
   * - The receiver waits for the hello, establishes its side of X3DH,
   *   sends an encrypted "ack" via SendPartyMessage (round 1).
   * - Both sides mark the session as ready once the ack is exchanged.
   *
   * Returns true when the session is ready. May need multiple calls
   * (polling) to complete the handshake.
   */
  async performHandshake(
    client: QkmsRpcClient,
    taskId: string,
    mySidecarId: string,
    myPartyId: number,
    peerId: string,
    peerPartyId: number,
    peerIdentity: PeerIdentity,
  ): Promise<boolean> {
    // Per-task readiness check
    const taskSessionKey = `${taskId}:${peerId}`;
    if (this.sessionReady.has(taskSessionKey)) return true;

    const isSender = mySidecarId < peerId;

    if (isSender) {
      return this.performSenderHandshake(client, taskId, mySidecarId, myPartyId, peerId, peerPartyId, peerIdentity);
    } else {
      return this.performReceiverHandshake(client, taskId, mySidecarId, myPartyId, peerId, peerPartyId, peerIdentity);
    }
  }

  private async performSenderHandshake(
    client: QkmsRpcClient,
    taskId: string,
    mySidecarId: string,
    myPartyId: number,
    peerId: string,
    peerPartyId: number,
    peerIdentity: PeerIdentity,
  ): Promise<boolean> {
    // Send hello (once per task) — also creates a fresh session
    const helloKey = `${taskId}:${peerId}:hello`;
    if (!this.helloSent.has(helloKey)) {
      // Fresh session per task
      this.sessions.delete(peerId);
      this.sessionReady.delete(peerId);
      this.establishSession(peerId, true, peerIdentity.identityKey, peerIdentity.signedPreKey);
      const envelope = this.encrypt(peerId, new TextEncoder().encode('hello'));
      await client.call('SendPartyMessage', {
        TaskId: taskId,
        SidecarId: mySidecarId,
        FromParty: myPartyId,
        ToParty: peerPartyId,
        Round: E2EE_ROUND_HELLO,
        Encrypted: true,
        Envelope: JSON.parse(envelope),
      });
      this.helloSent.add(helloKey);
    }

    // Check for ack
    try {
      const resp = await client.call<Record<string, unknown>, { Messages: PartyMessage[] }>(
        'GetPartyMessages',
        { TaskId: taskId, SidecarId: mySidecarId, ForParty: myPartyId, Round: E2EE_ROUND_ACK },
      );

      const msgs = resp.Messages ?? [];
      for (const msg of msgs) {
        if (msg.round === E2EE_ROUND_ACK && msg.encrypted) {
          const plaintext = this.decrypt(peerId, JSON.stringify(msg.envelope));
          const text = new TextDecoder().decode(plaintext);
          if (text === 'ack') {
            this.sessionReady.add(`${taskId}:${peerId}`);
            return true;
          }
        }
      }
    } catch {
      // Ack not received yet
    }

    return false;
  }

  private async performReceiverHandshake(
    client: QkmsRpcClient,
    taskId: string,
    mySidecarId: string,
    myPartyId: number,
    peerId: string,
    peerPartyId: number,
    peerIdentity: PeerIdentity,
  ): Promise<boolean> {
    // Check for hello
    try {
      const resp = await client.call<Record<string, unknown>, { Messages: PartyMessage[] }>(
        'GetPartyMessages',
        { TaskId: taskId, SidecarId: mySidecarId, ForParty: myPartyId, Round: E2EE_ROUND_HELLO },
      );

      for (const msg of resp.Messages ?? []) {
        if (msg.round === E2EE_ROUND_HELLO && msg.encrypted) {
          // Establish session as receiver (must happen before decrypt)
          if (!this.hasSession(peerId)) {
            this.establishSession(peerId, false, peerIdentity.identityKey, peerIdentity.signedPreKey);
          }

          const plaintext = this.decrypt(peerId, JSON.stringify(msg.envelope));
          const text = new TextDecoder().decode(plaintext);
          if (text === 'hello') {
            // Send ack
            const ackEnvelope = this.encrypt(peerId, new TextEncoder().encode('ack'));
            await client.call('SendPartyMessage', {
              TaskId: taskId,
              SidecarId: mySidecarId,
              FromParty: myPartyId,
              ToParty: peerPartyId,
              Round: E2EE_ROUND_ACK,
              Encrypted: true,
              Envelope: JSON.parse(ackEnvelope),
            });
            this.sessionReady.add(`${taskId}:${peerId}`);
            return true;
          }
        }
      }
    } catch {
      // No hello yet
    }

    return false;
  }

  // ---- Protocol messaging ----

  /**
   * Send an encrypted protocol message to a peer via SendPartyMessage.
   * The round is offset by E2EE_ROUND_PROTOCOL_START to avoid collision
   * with handshake rounds.
   */
  async sendMessage(
    client: QkmsRpcClient,
    taskId: string,
    mySidecarId: string,
    myPartyId: number,
    peerId: string,
    peerPartyId: number,
    protocolRound: number,
    plaintext: Uint8Array,
  ): Promise<void> {
    const envelope = this.encrypt(peerId, plaintext);
    await client.call('SendPartyMessage', {
      TaskId: taskId,
      SidecarId: mySidecarId,
      FromParty: myPartyId,
      ToParty: peerPartyId,
      Round: protocolRound + E2EE_ROUND_PROTOCOL_START,
      Encrypted: true,
      Envelope: JSON.parse(envelope),
    });
  }

  /**
   * Collect and decrypt protocol messages from peers for a given round.
   * Returns a map of fromPartyId → decrypted plaintext.
   */
  async collectMessages(
    client: QkmsRpcClient,
    taskId: string,
    mySidecarId: string,
    myPartyId: number,
    protocolRound: number,
    partyIdMap: Record<string, number>,
  ): Promise<Map<number, Uint8Array>> {
    const resp = await client.call<Record<string, unknown>, { Messages: PartyMessage[] }>(
      'GetPartyMessages',
      {
        TaskId: taskId,
        SidecarId: mySidecarId,
        ForParty: myPartyId,
        Round: protocolRound + E2EE_ROUND_PROTOCOL_START,
      },
    );

    // Build reverse map: partyId → sidecarId
    const partyToSidecar = new Map<number, string>();
    for (const [sid, pid] of Object.entries(partyIdMap)) {
      partyToSidecar.set(pid, sid);
    }

    const result = new Map<number, Uint8Array>();
    for (const msg of resp.Messages ?? []) {
      const senderSidecarId = partyToSidecar.get(msg.fromParty);
      if (!senderSidecarId) continue;
      try {
        const plaintext = this.decrypt(senderSidecarId, JSON.stringify(msg.envelope));
        result.set(msg.fromParty, plaintext);
      } catch (err) {
        console.warn(`[peer-channel] decrypt failed from party ${msg.fromParty}:`, err);
      }
    }

    return result;
  }

  // ---- Peer identity fetching ----

  /**
   * Fetch a peer sidecar's identity keys from QKMS.
   */
  static async fetchPeerIdentity(client: QkmsRpcClient, peerId: string): Promise<PeerIdentity> {
    const resp = await client.call<{ SidecarId: string }, {
      IdentityKey: string; // base64
      SignedPreKey: string; // base64
    }>('GetSidecar', { SidecarId: peerId });

    return {
      identityKey: base64ToBytes(resp.IdentityKey),
      signedPreKey: base64ToBytes(resp.SignedPreKey),
    };
  }
}

// ---- Wire types ----

interface PartyMessage {
  fromParty: number;
  toParty: number;
  round: number;
  encrypted: boolean;
  envelope: unknown; // P2PChannelEnvelope JSON object
}
