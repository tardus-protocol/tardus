/**
 * TARDUS relay HTTP client.
 *
 * Mirrors `crates/tardus-relay/src/api.rs`:
 *   POST   /inbox/{recipient_pk_hex}       — anonymous deposit
 *   GET    /inbox/{recipient_pk_hex}       — recipient polls
 *   DELETE /inbox/{recipient_pk_hex}/{id}  — mark consumed
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

export interface RelayMessage {
  id: string
  recipient: string // hex pk
  payload_hex: string
  expires_at: number // unix secs
}

export interface RelayInfo {
  version: string
  message_count: number
}

export class RelayError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'RelayError'
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Lightweight relay client. No persistent state — every call hits the
 * relay endpoint. Safe to instantiate per-component.
 */
export class RelayClient {
  readonly baseUrl: string

  constructor(baseUrl: string) {
    // Strip trailing slash for clean concatenation.
    this.baseUrl = baseUrl.replace(/\/+$/, '')
  }

  async health(): Promise<{ ok: boolean }> {
    const res = await fetch(`${this.baseUrl}/health`, { method: 'GET' })
    if (!res.ok) throw new RelayError(res.status, `health: ${res.statusText}`)
    return res.json()
  }

  async info(): Promise<RelayInfo> {
    const res = await fetch(`${this.baseUrl}/info`, { method: 'GET' })
    if (!res.ok) throw new RelayError(res.status, `info: ${res.statusText}`)
    return res.json()
  }

  async list(recipientPk: Uint8Array): Promise<RelayMessage[]> {
    if (recipientPk.length !== 32) {
      throw new RelayError(0, `recipientPk must be 32 bytes, got ${recipientPk.length}`)
    }
    const url = `${this.baseUrl}/inbox/${hex(recipientPk)}`
    const res = await fetch(url, { method: 'GET' })
    if (!res.ok) throw new RelayError(res.status, `list: ${res.statusText}`)
    const json = (await res.json()) as { messages: RelayMessage[] }
    return json.messages
  }

  async deposit(
    recipientPk: Uint8Array,
    payload: Uint8Array,
    ttlSecs = 3600,
  ): Promise<RelayMessage> {
    if (recipientPk.length !== 32) {
      throw new RelayError(0, `recipientPk must be 32 bytes`)
    }
    const url = `${this.baseUrl}/inbox/${hex(recipientPk)}`
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload_hex: hex(payload),
        ttl_secs: ttlSecs,
      }),
    })
    if (!res.ok) throw new RelayError(res.status, `deposit: ${res.statusText}`)
    return res.json()
  }

  async remove(recipientPk: Uint8Array, messageId: string): Promise<boolean> {
    const url = `${this.baseUrl}/inbox/${hex(recipientPk)}/${encodeURIComponent(messageId)}`
    const res = await fetch(url, { method: 'DELETE' })
    if (!res.ok) throw new RelayError(res.status, `remove: ${res.statusText}`)
    const json = (await res.json()) as { removed: boolean }
    return json.removed
  }
}

/** Decode the `payload_hex` field of a `RelayMessage` to raw bytes. */
export function payloadBytes(msg: RelayMessage): Uint8Array {
  const h = msg.payload_hex
  if (h.length % 2 !== 0) {
    throw new RelayError(0, `payload_hex length not even: ${h.length}`)
  }
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}
