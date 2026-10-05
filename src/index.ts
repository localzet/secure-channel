// SPDX-FileCopyrightText: 2026 Ivan Zorin <creator@localzet.com> (Localzet contributions)
// SPDX-License-Identifier: AGPL-3.0
/**
 * Secure Channel Protocol (client + lightweight server helper).
 * Matches current Gateway/Security flow: request/response + events/commands over mTLS WebSocket.
 */

import WebSocket, { WebSocketServer } from 'ws'
import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'

export type ChannelMessageType =
  | 'request'
  | 'response'
  | 'event'
  | 'command'
  | 'command-result'

export interface ChannelMessage {
  type: ChannelMessageType
  id?: string
  route?: string
  expectReply?: boolean
  statusCode?: number
  headers?: Record<string, string>
  payload?: any
  error?: string
}

export interface SecureChannelClientOptions {
  url: string
  serviceId: string
  certificate: string // PEM
  privateKey: string // PEM
  caCertificate?: string // PEM
  reconnectDelayMs?: number
  requestTimeoutMs?: number
  maxSkewMs?: number
  nonceTtlMs?: number
  nonceCacheSize?: number
}

export interface RequestOptions {
  route: string
  payload?: any
  expectReply?: boolean
  headers?: Record<string, string>
  timeoutMs?: number
}

/**
 * Client with auto-reconnect and pending request tracking.
 */
export class SecureChannelClient extends EventEmitter {
  private ws: WebSocket | null = null
  private connected = false
  private readonly opts: Required<SecureChannelClientOptions>
  private readonly pending = new Map<
    string,
    { resolve: (v: any) => void; reject: (e: any) => void; timeout: NodeJS.Timeout }
  >()
  private readonly nonces = new Map<string, number>()
  private manuallyDisconnected = false
  private connecting: Promise<void> | null = null
  private reconnectTimer: NodeJS.Timeout | null = null

  constructor(options: SecureChannelClientOptions) {
    super()
    this.opts = {
      reconnectDelayMs: options.reconnectDelayMs ?? 3000,
      requestTimeoutMs: options.requestTimeoutMs ?? 5000,
      maxSkewMs: options.maxSkewMs ?? 30_000,
      nonceTtlMs: options.nonceTtlMs ?? 60_000,
      nonceCacheSize: options.nonceCacheSize ?? 10_000,
      ...options,
    } as Required<SecureChannelClientOptions>
  }

  async connect(): Promise<void> {
    if (this.connected) return
    if (this.connecting) return this.connecting
    this.manuallyDisconnected = false
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
    const target = new URL(this.opts.url)
    if (target.protocol === 'https:') target.protocol = 'wss:'
    if (target.protocol !== 'wss:') throw new Error('Secure Channel requires a wss:// or https:// URL')
    if (!target.pathname.includes('/secure-channel/')) {
      target.pathname = `${target.pathname.replace(/\/$/, '')}/secure-channel/${encodeURIComponent(this.opts.serviceId)}`
    }
    const connection = new Promise<void>((resolve, reject) => {
      let opened = false

      const ws = new WebSocket(target, {
        cert: this.opts.certificate,
        key: this.opts.privateKey,
        ca: this.opts.caCertificate ? [this.opts.caCertificate] : undefined,
        rejectUnauthorized: true,
      })
      this.ws = ws

      ws.on('open', () => {
        opened = true
        this.ws = ws
        this.connected = true
        this.emit('connected')
        resolve()
      })

      ws.on('message', (data: Buffer) => {
        try {
          const msg = JSON.parse(data.toString()) as ChannelMessage
          this.handleMessage(msg)
        } catch (err) {
          if (this.listenerCount('error')) this.emit('error', err)
        }
      })

      ws.on('error', (err) => {
        this.connected = false
        if (this.listenerCount('error')) this.emit('error', err)
        reject(err)
      })

      ws.on('close', () => {
        if (this.ws !== ws) return
        this.ws = null
        this.connected = false
        this.rejectPending('Channel disconnected')
        if (!opened) reject(new Error('Channel closed before connection completed'))
        this.emit('disconnected')
        if (!this.manuallyDisconnected) {
          this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null
            void this.connect().catch(() => {})
          }, this.opts.reconnectDelayMs)
        }
      })
    })
    this.connecting = connection
    try {
      await connection
    } finally {
      if (this.connecting === connection) this.connecting = null
    }
  }

  async request(options: RequestOptions): Promise<any> {
    if (!this.connected || !this.ws) throw new Error('Channel not connected')

    const id = `req_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    const expectReply = options.expectReply !== false
    const timeoutMs = options.timeoutMs ?? this.opts.requestTimeoutMs

    return new Promise((resolve, reject) => {
      if (expectReply) {
        const timeout = setTimeout(() => {
          this.pending.delete(id)
          reject(new Error('Request timeout'))
        }, timeoutMs)
        this.pending.set(id, { resolve, reject, timeout })
      }

      const now = Date.now()
      const nonce = randomUUID()

      const msg: ChannelMessage = {
        type: 'request',
        id,
        route: options.route,
        expectReply,
        headers: {
          ...options.headers,
          'x-sc-ts': now.toString(),
          'x-sc-nonce': nonce,
        },
        payload: options.payload,
      }
      this.ws!.send(JSON.stringify(msg), (error) => {
        if (error) {
          const pending = this.pending.get(id)
          if (pending) clearTimeout(pending.timeout)
          this.pending.delete(id)
          reject(error)
        } else if (!expectReply) {
          resolve({ accepted: true })
        }
      })
    })
  }

  sendEvent(route: string, payload?: any): void {
    if (!this.connected || !this.ws) throw new Error('Channel not connected')
    const msg: ChannelMessage = { type: 'event', route, payload }
    this.ws.send(JSON.stringify(msg))
  }

  sendCommand(route: string, payload?: any, expectReply = true): Promise<any> | void {
    if (!this.connected || !this.ws) throw new Error('Channel not connected')
    if (!expectReply) {
      this.ws.send(JSON.stringify({ type: 'command', route, payload }))
      return
    }
    return this.request({ route, payload, expectReply: true })
  }

  disconnect(): void {
    this.manuallyDisconnected = true
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
    if (this.ws) {
      this.ws.close()
    }
    this.connected = false
    this.rejectPending('Channel disconnected')
  }

  private rejectPending(reason: string): void {
    this.pending.forEach(({ timeout, reject }) => {
      clearTimeout(timeout)
      reject(new Error(reason))
    })
    this.pending.clear()
  }

  isConnected(): boolean {
    return this.connected
  }

  private handleMessage(msg: ChannelMessage) {
    if (msg.type === 'response' && msg.id) {
      const pending = this.pending.get(msg.id)
      if (pending) {
        clearTimeout(pending.timeout)
        this.pending.delete(msg.id)
        if (msg.statusCode && msg.statusCode >= 400) {
          pending.reject(new Error(msg.payload?.error || msg.error || 'Request failed'))
        } else {
          pending.resolve(msg.payload)
        }
      }
      return
    }

    if (msg.type === 'command') {
      this.emit('command', msg)
      return
    }
    if (msg.type === 'command-result') {
      this.emit('command-result', msg)
      return
    }
    if (msg.type === 'event') {
      this.emit('event', msg)
      this.emit('message', msg)
    }
  }
}

export interface SecureChannelServerOptions {
  wss: WebSocketServer
  verifyClient?: (peerCert: any) => boolean
  onRequest: (route: string, payload: any, raw: ChannelMessage, ws?: any) => Promise<any>
  maxSkewMs?: number
  nonceTtlMs?: number
  nonceCacheSize?: number
}

/**
 * Lightweight server binder: attach to an existing WebSocketServer (with mTLS already configured).
 */
export function bindSecureChannelServer(options: SecureChannelServerOptions): void {
  const { wss, verifyClient, onRequest } = options
  const maxSkewMs = options.maxSkewMs ?? 30_000
  const nonceTtlMs = options.nonceTtlMs ?? 60_000
  const nonceCacheSize = options.nonceCacheSize ?? 10_000
  if (!Number.isFinite(maxSkewMs) || maxSkewMs < 0 || !Number.isFinite(nonceTtlMs) || nonceTtlMs < 2 * maxSkewMs || !Number.isSafeInteger(nonceCacheSize) || nonceCacheSize < 1) {
    throw new Error('Invalid replay protection limits')
  }
  const seenNonces = new Map<string, number>()

  wss.on('connection', (ws, req) => {
    const cert = (req.socket as any).getPeerCertificate ? (req.socket as any).getPeerCertificate() : null
    if ((req.socket as any).authorized !== true) {
      ws.close(4001, 'Unauthorized client certificate')
      return
    }
    try {
      if (verifyClient && !verifyClient(cert)) {
        ws.close(4001, 'Invalid client certificate')
        return
      }
    } catch {
      ws.close(4001, 'Client certificate verification failed')
      return
    }

    ws.on('message', async (data: Buffer) => {
      let msg: ChannelMessage | null = null
      try {
        msg = JSON.parse(data.toString()) as ChannelMessage
      } catch {
        return
      }
      if (!msg || msg.type !== 'request' || typeof msg.id !== 'string' || !msg.id || typeof msg.route !== 'string' || !msg.route) return

      // Anti-replay: timestamp + nonce window
      const tsStr = msg.headers?.['x-sc-ts']
      const nonce = msg.headers?.['x-sc-nonce']
      const now = Date.now()
      if (typeof tsStr !== 'string' || typeof nonce !== 'string' || !nonce || nonce.length > 128) return
      const ts = Number(tsStr)
      if (!Number.isFinite(ts) || Math.abs(now - ts) > maxSkewMs) return
      for (const [n, expiresAt] of seenNonces) {
        if (expiresAt <= now) seenNonces.delete(n)
      }
      if (seenNonces.has(nonce) || seenNonces.size >= nonceCacheSize) return
      seenNonces.set(nonce, now + nonceTtlMs)

      let statusCode = 200
      let payload: any = null

      try {
        payload = await onRequest(msg.route, msg.payload, msg, ws)
      } catch (err: any) {
        statusCode = 400
        payload = { error: 'Processing error' }
      }

      if (ws.readyState !== WebSocket.OPEN) return
      ws.send(
        JSON.stringify({
          type: 'response',
          id: msg.id,
          statusCode,
          payload,
        }),
        (error) => { if (error) ws.close(1011, 'Response delivery failed') }
      )
    })
  })
}
