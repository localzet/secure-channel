/**
 * Secure Channel Protocol
 * Hybrid WebSocket/HTTP protocol for secure service communication
 */

import WebSocket from 'ws'
import { EventEmitter } from 'events'

export interface SecureChannelOptions {
  gatewayUrl: string
  serviceId: string
  certificate: string // PEM format
  privateKey: string // PEM format
  caCertificate?: string // Root CA certificate
}

export interface RequestOptions {
  route: string
  expectReply?: boolean
  headers?: Record<string, string>
  payload?: any
}

export interface ChannelMessage {
  type: 'request' | 'response' | 'event' | 'command' | 'command-result'
  id?: string
  route?: string
  expectReply?: boolean
  statusCode?: number
  headers?: Record<string, string>
  payload?: any
  error?: string
}

/**
 * Secure Channel Client
 * Supports both request/response and full-duplex event streaming
 */
export class SecureChannel extends EventEmitter {
  private ws: WebSocket | null = null
  private gatewayUrl: string
  private serviceId: string
  private certificate: string
  private privateKey: string
  private caCertificate?: string
  private connected = false
  private pendingRequests = new Map<string, {
    resolve: (value: any) => void
    reject: (error: Error) => void
    timeout: NodeJS.Timeout
  }>()

  constructor(options: SecureChannelOptions) {
    super()
    this.gatewayUrl = options.gatewayUrl
    this.serviceId = options.serviceId
    this.certificate = options.certificate
    this.privateKey = options.privateKey
    this.caCertificate = options.caCertificate
  }

  /**
   * Connect to Gateway via secure channel
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        const url = this.gatewayUrl.replace('https://', 'wss://').replace('http://', 'ws://')
        const wsUrl = `${url}/secure-channel/${this.serviceId}`

        // Create WebSocket connection with TLS client certificate
        const ws = new WebSocket(wsUrl, {
          cert: this.certificate,
          key: this.privateKey,
          ca: this.caCertificate,
          rejectUnauthorized: !!this.caCertificate,
        })

        ws.on('open', () => {
          this.ws = ws
          this.connected = true
          this.emit('connected')
          resolve()
        })

        ws.on('message', (data: Buffer) => {
          try {
            const message: ChannelMessage = JSON.parse(data.toString())
            this.handleMessage(message)
          } catch (error) {
            console.error('Failed to parse message:', error)
          }
        })

        ws.on('error', (error) => {
          this.connected = false
          this.emit('error', error)
          reject(error)
        })

        ws.on('close', () => {
          this.connected = false
          this.emit('disconnected')
          // Auto-reconnect
          setTimeout(() => {
            if (!this.connected) {
              this.connect().catch(console.error)
            }
          }, 5000)
        })
      } catch (error) {
        reject(error)
      }
    })
  }

  /**
   * Send request (request/response mode)
   */
  async request(options: RequestOptions): Promise<any> {
    if (!this.connected || !this.ws) {
      throw new Error('Channel not connected')
    }

    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    const expectReply = options.expectReply !== false

    return new Promise((resolve, reject) => {
      let timeout: NodeJS.Timeout | undefined

      if (expectReply) {
        timeout = setTimeout(() => {
          this.pendingRequests.delete(requestId)
          reject(new Error('Request timeout'))
        }, 30000) // 30 seconds

        this.pendingRequests.set(requestId, { resolve, reject, timeout })
      }

      const message: ChannelMessage = {
        type: 'request',
        id: requestId,
        route: options.route,
        expectReply,
        headers: options.headers,
        payload: options.payload,
      }

      this.ws!.send(JSON.stringify(message))

      if (!expectReply) {
        resolve({ accepted: true })
      }
    })
  }

  /**
   * Send event (full-duplex mode)
   */
  send(data: { route?: string; payload?: any }): void {
    if (!this.connected || !this.ws) {
      throw new Error('Channel not connected')
    }

    const message: ChannelMessage = {
      type: 'event',
      route: data.route,
      payload: data.payload ?? data,
    }

    this.ws.send(JSON.stringify(message))
  }

  /**
   * Handle incoming messages
   */
  private handleMessage(message: ChannelMessage): void {
    if (message.type === 'response' && message.id) {
      // Handle request/response
      const pending = this.pendingRequests.get(message.id)
      if (pending) {
        clearTimeout(pending.timeout)
        this.pendingRequests.delete(message.id)

        const ok = message.statusCode === undefined || (message.statusCode >= 200 && message.statusCode < 300)
        ok ? pending.resolve(message.payload) : pending.reject(new Error(message.error || `Request failed with status ${message.statusCode}`))
      }
    } else if (message.type === 'command') {
      // Handle commands from Gateway
      this.emit('command', message)
    } else if (message.type === 'command-result') {
      this.emit('command-result', message)
    } else if (message.type === 'event') {
      // Handle events
      this.emit('message', message)
    }
  }

  /**
   * Disconnect
   */
  disconnect(): void {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.connected = false
    this.pendingRequests.forEach(({ timeout, reject }) => {
      clearTimeout(timeout)
      reject(new Error('Channel disconnected'))
    })
    this.pendingRequests.clear()
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.connected
  }
}

