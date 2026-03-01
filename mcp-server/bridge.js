// Origami Extension Bridge
// WebSocket server that the Chrome extension connects to as a client.
// Routes MCP tool calls to the extension and returns results.

import { WebSocketServer } from 'ws';
import { randomUUID, randomBytes } from 'node:crypto';

export class ExtensionBridge {
  constructor(port, log) {
    this.port = port;
    this.log = log || (() => {});
    this.ws = null;         // Active WebSocket connection (single extension client)
    this.wss = null;        // WebSocket server instance
    this.connectedAt = null;
    this.lastActivity = null;
    this._pending = new Map(); // requestId → { resolve, reject, timer }
    // Auth token — generated once per server session, must be presented by extension
    this.authToken = process.env.ORIGAMI_WS_TOKEN || randomBytes(24).toString('hex');
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.wss = new WebSocketServer({
        host: '127.0.0.1',
        port: this.port,
        maxPayload: 16 * 1024 * 1024, // 16MB max message size for large scan data
      });

      this.wss.on('listening', () => {
        this.log('WebSocket server ready on port ' + this.port);
        resolve();
      });

      this.wss.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          reject(new Error(`Port ${this.port} is already in use. Set ORIGAMI_WS_PORT env var to use a different port.`));
        } else {
          reject(err);
        }
      });

      this.wss.on('connection', (socket, req) => {
        const origin = req.headers.origin || 'unknown';
        this.log('Extension connected from: ' + origin);

        // Validate auth token from URL query parameter: ws://host:port/?token=xxx
        const url = new URL(req.url, 'http://localhost');
        const clientToken = url.searchParams.get('token');
        if (clientToken !== this.authToken) {
          this.log('Rejected connection: invalid auth token');
          socket.close(4001, 'Invalid auth token');
          return;
        }

        // Only allow one connection at a time
        if (this.ws) {
          this.log('Replacing existing connection');
          this.ws.close(1000, 'replaced');
        }

        this.ws = socket;
        this.connectedAt = new Date().toISOString();
        this.lastActivity = this.connectedAt;

        socket.on('message', (data) => {
          this.lastActivity = new Date().toISOString();
          this._handleMessage(data);
        });

        socket.on('close', (code, reason) => {
          this.log('Extension disconnected: ' + code + ' ' + reason);
          if (this.ws === socket) {
            this.ws = null;
            this.connectedAt = null;
          }
          // Reject all pending requests
          for (const [id, pending] of this._pending) {
            clearTimeout(pending.timer);
            pending.reject(new Error('Extension disconnected'));
          }
          this._pending.clear();
        });

        socket.on('error', (err) => {
          this.log('WebSocket error: ' + err.message);
        });

        // Send handshake
        socket.send(JSON.stringify({
          type: 'handshake',
          server: 'origami-mcp',
          version: '1.0.0',
          timestamp: this.connectedAt,
        }));
      });
    });
  }

  isConnected() {
    return this.ws !== null && this.ws.readyState === 1; // WebSocket.OPEN
  }

  // Send a request to the extension and wait for a response
  async send(action, params = {}, timeoutMs = 30000) {
    if (!this.isConnected()) {
      throw new Error('Extension not connected');
    }

    const requestId = randomUUID();

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(requestId);
        reject(new Error(`Request timed out after ${timeoutMs}ms: ${action}`));
      }, timeoutMs);

      this._pending.set(requestId, { resolve, reject, timer });

      const message = JSON.stringify({
        type: 'request',
        id: requestId,
        action,
        params,
      });

      this.ws.send(message, (err) => {
        if (err) {
          this._pending.delete(requestId);
          clearTimeout(timer);
          reject(new Error('Failed to send message: ' + err.message));
        }
      });
    });
  }

  // Handle incoming messages from the extension
  _handleMessage(raw) {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (e) {
      this.log('Invalid JSON from extension: ' + e.message);
      return;
    }

    // Response to a pending request
    if (msg.type === 'response' && msg.id) {
      const pending = this._pending.get(msg.id);
      if (pending) {
        this._pending.delete(msg.id);
        clearTimeout(pending.timer);

        if (msg.error) {
          pending.reject(new Error(msg.error));
        } else {
          pending.resolve(msg.data);
        }
      } else {
        this.log('Received response for unknown/timed-out request: ' + msg.id);
      }
      return;
    }

    // Push notification from extension (e.g., scan complete, new finding)
    if (msg.type === 'event') {
      this.log('Extension event: ' + msg.event);
      // Future: could emit events for MCP resource subscriptions
      return;
    }

    this.log('Unknown message type: ' + (msg.type || 'undefined'));
  }

  async stop() {
    if (this.ws) {
      this.ws.close(1000, 'server shutdown');
      this.ws = null;
    }
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }
  }
}
