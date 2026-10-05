const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const PORT = process.env.PORT || 8000;
const PUBLIC_DIR = __dirname;

// Detect local IPv4 address
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const devName in interfaces) {
    const iface = interfaces[devName];
    for (let i = 0; i < iface.length; i++) {
      const alias = iface[i];
      if (alias.family === 'IPv4' && !alias.internal && alias.address !== '127.0.0.1') {
        return alias.address;
      }
    }
  }
  return 'localhost';
}

const LOCAL_IP = getLocalIP();

// MIME Types
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
};

// Request Handler
function handleRequest(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let pathname = urlObj.pathname;

  // API endpoint for dynamic network info
  if (pathname === '/api/network-info') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ip: LOCAL_IP,
      port: PORT,
      url: `http://${LOCAL_IP}:${PORT}`,
      phoneUrl: `http://${LOCAL_IP}:${PORT}/phone.html`
    }));
    return;
  }

  if (pathname === '/') pathname = '/index.html';
  const filePath = path.join(PUBLIC_DIR, pathname);

  // Security: prevent directory traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
}

// Create HTTP Server
const server = http.createServer(handleRequest);

// In-Memory WebSocket signaling & video relay (Zero-dependency RFC 6455)
const clients = new Set();
const rooms = new Map(); // roomId -> Set of clients

server.on('upgrade', (req, socket, head) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.destroy();
    return;
  }

  const acceptKey = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  const headers = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
  ];

  socket.write(headers.join('\r\n') + '\r\n\r\n');

  const client = {
    socket,
    id: 'c_' + Math.random().toString(36).substr(2, 9),
    role: null, // 'desktop' | 'phone'
    roomId: null
  };
  clients.add(client);

  socket.on('data', (buffer) => {
    handleWsData(client, buffer);
  });

  socket.on('close', () => {
    clients.delete(client);
    if (client.roomId && rooms.has(client.roomId)) {
      const room = rooms.get(client.roomId);
      room.delete(client);
      if (room.size === 0) rooms.delete(client.roomId);
      else {
        broadcastToRoom(client.roomId, JSON.stringify({ type: 'peer-disconnected', role: client.role, id: client.id }), client);
      }
    }
  });

  socket.on('error', () => {
    socket.destroy();
  });
});

// RFC 6455 Frame Parser & Sender
function handleWsData(client, buffer) {
  if (buffer.length < 2) return;
  const firstByte = buffer[0];
  const secondByte = buffer[1];
  const opcode = firstByte & 0x0f;
  const isMasked = (secondByte & 0x80) !== 0;

  if (opcode === 0x8) { // Close frame
    client.socket.end();
    return;
  }
  if (opcode === 0x9) { // Ping frame
    sendWsFrame(client.socket, 0xa, Buffer.alloc(0)); // Pong
    return;
  }

  let payloadLength = secondByte & 0x7f;
  let offset = 2;

  if (payloadLength === 126) {
    payloadLength = buffer.readUInt16BE(2);
    offset = 4;
  } else if (payloadLength === 127) {
    payloadLength = Number(buffer.readBigUInt64BE(2));
    offset = 10;
  }

  let maskingKey = null;
  if (isMasked) {
    maskingKey = buffer.slice(offset, offset + 4);
    offset += 4;
  }

  const payload = buffer.slice(offset, offset + payloadLength);
  if (isMasked) {
    for (let i = 0; i < payload.length; i++) {
      payload[i] ^= maskingKey[i % 4];
    }
  }

  // Handle Text frame
  if (opcode === 0x1) {
    try {
      const text = payload.toString('utf8');
      const msg = JSON.parse(text);
      handleClientMessage(client, msg);
    } catch (e) {
      // Ignore parse error
    }
  } else if (opcode === 0x2) {
    // Binary video frame (e.g. JPEG blob from phone camera)
    // Forward directly to desktop in the same room
    if (client.roomId) {
      broadcastBinaryToRoom(client.roomId, payload, client);
    }
  }
}

function handleClientMessage(client, msg) {
  if (msg.type === 'join') {
    client.roomId = msg.room || 'default';
    client.role = msg.role || 'unknown';
    if (!rooms.has(client.roomId)) {
      rooms.set(client.roomId, new Set());
    }
    rooms.get(client.roomId).add(client);

    // Notify peers in room
    broadcastToRoom(client.roomId, JSON.stringify({
      type: 'peer-joined',
      role: client.role,
      id: client.id,
      timestamp: Date.now()
    }), client);

    sendWsFrame(client.socket, 0x1, Buffer.from(JSON.stringify({
      type: 'joined',
      roomId: client.roomId,
      clientId: client.id,
      localIP: LOCAL_IP
    })));
  } else if (msg.type === 'signal' || msg.type === 'camera-frame' || msg.type === 'telemetry') {
    // Relay signaling (SDP / ICE) or frame data to peers in room
    if (client.roomId) {
      broadcastToRoom(client.roomId, JSON.stringify(msg), client);
    }
  }
}

function broadcastToRoom(roomId, text, sender) {
  const room = rooms.get(roomId);
  if (!room) return;
  const payload = Buffer.from(text, 'utf8');
  for (const c of room) {
    if (c !== sender && c.socket.writable) {
      sendWsFrame(c.socket, 0x1, payload);
    }
  }
}

function broadcastBinaryToRoom(roomId, buffer, sender) {
  const room = rooms.get(roomId);
  if (!room) return;
  for (const c of room) {
    if (c !== sender && c.socket.writable) {
      sendWsFrame(c.socket, 0x2, buffer);
    }
  }
}

function sendWsFrame(socket, opcode, payload) {
  const len = payload.length;
  let header;

  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }

  socket.write(Buffer.concat([header, payload]));
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n======================================================`);
  console.log(`  PERIMETER SECURITY - SURVEILLANCE COMMAND SERVER`);
  console.log(`======================================================`);
  console.log(`  Desktop Dashboard : http://localhost:${PORT}`);
  console.log(`  Local Network     : http://${LOCAL_IP}:${PORT}`);
  console.log(`  Phone Camera Link : http://${LOCAL_IP}:${PORT}/phone.html`);
  console.log(`  WebSocket Relay   : ws://${LOCAL_IP}:${PORT}`);
  console.log(`======================================================\n`);
});
