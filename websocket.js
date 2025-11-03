const WebSocket = require('ws');

class CollaborationServer {
    constructor(server) {
        this.wss = new WebSocket.Server({ server });
        this.rooms = new Map(); // projectId -> Set of clients
        this.clients = new Map(); // ws -> { userId, userName, projectId, color }

        this.wss.on('connection', (ws) => {
            console.log('New WebSocket connection');

            ws.on('message', (message) => {
                try {
                    const data = JSON.parse(message);
                    this.handleMessage(ws, data);
                } catch (err) {
                    console.error('WebSocket message error:', err);
                }
            });

            ws.on('close', () => {
                this.handleDisconnect(ws);
            });

            ws.on('error', (error) => {
                console.error('WebSocket error:', error);
            });
        });

        console.log('WebSocket server initialized');
    }

    handleMessage(ws, data) {
        const { type, payload } = data;

        switch (type) {
            case 'join':
                this.handleJoin(ws, payload);
                break;
            case 'leave':
                this.handleLeave(ws);
                break;
            case 'cursor':
                this.broadcastToRoom(ws, { type: 'cursor', payload });
                break;
            case 'element-update':
                this.broadcastToRoom(ws, { type: 'element-update', payload });
                break;
            case 'element-add':
                this.broadcastToRoom(ws, { type: 'element-add', payload });
                break;
            case 'element-delete':
                this.broadcastToRoom(ws, { type: 'element-delete', payload });
                break;
            case 'selection':
                this.broadcastToRoom(ws, { type: 'selection', payload });
                break;
            default:
                console.log('Unknown message type:', type);
        }
    }

    handleJoin(ws, payload) {
        const { projectId, userId, userName } = payload;
        const color = this.getRandomColor();

        // Store client info
        this.clients.set(ws, { userId, userName, projectId, color });

        // Add to room
        if (!this.rooms.has(projectId)) {
            this.rooms.set(projectId, new Set());
        }
        this.rooms.get(projectId).add(ws);

        console.log(`User ${userName} joined project ${projectId}`);

        // Send current users to the new client
        const users = this.getUsersInRoom(projectId);
        ws.send(JSON.stringify({
            type: 'users',
            payload: { users }
        }));

        // Broadcast new user to others
        this.broadcastToRoom(ws, {
            type: 'user-joined',
            payload: { userId, userName, color }
        });
    }

    handleLeave(ws) {
        const client = this.clients.get(ws);
        if (!client) return;

        const { projectId, userId, userName } = client;

        // Remove from room
        if (this.rooms.has(projectId)) {
            this.rooms.get(projectId).delete(ws);
            if (this.rooms.get(projectId).size === 0) {
                this.rooms.delete(projectId);
            }
        }

        // Remove client
        this.clients.delete(ws);

        console.log(`User ${userName} left project ${projectId}`);

        // Broadcast user left
        this.broadcastToRoom(ws, {
            type: 'user-left',
            payload: { userId, userName }
        }, projectId);
    }

    handleDisconnect(ws) {
        this.handleLeave(ws);
    }

    broadcastToRoom(ws, message, roomId = null) {
        const client = this.clients.get(ws);
        if (!client && !roomId) return;

        const projectId = roomId || client.projectId;
        const room = this.rooms.get(projectId);
        
        if (!room) return;

        const messageStr = JSON.stringify({
            ...message,
            sender: client ? {
                userId: client.userId,
                userName: client.userName,
                color: client.color
            } : null
        });

        room.forEach(clientWs => {
            if (clientWs !== ws && clientWs.readyState === WebSocket.OPEN) {
                clientWs.send(messageStr);
            }
        });
    }

    getUsersInRoom(projectId) {
        const room = this.rooms.get(projectId);
        if (!room) return [];

        const users = [];
        room.forEach(ws => {
            const client = this.clients.get(ws);
            if (client) {
                users.push({
                    userId: client.userId,
                    userName: client.userName,
                    color: client.color
                });
            }
        });

        return users;
    }

    getRandomColor() {
        const colors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A',
            '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2'
        ];
        return colors[Math.floor(Math.random() * colors.length)];
    }
}

module.exports = CollaborationServer;