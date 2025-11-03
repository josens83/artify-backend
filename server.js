/**
 * Canva Clone - Node.js Backend Server
 * 
 * @description 사용자 인증, 프로젝트 관리, 파일 업로드를 담당하는 Express 서버
 * @author 김도현
 * @version 1.0.0
 * @created 2025-01-25
 * 
 * Features:
 * - JWT 기반 사용자 인증
 * - SQLite 데이터베이스
 * - 프로젝트 CRUD API
 * - WebSocket 실시간 통신
 * - 이미지 업로드 & 내보내기
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const dotenv = require('dotenv');

// 환경 변수 로드
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// 업로드 폴더 생성
const uploadsDir = path.join(__dirname, 'uploads');
const exportsDir = path.join(__dirname, 'exports');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(exportsDir)) fs.mkdirSync(exportsDir, { recursive: true });

// 업로드 설정
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Database 설정
const dbPath = path.join(__dirname, 'canva-clone.db');
const db = new Database(dbPath);

// 데이터베이스 초기화
function initDatabase() {
    // Users 테이블
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Projects 테이블
    db.exec(`
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            canvas_data TEXT,
            canvas_width INTEGER DEFAULT 800,
            canvas_height INTEGER DEFAULT 1000,
            thumbnail TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Files 테이블
    db.exec(`
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            filetype TEXT,
            filesize INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    `);

    console.log('📁 Database initialized at:', dbPath);
}

initDatabase();

// JWT 인증 미들웨어
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ============================================
// AUTH ROUTES
// ============================================

// 회원가입
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        // 이메일 중복 확인
        const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        // 비밀번호 해싱
        const hashedPassword = await bcrypt.hash(password, 10);

        // 사용자 생성
        const result = db.prepare(
            'INSERT INTO users (email, password, name) VALUES (?, ?, ?)'
        ).run(email, hashedPassword, name);

        // JWT 토큰 생성
        const token = jwt.sign(
            { id: result.lastInsertRowid, email, name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: result.lastInsertRowid, email, name }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 로그인
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // 사용자 조회
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // 비밀번호 확인
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // JWT 토큰 생성
        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 사용자 정보 조회
app.get('/api/auth/me', authenticateToken, (req, res) => {
    try {
        const user = db.prepare('SELECT id, email, name, created_at FROM users WHERE id = ?')
            .get(req.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================
// PROJECT ROUTES
// ============================================

// 프로젝트 목록 조회
app.get('/api/projects', authenticateToken, (req, res) => {
    try {
        const projects = db.prepare(
            'SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC'
        ).all(req.user.id);

        // canvas_data를 JSON으로 파싱
        const projectsWithData = projects.map(project => ({
            ...project,
            canvas_data: project.canvas_data ? JSON.parse(project.canvas_data) : []
        }));

        res.json(projectsWithData);
    } catch (error) {
        console.error('Get projects error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 프로젝트 조회
app.get('/api/projects/:id', authenticateToken, (req, res) => {
    try {
        const project = db.prepare(
            'SELECT * FROM projects WHERE id = ? AND user_id = ?'
        ).get(req.params.id, req.user.id);

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        // canvas_data를 JSON으로 파싱
        project.canvas_data = project.canvas_data ? JSON.parse(project.canvas_data) : [];

        res.json(project);
    } catch (error) {
        console.error('Get project error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 프로젝트 생성
app.post('/api/projects', authenticateToken, (req, res) => {
    const { title, canvas_width, canvas_height } = req.body;

    try {
        const result = db.prepare(`
            INSERT INTO projects (user_id, title, canvas_width, canvas_height, canvas_data)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            req.user.id,
            title || 'Untitled Project',
            canvas_width || 800,
            canvas_height || 1000,
            JSON.stringify([])
        );

        const project = db.prepare('SELECT * FROM projects WHERE id = ?')
            .get(result.lastInsertRowid);

        project.canvas_data = JSON.parse(project.canvas_data);

        res.status(201).json(project);
    } catch (error) {
        console.error('Create project error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 프로젝트 수정
app.put('/api/projects/:id', authenticateToken, (req, res) => {
    const { title, canvas_data, canvas_width, canvas_height } = req.body;
    const projectId = req.params.id;

    try {
        // 프로젝트 소유자 확인
        const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
            .get(projectId, req.user.id);

        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        // 프로젝트 업데이트
        db.prepare(`
            UPDATE projects 
            SET title = ?, 
                canvas_data = ?, 
                canvas_width = ?, 
                canvas_height = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        `).run(
            title || project.title,
            JSON.stringify(canvas_data || []),
            canvas_width || project.canvas_width,
            canvas_height || project.canvas_height,
            projectId,
            req.user.id
        );

        const updatedProject = db.prepare('SELECT * FROM projects WHERE id = ?')
            .get(projectId);

        updatedProject.canvas_data = JSON.parse(updatedProject.canvas_data);

        res.json(updatedProject);
    } catch (error) {
        console.error('Update project error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 프로젝트 삭제 ✅ 수정됨
app.delete('/api/projects/:id', authenticateToken, (req, res) => {
    const projectId = req.params.id;
    const userId = req.user.id;

    console.log(`🗑️ Delete request: Project ${projectId} by User ${userId}`);

    try {
        // 1. 프로젝트 존재 및 소유권 확인
        const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
            .get(projectId, userId);

        if (!project) {
            console.log(`❌ Project not found or unauthorized: ${projectId}`);
            return res.status(404).json({ 
                error: 'Project not found or you do not have permission to delete it' 
            });
        }

        // 2. 연결된 파일 먼저 삭제 (Foreign Key 제약 해결)
        const deleteFiles = db.prepare('DELETE FROM files WHERE project_id = ?');
        const filesResult = deleteFiles.run(projectId);
        console.log(`🗑️ Deleted ${filesResult.changes} files for project ${projectId}`);

        // 3. 프로젝트 삭제
        const deleteProject = db.prepare('DELETE FROM projects WHERE id = ? AND user_id = ?');
        const result = deleteProject.run(projectId, userId);

        if (result.changes === 0) {
            console.log(`❌ Failed to delete project: ${projectId}`);
            return res.status(500).json({ 
                error: 'Failed to delete project' 
            });
        }

        console.log(`✅ Project deleted successfully: ${projectId}`);
        res.json({ 
            message: 'Project deleted successfully',
            deletedId: parseInt(projectId),
            filesDeleted: filesResult.changes
        });

    } catch (error) {
        console.error('❌ Delete project error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// ============================================
// FILE UPLOAD ROUTES
// ============================================

// 파일 업로드
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const fileUrl = `/uploads/${req.file.filename}`;

        res.json({
            message: 'File uploaded successfully',
            filename: req.file.filename,
            url: fileUrl,
            size: req.file.size,
            mimetype: req.file.mimetype
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'File upload failed' });
    }
});

// 업로드된 파일 제공
app.use('/uploads', express.static(uploadsDir));

// ============================================
// EXPORT ROUTES
// ============================================

// 프로젝트 내보내기 (PNG, JPG 등)
app.post('/api/export', authenticateToken, (req, res) => {
    const { projectId, format } = req.body;

    try {
        // 실제 구현에서는 캔버스를 이미지로 변환
        // 현재는 placeholder 응답
        res.json({
            message: 'Export functionality will be implemented',
            projectId,
            format,
            downloadUrl: '/exports/placeholder.png'
        });
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ error: 'Export failed' });
    }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        database: fs.existsSync(dbPath) ? 'connected' : 'disconnected'
    });
});

// Health check endpoint 추가 (기존 코드 아래에)
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'artify-backend'
    });
});
// ============================================
// WEBSOCKET (Optional)
// ============================================

const http = require('http');
const WebSocket = require('ws');

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    console.log('🔌 New WebSocket connection');

    ws.on('message', (message) => {
        console.log('📨 Received:', message.toString());
        
        // 브로드캐스트 (모든 클라이언트에게 전송)
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        console.log('🔌 WebSocket connection closed');
    });
});

console.log('WebSocket server initialized');

// ============================================
// START SERVER
// ============================================

server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📁 Serving files from: ${path.join(__dirname, '../frontend')}`);
    console.log(`📁 Database: ${dbPath}`);
    console.log(`📁 Uploads: ${uploadsDir}`);
    console.log(`📁 Exports: ${exportsDir}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...');
    db.close();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});