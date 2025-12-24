const express = require('express');
const Database = require('better-sqlite3');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads', { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads');
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp|pdf|doc|docx/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Invalid file type'));
    }
});

// Initialize SQLite Database
const db = new Database('./database.sqlite');

// Create tables
db.exec(`
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        icon TEXT,
        description TEXT,
        clicks INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        mimetype TEXT,
        size INTEGER,
        path TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        page TEXT,
        action TEXT,
        ip TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

// Insert default links if table is empty
const linkCount = db.prepare('SELECT COUNT(*) as count FROM links').get();
if (linkCount.count === 0) {
    const insertLink = db.prepare('INSERT INTO links (title, url, icon, description, sort_order) VALUES (?, ?, ?, ?, ?)');
    insertLink.run('Instagram', 'https://instagram.com/celebritybiz1', 'fab fa-instagram', '@celebritybiz1 - Daily content & stories', 1);
    insertLink.run('YouTube', '#', 'fab fa-youtube', 'Long-form content & tutorials', 2);
    insertLink.run('TikTok', '#', 'fab fa-tiktok', 'Short-form viral content', 3);
    insertLink.run('Twitter / X', '#', 'fab fa-twitter', 'Thoughts & updates', 4);
    insertLink.run('LinkedIn', '#', 'fab fa-linkedin', 'Professional network', 5);
}

// ==================== API ROUTES ====================

// --- Contact Form ---
app.post('/api/contact', (req, res) => {
    try {
        const { name, email, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const stmt = db.prepare('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)');
        const result = stmt.run(name, email, message);
        
        res.json({ 
            success: true, 
            message: 'Message sent successfully!',
            id: result.lastInsertRowid 
        });
    } catch (error) {
        console.error('Contact error:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Get all contacts (admin)
app.get('/api/contacts', (req, res) => {
    try {
        const contacts = db.prepare('SELECT * FROM contacts ORDER BY created_at DESC').all();
        res.json(contacts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch contacts' });
    }
});

// Mark contact as read
app.patch('/api/contacts/:id/read', (req, res) => {
    try {
        const stmt = db.prepare('UPDATE contacts SET read = 1 WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update contact' });
    }
});

// Delete contact
app.delete('/api/contacts/:id', (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM contacts WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete contact' });
    }
});

// --- Newsletter Subscription ---
app.post('/api/subscribe', (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const stmt = db.prepare('INSERT OR IGNORE INTO subscribers (email) VALUES (?)');
        const result = stmt.run(email);
        
        if (result.changes === 0) {
            return res.json({ success: true, message: 'You are already subscribed!' });
        }
        
        res.json({ success: true, message: 'Successfully subscribed!' });
    } catch (error) {
        console.error('Subscribe error:', error);
        res.status(500).json({ error: 'Failed to subscribe' });
    }
});

// Get all subscribers (admin)
app.get('/api/subscribers', (req, res) => {
    try {
        const subscribers = db.prepare('SELECT * FROM subscribers ORDER BY created_at DESC').all();
        res.json(subscribers);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch subscribers' });
    }
});

// --- Links Management ---
app.get('/api/links', (req, res) => {
    try {
        const links = db.prepare('SELECT * FROM links WHERE active = 1 ORDER BY sort_order ASC').all();
        res.json(links);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch links' });
    }
});

app.post('/api/links', (req, res) => {
    try {
        const { title, url, icon, description } = req.body;
        const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM links').get();
        const sortOrder = (maxOrder.max || 0) + 1;
        
        const stmt = db.prepare('INSERT INTO links (title, url, icon, description, sort_order) VALUES (?, ?, ?, ?, ?)');
        const result = stmt.run(title, url, icon || 'fas fa-link', description || '', sortOrder);
        
        res.json({ success: true, id: result.lastInsertRowid });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.patch('/api/links/:id', (req, res) => {
    try {
        const { title, url, icon, description, active } = req.body;
        const stmt = db.prepare('UPDATE links SET title = ?, url = ?, icon = ?, description = ?, active = ? WHERE id = ?');
        stmt.run(title, url, icon, description, active ? 1 : 0, req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.delete('/api/links/:id', (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM links WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// Track link clicks
app.post('/api/links/:id/click', (req, res) => {
    try {
        const stmt = db.prepare('UPDATE links SET clicks = clicks + 1 WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to track click' });
    }
});

// --- File Upload ---
app.post('/api/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const stmt = db.prepare('INSERT INTO files (filename, original_name, mimetype, size, path) VALUES (?, ?, ?, ?, ?)');
        const result = stmt.run(
            req.file.filename,
            req.file.originalname,
            req.file.mimetype,
            req.file.size,
            req.file.path
        );

        res.json({
            success: true,
            file: {
                id: result.lastInsertRowid,
                filename: req.file.filename,
                originalName: req.file.originalname,
                url: `/uploads/${req.file.filename}`,
                size: req.file.size
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

// Get all uploaded files
app.get('/api/files', (req, res) => {
    try {
        const files = db.prepare('SELECT * FROM files ORDER BY created_at DESC').all();
        res.json(files);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch files' });
    }
});

// Delete file
app.delete('/api/files/:id', (req, res) => {
    try {
        const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
        if (file) {
            // Delete physical file
            if (fs.existsSync(file.path)) {
                fs.unlinkSync(file.path);
            }
            // Delete from database
            db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// --- Analytics ---
app.post('/api/analytics', (req, res) => {
    try {
        const { page, action } = req.body;
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];
        
        const stmt = db.prepare('INSERT INTO analytics (page, action, ip, user_agent) VALUES (?, ?, ?, ?)');
        stmt.run(page, action, ip, userAgent);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to log analytics' });
    }
});

// Get analytics summary
app.get('/api/analytics/summary', (req, res) => {
    try {
        const totalViews = db.prepare('SELECT COUNT(*) as count FROM analytics WHERE action = ?').get('pageview');
        const todayViews = db.prepare(`
            SELECT COUNT(*) as count FROM analytics 
            WHERE action = ? AND date(created_at) = date('now')
        `).get('pageview');
        const totalContacts = db.prepare('SELECT COUNT(*) as count FROM contacts').get();
        const totalSubscribers = db.prepare('SELECT COUNT(*) as count FROM subscribers WHERE active = 1').get();
        const totalClicks = db.prepare('SELECT SUM(clicks) as total FROM links').get();
        
        res.json({
            totalViews: totalViews.count,
            todayViews: todayViews.count,
            totalContacts: totalContacts.count,
            totalSubscribers: totalSubscribers.count,
            totalLinkClicks: totalClicks.total || 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

// --- Settings ---
app.get('/api/settings', (req, res) => {
    try {
        const settings = db.prepare('SELECT * FROM settings').all();
        const settingsObj = {};
        settings.forEach(s => settingsObj[s.key] = s.value);
        res.json(settingsObj);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.post('/api/settings', (req, res) => {
    try {
        const { key, value } = req.body;
        const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        stmt.run(key, value);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save setting' });
    }
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve admin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   🚀 Celebrity Wireless Server Running!               ║
    ║                                                       ║
    ║   📍 Main Site:  http://localhost:${PORT}               ║
    ║   📍 Admin:      http://localhost:${PORT}/admin         ║
    ║                                                       ║
    ║   📊 Database:   SQLite (./database.sqlite)           ║
    ║   📁 Uploads:    ./uploads/                           ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    `);
});

