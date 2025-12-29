const express = require('express');
const Database = require('better-sqlite3');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (required when behind nginx/reverse proxy)
app.set('trust proxy', 1);

// ==================== SECURITY CONFIGURATION ====================

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    crossOriginEmbedderPolicy: false,
}));

// Rate limiting - general
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});

// Rate limiting - strict for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts per windowMs
    message: { error: 'Too many login attempts, please try again in 15 minutes.' },
    skipSuccessfulRequests: true
});

// Rate limiting - API endpoints
const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // limit each IP to 30 API requests per minute
    message: { error: 'Too many API requests, please slow down.' }
});

app.use(generalLimiter);

// Session configuration
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'cw_session', // Custom session name
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    }
}));

// Middleware
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://celebritywireless.com', 'https://www.celebritywireless.com']
        : true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
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

// ==================== PASSWORD HASHING UTILITIES ====================

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return hash === verifyHash;
}

// ==================== DATABASE TABLES ====================

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
        uploaded_by INTEGER,
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

    -- NEW: Admin users table
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT DEFAULT 'admin',
        active INTEGER DEFAULT 1,
        last_login DATETIME,
        login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- NEW: Login audit log
    CREATE TABLE IF NOT EXISTS login_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        user_agent TEXT,
        success INTEGER,
        reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- NEW: Session tokens table for additional security
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE NOT NULL,
        ip TEXT,
        user_agent TEXT,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES admin_users(id)
    );
`);

// Create default admin user if none exists
const adminCount = db.prepare('SELECT COUNT(*) as count FROM admin_users').get();
if (adminCount.count === 0) {
    const defaultPassword = 'CelebAdmin2024!'; // Change this immediately!
    const hashedPassword = hashPassword(defaultPassword);
    
    const insertAdmin = db.prepare('INSERT INTO admin_users (username, password_hash, email, role) VALUES (?, ?, ?, ?)');
    insertAdmin.run('admin', hashedPassword, 'admin@celebritywireless.com', 'superadmin');
    
    console.log('\n⚠️  DEFAULT ADMIN CREATED:');
    console.log('   Username: admin');
    console.log('   Password: CelebAdmin2024!');
    console.log('   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!\n');
}

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

// ==================== AUTHENTICATION MIDDLEWARE ====================

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        // Verify user still exists and is active
        const user = db.prepare('SELECT id, username, role, active FROM admin_users WHERE id = ? AND active = 1').get(req.session.userId);
        if (user) {
            req.user = user;
            return next();
        }
    }
    res.status(401).json({ error: 'Unauthorized. Please log in.' });
}

function isSuperAdmin(req, res, next) {
    if (req.user && req.user.role === 'superadmin') {
        return next();
    }
    res.status(403).json({ error: 'Access denied. Superadmin required.' });
}

function logLoginAttempt(username, ip, userAgent, success, reason = null) {
    const stmt = db.prepare('INSERT INTO login_audit (username, ip, user_agent, success, reason) VALUES (?, ?, ?, ?, ?)');
    stmt.run(username, ip, userAgent, success ? 1 : 0, reason);
}

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', loginLimiter, (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        if (!username || !password) {
            logLoginAttempt(username, ip, userAgent, false, 'Missing credentials');
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);

        if (!user) {
            logLoginAttempt(username, ip, userAgent, false, 'User not found');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if account is locked
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            logLoginAttempt(username, ip, userAgent, false, 'Account locked');
            return res.status(423).json({ error: 'Account is temporarily locked. Try again later.' });
        }

        // Check if account is active
        if (!user.active) {
            logLoginAttempt(username, ip, userAgent, false, 'Account disabled');
            return res.status(403).json({ error: 'Account has been disabled' });
        }

        // Verify password
        if (!verifyPassword(password, user.password_hash)) {
            // Increment failed attempts
            const newAttempts = (user.login_attempts || 0) + 1;
            let lockedUntil = null;

            // Lock account after 5 failed attempts for 30 minutes
            if (newAttempts >= 5) {
                lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
            }

            db.prepare('UPDATE admin_users SET login_attempts = ?, locked_until = ? WHERE id = ?')
                .run(newAttempts, lockedUntil, user.id);

            logLoginAttempt(username, ip, userAgent, false, 'Invalid password');
            return res.status(401).json({ 
                error: 'Invalid credentials',
                attemptsRemaining: Math.max(0, 5 - newAttempts)
            });
        }

        // Successful login - reset attempts and update last login
        db.prepare('UPDATE admin_users SET login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?')
            .run(new Date().toISOString(), user.id);

        // Create session
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;

        logLoginAttempt(username, ip, userAgent, true, 'Success');

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('cw_session');
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// Check auth status
app.get('/api/auth/status', (req, res) => {
    if (req.session && req.session.userId) {
        const user = db.prepare('SELECT id, username, email, role FROM admin_users WHERE id = ?').get(req.session.userId);
        if (user) {
            return res.json({ authenticated: true, user });
        }
    }
    res.json({ authenticated: false });
});

// Change password
app.post('/api/auth/change-password', isAuthenticated, (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new password are required' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters' });
        }

        // Verify current password
        const user = db.prepare('SELECT password_hash FROM admin_users WHERE id = ?').get(req.user.id);
        if (!verifyPassword(currentPassword, user.password_hash)) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Update password
        const newHash = hashPassword(newPassword);
        db.prepare('UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?')
            .run(newHash, new Date().toISOString(), req.user.id);

        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// ==================== ADMIN USER MANAGEMENT (Superadmin only) ====================

app.get('/api/admin/users', isAuthenticated, isSuperAdmin, (req, res) => {
    try {
        const users = db.prepare('SELECT id, username, email, role, active, last_login, created_at FROM admin_users').all();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/admin/users', isAuthenticated, isSuperAdmin, (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        const hashedPassword = hashPassword(password);
        const stmt = db.prepare('INSERT INTO admin_users (username, password_hash, email, role) VALUES (?, ?, ?, ?)');
        const result = stmt.run(username, hashedPassword, email, role || 'admin');

        res.json({ success: true, id: result.lastInsertRowid });
    } catch (error) {
        if (error.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.delete('/api/admin/users/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    try {
        // Prevent deleting yourself
        if (parseInt(req.params.id) === req.user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        db.prepare('DELETE FROM admin_users WHERE id = ?').run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Get login audit log
app.get('/api/admin/audit-log', isAuthenticated, isSuperAdmin, (req, res) => {
    try {
        const logs = db.prepare('SELECT * FROM login_audit ORDER BY created_at DESC LIMIT 100').all();
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch audit log' });
    }
});

// ==================== PROTECTED API ROUTES ====================

// Apply API rate limiter to all /api routes
app.use('/api', apiLimiter);

// --- Contact Form (Public - but rate limited) ---
app.post('/api/contact', (req, res) => {
    try {
        const { name, email, message } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Sanitize inputs (basic XSS prevention)
        const sanitizedName = name.replace(/<[^>]*>/g, '').trim();
        const sanitizedMessage = message.replace(/<[^>]*>/g, '').trim();

        const stmt = db.prepare('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)');
        const result = stmt.run(sanitizedName, email, sanitizedMessage);
        
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

// Get all contacts (admin only)
app.get('/api/contacts', isAuthenticated, (req, res) => {
    try {
        const contacts = db.prepare('SELECT * FROM contacts ORDER BY created_at DESC').all();
        res.json(contacts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch contacts' });
    }
});

// Mark contact as read (admin only)
app.patch('/api/contacts/:id/read', isAuthenticated, (req, res) => {
    try {
        const stmt = db.prepare('UPDATE contacts SET read = 1 WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update contact' });
    }
});

// Delete contact (admin only)
app.delete('/api/contacts/:id', isAuthenticated, (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM contacts WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete contact' });
    }
});

// --- Newsletter Subscription (Public - but rate limited) ---
app.post('/api/subscribe', (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const stmt = db.prepare('INSERT OR IGNORE INTO subscribers (email) VALUES (?)');
        const result = stmt.run(email.toLowerCase().trim());
        
        if (result.changes === 0) {
            return res.json({ success: true, message: 'You are already subscribed!' });
        }
        
        res.json({ success: true, message: 'Successfully subscribed!' });
    } catch (error) {
        console.error('Subscribe error:', error);
        res.status(500).json({ error: 'Failed to subscribe' });
    }
});

// Get all subscribers (admin only)
app.get('/api/subscribers', isAuthenticated, (req, res) => {
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

app.post('/api/links', isAuthenticated, (req, res) => {
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

app.patch('/api/links/:id', isAuthenticated, (req, res) => {
    try {
        const { title, url, icon, description, active } = req.body;
        const stmt = db.prepare('UPDATE links SET title = ?, url = ?, icon = ?, description = ?, active = ? WHERE id = ?');
        stmt.run(title, url, icon, description, active ? 1 : 0, req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.delete('/api/links/:id', isAuthenticated, (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM links WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// Track link clicks (public)
app.post('/api/links/:id/click', (req, res) => {
    try {
        const stmt = db.prepare('UPDATE links SET clicks = clicks + 1 WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to track click' });
    }
});

// --- File Upload (admin only) ---
app.post('/api/upload', isAuthenticated, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const stmt = db.prepare('INSERT INTO files (filename, original_name, mimetype, size, path, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)');
        const result = stmt.run(
            req.file.filename,
            req.file.originalname,
            req.file.mimetype,
            req.file.size,
            req.file.path,
            req.user.id
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

// Get all uploaded files (admin only)
app.get('/api/files', isAuthenticated, (req, res) => {
    try {
        const files = db.prepare('SELECT * FROM files ORDER BY created_at DESC').all();
        res.json(files);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch files' });
    }
});

// Delete file (admin only)
app.delete('/api/files/:id', isAuthenticated, (req, res) => {
    try {
        const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
        if (file) {
            if (fs.existsSync(file.path)) {
                fs.unlinkSync(file.path);
            }
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
        const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];
        
        const stmt = db.prepare('INSERT INTO analytics (page, action, ip, user_agent) VALUES (?, ?, ?, ?)');
        stmt.run(page, action, ip, userAgent);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to log analytics' });
    }
});

// Get analytics summary (admin only)
app.get('/api/analytics/summary', isAuthenticated, (req, res) => {
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

// --- Settings (admin only) ---
app.get('/api/settings', isAuthenticated, (req, res) => {
    try {
        const settings = db.prepare('SELECT * FROM settings').all();
        const settingsObj = {};
        settings.forEach(s => settingsObj[s.key] = s.value);
        res.json(settingsObj);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.post('/api/settings', isAuthenticated, (req, res) => {
    try {
        const { key, value } = req.body;
        const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        stmt.run(key, value);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save setting' });
    }
});

// ==================== PAGE ROUTES ====================

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve admin page (SERVER-SIDE PROTECTED)
app.get('/admin', (req, res) => {
    // Check if user has valid session
    if (!req.session || !req.session.userId) {
        // Not authenticated - redirect to login
        return res.redirect('/login');
    }
    
    // Verify user still exists and is active
    const user = db.prepare('SELECT id, active FROM admin_users WHERE id = ? AND active = 1').get(req.session.userId);
    if (!user) {
        // Invalid session - destroy and redirect
        req.session.destroy();
        return res.redirect('/login');
    }
    
    // Authenticated - serve admin page
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🔒 Celebrity Wireless Server (SECURE MODE)                  ║
    ║                                                               ║
    ║   📍 Main Site:  http://localhost:${PORT}                       ║
    ║   📍 Login:      http://localhost:${PORT}/login                 ║
    ║   📍 Admin:      http://localhost:${PORT}/admin                 ║
    ║                                                               ║
    ║   🛡️  Security Features:                                      ║
    ║      ✓ Session-based authentication                          ║
    ║      ✓ Password hashing (PBKDF2-SHA512)                       ║
    ║      ✓ Rate limiting (login & API)                           ║
    ║      ✓ Account lockout (5 failed attempts)                   ║
    ║      ✓ Security headers (Helmet)                             ║
    ║      ✓ CORS protection                                       ║
    ║      ✓ Login audit logging                                   ║
    ║                                                               ║
    ║   📊 Database:   SQLite (./database.sqlite)                   ║
    ║   📁 Uploads:    ./uploads/                                   ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    `);
});
