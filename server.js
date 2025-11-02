// ==================== DEPENDENCIES ====================
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// ==================== INITIALIZATION ====================
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this';
const PAYMONGO_SECRET_KEY = process.env.PAYMONGO_SECRET_KEY;
const PAYMONGO_API_BASE = 'https://api.paymongo.com/v1';

// Create HTTP server and Socket.IO
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('Public'));

// ==================== DATABASE CONNECTION ====================
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'kusina_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Debug mode
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
  });
}

// Test database connection
db.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully!');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

// ==================== GOOGLE OAUTH ====================
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ==================== EMAIL SERVICE ====================
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// Verify email configuration
emailTransporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email configuration error:', error.message);
  } else {
    console.log('✅ Email service ready');
  }
});

// ==================== VERIFICATION CODE STORAGE ====================
const verificationCodes = new Map();
const loginVerificationCodes = new Map();

// Cleanup expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  
  for (const [email, data] of verificationCodes.entries()) {
    if (now > data.expiresAt) {
      verificationCodes.delete(email);
      console.log(`🗑️ Cleaned up expired signup code for: ${email}`);
    }
  }
  
  for (const [email, data] of loginVerificationCodes.entries()) {
    if (now > data.expiresAt) {
      loginVerificationCodes.delete(email);
      console.log(`🗑️ Cleaned up expired login code for: ${email}`);
    }
  }
}, 5 * 60 * 1000);

// ==================== HELPER FUNCTIONS ====================

// Generate 6-digit verification code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// PayMongo authentication header
const getPayMongoAuth = () => {
  if (!PAYMONGO_SECRET_KEY) {
    throw new Error('PayMongo secret key not configured');
  }
  const auth = Buffer.from(PAYMONGO_SECRET_KEY + ':').toString('base64');
  return `Basic ${auth}`;
};

// PayMongo API request helper
const payMongoRequest = async (endpoint, method = 'POST', data = null) => {
  try {
    const config = {
      method,
      url: `${PAYMONGO_API_BASE}${endpoint}`,
      headers: {
        'Authorization': getPayMongoAuth(),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    };

    if (data) {
      config.data = data;
    }

    const response = await axios(config);
    return { success: true, data: response.data };
  } catch (error) {
    console.error('PayMongo API Error:', error.response?.data || error.message);
    return { 
      success: false, 
      error: error.response?.data?.errors?.[0]?.detail || error.message 
    };
  }
};

// Send verification email
async function sendVerificationEmail(toEmail, code, userName = 'Valued Customer') {
  const mailOptions = {
    from: {
      name: 'Kusina ni Katya',
      address: process.env.MAIL_USER
    },
    to: toEmail,
    subject: 'Your Verification Code - Kusina ni Katya',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: 'Segoe UI', sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #cda45e 0%, #b8924e 100%); color: white; padding: 30px; text-align: center; }
          .header h1 { margin: 10px 0 0 0; font-size: 28px; }
          .content { padding: 40px 30px; text-align: center; }
          .code-box { background: #f8f9fa; border: 2px dashed #cda45e; border-radius: 10px; padding: 25px; margin: 30px 0; }
          .code { font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #cda45e; font-family: 'Courier New', monospace; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; text-align: left; border-radius: 5px; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Kusina ni Katya</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Authentic Filipino Cuisine</p>
          </div>
          
          <div class="content">
            <p style="font-size: 18px; color: #333; margin-bottom: 20px;">Hello ${userName}! 👋</p>
            <p style="font-size: 16px; color: #666; margin-bottom: 30px;">
              Thank you for signing up with Kusina ni Katya. To complete your registration, 
              please use the verification code below:
            </p>
            
            <div class="code-box">
              <p style="margin: 0; font-size: 14px; color: #666;">Your Verification Code</p>
              <div class="code">${code}</div>
              <p style="color: #999; font-size: 14px; margin-top: 15px;">This code will expire in 10 minutes</p>
            </div>
            
            <div class="warning">
              <strong style="color: #856404;">🔒 Security Notice:</strong><br>
              Never share this code with anyone. Kusina ni Katya staff will never ask for this code.
              If you didn't request this code, please ignore this email.
            </div>
          </div>
          
          <div class="footer">
            <p style="margin: 0 0 10px 0;">© 2025 Kusina ni Katya. All Rights Reserved.</p>
            <p style="margin: 0;">Aurora Blvd, Quezon City, Manila, Philippines</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  try {
    const info = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Verification email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Error sending email:', error.message);
    throw error;
  }
}

// Send login verification email
async function sendLoginVerificationEmail(toEmail, code, userName = 'Valued Customer') {
  const mailOptions = {
    from: {
      name: 'Kusina ni Katya',
      address: process.env.MAIL_USER
    },
    to: toEmail,
    subject: 'Login Verification Code - Kusina ni Katya',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: 'Segoe UI', sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
          .header { background: linear-gradient(135deg, #cda45e 0%, #b8924e 100%); color: white; padding: 30px; text-align: center; }
          .header h1 { margin: 0; font-size: 28px; }
          .content { padding: 40px 30px; text-align: center; }
          .code-box { background: #f8f9fa; border: 2px dashed #cda45e; border-radius: 10px; padding: 25px; margin: 30px 0; }
          .code { font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #cda45e; font-family: 'Courier New', monospace; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; text-align: left; border-radius: 5px; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Kusina ni Katya</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Authentic Filipino Cuisine</p>
          </div>
          
          <div class="content">
            <p style="font-size: 18px; color: #333; margin-bottom: 20px;">Hello ${userName}! 👋</p>
            <p style="font-size: 16px; color: #666; margin-bottom: 30px;">
              Someone is trying to sign in to your account. Please use the code below to verify your login:
            </p>
            
            <div class="code-box">
              <p style="margin: 0; font-size: 14px; color: #666;">Your Login Verification Code</p>
              <div class="code">${code}</div>
              <p style="color: #999; font-size: 14px; margin-top: 15px;">This code will expire in 10 minutes</p>
            </div>
            
            <div class="warning">
              <strong style="color: #856404;">⚠️ Security Notice:</strong><br>
              If you didn't attempt to sign in, please ignore this email and consider changing your password immediately.
              Never share this code with anyone.
            </div>
          </div>
          
          <div class="footer">
            <p style="margin: 0 0 10px 0;">© 2025 Kusina ni Katya. All Rights Reserved.</p>
            <p style="margin: 0;">Aurora Blvd, Quezon City, Manila, Philippines</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  try {
    const info = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Login verification email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Error sending login email:', error.message);
    throw error;
  }
}

// ==================== JWT MIDDLEWARE ====================
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

// Admin verification middleware
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Access denied. Admin only.' });
  }
  next();
};

// ==================== FILE UPLOAD SETUP ====================
const uploadsDir = path.join(__dirname, 'public', 'assets', 'images', 'menu');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('✅ Created menu uploads directory:', uploadsDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    let itemName = req.body.itemName || 'menu-item';
    
    const slug = itemName
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();
    
    const timestamp = Date.now();
    const filename = `${slug}-${timestamp}${ext}`;
    
    console.log('📁 Generating filename:', filename);
    cb(null, filename);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'));
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB max
  },
  fileFilter: fileFilter
});

// ==================== SOCKET.IO REAL-TIME ====================
const activeTrackingSessions = new Map();

io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);
  
  // Handle user joining their specific room
  socket.on('join-user', async (data) => {
    const { userId } = data;
    if (!userId) {
      console.log('⚠️ join-user: No userId provided');
      return;
    }
    
    // Join user-specific room
    const roomName = `user-${userId}`;
    socket.join(roomName);
    console.log(`[SOCKET][USER_${userId}] User joined room: ${roomName}`);
  });
  
  socket.on('track-order', (data) => {
    const { orderId } = data;
    console.log(`📍 Client ${socket.id} started tracking order: ${orderId}`);
    socket.join(`order-${orderId}`);
    
    if (!activeTrackingSessions.has(orderId)) {
      activeTrackingSessions.set(orderId, new Set());
    }
    activeTrackingSessions.get(orderId).add(socket.id);
    
    socket.emit('tracking-started', { orderId, message: 'Real-time tracking enabled' });
  });
  
  socket.on('update-location', (data) => {
    const { orderId, latitude, longitude } = data;
    io.to(`order-${orderId}`).emit('location-update', {
      orderId,
      latitude,
      longitude,
      timestamp: new Date().toISOString()
    });
    console.log(`📍 Location updated for order ${orderId}: [${latitude}, ${longitude}]`);
  });
  
  socket.on('stop-tracking', (data) => {
    const { orderId } = data;
    console.log(`🛑 Client ${socket.id} stopped tracking order: ${orderId}`);
    socket.leave(`order-${orderId}`);
    
    if (activeTrackingSessions.has(orderId)) {
      activeTrackingSessions.get(orderId).delete(socket.id);
      if (activeTrackingSessions.get(orderId).size === 0) {
        activeTrackingSessions.delete(orderId);
      }
    }
  });
  
  socket.on('order-delivered', (data) => {
    const { orderId } = data;
    console.log(`✅ Order ${orderId} marked as delivered`);
    
    io.to(`order-${orderId}`).emit('order-status-changed', {
      orderId,
      status: 'delivered',
      message: 'Your order has been delivered!',
      timestamp: new Date().toISOString()
    });
    
    db.query('UPDATE orders SET delivery_status = ? WHERE order_id = ?', ['delivered', orderId])
      .catch(err => console.error('Error updating order status:', err));
  });
  
  socket.on('admin-update-status', async (data) => {
    const { orderId, deliveryStatus } = data;
    console.log(`👨‍💼 Admin updating order ${orderId} status to: ${deliveryStatus}`);
    
    try {
      await db.query('UPDATE orders SET delivery_status = ? WHERE order_id = ?', [deliveryStatus, orderId]);
      
      // Get user_id to notify user room
      const [rows] = await db.query('SELECT user_id FROM orders WHERE order_id = ?', [orderId]);
      const userId = rows.length > 0 ? rows[0].user_id : null;
      
      // Notify order room
      io.to(`order-${orderId}`).emit('order-status-changed', {
        orderId,
        status: deliveryStatus,
        timestamp: new Date().toISOString()
      });
      
      // Notify user room
      if (userId) {
        io.to(`user-${userId}`).emit('order-status-changed', {
          orderId,
          status: deliveryStatus,
          timestamp: new Date().toISOString()
        });
        console.log(`[SOCKET][USER_${userId}] order-status-changed event triggered for order ${orderId}`);
      }
      
      socket.emit('status-update-success', { orderId, deliveryStatus });
    } catch (error) {
      console.error('Error updating status:', error);
      socket.emit('status-update-error', { orderId, error: error.message });
    }
  });
  
  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
    
    for (const [orderId, socketIds] of activeTrackingSessions.entries()) {
      socketIds.delete(socket.id);
      if (socketIds.size === 0) {
        activeTrackingSessions.delete(orderId);
      }
    }
  });
  
  socket.on('admin-connect', () => {
    console.log('👨‍💼 Admin connected:', socket.id);
    socket.join('admin-room');
  });
});

// Helper functions for broadcasting
function broadcastNewOrder(orderData) {
  io.to('admin-room').emit('new-order', orderData);
}

function broadcastOrderUpdate(orderId, updateData) {
  // Notify admin room
  io.to('admin-room').emit('order-updated', { orderId, ...updateData });
  
  // Notify order room
  io.to(`order-${orderId}`).emit('order-status-changed', { orderId, ...updateData });
  
  // Get user_id from order and notify user room
  db.query('SELECT user_id FROM orders WHERE order_id = ?', [orderId])
    .then(([rows]) => {
      if (rows.length > 0 && rows[0].user_id) {
        const userId = rows[0].user_id;
        io.to(`user-${userId}`).emit('order-status-changed', { orderId, ...updateData });
        console.log(`[SOCKET][USER_${userId}] order-status-changed event triggered for order ${orderId}`);
      }
    })
    .catch(err => console.error('Error getting user_id for order update:', err));
}

// ==================== AUTHENTICATION ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    paymongo: PAYMONGO_SECRET_KEY ? 'configured' : 'not configured',
    email: process.env.MAIL_USER ? 'configured' : 'not configured',
    socketio: 'enabled',
    activeTrackingSessions: activeTrackingSessions.size
  });
});

// Step 1: Signup - Send verification code
app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email, and password are required' 
      });
    }

    const [existingUsers] = await db.query(
      'SELECT id, email FROM users WHERE email = ?', 
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is already registered. Please sign in instead.' 
      });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const verificationCode = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    verificationCodes.set(email, {
      code: verificationCode,
      expiresAt,
      userData: {
        name,
        email,
        phone: phone || null,
        password: hashedPassword
      }
    });

    try {
      await sendVerificationEmail(email, verificationCode, name);
      console.log(`✅ Verification code sent to ${email}`);

      res.json({ 
        success: true,
        message: 'Verification code sent to your email',
        email: email,
        devCode: process.env.NODE_ENV === 'development' ? verificationCode : undefined
      });
    } catch (emailError) {
      console.error('📧 Email sending failed:', emailError.message);
      verificationCodes.delete(email);
      
      if (process.env.NODE_ENV === 'development') {
        return res.json({ 
          success: true,
          message: 'Verification code generated (email disabled in dev)',
          email: email,
          devCode: verificationCode
        });
      }
      
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send verification email. Please try again.' 
      });
    }

  } catch (error) {
    console.error('❌ Signup error:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during signup. Please try again.' 
    });
  }
});

// Step 2: Verify code and create account
app.post('/auth/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    console.log('🔍 Verifying code for:', email);

    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and verification code are required' 
      });
    }

    const verificationData = verificationCodes.get(email);

    if (!verificationData) {
      console.log('❌ No verification data found for:', email);
      return res.status(400).json({ 
        success: false, 
        message: 'No verification code found. Please request a new one.' 
      });
    }

    if (Date.now() > verificationData.expiresAt) {
      console.log('⏰ Code expired for:', email);
      verificationCodes.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'Verification code expired. Please request a new one.' 
      });
    }

    if (verificationData.code !== code.toString()) {
      console.log('❌ Code mismatch for:', email);
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid verification code. Please try again.' 
      });
    }

    console.log('✅ Code verified successfully for:', email);

    const { name, phone, password } = verificationData.userData;

    const [existingUsers] = await db.query(
      'SELECT id FROM users WHERE email = ?', 
      [email]
    );

    if (existingUsers.length > 0) {
      verificationCodes.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'Account already exists. Please sign in.' 
      });
    }

    const [result] = await db.query(
      `INSERT INTO users (name, email, phone, password_hash, auth_type, role, created_at, last_login) 
       VALUES (?, ?, ?, ?, 'email', 'customer', NOW(), NOW())`,
      [name, email, phone, password]
    );

    verificationCodes.delete(email);

    const token = jwt.sign(
      { userId: result.insertId, email, name, role: 'customer' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`✅ User created successfully: ${email} (ID: ${result.insertId})`);

    res.json({
      success: true,
      message: 'Account created successfully',
      token,
      user: {
        id: result.insertId,
        name,
        email,
        phone,
        role: 'customer',
        authType: 'email',
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('❌ Verification error:', error.message);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered. Please sign in.' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Server error during verification. Please try again.' 
    });
  }
});

// Resend verification code
app.post('/auth/resend-code', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    const verificationData = verificationCodes.get(email);

    if (!verificationData) {
      return res.status(400).json({ 
        success: false, 
        message: 'No pending verification found for this email. Please start signup again.' 
      });
    }

    const newCode = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    verificationCodes.set(email, {
      ...verificationData,
      code: newCode,
      expiresAt
    });

    await sendVerificationEmail(email, newCode, verificationData.userData.name);

    console.log(`🔄 New verification code sent to ${email}`);

    res.json({ 
      success: true, 
      message: 'New verification code sent',
      devCode: process.env.NODE_ENV === 'development' ? newCode : undefined
    });

  } catch (error) {
    console.error('❌ Resend code error:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to resend verification code' 
    });
  }
});

// Send login verification code
app.post('/auth/send-login-code', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('🔍 Login attempt for:', email);

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    const [users] = await db.query(
      'SELECT id, email, name, password_hash, role FROM users WHERE email = ? AND auth_type = ?',
      [email, 'email']
    );

    if (users.length === 0) {
      console.log('❌ User not found:', email);
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const user = users[0];
    console.log('✅ User found:', user.email, 'Role:', user.role);

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isPasswordValid) {
      console.log('❌ Invalid password for:', email);
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    console.log('✅ Password validated for:', email);

    // Skip email verification for admin
    if (user.role === 'admin') {
      await db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

      const token = jwt.sign(
        { userId: user.id, email, name: user.name, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      console.log(`✅ Admin logged in directly: ${email}`);

      return res.json({
        success: true,
        skipVerification: true,
        message: 'Admin login successful',
        token,
        user: {
          id: user.id,
          email,
          name: user.name,
          role: user.role,
          authType: 'email'
        }
      });
    }

    // Generate verification code for regular users
    const verificationCode = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    loginVerificationCodes.set(email, {
      code: verificationCode,
      expiresAt,
      userId: user.id,
      userName: user.name,
      userRole: user.role
    });

    try {
      await sendLoginVerificationEmail(email, verificationCode, user.name);
      console.log(`✅ Login verification code sent to ${email}`);

      res.json({ 
        success: true,
        skipVerification: false,
        message: 'Verification code sent to your email',
        email: email,
        devCode: process.env.NODE_ENV === 'development' ? verificationCode : undefined
      });
    } catch (emailError) {
      console.error('📧 Email sending failed:', emailError.message);
      loginVerificationCodes.delete(email);
      
      if (process.env.NODE_ENV === 'development') {
        return res.json({ 
          success: true,
          skipVerification: false,
          message: 'Verification code generated (email disabled in dev)',
          email: email,
          devCode: verificationCode
        });
      }
      
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send verification email' 
      });
    }

  } catch (error) {
    console.error('❌ Send login code error:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Verify login code
app.post('/auth/verify-login-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and code are required' 
      });
    }

    const loginData = loginVerificationCodes.get(email);

    if (!loginData) {
      return res.status(400).json({ 
        success: false, 
        message: 'No verification code found. Please request a new one.' 
      });
    }

    if (Date.now() > loginData.expiresAt) {
      loginVerificationCodes.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'Verification code expired. Please request a new one.' 
      });
    }

    if (loginData.code !== code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid verification code' 
      });
    }

    await db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [loginData.userId]);

    const token = jwt.sign(
      { userId: loginData.userId, email, name: loginData.userName, role: loginData.userRole },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    loginVerificationCodes.delete(email);

    console.log(`✅ User logged in successfully: ${email}`);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: loginData.userId,
        email,
        name: loginData.userName,
        role: loginData.userRole,
        authType: 'email'
      }
    });

  } catch (error) {
    console.error('❌ Verify login code error:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during verification' 
    });
  }
});

// Google OAuth
app.post('/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, message: 'No token provided' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const userId = payload.sub;
    const email = payload.email;
    const name = payload.name;
    const picture = payload.picture;

    const [existingUser] = await db.query(
      'SELECT * FROM users WHERE google_id = ? OR email = ?',
      [userId, email]
    );

    let user;
    if (existingUser.length > 0) {
      user = existingUser[0];

      if (!user.google_id) {
        await db.query(
          'UPDATE users SET google_id = ?, auth_type = ?, picture = ?, last_login = NOW() WHERE email = ?', 
          [userId, 'google', picture || null, email]
        );
      } else {
        await db.query('UPDATE users SET last_login = NOW() WHERE google_id = ?', [userId]);
      }
    } else {
      const [result] = await db.query(
        `INSERT INTO users (google_id, email, name, picture, auth_type, role, created_at, last_login)
         VALUES (?, ?, ?, ?, 'google', 'customer', NOW(), NOW())`,
        [userId, email, name, picture || null]
      );
      user = { id: result.insertId, google_id: userId, email, name, picture, role: 'customer' };
    }

    const appToken = jwt.sign(
      { userId: user.id || user.google_id, email, name, googleId: userId, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Google authentication successful',
      token: appToken,
      user: {
        id: user.id || user.google_id,
        email,
        name,
        picture,
        role: user.role,
        authType: 'google'
      }
    });

  } catch (error) {
    console.error('Google auth error:', error.message);
    res.status(400).json({ success: false, message: 'Google authentication failed', error: error.message });
  }
});

// Get current user
app.get('/auth/me', verifyToken, async (req, res) => {
  try {
    const [users] = await db.query(
      'SELECT id, email, name, picture, phone, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, user: users[0] });
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch user', error: error.message });
  }
});



// ==================== ORDER ROUTES ====================

// (Removed duplicate early implementations of create-order and orders routes; newer, safer versions defined below remain)

// ==================== SAFEST FIX: SELECT ALL COLUMNS ====================
// This will work regardless of your exact schema:

app.get('/api/orders', verifyToken, async (req, res) => {
  try {
    console.log('📦 Fetching orders for user:', req.user.userId);
    
    // Use SELECT * to get all columns (safest approach)
    const [orders] = await db.query(
      `SELECT * FROM orders 
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    console.log(`✅ Found ${orders.length} orders for user ${req.user.userId}`);

    // Parse items JSON if it's a string
    const ordersWithParsedItems = orders.map(order => {
      try {
        return {
          ...order,
          items: typeof order.items === 'string' ? JSON.parse(order.items) : order.items
        };
      } catch (e) {
        console.error('Error parsing items for order:', order.order_id, e);
        return {
          ...order,
          items: []
        };
      }
    });

    res.json(ordersWithParsedItems);

  } catch (error) {
    console.error('❌ Get user orders error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch orders',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== ALSO FIX CREATE ORDER ROUTE ====================
// Update the /api/create-order route to handle missing columns gracefully:

app.post('/api/create-order', verifyToken, async (req, res) => {
  try {
    const orderData = req.body;
    const orderId = 'KK' + Date.now() + Math.floor(Math.random() * 1000);

    console.log('📦 Creating order:', orderId);

    // Check if delivery_address column exists
    const [columns] = await db.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'orders' 
        AND COLUMN_NAME IN ('delivery_address', 'delivery_coordinates')
    `, [process.env.DB_NAME || 'kusina_db']);
    
    const hasDeliveryAddress = columns.some(col => col.COLUMN_NAME === 'delivery_address');
    const hasDeliveryCoords = columns.some(col => col.COLUMN_NAME === 'delivery_coordinates');

    // Build INSERT query dynamically
    let insertColumns = [
      'order_id', 'user_id', 'customer_name', 'customer_email', 'customer_phone',
      'items', 'subtotal', 'delivery_fee', 'tax', 'total',
      'delivery_option', 'payment_method', 'payment_status', 'delivery_status',
      'payment_intent_id', 'payment_source_id',
      'voucher_code', 'voucher_discount'
    ];
    
    let insertValues = [
      orderId, 
      req.user.userId, 
      orderData.customer_name,
      orderData.customer_email, 
      orderData.customer_phone,
      JSON.stringify(orderData.items || []),
      parseFloat(orderData.subtotal || 0),
      parseFloat(orderData.delivery_fee || 0),
      parseFloat(orderData.tax || 0),
      parseFloat(orderData.total || 0),
      orderData.delivery_option || 'delivery',
      orderData.payment_method || 'card',
      orderData.payment_status || 'pending',
      'placed',
      orderData.payment_intent_id || null,
      orderData.payment_source_id || null,
      orderData.voucher_code || null,
      parseFloat(orderData.voucher_discount || 0)
    ];
    
    // Add delivery columns if they exist
    if (hasDeliveryAddress) {
      insertColumns.splice(5, 0, 'delivery_address');
      insertValues.splice(5, 0, orderData.delivery_address || null);
    }
    
    if (hasDeliveryCoords) {
      insertColumns.splice(hasDeliveryAddress ? 6 : 5, 0, 'delivery_coordinates');
      insertValues.splice(hasDeliveryAddress ? 6 : 5, 0, orderData.delivery_coordinates || null);
    }
    
    const placeholders = insertColumns.map(() => '?').join(', ');
    const query = `INSERT INTO orders (${insertColumns.join(', ')}, created_at) 
                   VALUES (${placeholders}, NOW())`;

    const [result] = await db.query(query, insertValues);

    console.log('✅ Order created successfully:', orderId);

    // Mark voucher as used
    if (orderData.voucher_code) {
      try {
        await db.query(
          `UPDATE vouchers 
           SET is_used = TRUE, used_at = NOW() 
           WHERE code = ? AND user_id = ? AND is_used = FALSE`,
          [orderData.voucher_code, req.user.userId]
        );
        console.log(`✅ Voucher ${orderData.voucher_code} marked as used`);
      } catch (voucherError) {
        console.error('⚠️ Failed to mark voucher as used:', voucherError.message);
      }
    }

    // Broadcast new order to admin
    if (typeof broadcastNewOrder === 'function') {
      broadcastNewOrder({
        order_id: orderId,
        customer_name: orderData.customer_name,
        customer_email: orderData.customer_email,
        total: orderData.total,
        payment_status: orderData.payment_status,
        payment_method: orderData.payment_method,
        delivery_status: 'placed',
        delivery_option: orderData.delivery_option,
        items_count: orderData.items?.length || 0,
        voucher_applied: !!orderData.voucher_code,
        created_at: new Date().toISOString()
      });
    }

    // Emit order-updated event to the user who placed the order (their specific room)
    io.to(`user-${req.user.userId}`).emit('order-updated', {
      user_id: req.user.userId,
      order: {
        order_id: orderId,
        customer_name: orderData.customer_name,
        customer_email: orderData.customer_email,
        items: orderData.items || [],
        subtotal: orderData.subtotal,
        delivery_fee: orderData.delivery_fee,
        tax: orderData.tax,
        total: orderData.total,
        payment_status: orderData.payment_status || 'pending',
        delivery_status: 'placed',
        created_at: new Date().toISOString()
      },
      action: 'created'
    });
    console.log(`[SOCKET][USER_${req.user.userId}] order-updated event triggered`);

    res.json({ 
      success: true, 
      order_id: orderId,
      message: 'Order created successfully'
    });

  } catch (error) {
    console.error('❌ Create order error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create order',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== VOUCHER ROUTES ====================

// Validate voucher
app.post('/api/user/vouchers/validate', verifyToken, async (req, res) => {
  try {
    const { code, order_total } = req.body;

    if (!code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Voucher code is required' 
      });
    }

    const [vouchers] = await db.query(
      `SELECT * FROM vouchers 
       WHERE code = ? AND user_id = ?`,
      [code.toUpperCase(), req.user.userId]
    );

    if (vouchers.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Invalid voucher code or voucher does not belong to you' 
      });
    }

    const voucher = vouchers[0];

    if (voucher.is_used) {
      return res.status(400).json({ 
        success: false, 
        message: 'This voucher has already been used' 
      });
    }

    const expiryDate = new Date(voucher.expires_at);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (expiryDate < today) {
      return res.status(400).json({ 
        success: false, 
        message: 'This voucher has expired' 
      });
    }

    let discount = 0;
    if (voucher.discount_type === 'percentage') {
      discount = (parseFloat(order_total) * parseFloat(voucher.discount_value)) / 100;
    } else if (voucher.discount_type === 'fixed') {
      discount = parseFloat(voucher.discount_value);
    } else if (voucher.discount_type === 'shipping') {
      discount = 30;
    }

    discount = Math.min(discount, parseFloat(order_total));

    res.json({ 
      success: true, 
      voucher: {
        id: voucher.id,
        code: voucher.code,
        discount_type: voucher.discount_type,
        discount_value: voucher.discount_value,
        calculated_discount: discount.toFixed(2),
        expires_at: voucher.expires_at
      }
    });

  } catch (error) {
    console.error('❌ Validate voucher error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to validate voucher'
    });
  }
});

// Get user's own vouchers
app.get('/api/user/vouchers', verifyToken, async (req, res) => {
  try {
    const [vouchers] = await db.query(
      `SELECT 
        id, code, discount_type, discount_value, 
        expires_at, is_used, used_at,
        CASE 
          WHEN expires_at < CURDATE() THEN TRUE 
          ELSE FALSE 
        END as is_expired
       FROM vouchers 
       WHERE user_id = ? AND is_used = FALSE
       ORDER BY expires_at ASC`,
      [req.user.userId]
    );

    res.json({ 
      success: true, 
      vouchers 
    });

  } catch (error) {
    console.error('❌ Get user vouchers error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch vouchers',
      vouchers: []
    });
  }
});

// Combined overview: recent orders + available vouchers for the logged-in user
app.get('/api/user/overview', verifyToken, async (req, res) => {
  try {
    // Recent orders (limit 3)
    const [orders] = await db.query(
      `SELECT * FROM orders 
       WHERE user_id = ? 
       ORDER BY created_at DESC 
       LIMIT 3`,
      [req.user.userId]
    );

    const recentOrders = orders.map(order => {
      try {
        return {
          ...order,
          items: typeof order.items === 'string' ? JSON.parse(order.items) : order.items
        };
      } catch (_e) {
        return { ...order, items: [] };
      }
    });

    // Available vouchers (not used)
    const [vouchers] = await db.query(
      `SELECT 
        id, code, discount_type, discount_value, 
        expires_at, is_used, used_at,
        CASE WHEN expires_at < CURDATE() THEN TRUE ELSE FALSE END as is_expired
       FROM vouchers 
       WHERE user_id = ? AND is_used = FALSE
       ORDER BY expires_at ASC`,
      [req.user.userId]
    );

    res.json({ success: true, orders: recentOrders, vouchers });
  } catch (error) {
    console.error('❌ Get user overview error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch overview', orders: [], vouchers: [] });
  }
});

// ==================== ADMIN ORDER ROUTES ====================

// Get all orders (Admin)
app.get('/api/admin/get-all-orders', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
        order_id, user_id, customer_name, customer_email, customer_phone,
        items, subtotal, delivery_fee, tax, total,
        payment_method, payment_status, delivery_status, delivery_option, created_at
      FROM orders ORDER BY created_at DESC LIMIT 500`
    );
    res.json({ success: true, orders: rows });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch orders' });
  }
});

// Update order status (Admin)
app.patch('/api/admin/update-order-status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { order_id, status } = req.body;

    if (!order_id || !status) {
      return res.status(400).json({ success: false, message: 'Missing order_id or status' });
    }

    await db.query(
      'UPDATE orders SET payment_status = ? WHERE order_id = ?',
      [status, order_id]
    );

    broadcastOrderUpdate(order_id, { payment_status: status });

    res.json({ success: true, message: 'Order status updated' });
  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update order status' });
  }
});

// Update delivery status (Admin)
app.patch('/api/admin/update-delivery-status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { order_id, delivery_status } = req.body;

    if (!order_id || !delivery_status) {
      return res.status(400).json({ success: false, message: 'Missing order_id or delivery_status' });
    }

    const validStatuses = ['placed', 'preparing', 'delivering', 'delivered', 'cancelled'];
    if (!validStatuses.includes(delivery_status)) {
      return res.status(400).json({ success: false, message: 'Invalid delivery status' });
    }

    const [result] = await db.query(
      'UPDATE orders SET delivery_status = ? WHERE order_id = ?',
      [delivery_status, order_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    broadcastOrderUpdate(order_id, { 
      delivery_status: delivery_status,
      timestamp: new Date().toISOString()
    });

    res.json({ success: true, message: 'Delivery status updated' });

  } catch (error) {
    console.error('Admin update delivery status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update delivery status' });
  }
});

// Update order delivery status (Admin) - REST endpoint
app.post('/api/admin/orders/:orderId/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { delivery_status } = req.body;

    if (!delivery_status) {
      return res.status(400).json({ success: false, message: 'Missing delivery_status' });
    }

    const validStatuses = ['placed', 'preparing', 'delivering', 'delivered', 'cancelled'];
    if (!validStatuses.includes(delivery_status)) {
      return res.status(400).json({ success: false, message: 'Invalid delivery status' });
    }

    // Update order status
    const [result] = await db.query(
      'UPDATE orders SET delivery_status = ? WHERE order_id = ?',
      [delivery_status, orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    // Get user_id for Socket.IO emission
    const [orders] = await db.query('SELECT user_id FROM orders WHERE order_id = ?', [orderId]);
    const userId = orders.length > 0 ? orders[0].user_id : null;

    // Emit order-status-changed to user room
    if (userId) {
      io.to(`user-${userId}`).emit('order-status-changed', {
        orderId,
        status: delivery_status,
        delivery_status: delivery_status,
        timestamp: new Date().toISOString()
      });
      console.log(`[SOCKET][USER_${userId}] order-status-changed event triggered for order ${orderId}`);
    }

    // Also emit to order room
    io.to(`order-${orderId}`).emit('order-status-changed', {
      orderId,
      status: delivery_status,
      delivery_status: delivery_status,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true, 
      message: 'Order status updated',
      orderId,
      delivery_status
    });

  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update order status' });
  }
});

// ==================== PAYMONGO ROUTES ====================

// Create payment intent
app.post('/api/create-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount, currency, customer, card } = req.body;

    const cleanCardNumber = card.number.replace(/\s/g, '').replace(/\D/g, '');
    
    const pmResp = await axios.post(
      `${PAYMONGO_API_BASE}/payment_methods`,
      {
        data: {
          type: 'payment_method',
          attributes: {
            type: 'card',
            details: {
              card_number: cleanCardNumber,
              exp_month: card.exp_month,
              exp_year: card.exp_year,
              cvc: card.cvc
            },
            billing: { 
              name: customer.name, 
              email: customer.email 
            }
          }
        }
      },
      {
        headers: {
          'Authorization': getPayMongoAuth(),
          'Content-Type': 'application/json'
        }
      }
    );

    const pmId = pmResp.data.data.id;

    const piResult = await payMongoRequest('/payment_intents', 'POST', {
      data: {
        attributes: {
          amount: amount,
          currency: currency,
          payment_method_allowed: ['card'],
          payment_method_options: {
            card: {
              request_three_d_secure: 'automatic'
            }
          },
          description: `Order for ${customer.name}`
        }
      }
    });

    if (!piResult.success) {
      return res.status(400).json({ success: false, message: 'Failed to create payment intent', error: piResult.error });
    }

    const piId = piResult.data.data.id;

    const attachResult = await payMongoRequest(`/payment_intents/${piId}/attach`, 'POST', {
      data: {
        attributes: {
          payment_method: pmId,
          return_url: 'http://localhost:3000/dashboard.html'
        }
      }
    });

    if (!attachResult.success) {
      return res.status(400).json({ success: false, message: 'Failed to attach payment method', error: attachResult.error });
    }

    const status = attachResult.data.data.attributes.status;

    if (status === 'succeeded') {
      res.json({
        success: true,
        paymentIntentId: piId,
        status: 'succeeded',
        message: 'Payment processed successfully'
      });
    } else if (status === 'processing') {
      res.json({
        success: true,
        paymentIntentId: piId,
        status: 'processing',
        message: 'Payment is processing'
      });
    } else if (status === 'requires_action') {
      const clientSecret = attachResult.data.data.attributes.client_key;
      res.json({
        success: true,
        paymentIntentId: piId,
        status: 'requires_action',
        clientSecret: clientSecret,
        nextAction: attachResult.data.data.attributes.next_action
      });
    } else {
      res.json({
        success: true,
        paymentIntentId: piId,
        status: status
      });
    }

  } catch (error) {
    console.error('Payment intent error:', error.message);
    res.status(500).json({ success: false, message: 'Payment processing failed', error: error.message });
  }
});

// Create GCash payment
app.post('/api/paymongo/create-gcash-payment', verifyToken, async (req, res) => {
  try {
    const { amount, currency, customer } = req.body;

    if (!amount || !customer) {
      return res.status(400).json({ success: false, message: 'Missing required payment data' });
    }

    const result = await payMongoRequest('/sources', 'POST', {
      data: {
        attributes: {
          type: 'gcash',
          amount: amount,
          currency: currency,
          redirect: {
            success: 'http://localhost:3000/index.html?payment=success',
            failed: 'http://localhost:3000/index.html?payment=failed'
          },
          billing: {
            name: customer.name,
            email: customer.email
          }
        }
      }
    });

    if (!result.success) {
      return res.status(400).json({ success: false, message: 'Failed to create GCash payment', error: result.error });
    }

    const checkoutUrl = result.data.data.attributes.redirect.checkout_url;
    const sourceId = result.data.data.id;

    res.json({
      success: true,
      source_id: sourceId,
      checkout_url: checkoutUrl,
      message: 'GCash payment source created'
    });

  } catch (error) {
    console.error('GCash payment error:', error.message);
    res.status(500).json({ success: false, message: 'GCash payment failed', error: error.message });
  }
});

// PayMongo webhook
app.post('/api/paymongo/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const event = JSON.parse(req.body.toString());
    console.log('🔔 PayMongo Webhook received:', event.type);

    if (event.type === 'payment.paid') {
      const paymentId = event.data.id;
      console.log('✅ Payment received:', paymentId);
    } else if (event.type === 'source.chargeable') {
      const sourceId = event.data.id;
      console.log('✅ Source chargeable:', sourceId);
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== MENU ROUTES ====================

// Get public menu
app.get('/api/menu', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, name, slug, description, price, image_url, 
              is_featured, category, badge 
       FROM menu_items 
       WHERE is_active = TRUE 
       ORDER BY is_featured DESC, name ASC`
    );
    
    res.json({ success: true, items: rows });
  } catch (error) {
    console.error('❌ Get menu error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch menu items' 
    });
  }
});

// Get all menu items (Admin)
app.get('/api/admin/menu', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, name, slug, description, price, image_url, 
              is_featured, is_active, category, badge, 
              created_at, updated_at 
       FROM menu_items 
       ORDER BY created_at DESC`
    );
    
    res.json({ success: true, items: rows });
  } catch (error) {
    console.error('❌ Get admin menu error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch menu items' 
    });
  }
});

// Create menu item (Admin)
app.post('/api/admin/menu', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { 
      name, 
      description, 
      price, 
      image_url, 
      category, 
      badge,
      is_featured, 
      is_active 
    } = req.body;

    if (!name || !price) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name and price are required' 
      });
    }

    const slug = name.toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();

    const [result] = await db.query(
      `INSERT INTO menu_items 
       (name, slug, description, price, image_url, category, badge, is_featured, is_active, created_at, updated_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [
        name,
        slug,
        description || null,
        parseFloat(price),
        image_url || null,
        category || 'main',
        badge || null,
        is_featured ? 1 : 0,
        is_active !== false ? 1 : 0
      ]
    );

    io.emit('menu-updated', { 
      action: 'created', 
      itemId: result.insertId,
      item: { id: result.insertId, name, price, is_featured, is_active }
    });

    res.json({ 
      success: true, 
      message: 'Menu item created successfully',
      itemId: result.insertId 
    });

  } catch (error) {
    console.error('❌ Create menu item error:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        success: false, 
        message: 'An item with a similar name already exists' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create menu item' 
    });
  }
});

// Update menu item (Admin)
app.patch('/api/admin/menu/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = [];
    const values = [];

    const allowedFields = ['name', 'description', 'price', 'image_url', 'category', 'badge', 'is_featured', 'is_active'];
    
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        if (field === 'name') {
          updates.push('name = ?', 'slug = ?');
          values.push(req.body[field].trim());
          const slug = req.body[field].toLowerCase()
            .replace(/[^\w\s-]/g, '')
            .replace(/\s+/g, '-')
            .replace(/-+/g, '-')
            .trim();
          values.push(slug);
        } else if (field === 'price') {
          updates.push('price = ?');
          values.push(parseFloat(req.body[field]));
        } else if (field === 'is_featured' || field === 'is_active') {
          updates.push(`${field} = ?`);
          values.push(req.body[field] ? 1 : 0);
        } else {
          updates.push(`${field} = ?`);
          values.push(req.body[field] || null);
        }
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No valid fields to update' 
      });
    }

    updates.push('updated_at = NOW()');
    values.push(id);

    const [result] = await db.query(
      `UPDATE menu_items SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Menu item not found' 
      });
    }

    io.emit('menu-updated', { 
      action: 'updated', 
      itemId: id,
      updates: req.body
    });

    res.json({ 
      success: true, 
      message: 'Menu item updated successfully',
      changes: result.changedRows
    });

  } catch (error) {
    console.error('❌ Update menu item error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update menu item'
    });
  }
});

// Delete menu item (Admin)
app.delete('/api/admin/menu/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const [existing] = await db.query(
      'SELECT id, name, image_url FROM menu_items WHERE id = ?',
      [id]
    );

    if (existing.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Menu item not found' 
      });
    }

    const item = existing[0];

    if (item.image_url) {
      const imagePath = path.join(__dirname, 'public', item.image_url);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await db.query('DELETE FROM menu_items WHERE id = ?', [id]);

    io.emit('menu-updated', { 
      action: 'deleted', 
      itemId: id,
      itemName: item.name
    });

    res.json({ 
      success: true, 
      message: 'Menu item deleted successfully' 
    });

  } catch (error) {
    console.error('❌ Delete menu item error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete menu item' 
    });
  }
});

// Upload menu item image (Admin)
app.post('/api/admin/menu/upload-image', 
  verifyToken, 
  verifyAdmin, 
  upload.single('image'), 
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ 
          success: false, 
          message: 'No image file provided' 
        });
      }

      const imageUrl = `/assets/images/menu/${req.file.filename}`;

      res.json({ 
        success: true, 
        imageUrl: imageUrl,
        message: 'Image uploaded successfully' 
      });

    } catch (error) {
      console.error('❌ Image upload error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to upload image',
        error: error.message 
      });
    }
  }
);

// ==================== USER MANAGEMENT ROUTES (Admin) ====================

// Get all users
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [users] = await db.query(
      `SELECT 
        id, name, email, phone, role, auth_type, 
        COALESCE(is_active, TRUE) as is_active,
        created_at, last_login, picture
       FROM users 
       ORDER BY created_at DESC`
    );

    res.json({ success: true, users });
  } catch (error) {
    console.error('❌ Get users error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch users' 
    });
  }
});

// Update user (Admin)
app.patch('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, is_active } = req.body;

    const updates = [];
    const values = [];

    if (role !== undefined) {
      if (!['customer', 'admin'].includes(role)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid role. Must be customer or admin.' 
        });
      }
      updates.push('role = ?');
      values.push(role);
    }

    if (is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(is_active ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No fields to update' 
      });
    }

    values.push(id);

    const [result] = await db.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({ 
      success: true, 
      message: 'User updated successfully' 
    });

  } catch (error) {
    console.error('❌ Update user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update user' 
    });
  }
});

// Delete user
app.delete('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Cannot delete your own account' 
      });
    }

    const [result] = await db.query('DELETE FROM users WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({ 
      success: true, 
      message: 'User deleted successfully' 
    });

  } catch (error) {
    console.error('❌ Delete user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete user' 
    });
  }
});

// ==================== VOUCHER ROUTES (Admin) ====================

// Create voucher (Admin)
app.post('/api/admin/vouchers', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { user_id, code, discount_type, discount_value, expires_at } = req.body;

    if (!user_id || !code || !discount_type || !discount_value || !expires_at) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    if (!['percentage', 'fixed'].includes(discount_type)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Discount type must be percentage or fixed' 
      });
    }

    const value = parseFloat(discount_value);
    if (isNaN(value) || value <= 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Discount value must be a positive number' 
      });
    }

    if (discount_type === 'percentage' && value > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Percentage discount cannot exceed 100%' 
      });
    }

    const [result] = await db.query(
      `INSERT INTO vouchers (user_id, code, discount_type, discount_value, expires_at, created_at) 
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [user_id, code.toUpperCase(), discount_type, value, expires_at]
    );

    // Get user email for Socket.IO emission
    const [users] = await db.query('SELECT email FROM users WHERE id = ?', [user_id]);
    const userEmail = users.length > 0 ? users[0].email : null;

    // Emit voucher-updated event to the specific user's room
    if (user_id) {
      io.to(`user-${user_id}`).emit('voucher-updated', {
        user_id: user_id,
        user_email: userEmail,
        voucher: {
          id: result.insertId,
          code: code.toUpperCase(),
          discount_type: discount_type,
          discount_value: value,
          expires_at: expires_at
        },
        action: 'created'
      });
      console.log(`[SOCKET][USER_${user_id}] voucher-updated event triggered (created)`);
    }

    res.json({ 
      success: true, 
      message: 'Voucher created successfully',
      voucherId: result.insertId 
    });

  } catch (error) {
    console.error('❌ Create voucher error:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        success: false, 
        message: 'Voucher code already exists' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create voucher'
    });
  }
});

// Get vouchers for specific user (Admin)
app.get('/api/admin/vouchers', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { user_id } = req.query;

    if (!user_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required' 
      });
    }

    const [vouchers] = await db.query(
      `SELECT 
        id, code, discount_type, discount_value, 
        expires_at, is_used, used_at, created_at,
        CASE 
          WHEN expires_at < CURDATE() THEN TRUE 
          ELSE FALSE 
        END as is_expired
       FROM vouchers 
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [user_id]
    );

    res.json({ 
      success: true, 
      vouchers 
    });

  } catch (error) {
    console.error('❌ Get vouchers error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch vouchers',
      vouchers: []
    });
  }
});

// Delete voucher (Admin)
app.delete('/api/admin/vouchers/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Get voucher info before deleting
    const [vouchers] = await db.query('SELECT user_id FROM vouchers WHERE id = ?', [id]);
    
    if (vouchers.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Voucher not found' 
      });
    }

    const user_id = vouchers[0].user_id;
    const [users] = await db.query('SELECT email FROM users WHERE id = ?', [user_id]);
    const userEmail = users.length > 0 ? users[0].email : null;

    const [result] = await db.query('DELETE FROM vouchers WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Voucher not found' 
      });
    }

    // Emit voucher-updated event for deletion to the specific user's room
    if (user_id) {
      io.to(`user-${user_id}`).emit('voucher-updated', {
        user_id: user_id,
        user_email: userEmail,
        voucher: { id: parseInt(id) },
        action: 'deleted'
      });
      console.log(`[SOCKET][USER_${user_id}] voucher-updated event triggered (deleted)`);
    }

    res.json({ 
      success: true, 
      message: 'Voucher deleted successfully' 
    });

  } catch (error) {
    console.error('❌ Delete voucher error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete voucher' 
    });
  }
});

// ==================== RATE LIMITING ====================

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.'
});

app.use('/auth/signup', authLimiter);
app.use('/auth/send-login-code', authLimiter);
app.use('/api/', apiLimiter);

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ 
      success: false, 
      message: 'Invalid token' 
    });
  }

  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        success: false, 
        message: 'File too large. Maximum size is 5MB.' 
      });
    }
  }

  res.status(500).json({ 
    success: false, 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==================== START SERVER ====================

server.listen(PORT, () => {
  console.log('\n🚀 ========================================');
  console.log(`   Kusina ni Katya Server Running`);
  console.log('🚀 ========================================');
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
  console.log(`💳 PayMongo: ${PAYMONGO_SECRET_KEY ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`📧 Email: ${process.env.MAIL_USER ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`🔐 JWT: ${JWT_SECRET ? '✅ Configured' : '⚠️  Using default (change this!)'}`);
  console.log(`🗄️  Database: ${process.env.DB_NAME || 'kusina_db'}`);
  console.log('========================================\n');
});

// ==================== GRACEFUL SHUTDOWN ====================

let isShuttingDown = false;

function gracefulShutdown(signal) {
  if (isShuttingDown) {
    process.exit(1);
    return;
  }
  isShuttingDown = true;
  console.log(`\n🔴 ${signal} - Shutting down...`);
  
  const timer = setTimeout(() => {
    console.error('❌ Timeout - Forcing exit');
    process.exit(1);
  }, 5000);
  
  server.close(() => {
    if (io) io.close();
    db.end()
      .then(() => {
        clearTimeout(timer);
        process.exit(0);
      })
      .catch(() => process.exit(1));
  });
}

process.removeAllListeners('SIGTERM');
process.removeAllListeners('SIGINT');
process.once('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.once('SIGINT', () => gracefulShutdown('SIGINT'));