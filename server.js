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
app.use(express.static('public'));

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
    
    console.log('📝 Generating filename:', filename);
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
  console.log('📌 Client connected:', socket.id);
  
  socket.on('track-order', (data) => {
    const { orderId } = data;
    console.log(`🔍 Client ${socket.id} started tracking order: ${orderId}`);
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
      
      io.to(`order-${orderId}`).emit('order-status-changed', {
        orderId,
        status: deliveryStatus,
        timestamp: new Date().toISOString()
      });
      
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
  io.to('admin-room').emit('order-updated', { orderId, ...updateData });
  io.to(`order-${orderId}`).emit('order-status-changed', { orderId, ...updateData });
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

    console.log('🔐 Login attempt for:', email);

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

// Create order
app.post('/api/create-order', verifyToken, async (req, res) => {
  try {
    const orderData = req.body;
    const orderId = 'KK' + Date.now() + Math.floor(Math.random() * 1000);

    const [result] = await db.query(
      `INSERT INTO orders (
        order_id, user_id, customer_name, customer_email, customer_phone,
        items, subtotal, delivery_fee, tax, total,
        delivery_option, payment_method, payment_status, delivery_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
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
        'placed'
      ]
    );

    broadcastNewOrder({
      order_id: orderId,
      customer_name: orderData.customer_name,
      total: orderData.total,
      payment_status: orderData.payment_status,
      delivery_status: 'placed',
      created_at: new Date().toISOString()
    });

    console.log('✅ Order created and broadcasted:', orderId);
    res.json({ success: true, order_id: orderId });

  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ success: false, message: 'Failed to create order' });
  }
});

// Get user orders
app.get('/api/my-orders', verifyToken, async (req, res) => {
  try {
    console.log('📦 Fetching orders for user:', req.user.userId);
    
    const [rows] = await db.query(
      'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.userId]
    );
    
    console.log(`✅ Found ${rows.length} orders for user ${req.user.userId}`);
    res.json({ success: true, orders: rows });
  } catch (error) {
    console.error('❌ Get my orders error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to retrieve orders', 
      error: error.message 
    });
  }
});

// Get specific order
app.get('/api/get-order/:orderId', verifyToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const [rows] = await db.query(
      'SELECT * FROM orders WHERE order_id = ? AND user_id = ?',
      [orderId, req.user.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    res.json({ success: true, order: rows[0] });
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({ success: false, message: 'Failed to retrieve order', error: error.message });
  }
});

// Update order status
app.post('/api/update-order-status', verifyToken, async (req, res) => {
  try {
    const { order_id, status } = req.body;

    if (!order_id || !status) {
      return res.status(400).json({ success: false, message: 'Missing order_id or status' });
    }

    await db.query(
      'UPDATE orders SET payment_status = ? WHERE order_id = ? AND user_id = ?',
      [status, order_id, req.user.userId]
    );

    broadcastOrderUpdate(order_id, { payment_status: status });

    console.log(`✅ Order ${order_id} status updated to ${status}`);
    res.json({ success: true, message: 'Order status updated' });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ success: false, message: 'Failed to update order', error: error.message });
  }
});

// Update delivery status
app.patch('/api/update-delivery-status', verifyToken, async (req, res) => {
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

    console.log(`✅ Delivery status updated: ${order_id} -> ${delivery_status}`);
    res.json({ success: true, message: 'Delivery status updated' });

  } catch (error) {
    console.error('Update delivery status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update delivery status' });
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

    console.log(`✅ Admin updated delivery status: ${order_id} -> ${delivery_status}`);
    res.json({ success: true, message: 'Delivery status updated' });

  } catch (error) {
    console.error('Admin update delivery status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update delivery status' });
  }
});

// ==================== PAYMONGO ROUTES ====================

// Create payment intent
app.post('/api/create-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount, currency, customer, card } = req.body;

    console.log('💳 Creating PayMongo payment intent...');

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
    console.log('✅ Payment method created');

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
    console.log('✅ Payment intent created:', piId);

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

    console.log('✅ Payment method attached');

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

    console.log('📱 Creating GCash payment source...');

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

    console.log('✅ GCash source created:', sourceId);

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
    const event = JSON.parse(req.body);
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
    
    console.log(`✅ Admin fetched ${rows.length} menu items`);
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

    console.log(`✅ Menu item created: ${name} (ID: ${result.insertId})`);

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

    const hasUpdates = [name, description, price, image_url, category, badge, is_featured, is_active]
      .some(field => field !== undefined);

    if (!hasUpdates) {
      return res.status(400).json({ 
        success: false, 
        message: 'No fields provided for update' 
      });
    }

    const [existing] = await db.query(
      'SELECT id, name FROM menu_items WHERE id = ?',
      [id]
    );

    if (existing.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Menu item not found' 
      });
    }

    const updates = [];
    const values = [];

    if (name !== undefined) {
      if (!name || name.trim().length === 0) {
        return res.status(400).json({ 
          success: false, 
          message: 'Name cannot be empty' 
        });
      }

      updates.push('name = ?');
      values.push(name.trim());
      
      const slug = name.toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim();
      updates.push('slug = ?');
      values.push(slug);
    }

    if (description !== undefined) {
      updates.push('description = ?');
      values.push(description ? description.trim() : null);
    }

    if (price !== undefined) {
      const parsedPrice = parseFloat(price);
      if (isNaN(parsedPrice) || parsedPrice < 0) {
        return res.status(400).json({ 
          success: false, 
          message: 'Price must be a valid positive number' 
        });
      }
      updates.push('price = ?');
      values.push(parsedPrice);
    }

    if (image_url !== undefined) {
      updates.push('image_url = ?');
      values.push(image_url || null);
    }

    if (category !== undefined) {
      const validCategories = ['main', 'breakfast', 'special', 'dessert', 'drink'];
      if (category && !validCategories.includes(category)) {
        return res.status(400).json({ 
          success: false, 
          message: `Invalid category. Must be one of: ${validCategories.join(', ')}` 
        });
      }
      updates.push('category = ?');
      values.push(category || 'main');
    }

    if (badge !== undefined) {
      updates.push('badge = ?');
      values.push(badge ? badge.trim() : null);
    }

    if (is_featured !== undefined) {
      updates.push('is_featured = ?');
      values.push(is_featured ? 1 : 0);
    }

    if (is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(is_active ? 1 : 0);
    }

    updates.push('updated_at = NOW()');

    if (updates.length === 1) {
      return res.status(400).json({ 
        success: false, 
        message: 'No valid fields to update' 
      });
    }

    values.push(id);

    const [result] = await db.query(
      `UPDATE menu_items SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Menu item not found or no changes made' 
      });
    }

    console.log(`✅ Menu item updated: ID ${id} (${result.changedRows} changes)`);

    io.emit('menu-updated', { 
      action: 'updated', 
      itemId: id,
      updates: req.body,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true, 
      message: 'Menu item updated successfully',
      changes: result.changedRows
    });

  } catch (error) {
    console.error('❌ Update menu item error:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        success: false, 
        message: 'An item with this name already exists' 
      });
    }
    
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

    // Delete image file if exists
    if (item.image_url) {
      const imagePath = path.join(__dirname, 'public', item.image_url);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
        console.log('🗑️ Deleted image file:', imagePath);
      }
    }

    const [result] = await db.query('DELETE FROM menu_items WHERE id = ?', [id]);

    console.log(`✅ Menu item deleted: ${item.name} (ID: ${id})`);

    io.emit('menu-updated', { 
      action: 'deleted', 
      itemId: id,
      itemName: item.name,
      timestamp: new Date().toISOString()
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
      
      console.log('✅ Image uploaded successfully:', imageUrl);

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

// ==================== ANALYTICS ROUTES (Admin) ====================

// Get dashboard stats
app.get('/api/admin/dashboard-stats', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [totalOrders] = await db.query(
      'SELECT COUNT(*) as count FROM orders'
    );

    const [totalRevenue] = await db.query(
      'SELECT COALESCE(SUM(total), 0) as revenue FROM orders WHERE payment_status = "paid"'
    );

    const [activeOrders] = await db.query(
      `SELECT COUNT(*) as count FROM orders 
       WHERE delivery_status IN ('placed', 'preparing', 'delivering')`
    );

    const [totalCustomers] = await db.query(
      'SELECT COUNT(*) as count FROM users WHERE role = "customer"'
    );

    const [recentOrders] = await db.query(
      `SELECT order_id, customer_name, total, payment_status, delivery_status, created_at 
       FROM orders 
       ORDER BY created_at DESC 
       LIMIT 10`
    );

    const [ordersByStatus] = await db.query(
      `SELECT delivery_status, COUNT(*) as count 
       FROM orders 
       GROUP BY delivery_status`
    );

    res.json({
      success: true,
      stats: {
        totalOrders: totalOrders[0].count,
        totalRevenue: parseFloat(totalRevenue[0].revenue),
        activeOrders: activeOrders[0].count,
        totalCustomers: totalCustomers[0].count
      },
      recentOrders: recentOrders,
      ordersByStatus: ordersByStatus
    });

  } catch (error) {
    console.error('❌ Get dashboard stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch dashboard stats' 
    });
  }
});

// Get sales analytics
app.get('/api/admin/sales-analytics', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { period } = req.query; // 'week', 'month', 'year'

    let dateFilter = '';
    switch (period) {
      case 'week':
        dateFilter = 'DATE(created_at) >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)';
        break;
      case 'month':
        dateFilter = 'DATE(created_at) >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)';
        break;
      case 'year':
        dateFilter = 'DATE(created_at) >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)';
        break;
      default:
        dateFilter = '1=1';
    }

    const [salesData] = await db.query(
      `SELECT 
        DATE(created_at) as date,
        COUNT(*) as orders,
        SUM(total) as revenue
       FROM orders 
       WHERE ${dateFilter} AND payment_status = 'paid'
       GROUP BY DATE(created_at)
       ORDER BY date DESC`
    );

    res.json({
      success: true,
      period: period || 'all',
      data: salesData
    });

  } catch (error) {
    console.error('❌ Get sales analytics error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch sales analytics' 
    });
  }
});

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

    console.log(`✅ Admin fetched ${users.length} users`);

    res.json({ success: true, users });
  } catch (error) {
    console.error('❌ Get users error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch users' 
    });
  }
});

// ADD this new route for updating users (handles both role and is_active)
app.patch('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, is_active } = req.body;

    console.log('📝 Updating user:', id, { role, is_active });

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

    console.log(`✅ User ${id} updated successfully`);

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

// Update user role
app.patch('/api/admin/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!['customer', 'admin'].includes(role)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid role. Must be customer or admin.' 
      });
    }

    const [result] = await db.query(
      'UPDATE users SET role = ? WHERE id = ?',
      [role, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    console.log(`✅ User role updated: ID ${id} -> ${role}`);

    res.json({ 
      success: true, 
      message: 'User role updated successfully' 
    });

  } catch (error) {
    console.error('❌ Update user role error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update user role' 
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

    console.log(`✅ User deleted: ID ${id}`);

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

// ==================== RESERVATION ROUTES ====================

// Create reservation
app.post('/api/reservations', verifyToken, async (req, res) => {
  try {
    const { name, email, phone, date, time, guests, message } = req.body;

    if (!name || !email || !phone || !date || !time || !guests) {
      return res.status(400).json({ 
        success: false, 
        message: 'All required fields must be provided' 
      });
    }

    const [result] = await db.query(
      `INSERT INTO reservations 
       (user_id, name, email, phone, date, time, guests, message, status, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
      [req.user.userId, name, email, phone, date, time, guests, message || null]
    );

    console.log(`✅ Reservation created: ID ${result.insertId}`);

    io.to('admin-room').emit('new-reservation', {
      id: result.insertId,
      name,
      email,
      date,
      time,
      guests,
      status: 'pending'
    });

    res.json({ 
      success: true, 
      message: 'Reservation created successfully',
      reservationId: result.insertId 
    });

  } catch (error) {
    console.error('❌ Create reservation error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create reservation' 
    });
  }
});

// Get user reservations
app.get('/api/reservations', verifyToken, async (req, res) => {
  try {
    const [reservations] = await db.query(
      `SELECT * FROM reservations 
       WHERE user_id = ? 
       ORDER BY date DESC, time DESC`,
      [req.user.userId]
    );

    res.json({ success: true, reservations });
  } catch (error) {
    console.error('❌ Get reservations error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch reservations' 
    });
  }
});

// Get all reservations (Admin)
app.get('/api/admin/reservations', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [reservations] = await db.query(
      `SELECT * FROM reservations 
       ORDER BY date DESC, time DESC 
       LIMIT 500`
    );

    res.json({ success: true, reservations });
  } catch (error) {
    console.error('❌ Get admin reservations error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch reservations' 
    });
  }
});

// Update reservation status (Admin)
app.patch('/api/admin/reservations/:id/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid status' 
      });
    }

    const [result] = await db.query(
      'UPDATE reservations SET status = ? WHERE id = ?',
      [status, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Reservation not found' 
      });
    }

    console.log(`✅ Reservation status updated: ID ${id} -> ${status}`);

    res.json({ 
      success: true, 
      message: 'Reservation status updated successfully' 
    });

  } catch (error) {
    console.error('❌ Update reservation status error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update reservation status' 
    });
  }
});

// ==================== VOUCHER ROUTES ====================

// Create voucher (Admin)
app.post('/api/admin/vouchers', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { user_id, code, discount_type, discount_value, expires_at } = req.body;

    console.log('📝 Creating voucher:', { user_id, code, discount_type, discount_value, expires_at });

    if (!user_id || !code || !discount_type || !discount_value || !expires_at) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    // Validate discount type
    if (!['percentage', 'fixed'].includes(discount_type)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Discount type must be percentage or fixed' 
      });
    }

    // Validate discount value
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

    // Check if user exists
    const [userCheck] = await db.query('SELECT id FROM users WHERE id = ?', [user_id]);
    if (userCheck.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Insert voucher
    const [result] = await db.query(
      `INSERT INTO vouchers (user_id, code, discount_type, discount_value, expires_at, created_at) 
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [user_id, code.toUpperCase(), discount_type, value, expires_at]
    );

    console.log(`✅ Voucher created: ${code} for user ${user_id} (ID: ${result.insertId})`);

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

    if (error.code === 'ER_NO_SUCH_TABLE') {
      return res.status(500).json({ 
        success: false, 
        message: 'Vouchers table does not exist. Please run the database migration.' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create voucher',
      error: error.message 
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

    console.log(`✅ Fetched ${vouchers.length} vouchers for user ${user_id}`);

    res.json({ 
      success: true, 
      vouchers 
    });

  } catch (error) {
    console.error('❌ Get vouchers error:', error);
    
    if (error.code === 'ER_NO_SUCH_TABLE') {
      return res.status(500).json({ 
        success: false, 
        message: 'Vouchers table does not exist',
        vouchers: []
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch vouchers',
      vouchers: []
    });
  }
});

// Get user's own vouchers
app.get('/api/user/vouchers', verifyToken, async (req, res) => {
  try {
    console.log('🎟️ Fetching vouchers for user:', req.user.userId);

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

    console.log(`✅ User ${req.user.userId} has ${vouchers.length} available vouchers`);

    res.json({ 
      success: true, 
      vouchers 
    });

  } catch (error) {
    console.error('❌ Get user vouchers error:', error);
    
    if (error.code === 'ER_NO_SUCH_TABLE') {
      return res.json({ 
        success: true, 
        vouchers: [],
        message: 'Vouchers feature not yet available'
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch vouchers',
      vouchers: []
    });
  }
});

// Validate voucher (used by cart)
app.post('/api/user/vouchers/validate', verifyToken, async (req, res) => {
  try {
    const { code, order_total } = req.body;

    console.log('🔍 Validating voucher:', code, 'for order:', order_total);

    if (!code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Voucher code is required' 
      });
    }

    const [vouchers] = await db.query(
      `SELECT * FROM vouchers 
       WHERE code = ? AND user_id = ? AND is_used = FALSE`,
      [code.toUpperCase(), req.user.userId]
    );

    if (vouchers.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Invalid or already used voucher code' 
      });
    }

    const voucher = vouchers[0];

    // Check expiration
    const expiryDate = new Date(voucher.expires_at);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (expiryDate < today) {
      return res.status(400).json({ 
        success: false, 
        message: 'This voucher has expired' 
      });
    }

    // Calculate discount
    let discount = 0;
    if (voucher.discount_type === 'percentage') {
      discount = (parseFloat(order_total) * parseFloat(voucher.discount_value)) / 100;
    } else {
      discount = parseFloat(voucher.discount_value);
    }

    // Ensure discount doesn't exceed order total
    discount = Math.min(discount, parseFloat(order_total));

    console.log('✅ Voucher valid. Discount:', discount);

    res.json({ 
      success: true, 
      voucher: {
        id: voucher.id,
        code: voucher.code,
        discount_type: voucher.discount_type,
        discount_value: voucher.discount_value,
        calculated_discount: discount.toFixed(2)
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

// Mark voucher as used (called after successful order)
app.post('/api/user/vouchers/use', verifyToken, async (req, res) => {
  try {
    const { code } = req.body;

    console.log('✓ Marking voucher as used:', code);

    if (!code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Voucher code is required' 
      });
    }

    const [result] = await db.query(
      `UPDATE vouchers 
       SET is_used = TRUE, used_at = NOW() 
       WHERE code = ? AND user_id = ? AND is_used = FALSE`,
      [code.toUpperCase(), req.user.userId]
    );

    if (result.affectedRows === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Voucher not found or already used' 
      });
    }

    console.log(`✅ Voucher ${code} marked as used for user ${req.user.userId}`);

    res.json({ 
      success: true, 
      message: 'Voucher applied successfully' 
    });

  } catch (error) {
    console.error('❌ Use voucher error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to use voucher' 
    });
  }
});

// Delete voucher (Admin)
app.delete('/api/admin/vouchers/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await db.query('DELETE FROM vouchers WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Voucher not found' 
      });
    }

    console.log(`✅ Voucher deleted: ID ${id}`);

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


// ==================== CONTACT/FEEDBACK ROUTES ====================

// Submit contact form
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email, and message are required' 
      });
    }

    const [result] = await db.query(
      `INSERT INTO contact_messages (name, email, subject, message, created_at) 
       VALUES (?, ?, ?, ?, NOW())`,
      [name, email, subject || 'General Inquiry', message]
    );

    console.log(`✅ Contact message received from: ${email}`);

    io.to('admin-room').emit('new-contact-message', {
      id: result.insertId,
      name,
      email,
      subject,
      created_at: new Date().toISOString()
    });

    res.json({ 
      success: true, 
      message: 'Your message has been sent successfully' 
    });

  } catch (error) {
    console.error('❌ Contact form error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send message' 
    });
  }
});

// Get contact messages (Admin)
app.get('/api/admin/contact-messages', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [messages] = await db.query(
      `SELECT * FROM contact_messages 
       ORDER BY created_at DESC 
       LIMIT 200`
    );

    res.json({ success: true, messages });
  } catch (error) {
    console.error('❌ Get contact messages error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch messages' 
    });
  }
});

// ==================== RATE LIMITING ====================

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
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
  console.log('✅ Voucher routes and user management routes loaded successfully');
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