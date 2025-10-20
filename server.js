const express = require('express');
const cors = require('cors');
const axios = require('axios');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Google OAuth Setup
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this';

// MySQL connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'kusina_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
db.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully!');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

// ==================== EMAIL SERVICE SETUP ====================
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// Verify email configuration on startup
emailTransporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email configuration error:', error.message);
  } else {
    console.log('✅ Email service is ready to send messages');
  }
});

/**
 * 📧 Send verification code email
 */
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
          .header h1 { margin: 0; font-size: 28px; }
          .content { padding: 40px 30px; text-align: center; }
          .code-box { background: #f8f9fa; border: 2px dashed #cda45e; border-radius: 10px; padding: 25px; margin: 30px 0; }
          .code { font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #cda45e; font-family: 'Courier New', monospace; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; text-align: left; border-radius: 5px; }
          .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }
          .logo { width: 60px; height: 60px; background: white; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; color: #cda45e; margin-bottom: 10px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">K</div>
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
            
            <p style="color: #999; font-size: 14px; margin-top: 30px;">
              Having trouble? Contact us at 
              <a href="mailto:${process.env.MAIL_USER}" style="color: #cda45e;">${process.env.MAIL_USER}</a>
            </p>
          </div>
          
          <div class="footer">
            <p style="margin: 0 0 10px 0;">© 2025 Kusina ni Katya. All Rights Reserved.</p>
            <p style="margin: 0;">Aurora Blvd, Quezon City, Manila, Philippines</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
Hello ${userName}!

Thank you for signing up with Kusina ni Katya.

Your verification code is: ${code}

This code will expire in 10 minutes.

Security Notice: Never share this code with anyone. If you didn't request this code, please ignore this email.

© 2025 Kusina ni Katya
Aurora Blvd, Quezon City, Manila, Philippines
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

/**
 * 📧 Send LOGIN verification code email
 */
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
          .logo { width: 60px; height: 60px; background: white; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; color: #cda45e; margin-bottom: 10px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">K</div>
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
            
            <p style="color: #999; font-size: 14px; margin-top: 30px;">
              Having trouble? Contact us at 
              <a href="mailto:${process.env.MAIL_USER}" style="color: #cda45e;">${process.env.MAIL_USER}</a>
            </p>
          </div>
          
          <div class="footer">
            <p style="margin: 0 0 10px 0;">© 2025 Kusina ni Katya. All Rights Reserved.</p>
            <p style="margin: 0;">Aurora Blvd, Quezon City, Manila, Philippines</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
Hello ${userName}!

Someone is trying to sign in to your account. Please use the code below to verify your login:

Your verification code is: ${code}

This code will expire in 10 minutes.

Security Notice: If you didn't attempt to sign in, please ignore this email and consider changing your password. Never share this code with anyone.

© 2025 Kusina ni Katya
Aurora Blvd, Quezon City, Manila, Philippines
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

// ==================== VERIFICATION CODE STORAGE ====================
const verificationCodes = new Map();
const loginVerificationCodes = new Map(); // 👈 NEW: For login verification

/**
 * Generate a random 6-digit verification code
 */
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// PayMongo Configuration
const PAYMONGO_SECRET_KEY = process.env.PAYMONGO_SECRET_KEY;
const PAYMONGO_API_BASE = 'https://api.paymongo.com/v1';

// Helper function to create Base64 auth header
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

// Create HTTP server and Socket.IO
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('🔌 Admin connected:', socket.id);
  
  socket.on('disconnect', () => {
    console.log('❌ Admin disconnected:', socket.id);
  });
});

// JWT Middleware
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

// ==================== AUTHENTICATION ROUTES ====================

/**
 * 📝 POST /auth/signup - Step 1: Send verification code
 */
app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide name, email, and password' 
      });
    }

    const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered' 
      });
    }

    const verificationCode = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    verificationCodes.set(email, {
      code: verificationCode,
      expiresAt,
      userData: { name, email, phone, password }
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
      
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send verification email. Please check your email configuration.' 
      });
    }

  } catch (error) {
    console.error('❌ Signup error:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during signup' 
    });
  }
});

/**
 * ✅ POST /auth/verify-code - Step 2: Verify code and create account
 */
app.post('/auth/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and verification code are required' 
      });
    }

    const verificationData = verificationCodes.get(email);

    if (!verificationData) {
      return res.status(400).json({ 
        success: false, 
        message: 'No verification code found. Please request a new one.' 
      });
    }

    if (Date.now() > verificationData.expiresAt) {
      verificationCodes.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'Verification code expired. Please request a new one.' 
      });
    }

    if (verificationData.code !== code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid verification code' 
      });
    }

    const { name, phone, password } = verificationData.userData;

    const [result] = await db.query(
      `INSERT INTO users (name, email, phone, password_hash, auth_type, role, created_at, last_login) 
       VALUES (?, ?, ?, ?, 'email', 'customer', NOW(), NOW())`,
      [name, email, phone || null, password]
    );

    verificationCodes.delete(email);

    const token = jwt.sign(
      { userId: result.insertId, email, name, role: 'customer' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`✅ User created successfully: ${email}`);

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
    res.status(500).json({ 
      success: false, 
      message: 'Server error during verification' 
    });
  }
});

/**
 * 🔄 POST /auth/resend-code - Resend verification code
 */
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

// ==================== NEW LOGIN WITH EMAIL VERIFICATION ====================

/**
 * 🔐 POST /auth/send-login-code - Send login verification code
 */
app.post('/auth/send-login-code', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    // Check if user exists and validate password
    const [users] = await db.query(
      'SELECT id, email, name, password_hash, role FROM users WHERE email = ? AND auth_type = ?',
      [email, 'email']
    );

    if (users.length === 0 || password !== users[0].password_hash) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }

    const user = users[0];

    // Generate verification code
    const verificationCode = generateVerificationCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    // Store login verification code
    loginVerificationCodes.set(email, {
      code: verificationCode,
      expiresAt,
      userId: user.id,
      userName: user.name,
      userRole: user.role
    });

    // Send verification email
    try {
      await sendLoginVerificationEmail(email, verificationCode, user.name);
      console.log(`✅ Login verification code sent to ${email}`);

      res.json({ 
        success: true, 
        message: 'Verification code sent to your email',
        email: email,
        devCode: process.env.NODE_ENV === 'development' ? verificationCode : undefined
      });
    } catch (emailError) {
      console.error('📧 Email sending failed:', emailError.message);
      loginVerificationCodes.delete(email);
      
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

/**
 * ✅ POST /auth/verify-login-code - Verify login code and complete sign in
 */
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

    // Code is valid - update last login
    await db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [loginData.userId]);

    // Generate JWT token
    const token = jwt.sign(
      { userId: loginData.userId, email, name: loginData.userName, role: loginData.userRole },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Delete used code
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

// ==================== EXISTING AUTH ROUTES ====================

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

app.post('/auth/verify-login-code', async (req, res) => {
  try {
    let { email, code } = req.body;

    console.log('🔍 Verifying login code for:', email);
    console.log('📥 Received code:', code, 'Length:', code?.length);

    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and code are required' 
      });
    }

    const [users] = await db.query(
      'SELECT id, email, name, password_hash, role FROM users WHERE email = ? AND auth_type = ?',
      [email, 'email']
    );

    if (users.length === 0 || password !== users[0].password_hash) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const user = users[0];
    await db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    const appToken = jwt.sign(
      { userId: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token: appToken,
      user: { id: user.id, email: user.email, name: user.name, role: user.role, authType: 'email' }
    });

  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ success: false, message: 'Login failed', error: error.message });
  }
});

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

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    paymongo: PAYMONGO_SECRET_KEY ? 'configured' : 'not configured',
    email: process.env.MAIL_USER ? 'configured' : 'not configured'
  });
});

app.post('/api/create-order', verifyToken, async (req, res) => {
  try {
    const orderData = req.body;
    const orderId = 'KK' + Date.now() + Math.floor(Math.random() * 1000);

    const [result] = await db.query(
      `INSERT INTO orders (
        order_id, user_id, customer_name, customer_email, customer_phone,
        items, subtotal, delivery_fee, tax, total,
        delivery_option, payment_method, payment_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        orderId, req.user.userId, orderData.customer_name,
        orderData.customer_email, orderData.customer_phone,
        JSON.stringify(orderData.items || []),
        parseFloat(orderData.subtotal || 0),
        parseFloat(orderData.delivery_fee || 0),
        parseFloat(orderData.tax || 0),
        parseFloat(orderData.total || 0),
        orderData.delivery_option || 'delivery',
        orderData.payment_method || 'card',
        orderData.payment_status || 'pending'
      ]
    );

    // 🔥 EMIT NEW ORDER TO ALL CONNECTED ADMINS
    io.emit('new-order', {
      order_id: orderId,
      customer_name: orderData.customer_name,
      total: orderData.total,
      payment_status: orderData.payment_status,
      created_at: new Date().toISOString()
    });

    console.log('✅ Order saved and broadcasted:', orderId);
    res.json({ success: true, order_id: orderId });

  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ success: false, message: 'Failed to create order' });
  }
});

app.get('/api/get-orders', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 100',
      [req.user.userId]
    );
    
    res.json({ success: true, orders: rows });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ success: false, message: 'Failed to retrieve orders', error: error.message });
  }
});

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

    console.log(`✅ Order ${order_id} status updated to ${status}`);
    res.json({ success: true, message: 'Order status updated' });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ success: false, message: 'Failed to update order', error: error.message });
  }
});

// ==================== PAYMONGO PAYMENT ROUTES ====================

app.post('/api/create-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount, currency, customer, card } = req.body;

    console.log('💳 Creating PayMongo payment intent...');
    console.log('Amount:', amount, 'Currency:', currency);

    const cleanCardNumber = card.number.replace(/\s/g, '').replace(/\D/g, '');
    
    console.log('Step 1: Creating payment method...');
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

    const pmData = pmResp.data;
    const pmId = pmData.data.id;
    console.log('✅ Payment method created');

    console.log('Step 2: Creating payment intent...');
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

    console.log('Step 3: Attaching payment method to intent...');
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
    console.log('Payment Status:', status);

    if (status === 'succeeded') {
      console.log('✅ Payment succeeded immediately');
      res.json({
        success: true,
        paymentIntentId: piId,
        status: 'succeeded',
        message: 'Payment processed successfully'
      });
    } else if (status === 'processing') {
      console.log('⏳ Payment processing...');
      res.json({
        success: true,
        paymentIntentId: piId,
        status: 'processing',
        message: 'Payment is processing'
      });
    } else if (status === 'requires_action') {
      const clientSecret = attachResult.data.data.attributes.client_key;
      console.log('🔐 3D Secure required');
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
    console.log('Checkout URL:', checkoutUrl);

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

// ==================== CLEANUP EXPIRED CODES ====================
// Clean up expired verification codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  
  // Clean signup verification codes
  for (const [email, data] of verificationCodes.entries()) {
    if (now > data.expiresAt) {
      verificationCodes.delete(email);
      console.log(`🗑️ Cleaned up expired signup code for: ${email}`);
    }
  }
  
  // Clean login verification codes
  for (const [email, data] of loginVerificationCodes.entries()) {
    if (now > data.expiresAt) {
      loginVerificationCodes.delete(email);
      console.log(`🗑️ Cleaned up expired login code for: ${email}`);
    }
  }
}, 5 * 60 * 1000);

// ==================== START SERVER ====================

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔌 Socket.IO enabled`);});
  console.log('\n🚀 ========================================');
  console.log(`🍽️  Kusina ni Katya Backend Server`);
  console.log(`📡 Running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`🔐 Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`💳 PayMongo: ${PAYMONGO_SECRET_KEY ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`📧 Email Service: ${process.env.MAIL_USER ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`🗄️  Database: ${process.env.DB_NAME || 'kusina_db'}`);
  console.log('========================================\n');
  console.log('📋 Available endpoints:');
  console.log('   AUTH ROUTES:');
  console.log('   POST /auth/signup                - Send verification code');
  console.log('   POST /auth/verify-code           - Verify code & create account');
  console.log('   POST /auth/resend-code           - Resend verification code');
  console.log('   POST /auth/send-login-code       - Send login verification code (NEW) 🔐');
  console.log('   POST /auth/verify-login-code     - Verify login code & sign in (NEW) 🔐');
  console.log('   POST /auth/google                - Google OAuth');
  console.log('   POST /auth/login                 - Email/password login (old method)');
  console.log('   GET  /auth/me                    - Get current user (protected)');
  console.log('   ORDER ROUTES (Protected):');
  console.log('   GET  /api/health');
  console.log('   GET  /api/get-orders');
  console.log('   POST /api/create-order');
  console.log('   GET  /api/get-order/:id');
  console.log('   POST /api/update-order-status');
  console.log('   PAYMONGO ROUTES (Protected):');
  console.log('   POST /api/create-payment-intent');
  console.log('   POST /api/paymongo/create-gcash-payment');
  console.log('   POST /api/paymongo/webhook');
  console.log('========================================\n');


module.exports = app;