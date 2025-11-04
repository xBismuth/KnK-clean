// ==================== MAIN SERVER FILE ====================
const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

// Import configurations
const db = require('./config/db');
const { emailTransporter } = require('./config/email');

// Import middlewares
const { apiLimiter } = require('./middlewares/rateLimiter');

// Import routes
const authRoutes = require('./routes/authRoutes');
const orderRoutes = require('./routes/orderRoutes');
const voucherRoutes = require('./routes/voucherRoutes');
const menuRoutes = require('./routes/menuRoutes');
const userRoutes = require('./routes/userRoutes');
const supportRoutes = require('./routes/supportRoutes');
const paymongoRoutes = require('./routes/paymongoRoutes');

// Import socket handlers
const initializeOrderSockets = require('./sockets/orderSockets');

// ==================== INITIALIZATION ====================
// Lightweight logger helpers for clean, consistent logs
const ts = () => new Date().toISOString();
const log = {
  info: (...args) => console.log(`[INFO ${ts()}]`, ...args),
  warn: (...args) => console.warn(`[WARN ${ts()}]`, ...args),
  error: (...args) => console.error(`[ERROR ${ts()}]`, ...args)
};
const app = express();
const PORT = process.env.PORT || 3000;

// Create HTTP server and Socket.IO
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Make io accessible to routes
app.set('socketio', io);

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('Public'));

// Request log (dev only)
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    log.info(`${req.method} ${req.originalUrl}`);
    next();
  });
}

// Rate limiting
app.use('/api/', apiLimiter);

// ==================== ROUTES ====================
// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    paymongo: process.env.PAYMONGO_SECRET_KEY ? 'configured' : 'not configured',
    email: process.env.MAIL_USER ? 'configured' : 'not configured',
    socketio: 'enabled'
  });
});

// Mount routes
app.use('/auth', authRoutes);
app.use('/api', orderRoutes);
app.use('/api', voucherRoutes);
app.use('/api', menuRoutes);
app.use('/api', userRoutes);
app.use('/api', supportRoutes);
app.use('/api', paymongoRoutes);

// ==================== SOCKET.IO ====================
initializeOrderSockets(io, db);

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
  log.error('Unhandled error', err.message);
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ 
      success: false, 
      message: 'Invalid token' 
    });
  }

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ 
      success: false, 
      message: 'File too large. Maximum size is 5MB.' 
    });
  }

  res.status(500).json({ 
    success: false, 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ==================== START SERVER ====================
server.listen(PORT, () => {
  const paymongoOk = !!process.env.PAYMONGO_SECRET_KEY;
  const emailOk = !!process.env.MAIL_USER;
  const jwtOk = !!process.env.JWT_SECRET;
  const dbName = process.env.DB_NAME || 'kusina_db';

  const allOk = paymongoOk && emailOk && jwtOk;

  if (allOk) {
    console.log(`\n✅ Ready: http://localhost:${PORT}  (ws enabled)\n   DB: ${dbName}  |  Email: on  |  PayMongo: on\n`);
  } else {
    log.info(`Server: http://localhost:${PORT} (ws enabled)`);
    log.info(`DB: ${dbName}`);
    log.info(`Email: ${emailOk ? 'on' : 'off'}`);
    log.info(`PayMongo: ${paymongoOk ? 'on' : 'off'}`);
    log.info(`JWT: ${jwtOk ? 'custom' : 'default'}`);
  }
});

// ==================== GRACEFUL SHUTDOWN ====================
let isShuttingDown = false;

function gracefulShutdown(signal) {
  if (isShuttingDown) {
    process.exit(1);
    return;
  }
  isShuttingDown = true;
  log.warn(`${signal} received - Shutting down...`);
  
  const timer = setTimeout(() => {
    log.error('Shutdown timeout - forcing exit');
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

module.exports = { app, server, io };