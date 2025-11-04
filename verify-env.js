// ==================== ENVIRONMENT VERIFICATION SCRIPT ====================
// Save as: verify-env.js
// Run with: node verify-env.js

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// Colors for console output
const c = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(msg, type = 'info') {
  const icons = { ok: '✅', err: '❌', warn: '⚠️', info: 'ℹ️' };
  const colors = { ok: c.green, err: c.red, warn: c.yellow, info: c.cyan };
  console.log(`${colors[type]}${icons[type]} ${msg}${c.reset}`);
}

function header(text) {
  console.log(`\n${c.cyan}${c.bold}${'='.repeat(60)}${c.reset}`);
  console.log(`${c.cyan}${c.bold}${text}${c.reset}`);
  console.log(`${c.cyan}${c.bold}${'='.repeat(60)}${c.reset}\n`);
}

// ==================== CHECK 1: .env File ====================
async function checkEnvFile() {
  header('1. Checking .env File');
  
  const envPath = path.join(__dirname, '.env');
  
  if (!fs.existsSync(envPath)) {
    log('.env file not found!', 'err');
    log('Create .env file with required variables', 'warn');
    return false;
  }
  
  log('.env file exists', 'ok');
  
  require('dotenv').config();
  
  const required = [
    'PORT',
    'JWT_SECRET',
    'DB_HOST',
    'DB_USER',
    'DB_PASS',
    'DB_NAME',
    'MAIL_USER',
    'MAIL_PASS'
  ];
  
  let allPresent = true;
  
  for (const key of required) {
    if (process.env[key]) {
      log(`${key}: configured`, 'ok');
    } else {
      log(`${key}: missing!`, 'err');
      allPresent = false;
    }
  }
  
  // Optional but recommended
  const optional = ['PAYMONGO_SECRET_KEY', 'GOOGLE_CLIENT_ID'];
  for (const key of optional) {
    if (process.env[key]) {
      log(`${key}: configured`, 'ok');
    } else {
      log(`${key}: not configured (optional)`, 'warn');
    }
  }
  
  return allPresent;
}

// ==================== CHECK 2: Required Files ====================
async function checkRequiredFiles() {
  header('2. Checking Required Files');
  
  const files = [
    'server.js',
    'package.json',
    'Public/index.html',
    'Public/login.html',
    'Public/signup.html',
    'Public/menu.html',
    'Public/cart.html',
    'Public/orders.html',
    'Public/profile.html',
    'Public/dashboard.html',
    'Public/admin-menu.html',
    'Public/admin-users.html'
  ];
  
  let allPresent = true;
  
  for (const file of files) {
    const filePath = path.join(__dirname, file);
    if (fs.existsSync(filePath)) {
      log(`${file}`, 'ok');
    } else {
      log(`${file} - NOT FOUND`, 'err');
      allPresent = false;
    }
  }
  
  return allPresent;
}

// ==================== CHECK 3: Database Connection ====================
async function checkDatabase() {
  header('3. Checking Database Connection');
  
  require('dotenv').config();
  
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASS || '',
      database: process.env.DB_NAME || 'kusina_db'
    });
    
    log('Database connection successful', 'ok');
    
    // Check required tables
    const [tables] = await connection.query('SHOW TABLES');
    const tableNames = tables.map(t => Object.values(t)[0]);
    
    const required = ['users', 'orders', 'menu_items', 'vouchers'];
    
    log('\nChecking tables:', 'info');
    for (const table of required) {
      if (tableNames.includes(table)) {
        log(`  ${table} table exists`, 'ok');
      } else {
        log(`  ${table} table MISSING`, 'err');
      }
    }
    
    // Check vouchers table structure
    if (tableNames.includes('vouchers')) {
      const [columns] = await connection.query('DESCRIBE vouchers');
      const columnNames = columns.map(c => c.Field);
      
      const requiredCols = ['id', 'user_id', 'code', 'discount_type', 'discount_value', 'expires_at', 'is_used'];
      
      log('\nVouchers table columns:', 'info');
      let allCols = true;
      for (const col of requiredCols) {
        if (columnNames.includes(col)) {
          log(`  ${col}`, 'ok');
        } else {
          log(`  ${col} MISSING`, 'err');
          allCols = false;
        }
      }
      
      if (!allCols) {
        log('\nRun database migration to fix vouchers table', 'warn');
      }
    }
    
    // Check users table for is_active column
    if (tableNames.includes('users')) {
      const [userCols] = await connection.query('DESCRIBE users');
      const userColNames = userCols.map(c => c.Field);
      
      if (userColNames.includes('is_active')) {
        log('users.is_active column exists', 'ok');
      } else {
        log('users.is_active column MISSING', 'err');
        log('Run: ALTER TABLE users ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER role;', 'warn');
      }
    }
    
    await connection.end();
    return true;
    
  } catch (error) {
    log(`Database connection failed: ${error.message}`, 'err');
    log('Check DB credentials in .env file', 'warn');
    return false;
  }
}

// ==================== CHECK 4: Node Modules ====================
async function checkNodeModules() {
  header('4. Checking Node Modules');
  
  const required = [
    'express',
    'cors',
    'axios',
    'mysql2',
    'jsonwebtoken',
    'google-auth-library',
    'nodemailer',
    'socket.io',
    'bcrypt',
    'express-rate-limit',
    'multer',
    'dotenv'
  ];
  
  let allInstalled = true;
  
  for (const module of required) {
    try {
      require.resolve(module);
      log(`${module}`, 'ok');
    } catch (error) {
      log(`${module} - NOT INSTALLED`, 'err');
      allInstalled = false;
    }
  }
  
  if (!allInstalled) {
    log('\nRun: npm install', 'warn');
  }
  
  return allInstalled;
}

// ==================== CHECK 5: Port Availability ====================
async function checkPort() {
  header('5. Checking Port Availability');
  
  require('dotenv').config();
  const port = process.env.PORT || 3000;
  
  const net = require('net');
  
  return new Promise((resolve) => {
    const server = net.createServer();
    
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        log(`Port ${port} is already in use`, 'err');
        log('Stop the running server or change PORT in .env', 'warn');
        resolve(false);
      }
    });
    
    server.once('listening', () => {
      server.close();
      log(`Port ${port} is available`, 'ok');
      resolve(true);
    });
    
    server.listen(port);
  });
}

// ==================== CHECK 6: File Permissions ====================
async function checkPermissions() {
  header('6. Checking File Permissions');
  
  const dirs = [
    'Public/assets/images/menu',
    'Public/assets/images',
    'Public/assets'
  ];
  
  let allWritable = true;
  
  for (const dir of dirs) {
    const dirPath = path.join(__dirname, dir);
    
    try {
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
        log(`Created directory: ${dir}`, 'ok');
      } else {
        fs.accessSync(dirPath, fs.constants.W_OK);
        log(`${dir} is writable`, 'ok');
      }
    } catch (error) {
      log(`${dir} is NOT writable`, 'err');
      allWritable = false;
    }
  }
  
  return allWritable;
}

// ==================== CHECK 7: Server.js Syntax ====================
async function checkServerSyntax() {
  header('7. Checking server.js Syntax');
  
  try {
    require('./server.js');
    log('server.js syntax is valid', 'ok');
    return true;
  } catch (error) {
    log(`server.js has syntax errors: ${error.message}`, 'err');
    return false;
  }
}

// ==================== MAIN VERIFICATION ====================
async function runVerification() {
  console.clear();
  console.log(`${c.cyan}${c.bold}╔═══════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.cyan}${c.bold}║     🔍 KUSINA NI KATYA - ENVIRONMENT VERIFICATION      ║${c.reset}`);
  console.log(`${c.cyan}${c.bold}╚═══════════════════════════════════════════════════════════╝${c.reset}`);
  
  const results = {
    passed: 0,
    failed: 0
  };
  
  // Run all checks
  const checks = [
    { name: 'Environment Variables', fn: checkEnvFile },
    { name: 'Required Files', fn: checkRequiredFiles },
    { name: 'Node Modules', fn: checkNodeModules },
    { name: 'Database', fn: checkDatabase },
    { name: 'Port Availability', fn: checkPort },
    { name: 'File Permissions', fn: checkPermissions },
    { name: 'server.js Syntax', fn: checkServerSyntax }
  ];
  
  for (const check of checks) {
    try {
      const result = await check.fn();
      if (result) {
        results.passed++;
      } else {
        results.failed++;
      }
    } catch (error) {
      log(`Check failed: ${error.message}`, 'err');
      results.failed++;
    }
  }
  
  // Print summary
  header('VERIFICATION SUMMARY');
  
  console.log(`${c.green}✅ Passed: ${results.passed}${c.reset}`);
  console.log(`${c.red}❌ Failed: ${results.failed}${c.reset}`);
  
  if (results.failed === 0) {
    console.log(`\n${c.green}${c.bold}╔═══════════════════════════════════════╗${c.reset}`);
    console.log(`${c.green}${c.bold}║   🎉 ENVIRONMENT IS READY! 🎉       ║${c.reset}`);
    console.log(`${c.green}${c.bold}╚═══════════════════════════════════════╝${c.reset}`);
    console.log(`\n${c.cyan}You can now start the server with: ${c.bold}node server.js${c.reset}\n`);
  } else {
    console.log(`\n${c.red}${c.bold}╔═══════════════════════════════════════╗${c.reset}`);
    console.log(`${c.red}${c.bold}║   ⚠️  FIX ISSUES BEFORE STARTING   ║${c.reset}`);
    console.log(`${c.red}${c.bold}╚═══════════════════════════════════════╝${c.reset}\n`);
  }
}

// Run verification
runVerification().catch(error => {
  log(`Fatal error: ${error.message}`, 'err');
  process.exit(1);
});