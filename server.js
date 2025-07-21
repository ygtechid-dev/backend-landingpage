// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'workwise',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Connected to MySQL database');
    connection.release();
  } catch (error) {
    console.error('❌ Error connecting to database:', error.message);
    process.exit(1);
  }
}

// Generate company ID
function generateCompanyId() {
  const timestamp = Date.now();
  const randomString = Math.random().toString(36).substring(2, 8);
  return `CMP-${timestamp}${randomString}`;
}

// Simple authentication middleware using email and password
const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ 
      status: false, 
      message: 'Basic authentication required' 
    });
  }

  try {
    // Decode Basic auth (email:password)
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [email, password] = credentials.split(':');

    if (!email || !password) {
      return res.status(401).json({ 
        status: false, 
        message: 'Email and password required' 
      });
    }

    // Find user by email
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ? AND is_active = 1',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ 
        status: false, 
        message: 'Invalid credentials' 
      });
    }

    const user = users[0];

    // Check if login is enabled
    if (!user.is_login_enable) {
      return res.status(403).json({
        status: false,
        message: 'Login is disabled for this account'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        status: false, 
        message: 'Invalid credentials' 
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ 
      status: false, 
      message: 'Authentication failed' 
    });
  }
};

// REGISTER ENDPOINT
app.post('/api/register', [
  body('first_name').notEmpty().withMessage('First name is required'),
  body('last_name').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('type').isIn(['company', 'employee', 'admin']).withMessage('Type must be company, employee, or admin')
], async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: false,
        message: 'Validation errors',
        errors: errors.array()
      });
    }

    const {
      first_name,
      last_name,
      email,
      password,
      type,
      lang = 'en',
      avatar = ''
    } = req.body;

    // Set default subscription to Basic - tidak bisa diubah saat register
    const subscription = 'Basic';

    // Check if email already exists
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({
        status: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate company_id for company type
    const companyId = type === 'company' ? generateCompanyId() : null;

    // Insert new user
    const [result] = await pool.execute(
      `INSERT INTO users (
        first_name, last_name, email, password, type, company_id, 
        subscription, lang, plan, avatar, created_by, is_active, is_login_enable, 
        dark_mode, messenger_color, is_disable, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [
        first_name,
        last_name,
        email,
        hashedPassword,
        type,
        companyId,
        subscription,
        lang,
        0, // plan - Basic = 0
        avatar, // avatar dari request body atau empty string
        0, // created_by - default 0
        1, // is_active
        1, // is_login_enable
        0, // dark_mode
        '#2180f3', // messenger_color
        1  // is_disable
      ]
    );

    // Get the created user
    const [newUser] = await pool.execute(
      'SELECT * FROM users WHERE id = ?',
      [result.insertId]
    );

    // Remove password from response
    const userData = { ...newUser[0] };
    delete userData.password;

    res.status(201).json({
      status: true,
      message: 'User registered successfully',
      data: {
        user: userData
      }
    });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      status: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// LOGIN ENDPOINT
app.post('/api/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: false,
        message: 'Validation errors',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({
        status: false,
        message: 'Invalid email or password'
      });
    }

    const user = users[0];

    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({
        status: false,
        message: 'Account is not active'
      });
    }

    if (!user.is_login_enable) {
      return res.status(403).json({
        status: false,
        message: 'Login is disabled for this account'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        status: false,
        message: 'Invalid email or password'
      });
    }

    // Update last login
    await pool.execute(
      'UPDATE users SET last_login = NOW() WHERE id = ?',
      [user.id]
    );

    // Remove password from response
    const userData = { ...user };
    delete userData.password;

    res.json({
      status: true,
      message: 'Login successful',
      data: {
        user: userData
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      status: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// GET PROFILE ENDPOINT
app.get('/api/profile', authenticateUser, async (req, res) => {
  try {
    // User data already available from middleware
    const userData = { ...req.user };
    delete userData.password;

    res.json({
      status: true,
      message: 'Profile retrieved successfully',
      data: {
        user: userData
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      status: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// UPDATE PROFILE ENDPOINT
app.put('/api/profile', authenticateUser, [
  body('first_name').optional().notEmpty().withMessage('First name cannot be empty'),
  body('last_name').optional().notEmpty().withMessage('Last name cannot be empty'),
  body('subscription').optional().isIn(['Basic', 'Silver', 'Premium', 'Enterprise']).withMessage('Invalid subscription type')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status: false,
        message: 'Validation errors',
        errors: errors.array()
      });
    }

    const userId = req.user.id;
    const updates = {};
    const values = [];
    let query = 'UPDATE users SET ';

    // Build dynamic update query
    Object.keys(req.body).forEach(key => {
      if (req.body[key] !== undefined && key !== 'password') {
        updates[key] = '?';
        values.push(req.body[key]);
      }
    });

    if (values.length === 0) {
      return res.status(400).json({
        status: false,
        message: 'No valid fields to update'
      });
    }

    // Update plan based on subscription if subscription is being updated
    if (req.body.subscription) {
      const planMap = { 'Basic': 0, 'Silver': 1, 'Premium': 2, 'Enterprise': 3 };
      updates.plan = '?';
      values.push(planMap[req.body.subscription]);
    }

    updates.updated_at = 'NOW()';
    query += Object.keys(updates).map(key => `${key} = ${updates[key]}`).join(', ');
    query += ' WHERE id = ?';
    values.push(userId);

    await pool.execute(query, values);

    // Get updated user
    const [updatedUser] = await pool.execute(
      'SELECT * FROM users WHERE id = ?',
      [userId]
    );

    const userData = { ...updatedUser[0] };
    delete userData.password;

    res.json({
      status: true,
      message: 'Profile updated successfully',
      data: {
        user: userData
      }
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      status: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// LOGOUT ENDPOINT
app.post('/api/logout', authenticateUser, async (req, res) => {
  try {
    res.json({
      status: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      status: false,
      message: 'Internal server error'
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: true,
    message: 'API is running',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    status: false,
    message: 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    status: false,
    message: 'Endpoint not found'
  });
});

// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
  await testConnection();
  
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📚 Available endpoints:`);
    console.log(`   POST /api/register - Register new user`);
    console.log(`   POST /api/login - User login`);
    console.log(`   GET /api/profile - Get user profile`);
    console.log(`   PUT /api/profile - Update user profile`);
    console.log(`   POST /api/logout - User logout`);
    console.log(`   GET /api/health - Health check`);
  });
}

startServer();

module.exports = app;