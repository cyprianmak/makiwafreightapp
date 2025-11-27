// server.js - COMPLETE FIX WITH DATABASE SCHEMA RESET
const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { Pool } = require('pg');
const app = express();
const PORT = process.env.PORT || 10000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Initialize database - COMPLETELY RESET TABLES
const initializeDatabase = async () => {
  try {
    console.log('🚀 Initializing database...');
    
    // DROP AND RECREATE ALL TABLES TO ENSURE CORRECT SCHEMA
    console.log('Dropping existing tables...');
    await pool.query('DROP TABLE IF EXISTS messages CASCADE');
    await pool.query('DROP TABLE IF EXISTS loads CASCADE');
    await pool.query('DROP TABLE IF EXISTS acl CASCADE');
    await pool.query('DROP TABLE IF EXISTS banners CASCADE');
    await pool.query('DROP TABLE IF EXISTS users CASCADE');

    // Create users table WITH PASSWORD COLUMN
    console.log('Creating users table...');
    await pool.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        company VARCHAR(255),
        address TEXT,
        role VARCHAR(50) NOT NULL,
        vehicle_info TEXT,
        membership_number VARCHAR(20) UNIQUE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create loads table
    console.log('Creating loads table...');
    await pool.query(`
      CREATE TABLE loads (
        id SERIAL PRIMARY KEY,
        ref VARCHAR(20) NOT NULL,
        origin VARCHAR(255) NOT NULL,
        destination VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        cargo_type VARCHAR(255) NOT NULL,
        weight DECIMAL(10,2) NOT NULL,
        notes TEXT,
        shipper_id INTEGER REFERENCES users(id),
        shipper_name VARCHAR(255),
        shipper_email VARCHAR(255),
        shipper_membership VARCHAR(20),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        status VARCHAR(50) DEFAULT 'active'
      )
    `);

    // Create messages table
    console.log('Creating messages table...');
    await pool.query(`
      CREATE TABLE messages (
        id SERIAL PRIMARY KEY,
        sender_membership VARCHAR(20) NOT NULL,
        recipient_membership VARCHAR(20) NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create acl table
    console.log('Creating acl table...');
    await pool.query(`
      CREATE TABLE acl (
        id SERIAL PRIMARY KEY,
        user_email VARCHAR(255) UNIQUE,
        post BOOLEAN DEFAULT false,
        market BOOLEAN DEFAULT false
      )
    `);

    // Create banners table
    console.log('Creating banners table...');
    await pool.query(`
      CREATE TABLE banners (
        id SERIAL PRIMARY KEY,
        page VARCHAR(50) NOT NULL,
        banner TEXT,
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // CREATE ADMIN USER WITH PROPER PASSWORD
    const adminEmail = 'cyprianmak@gmail.com';
    const adminPassword = 'Muchandida@1';
    
    console.log('Creating admin user...');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminPassword, salt);
    const adminMembership = 'MFADMIN01';
    
    await pool.query(
      `INSERT INTO users (name, email, password, role, membership_number, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
      ['Admin', adminEmail, hashedPassword, 'admin', adminMembership]
    );

    await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, true, true)', [adminEmail]);
    
    // Initialize banners
    await pool.query("INSERT INTO banners (page, banner) VALUES ('index', ''), ('dashboard', '')");

    console.log('✅ Database initialized successfully with admin user!');
    console.log('📧 Admin Email:', adminEmail);
    console.log('🔑 Admin Password:', adminPassword);
    console.log('🔢 Membership Number:', adminMembership);
    
  } catch (err) {
    console.error('❌ Error initializing database:', err);
  }
};

// DEBUG ROUTES - FORCE RESET DATABASE
app.get('/api/debug/reset-database', async (req, res) => {
  try {
    await initializeDatabase();
    res.json({ message: '✅ Database reset successfully! Admin user created.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/debug/check-admin', async (req, res) => {
  try {
    const adminResult = await pool.query('SELECT * FROM users WHERE email = $1', ['cyprianmak@gmail.com']);
    
    if (adminResult.rows.length === 0) {
      return res.json({ message: '❌ Admin user does not exist' });
    }
    
    const admin = adminResult.rows[0];
    res.json({ 
      message: '✅ Admin user exists',
      admin: {
        email: admin.email,
        role: admin.role,
        membership_number: admin.membership_number,
        has_password: !!admin.password,
        password_length: admin.password ? admin.password.length : 0
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/debug/all-users', async (req, res) => {
  try {
    const users = await pool.query('SELECT id, name, email, role, membership_number, LENGTH(password) as password_length FROM users');
    res.json(users.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API Routes

// Auth routes - SIMPLIFIED
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log('🔐 Login attempt for:', email);
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log('❌ Invalid password for user:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('✅ Login successful for:', email);

    // Get ACLs
    let acl = {};
    try {
      const aclResult = await pool.query('SELECT * FROM acl WHERE user_email = $1', [email]);
      acl = aclResult.rows[0] || {};
    } catch (aclError) {
      console.log('ACL not found, using defaults');
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    
    res.json({ 
      message: 'Login successful',
      data: { 
        user: userWithoutPassword, 
        token: 'mock-jwt-token-' + user.id,
        acl 
      } 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, phone, company, address, role, vehicle_info } = req.body;

  try {
    // Check if user exists
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Generate membership number
    const prefix = role === 'shipper' ? 'MFS' : 'MFT';
    const randomNum = Math.floor(1000 + Math.random() * 9000);
    const membershipNumber = `${prefix}${randomNum}`;

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (name, email, password, phone, company, address, role, vehicle_info, membership_number, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) RETURNING *`,
      [name, email, hashedPassword, phone, company, address, role, vehicle_info, membershipNumber]
    );

    const newUser = result.rows[0];

    // Set default ACLs
    try {
      await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, $2, $3)', [
        email, 
        role === 'shipper' ? true : false, 
        role === 'transporter' ? true : false
      ]);
    } catch (aclError) {
      console.log('ACL creation failed, but user was created');
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = newUser;

    res.status(201).json({ 
      message: 'Registration successful',
      data: { 
        user: userWithoutPassword, 
        token: 'mock-jwt-token-' + newUser.id 
      },
      membership_number: membershipNumber
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// User routes
app.get('/api/users/me', async (req, res) => {
  try {
    const user = await pool.query('SELECT id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at FROM users ORDER BY id LIMIT 1');
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ data: { user: user.rows[0] } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Load routes
app.post('/api/loads', async (req, res) => {
  const { origin, destination, date, cargo_type, weight, notes } = req.body;

  try {
    const shipper_id = 1;
    
    const userResult = await pool.query('SELECT name, email, membership_number FROM users WHERE id = $1', [shipper_id]);
    const user = userResult.rows[0];
    
    const ref = 'LD' + Date.now().toString().slice(-6);
    
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + 7);

    const result = await pool.query(
      `INSERT INTO loads (ref, origin, destination, date, cargo_type, weight, notes, shipper_id, shipper_name, shipper_email, shipper_membership, created_at, updated_at, expires_at, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, 'active') RETURNING *`,
      [ref, origin, destination, date, cargo_type, weight, notes, shipper_id, user.name, user.email, user.membership_number, expires_at]
    );

    res.status(201).json({ 
      message: 'Load posted successfully',
      data: { load: result.rows[0] } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/loads', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.membership_number as shipper_membership 
      FROM loads l 
      LEFT JOIN users u ON l.shipper_id = u.id 
      WHERE expires_at > NOW() AND status = 'active' 
      ORDER BY created_at DESC`
    );
    res.json({ data: { loads: result.rows } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Message routes
app.post('/api/messages', async (req, res) => {
  const { recipient_membership, body } = req.body;

  try {
    const sender_membership = 'MFADMIN01';
    
    const recipientResult = await pool.query('SELECT * FROM users WHERE membership_number = $1', [recipient_membership]);
    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const result = await pool.query(
      'INSERT INTO messages (sender_membership, recipient_membership, body, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [sender_membership, recipient_membership, body]
    );

    res.status(201).json({ 
      message: 'Message sent successfully',
      data: { message: result.rows[0] } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/messages', async (req, res) => {
  try {
    const userMembership = 'MFADMIN01';
    const result = await pool.query(
      `SELECT * FROM messages 
       WHERE sender_membership = $1 OR recipient_membership = $1 
       ORDER BY created_at DESC`,
      [userMembership]
    );
    res.json({ data: { messages: result.rows } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin routes
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at, updated_at FROM users ORDER BY created_at DESC');
    res.json({ data: { users: result.rows } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 MakiwaFreight server running on port ${PORT}`);
  console.log(`🌐 Visit: https://makiwafreightapp.onrender.com`);
  console.log(`🔧 Initializing database with fresh schema...`);
  await initializeDatabase();
  console.log(`✅ Server is ready!`);
  console.log(`📧 Admin login: cyprianmak@gmail.com`);
  console.log(`🔑 Admin password: Muchandida@1`);
});
