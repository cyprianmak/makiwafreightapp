// server.js - ULTRA SIMPLE WORKING VERSION
const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { Pool } = require('pg');
const app = express();
const PORT = process.env.PORT || 10000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// SIMPLE DATABASE SETUP
const setupDatabase = async () => {
  try {
    console.log('🔧 Setting up database...');
    
    // Drop tables if they exist
    await pool.query(`
      DROP TABLE IF EXISTS users CASCADE;
    `);
    
    // Create users table
    await pool.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        membership_number VARCHAR(20) UNIQUE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    
    console.log('✅ Users table created');
    
    // CREATE ADMIN USER
    const saltRounds = 10;
    const plainPassword = 'Muchandida@1';
    const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
    
    await pool.query(
      `INSERT INTO users (name, email, password, role, membership_number) 
       VALUES ($1, $2, $3, $4, $5)`,
      ['Admin', 'cyprianmak@gmail.com', hashedPassword, 'admin', 'MFADMIN01']
    );
    
    console.log('✅ Admin user created');
    console.log('📧 Email: cyprianmak@gmail.com');
    console.log('🔑 Password: Muchandida@1');
    
  } catch (error) {
    console.error('❌ Database setup error:', error);
  }
};

// TEST ADMIN ENDPOINT
app.get('/api/test-admin', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', ['cyprianmak@gmail.com']);
    
    if (result.rows.length === 0) {
      return res.json({ error: 'Admin user not found' });
    }
    
    const admin = result.rows[0];
    res.json({
      message: 'Admin user exists',
      admin: {
        email: admin.email,
        role: admin.role,
        hasPassword: !!admin.password,
        passwordLength: admin.password ? admin.password.length : 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// RESET DATABASE ENDPOINT
app.get('/api/reset-db', async (req, res) => {
  try {
    await setupDatabase();
    res.json({ message: '✅ Database reset complete! Admin user created.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// LOGIN ENDPOINT - SIMPLE AND WORKING
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('Login attempt for:', email);
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      console.log('User not found:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    console.log('User found:', user.email, 'Password exists:', !!user.password);
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      console.log('Invalid password for:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    console.log('✅ Login successful for:', email);
    
    // Return user data (without password)
    const { password: _, ...userWithoutPassword } = user;
    
    res.json({
      message: 'Login successful',
      data: {
        user: userWithoutPassword,
        token: 'jwt-token-' + user.id
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server started on port ${PORT}`);
  console.log(`🌐 Visit: https://makiwafreightapp.onrender.com`);
  
  // Setup database on startup
  await setupDatabase();
  
  console.log(`✅ Server is ready!`);
  console.log(`👉 Test admin: https://makiwafreightapp.onrender.com/api/test-admin`);
  console.log(`👉 Reset DB: https://makiwafreightapp.onrender.com/api/reset-db`);
});
