const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { Pool } = require('pg');
const app = express();
const PORT = process.env.PORT || 10000;

// Database connection for Render PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
const testConnection = async () => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    console.log('✅ Database connected successfully');
    client.release();
    return true;
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    return false;
  }
};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Helper function to generate membership number
const generateMembershipNumber = () => {
  return 'MF' + Math.random().toString(36).substr(2, 6).toUpperCase();
};

// Helper function to generate load reference
const generateLoadReference = () => {
  return 'LD' + Date.now().toString().slice(-8);
};

// API Routes

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = await testConnection();
    res.json({ 
      status: 'OK', 
      database: dbStatus ? 'Connected' : 'Disconnected',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'Error', 
      database: 'Disconnected',
      error: error.message 
    });
  }
});

// Database reset endpoint (for development)
app.post('/api/admin/reset-db', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Database reset not allowed in production' });
  }

  try {
    console.log('Resetting database tables...');
    
    // Drop tables in correct order (due to foreign key constraints)
    await pool.query('DROP TABLE IF EXISTS messages CASCADE');
    await pool.query('DROP TABLE IF EXISTS loads CASCADE');
    await pool.query('DROP TABLE IF EXISTS acl CASCADE');
    await pool.query('DROP TABLE IF EXISTS banners CASCADE');
    await pool.query('DROP TABLE IF EXISTS users CASCADE');
    
    console.log('Tables dropped, recreating...');
    await initializeDatabase();
    
    res.json({ message: 'Database reset successfully' });
  } catch (err) {
    console.error('Reset database error:', err);
    res.status(500).json({ error: 'Failed to reset database: ' + err.message });
  }
});

// User registration
app.post('/api/users/register', async (req, res) => {
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
    const membership_number = generateMembershipNumber();

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (name, email, password, phone, company, address, role, vehicle_info, membership_number, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) 
       RETURNING id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at`,
      [name, email, hashedPassword, phone, company, address, role, vehicle_info, membership_number]
    );

    // Set default ACLs based on role
    const defaultPostAccess = role === 'shipper' || role === 'admin';
    const defaultMarketAccess = role === 'transporter' || role === 'admin';
    
    await pool.query(
      'INSERT INTO acl (user_id, post_access, market_access) VALUES ($1, $2, $3)',
      [result.rows[0].id, defaultPostAccess, defaultMarketAccess]
    );

    res.status(201).json({
      message: 'Registration successful',
      user: result.rows[0],
      token: 'auth-token-' + Date.now()
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// User login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT id, name, email, password, phone, company, address, role, vehicle_info, membership_number, created_at FROM users WHERE email = $1', 
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Get ACLs
    const aclResult = await pool.query(
      'SELECT post_access, market_access FROM acl WHERE user_id = $1', 
      [user.id]
    );
    
    const acl = aclResult.rows[0] || { post_access: false, market_access: false };

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    
    res.json({
      ...userWithoutPassword,
      acl,
      token: 'auth-token-' + Date.now()
    });
  } catch (err) {
    console.error('Login error:', err);
    
    // If column doesn't exist, suggest reset
    if (err.code === '42703') {
      return res.status(500).json({ 
        error: 'Database configuration error',
        hint: 'The database schema may be outdated. Try resetting the database or contact administrator.'
      });
    }
    
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ... [Include all the other endpoints from the previous version] ...

// Initialize database tables
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database tables...');

    // Check if tables already exist
    const tablesCheck = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);

    if (tablesCheck.rows.length > 0) {
      console.log('✅ Tables already exist, skipping creation');
      return;
    }

    // Create users table
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
    await pool.query(`
      CREATE TABLE loads (
        id SERIAL PRIMARY KEY,
        ref VARCHAR(20) NOT NULL UNIQUE,
        origin VARCHAR(255) NOT NULL,
        destination VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        cargo_type VARCHAR(255) NOT NULL,
        weight DECIMAL(10,2) NOT NULL,
        notes TEXT,
        shipper_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        status VARCHAR(50) DEFAULT 'active'
      )
    `);

    // Create messages table
    await pool.query(`
      CREATE TABLE messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        receiver_id INTEGER REFERENCES users(id),
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        read BOOLEAN DEFAULT FALSE
      )
    `);

    // Create acl table
    await pool.query(`
      CREATE TABLE acl (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id),
        post_access BOOLEAN DEFAULT false,
        market_access BOOLEAN DEFAULT false
      )
    `);

    // Create banners table
    await pool.query(`
      CREATE TABLE banners (
        id SERIAL PRIMARY KEY,
        page VARCHAR(50) UNIQUE NOT NULL,
        content TEXT DEFAULT ''
      )
    `);

    console.log('✅ All tables created successfully');

    // Create admin user
    const adminEmail = 'admin@makiwafreight.com';
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('Admin123!', salt);
    const adminMembership = generateMembershipNumber();
    
    const adminUser = await pool.query(
      `INSERT INTO users (name, email, password, role, membership_number, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING id`,
      ['System Administrator', adminEmail, hashedPassword, 'admin', adminMembership]
    );

    // Set admin ACLs
    await pool.query(
      'INSERT INTO acl (user_id, post_access, market_access) VALUES ($1, true, true)',
      [adminUser.rows[0].id]
    );

    // Create default banners
    await pool.query(
      "INSERT INTO banners (page, content) VALUES ('index', 'Welcome to MakiwaFreight - Your Trusted Logistics Partner'), ('dashboard', 'Manage your loads and connect with partners efficiently')"
    );

    console.log('✅ Admin user created successfully');
    console.log('📧 Email: admin@makiwafreight.com');
    console.log('🔑 Password: Admin123!');
    console.log('🎫 Membership Number:', adminMembership);

  } catch (err) {
    console.error('❌ Error initializing database:', err.message);
  }
};

// Serve the main application
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 MakiwaFreight Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 App URL: https://makiwafreightapp.onrender.com`);
  console.log(`🔗 Health check: https://makiwafreightapp.onrender.com/api/health`);
  
  // Test database connection
  const dbConnected = await testConnection();
  
  if (dbConnected) {
    await initializeDatabase();
    console.log('✅ Server initialization complete');
  } else {
    console.log('❌ Server started but database is not connected');
    console.log('💡 Check your DATABASE_URL environment variable');
  }
  
  console.log('\n📍 Admin Credentials:');
  console.log('   📧 Email: admin@makiwafreight.com');
  console.log('   🔑 Password: Admin123!');
});
