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
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_DATABASE || 'makiwafreight',
  password: process.env.DB_PASSWORD || 'password',
  port: process.env.DB_PORT || 5432,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) RETURNING id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at`,
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
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get user by ID
app.get('/api/users/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at FROM users WHERE id = $1', 
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user
app.put('/api/users/:id', async (req, res) => {
  const { name, phone, address, password, company, vehicle_info } = req.body;
  const id = req.params.id;

  try {
    // Build the update query dynamically
    let updateFields = [];
    let values = [];
    let paramIndex = 1;

    if (name) {
      updateFields.push(`name = $${paramIndex++}`);
      values.push(name);
    }
    if (phone) {
      updateFields.push(`phone = $${paramIndex++}`);
      values.push(phone);
    }
    if (address) {
      updateFields.push(`address = $${paramIndex++}`);
      values.push(address);
    }
    if (company) {
      updateFields.push(`company = $${paramIndex++}`);
      values.push(company);
    }
    if (vehicle_info) {
      updateFields.push(`vehicle_info = $${paramIndex++}`);
      values.push(vehicle_info);
    }
    if (password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      updateFields.push(`password = $${paramIndex++}`);
      values.push(hashedPassword);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updateFields.push(`updated_at = NOW()`);
    values.push(id);

    const query = `
      UPDATE users SET ${updateFields.join(', ')} 
      WHERE id = $${paramIndex} 
      RETURNING id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at
    `;
    
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create a load
app.post('/api/loads', async (req, res) => {
  const { origin, destination, date, cargo_type, weight, notes, shipper_id } = req.body;

  try {
    // Calculate expiry date (7 days from now)
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + 7);

    // Generate load reference
    const ref = generateLoadReference();

    const result = await pool.query(
      `INSERT INTO loads (ref, origin, destination, date, cargo_type, weight, notes, shipper_id, created_at, updated_at, expires_at, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, 'active') 
       RETURNING *`,
      [ref, origin, destination, date, cargo_type, weight, notes, shipper_id, expires_at]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create load error:', err);
    res.status(500).json({ error: 'Server error creating load' });
  }
});

// Get loads by shipper ID
app.get('/api/loads/shipper/:shipperId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, u.name as shipper_name, u.membership_number as shipper_membership 
       FROM loads l 
       LEFT JOIN users u ON l.shipper_id = u.id 
       WHERE l.shipper_id = $1 
       ORDER BY l.created_at DESC`, 
      [req.params.shipperId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get shipper loads error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all active loads (for market)
app.get('/api/loads', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, u.name as shipper_name, u.membership_number as shipper_membership 
       FROM loads l 
       LEFT JOIN users u ON l.shipper_id = u.id 
       WHERE l.expires_at > NOW() AND l.status = 'active' 
       ORDER BY l.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get loads error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a load
app.delete('/api/loads/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM loads WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Load not found' });
    }
    res.json({ message: 'Load deleted successfully' });
  } catch (err) {
    console.error('Delete load error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update a load
app.put('/api/loads/:id', async (req, res) => {
  const { origin, destination, date, cargo_type, weight, notes } = req.body;
  const id = req.params.id;

  try {
    const result = await pool.query(
      `UPDATE loads SET origin = $1, destination = $2, date = $3, cargo_type = $4, weight = $5, notes = $6, updated_at = NOW() 
       WHERE id = $7 RETURNING *`,
      [origin, destination, date, cargo_type, weight, notes, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Load not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update load error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Send a message
app.post('/api/messages', async (req, res) => {
  const { sender_id, receiver_email, body } = req.body;

  try {
    // Get receiver ID
    const receiverResult = await pool.query('SELECT id FROM users WHERE email = $1', [receiver_email]);
    if (receiverResult.rows.length === 0) {
      return res.status(404).json({ error: 'Receiver not found' });
    }

    const receiver_id = receiverResult.rows[0].id;

    const result = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, body, created_at) 
       VALUES ($1, $2, $3, NOW()) 
       RETURNING *`,
      [sender_id, receiver_id, body]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: 'Server error sending message' });
  }
});

// Get messages for a user
app.get('/api/messages/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, u.name as sender_name, u.email as sender_email, u.membership_number as sender_membership
       FROM messages m 
       JOIN users u ON m.sender_id = u.id 
       WHERE m.receiver_id = $1 
       ORDER BY m.created_at DESC`,
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a message
app.delete('/api/messages/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM messages WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json({ message: 'Message deleted successfully' });
  } catch (err) {
    console.error('Delete message error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin routes

// Get all users (admin)
app.get('/api/admin/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a user (admin)
app.delete('/api/admin/users/:email', async (req, res) => {
  try {
    // First, get the user ID
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [req.params.email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userId = userResult.rows[0].id;

    // Delete related data
    await pool.query('DELETE FROM messages WHERE sender_id = $1 OR receiver_id = $1', [userId]);
    await pool.query('DELETE FROM loads WHERE shipper_id = $1', [userId]);
    await pool.query('DELETE FROM acl WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE email = $1', [req.params.email]);

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password (admin)
app.post('/api/admin/reset-password', async (req, res) => {
  const { email, new_password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(new_password, salt);

    const result = await pool.query(
      'UPDATE users SET password = $1, updated_at = NOW() WHERE email = $2 RETURNING *',
      [hashedPassword, email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all loads (admin)
app.get('/api/admin/loads', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, u.name as shipper_name, u.membership_number as shipper_membership 
       FROM loads l 
       LEFT JOIN users u ON l.shipper_id = u.id 
       ORDER BY l.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get admin loads error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get ACLs (admin)
app.get('/api/admin/acl', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.*, u.name, u.email, u.role 
       FROM acl a 
       JOIN users u ON a.user_id = u.id`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get ACL error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update ACL (admin)
app.put('/api/admin/acl/:userId', async (req, res) => {
  const { post_access, market_access } = req.body;
  const userId = req.params.userId;

  try {
    const result = await pool.query(
      'UPDATE acl SET post_access = $1, market_access = $2 WHERE user_id = $3 RETURNING *',
      [post_access, market_access, userId]
    );

    if (result.rows.length === 0) {
      // Insert if not exists
      const insertResult = await pool.query(
        'INSERT INTO acl (user_id, post_access, market_access) VALUES ($1, $2, $3) RETURNING *',
        [userId, post_access, market_access]
      );
      return res.json(insertResult.rows[0]);
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update ACL error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user access (admin)
app.get('/api/admin/acl/user/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM acl WHERE user_id = $1',
      [req.params.userId]
    );
    
    if (result.rows.length === 0) {
      return res.json({ post_access: false, market_access: false });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Get user ACL error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get banners (admin)
app.get('/api/admin/banners', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM banners');
    if (result.rows.length === 0) {
      // Insert default banners if not exist
      await pool.query("INSERT INTO banners (page, content) VALUES ('index', ''), ('dashboard', '')");
      const newResult = await pool.query('SELECT * FROM banners');
      return res.json(newResult.rows);
    }
    res.json(result.rows);
  } catch (err) {
    console.error('Get banners error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update banners (admin)
app.put('/api/admin/banners', async (req, res) => {
  const { page, content } = req.body;

  try {
    const result = await pool.query(
      'UPDATE banners SET content = $1 WHERE page = $2 RETURNING *',
      [content, page]
    );

    if (result.rows.length === 0) {
      // Insert if not exists
      const insertResult = await pool.query(
        'INSERT INTO banners (page, content) VALUES ($1, $2) RETURNING *',
        [page, content]
      );
      return res.json(insertResult.rows[0]);
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update banners error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get active banners for page
app.get('/api/banners/active', async (req, res) => {
  const { page } = req.query;
  
  try {
    const result = await pool.query(
      'SELECT content FROM banners WHERE page = $1',
      [page]
    );
    
    if (result.rows.length === 0) {
      return res.json({ banner: '' });
    }
    
    res.json({ banner: result.rows[0].content });
  } catch (err) {
    console.error('Get active banners error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize database tables
const initializeDatabase = async () => {
  try {
    console.log('Initializing database tables...');

    // Create tables if they don't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS loads (
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        receiver_id INTEGER REFERENCES users(id),
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        read BOOLEAN DEFAULT FALSE
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS acl (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id),
        post_access BOOLEAN DEFAULT false,
        market_access BOOLEAN DEFAULT false
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS banners (
        id SERIAL PRIMARY KEY,
        page VARCHAR(50) UNIQUE NOT NULL,
        content TEXT DEFAULT ''
      )
    `);

    // Check if admin user exists
    const adminEmail = 'admin@makiwafreight.com';
    const adminResult = await pool.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
    
    if (adminResult.rows.length === 0) {
      console.log('Creating admin user...');
      
      // Create admin user
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

      console.log('Admin user created successfully');
      console.log('Email: admin@makiwafreight.com');
      console.log('Password: Admin123!');
      console.log('Membership Number:', adminMembership);
    } else {
      console.log('Admin user already exists');
    }

    // Check if banners exist
    const bannerResult = await pool.query('SELECT * FROM banners');
    if (bannerResult.rows.length === 0) {
      await pool.query(
        "INSERT INTO banners (page, content) VALUES ('index', 'Welcome to MakiwaFreight - Your Trusted Logistics Partner'), ('dashboard', 'Manage your loads and connect with partners efficiently')"
      );
    }

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
};

// Serve the main application
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
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
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
  
  await initializeDatabase();
  
  console.log('\n📍 Available Admin Credentials:');
  console.log('   Email: admin@makiwafreight.com');
  console.log('   Password: Admin123!');
  console.log('\n📍 Available Endpoints:');
  console.log('   POST /api/users/register - User registration');
  console.log('   POST /api/users/login - User login');
  console.log('   POST /api/loads - Create load');
  console.log('   GET /api/loads - Get all loads');
  console.log('   GET /api/admin/users - Get all users (admin)');
  console.log('   GET /api/banners/active - Get active banners');
});
