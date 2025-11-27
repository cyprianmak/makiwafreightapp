// server.js - Updated with Admin Password Fix
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Database configuration
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key-change-in-production';

// Initialize database tables
const initializeDatabase = async () => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255),
        role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'shipper', 'transporter')),
        membership_number VARCHAR(20) UNIQUE,
        company VARCHAR(100),
        phone VARCHAR(20),
        address TEXT,
        vehicle_info TEXT,
        membership_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create loads table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS loads (
        id SERIAL PRIMARY KEY,
        ref VARCHAR(20) UNIQUE NOT NULL,
        origin VARCHAR(100) NOT NULL,
        destination VARCHAR(100) NOT NULL,
        date DATE NOT NULL,
        cargo_type VARCHAR(100) NOT NULL,
        weight DECIMAL(10,2) NOT NULL,
        notes TEXT,
        shipper_id INTEGER REFERENCES users(id),
        shipper_name VARCHAR(100),
        shipper_email VARCHAR(100),
        shipper_membership VARCHAR(20),
        secured_by INTEGER REFERENCES users(id),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create messages table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_membership VARCHAR(20) NOT NULL,
        recipient_membership VARCHAR(20) NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create banners table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS banners (
        id SERIAL PRIMARY KEY,
        page VARCHAR(50) NOT NULL,
        banner TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create access_control table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS access_control (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        pages JSONB DEFAULT '{}',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create admin user if not exists
    const adminCheck = await pool.query('SELECT * FROM users WHERE email = $1', ['cyprianmak@gmail.com']);
    if (adminCheck.rows.length === 0) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('Muchandida@1', salt);
      
      await pool.query(
        `INSERT INTO users (name, email, password, role, membership_number, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
        ['Admin', 'cyprianmak@gmail.com', hashedPassword, 'admin', 'MFADMIN01']
      );
      console.log('Admin user created successfully');
    } else {
      console.log('Admin user already exists');
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
};

// Auth middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.user.id]);
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Token is not valid' });
    }

    req.user = userResult.rows[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token is not valid' });
  }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admin only.' });
  }
  next();
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'MakiwaFreight API is running' });
});

// DEBUG ROUTES - Add these to fix the admin password issue

// Debug route to check and fix admin user
app.get('/api/debug/fix-admin', async (req, res) => {
  try {
    // Check if admin exists
    const adminResult = await pool.query('SELECT * FROM users WHERE email = $1', ['cyprianmak@gmail.com']);
    
    if (adminResult.rows.length === 0) {
      // Create admin user
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('Muchandida@1', salt);
      
      await pool.query(
        `INSERT INTO users (name, email, password, role, membership_number, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
        ['Admin', 'cyprianmak@gmail.com', hashedPassword, 'admin', 'MFADMIN01']
      );
      
      return res.json({ message: 'Admin user created successfully' });
    } else {
      const admin = adminResult.rows[0];
      
      // Check if password is missing or invalid
      if (!admin.password || admin.password === 'undefined') {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('Muchandida@1', salt);
        
        await pool.query(
          'UPDATE users SET password = $1, updated_at = NOW() WHERE email = $2',
          [hashedPassword, 'cyprianmak@gmail.com']
        );
        
        return res.json({ message: 'Admin password fixed successfully' });
      }
      
      return res.json({ 
        message: 'Admin user exists', 
        admin: { 
          email: admin.email, 
          role: admin.role,
          has_password: !!admin.password
        } 
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Debug route to see all users in database
app.get('/api/debug/all-users', async (req, res) => {
  try {
    const users = await pool.query('SELECT id, name, email, role, membership_number, password IS NOT NULL as has_password FROM users');
    res.json(users.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, company, phone, address, vehicle_info } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'Name, email, password and role are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Generate membership number
    const prefix = role === 'shipper' ? 'MFS' : 'MFT';
    const randomNum = Math.floor(1000 + Math.random() * 9000);
    const membershipNumber = `${prefix}${randomNum}`;

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (name, email, password, role, membership_number, company, phone, address, vehicle_info, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) 
       RETURNING id, name, email, role, membership_number, company, phone, address, vehicle_info, created_at`,
      [name, email, hashedPassword, role, membershipNumber, company, phone, address, vehicle_info]
    );

    const user = result.rows[0];

    // Generate token
    const token = jwt.sign(
      { user: { id: user.id, email: user.email, role: user.role } },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      data: {
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          membership_number: user.membership_number,
          company: user.company,
          phone: user.phone,
          address: user.address,
          vehicle_info: user.vehicle_info,
          created_at: user.created_at
        }
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Check if password is set
    if (!user.password) {
      return res.status(400).json({ error: 'Password not set for this user. Please contact admin.' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { user: { id: user.id, email: user.email, role: user.role } },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          membership_number: user.membership_number,
          company: user.company,
          phone: user.phone,
          address: user.address,
          vehicle_info: user.vehicle_info,
          created_at: user.created_at
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// User routes
app.get('/api/users/me', authMiddleware, async (req, res) => {
  try {
    res.json({
      data: {
        user: req.user
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const { name, phone, address, password, company, vehicle_info } = req.body;
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (name) {
      updates.push(`name = $${paramCount}`);
      values.push(name);
      paramCount++;
    }
    if (phone) {
      updates.push(`phone = $${paramCount}`);
      values.push(phone);
      paramCount++;
    }
    if (address) {
      updates.push(`address = $${paramCount}`);
      values.push(address);
      paramCount++;
    }
    if (company) {
      updates.push(`company = $${paramCount}`);
      values.push(company);
      paramCount++;
    }
    if (vehicle_info) {
      updates.push(`vehicle_info = $${paramCount}`);
      values.push(vehicle_info);
      paramCount++;
    }
    if (password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      updates.push(`password = $${paramCount}`);
      values.push(hashedPassword);
      paramCount++;
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(req.user.id);

    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount} RETURNING *`;
    const result = await pool.query(query, values);

    res.json({
      message: 'Profile updated successfully',
      data: {
        user: result.rows[0]
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/me/loads', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM loads WHERE shipper_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );

    res.json({
      data: {
        loads: result.rows
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Load routes
app.get('/api/loads', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.name as shipper_name, u.email as shipper_email, u.membership_number as shipper_membership 
      FROM loads l 
      LEFT JOIN users u ON l.shipper_id = u.id 
      ORDER BY l.created_at DESC
    `);

    res.json({
      data: {
        loads: result.rows
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/loads', authMiddleware, async (req, res) => {
  try {
    const { origin, destination, date, cargo_type, weight, notes } = req.body;

    if (!origin || !destination || !date || !cargo_type || !weight) {
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    const ref = 'LD' + Date.now().toString().slice(-6);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const result = await pool.query(
      `INSERT INTO loads (ref, origin, destination, date, cargo_type, weight, notes, shipper_id, shipper_name, shipper_email, shipper_membership, expires_at, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW()) 
       RETURNING *`,
      [ref, origin, destination, date, cargo_type, weight, notes, req.user.id, req.user.name, req.user.email, req.user.membership_number, expiresAt]
    );

    res.status(201).json({
      message: 'Load posted successfully',
      data: {
        load: result.rows[0]
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/loads/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { origin, destination, date, cargo_type, weight, notes } = req.body;

    // Check if load exists and user owns it or is admin
    const loadCheck = await pool.query('SELECT * FROM loads WHERE id = $1', [id]);
    if (loadCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Load not found' });
    }

    if (req.user.role !== 'admin' && loadCheck.rows[0].shipper_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updates = [];
    const values = [];
    let paramCount = 1;

    if (origin) {
      updates.push(`origin = $${paramCount}`);
      values.push(origin);
      paramCount++;
    }
    if (destination) {
      updates.push(`destination = $${paramCount}`);
      values.push(destination);
      paramCount++;
    }
    if (date) {
      updates.push(`date = $${paramCount}`);
      values.push(date);
      paramCount++;
    }
    if (cargo_type) {
      updates.push(`cargo_type = $${paramCount}`);
      values.push(cargo_type);
      paramCount++;
    }
    if (weight) {
      updates.push(`weight = $${paramCount}`);
      values.push(parseFloat(weight));
      paramCount++;
    }
    if (notes !== undefined) {
      updates.push(`notes = $${paramCount}`);
      values.push(notes);
      paramCount++;
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const query = `UPDATE loads SET ${updates.join(', ')} WHERE id = $${paramCount} RETURNING *`;
    const result = await pool.query(query, values);

    res.json({
      message: 'Load updated successfully',
      data: {
        load: result.rows[0]
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/loads/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if load exists and user owns it or is admin
    const loadCheck = await pool.query('SELECT * FROM loads WHERE id = $1', [id]);
    if (loadCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Load not found' });
    }

    if (req.user.role !== 'admin' && loadCheck.rows[0].shipper_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await pool.query('DELETE FROM loads WHERE id = $1', [id]);

    res.json({ message: 'Load deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Message routes
app.get('/api/messages', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM messages ORDER BY created_at DESC'
    );

    res.json({
      data: {
        messages: result.rows
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { recipient_membership, body } = req.body;

    if (!recipient_membership || !body) {
      return res.status(400).json({ error: 'Recipient and message body are required' });
    }

    // Verify recipient exists
    const recipientCheck = await pool.query(
      'SELECT * FROM users WHERE membership_number = $1',
      [recipient_membership]
    );

    if (recipientCheck.rows.length === 0 && recipient_membership !== 'Admin') {
      return res.status(400).json({ error: 'Recipient not found' });
    }

    const senderMembership = req.user.membership_number || 'Admin';

    const result = await pool.query(
      'INSERT INTO messages (sender_membership, recipient_membership, body, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [senderMembership, recipient_membership, body]
    );

    res.status(201).json({
      message: 'Message sent successfully',
      data: {
        message: result.rows[0]
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM messages WHERE id = $1', [id]);

    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin routes
app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, role, membership_number, company, phone, address, vehicle_info, created_at FROM users ORDER BY created_at DESC'
    );

    res.json({
      data: {
        users: result.rows
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/users/:email', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email } = req.params;

    await pool.query('DELETE FROM users WHERE email = $1', [email]);

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/reset-password', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email, new_password } = req.body;

    if (!email || !new_password) {
      return res.status(400).json({ error: 'Email and new password are required' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(new_password, salt);

    await pool.query(
      'UPDATE users SET password = $1, updated_at = NOW() WHERE email = $2',
      [hashedPassword, email]
    );

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Banner routes
app.get('/api/banners/active', async (req, res) => {
  try {
    const { page } = req.query;
    
    if (!page) {
      return res.status(400).json({ error: 'Page parameter is required' });
    }

    const result = await pool.query(
      'SELECT banner FROM banners WHERE page = $1',
      [page]
    );

    if (result.rows.length === 0) {
      return res.json({ data: { banner: '' } });
    }

    res.json({
      data: {
        banner: result.rows[0].banner
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/banners', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM banners');

    const banners = {};
    result.rows.forEach(row => {
      banners[row.page] = row.banner;
    });

    res.json({
      data: banners
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/banners', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const banners = req.body;

    for (const [page, banner] of Object.entries(banners)) {
      const existing = await pool.query('SELECT * FROM banners WHERE page = $1', [page]);
      
      if (existing.rows.length > 0) {
        await pool.query(
          'UPDATE banners SET banner = $1, updated_at = NOW() WHERE page = $2',
          [banner, page]
        );
      } else {
        await pool.query(
          'INSERT INTO banners (page, banner, updated_at) VALUES ($1, $2, NOW())',
          [page, banner]
        );
      }
    }

    res.json({ message: 'Banners updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Access control routes
app.get('/api/admin/access-control', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM access_control');

    const accessControl = {};
    result.rows.forEach(row => {
      accessControl[row.user_id] = row.pages;
    });

    res.json({
      data: accessControl
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/access-control', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const accessControl = req.body;

    for (const [userId, pages] of Object.entries(accessControl)) {
      const existing = await pool.query('SELECT * FROM access_control WHERE user_id = $1', [userId]);
      
      if (existing.rows.length > 0) {
        await pool.query(
          'UPDATE access_control SET pages = $1, updated_at = NOW() WHERE user_id = $2',
          [pages, userId]
        );
      } else {
        await pool.query(
          'INSERT INTO access_control (user_id, pages, updated_at) VALUES ($1, $2, NOW())',
          [userId, pages]
        );
      }
    }

    res.json({ message: 'Access control updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/users/:userId/access', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await pool.query(
      'SELECT pages FROM access_control WHERE user_id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.json({
        data: {
          pages: {}
        }
      });
    }

    res.json({
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/users/:userId/access', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const { pages } = req.body;

    const existing = await pool.query('SELECT * FROM access_control WHERE user_id = $1', [userId]);
    
    if (existing.rows.length > 0) {
      await pool.query(
        'UPDATE access_control SET pages = $1, updated_at = NOW() WHERE user_id = $2',
        [pages, userId]
      );
    } else {
      await pool.query(
        'INSERT INTO access_control (user_id, pages, updated_at) VALUES ($1, $2, NOW())',
        [userId, pages]
      );
    }

    res.json({ message: 'User access updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
const startServer = async () => {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`MakiwaFreight server running on port ${PORT}`);
      console.log(`Visit: https://makiwafreightapp.onrender.com`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
