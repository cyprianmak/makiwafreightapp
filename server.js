// server.js - COMPLETE BACKEND FOR MAKIWAFREIGHT
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

// API Routes

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Get ACLs
    const aclResult = await pool.query('SELECT * FROM acl WHERE user_email = $1', [email]);
    const acl = aclResult.rows[0] || {};

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    
    res.json({ 
      data: { 
        user: userWithoutPassword, 
        token: 'mock-jwt-token-' + user.id,
        acl 
      } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
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
    const membershipNumber = 'MF' + Math.random().toString(36).substr(2, 6).toUpperCase();

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (name, email, password, phone, company, address, role, vehicle_info, membership_number, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) RETURNING *`,
      [name, email, hashedPassword, phone, company, address, role, vehicle_info, membershipNumber]
    );

    const newUser = result.rows[0];

    // Set default ACLs
    await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, $2, $3)', [
      email, 
      role === 'shipper' ? true : false, 
      role === 'transporter' ? true : false
    ]);

    // Remove password from response
    const { password: _, ...userWithoutPassword } = newUser;

    res.status(201).json({ 
      data: { 
        user: userWithoutPassword, 
        token: 'mock-jwt-token-' + newUser.id 
      },
      membership_number: membershipNumber
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// User routes
app.get('/api/users/me', async (req, res) => {
  try {
    // Mock - implement proper auth
    const user = await pool.query('SELECT id, name, email, phone, company, address, role, vehicle_info, membership_number, created_at FROM users ORDER BY id LIMIT 1');
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ data: user.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/me', async (req, res) => {
  const { name, phone, address, password } = req.body;

  try {
    // Mock user ID
    const userId = 1;
    
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
    values.push(userId);

    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { password: _, ...userWithoutPassword } = result.rows[0];
    res.json({ data: userWithoutPassword });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Load routes
app.post('/api/loads', async (req, res) => {
  const { origin, destination, date, cargo_type, weight, notes } = req.body;

  try {
    const shipper_id = 1; // Mock user ID
    const ref = 'LD' + Date.now().toString().slice(-6);
    
    // Calculate expiry date (7 days from now)
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + 7);

    const result = await pool.query(
      `INSERT INTO loads (ref, origin, destination, date, cargo_type, weight, notes, shipper_id, created_at, updated_at, expires_at, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, 'active') RETURNING *`,
      [ref, origin, destination, date, cargo_type, weight, notes, shipper_id, expires_at]
    );

    res.status(201).json({ data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/loads', async (req, res) => {
  try {
    const result = await pool.query("SELECT l.*, u.membership_number as shipper_membership FROM loads l LEFT JOIN users u ON l.shipper_id = u.id WHERE expires_at > NOW() AND status = 'active' ORDER BY created_at DESC");
    res.json({ data: { loads: result.rows } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/me/loads', async (req, res) => {
  try {
    const shipper_id = 1; // Mock user ID
    const result = await pool.query('SELECT * FROM loads WHERE shipper_id = $1 ORDER BY created_at DESC', [shipper_id]);
    res.json({ data: { loads: result.rows } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

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

    res.json({ data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/loads/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM loads WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Load not found' });
    }
    res.json({ message: 'Load deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Message routes
app.post('/api/messages', async (req, res) => {
  const { sender_membership, recipient_membership, body } = req.body;

  try {
    const senderResult = await pool.query('SELECT id FROM users WHERE membership_number = $1', [sender_membership]);
    const receiverResult = await pool.query('SELECT id FROM users WHERE membership_number = $1', [recipient_membership]);
    
    if (senderResult.rows.length === 0 || receiverResult.rows.length === 0) {
      return res.status(404).json({ error: 'Sender or recipient not found' });
    }

    const sender_id = senderResult.rows[0].id;
    const receiver_id = receiverResult.rows[0].id;

    const result = await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, body, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [sender_id, receiver_id, body]
    );

    res.status(201).json({ data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/messages', async (req, res) => {
  try {
    const userId = 1; // Mock user ID
    const result = await pool.query(
      `SELECT m.*, 
              u1.membership_number as sender_membership,
              u2.membership_number as recipient_membership
       FROM messages m 
       JOIN users u1 ON m.sender_id = u1.id 
       JOIN users u2 ON m.receiver_id = u2.id 
       WHERE m.sender_id = $1 OR m.receiver_id = $1 
       ORDER BY m.created_at DESC`,
      [userId]
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

app.delete('/api/admin/users/:email', async (req, res) => {
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [req.params.email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userId = userResult.rows[0].id;

    await pool.query('DELETE FROM messages WHERE sender_id = $1 OR receiver_id = $1', [userId]);
    await pool.query('DELETE FROM loads WHERE shipper_id = $1', [userId]);
    await pool.query('DELETE FROM acl WHERE user_email = $1', [req.params.email]);
    await pool.query('DELETE FROM users WHERE email = $1', [req.params.email]);

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

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
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize database
const initializeDatabase = async () => {
  try {
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
        ref VARCHAR(10) NOT NULL,
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
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS acl (
        id SERIAL PRIMARY KEY,
        user_email VARCHAR(255) UNIQUE REFERENCES users(email),
        post BOOLEAN DEFAULT false,
        market BOOLEAN DEFAULT false
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS banners (
        id SERIAL PRIMARY KEY,
        index TEXT DEFAULT '',
        dashboard TEXT DEFAULT ''
      )
    `);

    // Create admin user
    const adminEmail = 'cyprianmak@gmail.com';
    const adminResult = await pool.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
    
    if (adminResult.rows.length === 0) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('Muchandida@1', salt);
      const adminMembership = 'MFADMIN01';
      
      await pool.query(
        `INSERT INTO users (name, email, password, role, membership_number, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
        ['Admin', adminEmail, hashedPassword, 'admin', adminMembership]
      );

      await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, true, true)', [adminEmail]);
    }

    const bannerResult = await pool.query('SELECT * FROM banners');
    if (bannerResult.rows.length === 0) {
      await pool.query("INSERT INTO banners (index, dashboard) VALUES ('', '')");
    }

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
};

// Start server
app.listen(PORT, async () => {
  console.log(`MakiwaFreight server running on port ${PORT}`);
  await initializeDatabase();
});
