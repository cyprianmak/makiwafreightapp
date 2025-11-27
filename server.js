// server.js - COMPLETE BACKEND FOR MAKIWAFREIGHT - FIXED VERSION
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

// Initialize database
const initializeDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_membership VARCHAR(20) NOT NULL,
        recipient_membership VARCHAR(20) NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS acl (
        id SERIAL PRIMARY KEY,
        user_email VARCHAR(255) UNIQUE,
        post BOOLEAN DEFAULT false,
        market BOOLEAN DEFAULT false
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS banners (
        id SERIAL PRIMARY KEY,
        page VARCHAR(50) NOT NULL,
        banner TEXT,
        updated_at TIMESTAMP DEFAULT NOW()
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
      console.log('Admin user created successfully');
    } else {
      // Fix admin password if needed
      const admin = adminResult.rows[0];
      if (!admin.password || admin.password === 'undefined') {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('Muchandida@1', salt);
        
        await pool.query(
          'UPDATE users SET password = $1, updated_at = NOW() WHERE email = $2',
          [hashedPassword, adminEmail]
        );
        console.log('Admin password fixed');
      }
    }

    // Initialize banners
    const bannerResult = await pool.query('SELECT * FROM banners');
    if (bannerResult.rows.length === 0) {
      await pool.query("INSERT INTO banners (page, banner) VALUES ('index', ''), ('dashboard', '')");
    }

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
};

// DEBUG ROUTES - Add these first to fix issues
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
      
      await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, true, true)', ['cyprianmak@gmail.com']);
      
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

app.get('/api/debug/all-users', async (req, res) => {
  try {
    const users = await pool.query('SELECT id, name, email, role, membership_number, password IS NOT NULL as has_password FROM users');
    res.json(users.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API Routes

// Auth routes - FIXED VERSION
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log('Login attempt for:', email);
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    
    // Check if password exists
    if (!user.password) {
      return res.status(401).json({ error: 'Password not set for this user. Please contact admin.' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Get ACLs - with error handling
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
    // Mock - implement proper auth
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
    res.json({ data: { user: userWithoutPassword } });
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
    
    // Get user details for the load
    const userResult = await pool.query('SELECT name, email, membership_number FROM users WHERE id = $1', [shipper_id]);
    const user = userResult.rows[0];
    
    const ref = 'LD' + Date.now().toString().slice(-6);
    
    // Calculate expiry date (7 days from now)
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

    res.json({ 
      message: 'Load updated successfully',
      data: { load: result.rows[0] } 
    });
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
  const { recipient_membership, body } = req.body;

  try {
    const sender_membership = 'MFADMIN01'; // Mock sender for now
    
    // Verify recipient exists
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
    const userMembership = 'MFADMIN01'; // Mock user membership
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

app.delete('/api/admin/users/:email', async (req, res) => {
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [req.params.email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userId = userResult.rows[0].id;

    await pool.query('DELETE FROM messages WHERE sender_membership IN (SELECT membership_number FROM users WHERE id = $1) OR recipient_membership IN (SELECT membership_number FROM users WHERE id = $1)', [userId]);
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

// Banner routes
app.get('/api/banners/active', async (req, res) => {
  try {
    const { page } = req.query;
    const result = await pool.query('SELECT banner FROM banners WHERE page = $1', [page]);
    
    if (result.rows.length === 0) {
      return res.json({ data: { banner: '' } });
    }

    res.json({ data: { banner: result.rows[0].banner } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/banners', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM banners');
    const banners = {};
    result.rows.forEach(row => {
      banners[row.page] = row.banner;
    });
    res.json({ data: banners });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/banners', async (req, res) => {
  try {
    const banners = req.body;
    
    for (const [page, banner] of Object.entries(banners)) {
      const existing = await pool.query('SELECT * FROM banners WHERE page = $1', [page]);
      
      if (existing.rows.length > 0) {
        await pool.query('UPDATE banners SET banner = $1, updated_at = NOW() WHERE page = $2', [banner, page]);
      } else {
        await pool.query('INSERT INTO banners (page, banner, updated_at) VALUES ($1, $2, NOW())', [page, banner]);
      }
    }

    res.json({ message: 'Banners updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`MakiwaFreight server running on port ${PORT}`);
  console.log(`Visit: https://makiwafreightapp.onrender.com`);
  await initializeDatabase();
});
