const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { Pool } = require('pg');
const app = express();
const PORT = process.env.PORT || 10000;

// Database connection
let pool;
if (process.env.DATABASE_URL) {
  // Use DATABASE_URL when provided (preferred for managed DBs)
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // required for many hosted Postgres providers like Render
  });
} else {
  // Fallback to individual environment variables
  pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
    ssl: { rejectUnauthorized: false }
  });
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// API Routes

// Generic database query endpoint with authentication and validation
app.post('/api/db/query', authenticateToken, requireAdmin, async (req, res) => {
  const { sql, params = [] } = req.body;

  try {
    // Execute the query against PostgreSQL
    const result = await pool.query(sql, params);
    res.json(result);
  } catch (err) {
    console.error('Database query error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Token generation endpoint
app.post('/api/auth/token', async (req, res) => {
  const { userId, isAdmin } = req.body;

  try {
    const user = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [userId]);
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = user.rows[0];
    
    // Create JWT token
    const token = jwt.sign(
      { 
        id: userData.id, 
        email: userData.email, 
        role: userData.role,
        isAdmin: userData.role === 'admin'
      },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.json({ token, user: userData });
  } catch (err) {
    console.error('Token generation error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify token endpoint
app.post('/api/auth/verify-token', authenticateToken, async (req, res) => {
  try {
    // Get fresh user data
    const user = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [req.user.id]);
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: user.rows[0] });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Password hashing endpoint (server-side only)
app.post('/api/auth/hash', async (req, res) => {
  const { password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    res.json({ hashedPassword });
  } catch (err) {
    console.error('Password hashing error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Password verification endpoint (server-side only)
app.post('/api/auth/verify', async (req, res) => {
  const { password, hashedPassword } = req.body;

  try {
    const valid = await bcrypt.compare(password, hashedPassword);
    res.json({ valid });
  } catch (err) {
    console.error('Password verification error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get access control settings
app.get('/api/access-control', authenticateToken, async (req, res) => {
  try {
    // Only admins can get all access control settings
    if (req.user.role !== 'admin') {
      // Non-admin users can only get their own access settings
      const userResult = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const userEmail = userResult.rows[0].email;
      const aclResult = await pool.query('SELECT * FROM acl WHERE user_email = $1', [userEmail]);
      
      return res.json({
        user_access: {
          [req.user.id]: aclResult.rows[0] || { post: true, market: true }
        }
      });
    }
    
    // Admin can get all settings
    const aclResult = await pool.query('SELECT * FROM acl');
    const bannerResult = await pool.query('SELECT * FROM banners');
    
    // Transform the result into the expected format
    const accessControl = {
      post_loads_enabled: true, // Default value
      user_access: {},
      pages: {},
      banners: {
        index: bannerResult.rows[0]?.index || '',
        dashboard: bannerResult.rows[0]?.dashboard || ''
      }
    };
    
    // Process ACL rows
    for (const row of aclResult.rows) {
      // Get user ID from email
      const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [row.user_email]);
      if (userResult.rows.length > 0) {
        const userId = userResult.rows[0].id;
        accessControl.user_access[userId] = {
          can_post_loads: row.post,
          can_access_market: row.market
        };
      }
    }
    
    res.json(accessControl);
  } catch (err) {
    console.error('Get access control error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update access control settings
app.put('/api/access-control', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const acl = req.body;
    
    // Update post_loads_enabled setting
    if (acl.post_loads_enabled !== undefined) {
      // This would typically be stored in a settings table
      // For now, we'll just acknowledge the update
    }
    
    // Update banners
    if (acl.banners) {
      await pool.query(
        'UPDATE banners SET index = $1, dashboard = $2 WHERE id = 1',
        [acl.banners.index || '', acl.banners.dashboard || '']
      );
    }
    
    // Update user access settings
    if (acl.user_access) {
      for (const userId in acl.user_access) {
        // Get user email from ID
        const userResult = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
        if (userResult.rows.length > 0) {
          const userEmail = userResult.rows[0].email;
          const userAccess = acl.user_access[userId];
          
          // Update or insert ACL
          await pool.query(
            `INSERT INTO acl (user_email, post, market) 
             VALUES ($1, $2, $3) 
             ON CONFLICT (user_email) 
             DO UPDATE SET post = $2, market = $3`,
            [userEmail, userAccess.can_post_loads, userAccess.can_access_market]
          );
        }
      }
    }
    
    res.json({ message: 'Access control updated successfully' });
  } catch (err) {
    console.error('Update access control error:', err);
    res.status(500).json({ error: 'Server error' });
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

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (name, email, password, phone, company, address, role, vehicle_info, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW()) RETURNING *`,
      [name, email, hashedPassword, phone, company, address, role, vehicle_info]
    );

    // Set default ACLs
    await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, $2, $3)', [
      email, 
      role === 'shipper' ? true : false, 
      role === 'transporter' ? true : false
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// User login (updated version)
app.post('/api/users/login', async (req, res) => {
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

    // Create JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        isAdmin: user.role === 'admin'
      },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    res.json({ 
      user: { ...userWithoutPassword, acl }, 
      token 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user by ID
app.get('/api/users/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, company, address, role, vehicle_info, created_at, updated_at FROM users WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user
app.put('/api/users/:id', async (req, res) => {
  const { name, phone, address, password } = req.body;
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

    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = result.rows[0];
    res.json(userWithoutPassword);
  } catch (err) {
    console.error(err);
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

    const result = await pool.query(
      `INSERT INTO loads (origin, destination, date, cargo_type, weight, notes, shipper_id, created_at, updated_at, expires_at, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8, 'active') RETURNING *`,
      [origin, destination, date, cargo_type, weight, notes, shipper_id, expires_at]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get loads by shipper ID
app.get('/api/loads/shipper/:shipperId', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM loads WHERE shipper_id = $1 ORDER BY created_at DESC', [req.params.shipperId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all active loads (for market)
app.get('/api/loads', async (req, res) => {
  try {
    // Only return loads that haven't expired
    const result = await pool.query("SELECT * FROM loads WHERE expires_at > NOW() AND status = 'active' ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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
    console.error(err);
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
    console.error(err);
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
      'INSERT INTO messages (sender_id, receiver_id, body, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [sender_id, receiver_id, body]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get messages for a user
app.get('/api/messages/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, u.name as sender_name, u.email as sender_email 
       FROM messages m 
       JOIN users u ON m.sender_id = u.id 
       WHERE m.receiver_id = $1 
       ORDER BY m.created_at DESC`,
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin routes

// Get all users (admin)
app.get('/api/admin/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, company, address, role, vehicle_info, created_at, updated_at FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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
    await pool.query('DELETE FROM acl WHERE user_email = $1', [req.params.email]);
    await pool.query('DELETE FROM users WHERE email = $1', [req.params.email]);

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password (admin)
app.post('/api/admin/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

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

// Get all loads (admin)
app.get('/api/admin/loads', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM loads ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get ACLs (admin)
app.get('/api/admin/acl', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM acl');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update ACL (admin)
app.put('/api/admin/acl', async (req, res) => {
  const { user_email, post, market } = req.body;

  try {
    const result = await pool.query(
      'UPDATE acl SET post = $1, market = $2 WHERE user_email = $3 RETURNING *',
      [post, market, user_email]
    );

    if (result.rows.length === 0) {
      // Insert if not exists
      const insertResult = await pool.query(
        'INSERT INTO acl (user_email, post, market) VALUES ($1, $2, $3) RETURNING *',
        [user_email, post, market]
      );
      return res.json(insertResult.rows[0]);
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get banners (admin)
app.get('/api/admin/banners', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM banners');
    if (result.rows.length === 0) {
      // Insert default banners if not exist
      await pool.query("INSERT INTO banners (index, dashboard) VALUES ('', '')");
      const newResult = await pool.query('SELECT * FROM banners');
      return res.json(newResult.rows[0]);
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update banners (admin)
app.put('/api/admin/banners', async (req, res) => {
  const { index, dashboard } = req.body;

  try {
    const result = await pool.query(
      'UPDATE banners SET index = $1, dashboard = $2 WHERE id = 1 RETURNING *',
      [index, dashboard]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize database tables
const initializeDatabase = async () => {
  try {
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

    // Check if admin user exists
    const adminEmail = 'cyprianmak@gmail.com';
    const adminResult = await pool.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
    
    if (adminResult.rows.length === 0) {
      // Create admin user
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('Muchandida@1', salt);
      
      await pool.query(
        `INSERT INTO users (name, email, password, role, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, NOW(), NOW())`,
        ['Admin', adminEmail, hashedPassword, 'admin']
      );

      // Set admin ACLs
      await pool.query('INSERT INTO acl (user_email, post, market) VALUES ($1, true, true)', [adminEmail]);
    }

    // Check if banners exist
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
  console.log(`Server running on port ${PORT}`);
  await initializeDatabase();
});
