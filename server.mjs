import express from 'express';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3003;
const JWT_SECRET = process.env.JWT_SECRET || '91bbc8a7d1dab1b0604d9b91c89f2646';

// Database configuration
const dbConfig = {
  host: '210.246.215.19',
  port: 3306,
  user: 'vhouseuser',
  password: 'StrongPass123!',
  database: 'vhousespace',
  ssl: {
    rejectUnauthorized: false
  }
};

// Create database connection pool
const pool = mysql.createPool(dbConfig);

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:3000', 'https://vhouse.space', 'https://web-rental-frontend.vercel.app', 'https://www.vhouse.space', 'https://wichx-seller-sites-frontend.vercel.app'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Helper function to decrypt password
const decryptPassword = async (encryptedPassword) => {
  try {
    if (!encryptedPassword || !encryptedPassword.includes(':')) {
      return encryptedPassword; // Return as is if not encrypted
    }

    const crypto = await import('crypto');
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);

    const [ivHex, encryptedData] = encryptedPassword.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Decrypt error:', error);
    return encryptedPassword; // Return original if decryption fails
  }
};

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};

// ==================== RESELL USERS API ====================

// Signup endpoint
app.post('/api/resell/signup', async (req, res) => {
  try {
    const { username, password, email, role = 'user' } = req.body;

    // Validate required fields
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Check if username already exists
    const [existingUser] = await pool.execute(
      'SELECT user_id FROM resell_users WHERE username = ?',
      [username]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Username already exists'
      });
    }

    // Check if email already exists (if provided)
    if (email) {
      const [existingEmail] = await pool.execute(
        'SELECT user_id FROM resell_users WHERE email = ?',
        [email]
      );

      if (existingEmail.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Email already exists'
        });
      }
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const [result] = await pool.execute(
      'INSERT INTO resell_users (username, password, email, role, balance) VALUES (?, ?, ?, ?, 0.00)',
      [username, hashedPassword, email, role]
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        user_id: result.insertId,
        username,
        email,
        role
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Login endpoint
app.post('/api/resell/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate required fields
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Find user by username
    const [users] = await pool.execute(
      'SELECT user_id, username, password, email, role, balance FROM resell_users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    const user = users[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        user_id: user.user_id,
        username: user.username,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          user_id: user.user_id,
          username: user.username,
          email: user.email,
          role: user.role,
          balance: user.balance
        }
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get user profile endpoint
app.get('/api/resell/myprofile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    const [users] = await pool.execute(
      'SELECT user_id, username, email, role, balance, created_at FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = users[0];

    res.json({
      success: true,
      message: 'Profile retrieved successfully',
      data: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance,
        created_at: user.created_at
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Purchase site endpoint
app.post('/api/resell/purchase-site/model1', authenticateToken, async (req, res) => {
  try {
    const { website_name, admin_user, admin_password, method } = req.body;
    const userId = req.user.user_id;

    // Validate required fields
    if (!website_name || !admin_user || !admin_password || !method) {
      return res.status(400).json({
        success: false,
        message: 'Website name, admin user, admin password, and method are required'
      });
    }

    // Start database transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Get user balance
      const [users] = await connection.execute(
        'SELECT balance FROM resell_users WHERE user_id = ?',
        [userId]
      );

      if (users.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const userBalance = parseFloat(users[0].balance);

      // Get config data for pricing and banners
      const [configs] = await connection.execute(
        'SELECT Model1_price, Model1_1500x1500Banner, Model1_2000x500Banner, Model1_1000x500Banner, Model1_1640x500Banner FROM resell_config ORDER BY id ASC LIMIT 1'
      );

      if (configs.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(500).json({
          success: false,
          message: 'Config not found'
        });
      }

      const config = configs[0];
      const sitePrice = parseFloat(config.Model1_price);

      // Check if user has enough balance
      if (userBalance < sitePrice) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({
          success: false,
          message: 'Insufficient balance',
          required: sitePrice,
          current: userBalance
        });
      }

      // Check if method is 'new' and website_name already exists
      if (method === 'new') {
        const [existingSites] = await connection.execute(
          'SELECT customer_id FROM auth_sites WHERE website_name = ?',
          [website_name]
        );

        if (existingSites.length > 0) {
          await connection.rollback();
          connection.release();
          return res.status(400).json({
            success: false,
            message: 'Website name already exists. Please choose a different name or use renew method.'
          });
        }
      }

      // For new sites, get customer_id
      let customerId;
      let expiredDay;

      if (method === 'new') {
        // New website, get next customer_id
        const [maxCustomer] = await connection.execute(
          'SELECT MAX(CAST(customer_id AS UNSIGNED)) as max_id FROM auth_sites'
        );
        customerId = (maxCustomer[0].max_id || 0) + 1;

        // Add 31 days from today for new site
        expiredDay = new Date();
        expiredDay.setDate(expiredDay.getDate() + 31);
      }

      // Encrypt admin_password using secret key
      const crypto = await import('crypto');
      const algorithm = 'aes-256-cbc';
      const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      let encryptedPassword = cipher.update(admin_password, 'utf8', 'hex');
      encryptedPassword += cipher.final('hex');
      // Combine IV and encrypted data
      encryptedPassword = iv.toString('hex') + ':' + encryptedPassword;

      // Insert new site (only for method = 'new')
      await connection.execute(
        'INSERT INTO auth_sites (customer_id, website_name, admin_user, admin_password, expiredDay) VALUES (?, ?, ?, ?, ?)',
        [customerId.toString(), website_name, admin_user, encryptedPassword, expiredDay.toISOString().split('T')[0]]
      );

      // Deduct money from user balance
      const newBalance = userBalance - sitePrice;
      await connection.execute(
        'UPDATE resell_users SET balance = ? WHERE user_id = ?',
        [newBalance, userId]
      );

      // Record transaction
      const methodText = 'เช่า';
      const formattedUsername = admin_user.includes('@') ? admin_user : `${admin_user}@gmail.com`;
      const transactionDescription = `${website_name};Username: ${formattedUsername};Password: ${admin_password};${methodText}`;
      await connection.execute(
        'INSERT INTO resell_transactions (user_id, type, amount, description, status) VALUES (?, ?, ?, ?, ?)',
        [userId, 'purchase', sitePrice, transactionDescription, 'success']
      );

      // Insert data into other tables with the same customer_id (only for new sites)
      try {
        // Insert into categories table
        const [categoryResult] = await connection.execute(
          'INSERT INTO categories (customer_id, title, subtitle, image, category, featured, isActive, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [customerId.toString(), `${website_name} Category`, `Category for ${website_name}`, config.Model1_1640x500Banner || `https://img2.pic.in.th/pic/1640x500ebe7d18bc84a1cf6.png`, `${website_name.toLowerCase()}_category`, 0, 1, 0]
        );
        const categoryId = categoryResult.insertId;
        console.log(`Inserted category for customer_id: ${customerId}`);

        // Insert into roles table
        await connection.execute(
          'INSERT INTO roles (customer_id, rank_name, can_edit_categories, can_edit_products, can_edit_users, can_edit_orders, can_manage_keys, can_view_reports, can_manage_promotions, can_manage_settings, can_access_reseller_price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [customerId.toString(), 'admin', 1, 1, 1, 1, 1, 1, 1, 1, 0]
        );
        console.log(`Inserted role for customer_id: ${customerId}`);

        // Insert into theme_settings table
        await connection.execute(
          'INSERT INTO theme_settings (customer_id, primary_color, secondary_color, background_color, text_color, theme_mode) VALUES (?, ?, ?, ?, ?, ?)',
          [customerId.toString(), '#2994ff', '#29f8ff', '#FFFFFF', '#000000', 'dark']
        );
        console.log(`Inserted theme settings for customer_id: ${customerId}`);

        // Insert into users table (admin user for the site)
        const hashedPassword = await bcrypt.hash(admin_password, 10);

        // Auto-convert admin to admin@gmail.com if no @ symbol found
        let adminEmail = admin_user;
        if (!admin_user.includes('@')) {
          adminEmail = `${admin_user}@gmail.com`;
        }

        await connection.execute(
          'INSERT INTO users (customer_id, fullname, email, password, money, points, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [customerId.toString(), `${website_name} Admin`, adminEmail, hashedPassword, 0.00, 0, 'admin']
        );
        console.log(`Inserted user for customer_id: ${customerId}`);

        // Insert sample product
        await connection.execute(
          'INSERT INTO products (customer_id, category_id, title, subtitle, price, reseller_price, stock, duration, image, download_link, isSpecial, featured, isActive, isWarrenty, warrenty_text, primary_color, secondary_color, priority, discount_percent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [customerId.toString(), categoryId, 'Sample Product', 'This is a sample product for your new site', 10.00, 8.00, 100, '30 days', config.Model1_1500x1500Banner || `https://img5.pic.in.th/file/secure-sv1/1500x1500232d3d161739dfd2.png`, null, 0, 1, 1, 0, null, '#ff0000', '#b3ffc7', 0, 0]
        );
        console.log(`Inserted sample product for customer_id: ${customerId}`);

        // Insert config data
        await connection.execute(
          'INSERT INTO config (customer_id, owner_phone, site_name, site_logo, meta_title, meta_description, meta_keywords, meta_author, discord_link, discord_webhook, banner_link, banner2_link, banner3_link, navigation_banner_1, navigation_link_1, navigation_banner_2, navigation_link_2, navigation_banner_3, navigation_link_3, navigation_banner_4, navigation_link_4, background_image, footer_image, load_logo, footer_logo, theme, ad_banner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [customerId.toString(), '0000000000', website_name, config.Model1_1500x1500Banner || `https://img5.pic.in.th/file/secure-sv1/1500x1500232d3d161739dfd2.png`, `(⭐) ${website_name} - Digital Store`, `Welcome to ${website_name} - Your trusted digital products store`, 'digital, products, store, gaming', `${website_name} Admin`, null, null, config.Model1_2000x500Banner || 'https://img2.pic.in.th/pic/2000x500172fb60914209eb0.png', config.Model1_2000x500Banner || 'https://img2.pic.in.th/pic/2000x500172fb60914209eb0.png', config.Model1_2000x500Banner || 'https://img2.pic.in.th/pic/2000x500172fb60914209eb0.png', config.Model1_1000x500Banner || 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, config.Model1_1000x500Banner || 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, config.Model1_1000x500Banner || 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, config.Model1_1000x500Banner || 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, null, null, null, null, 'Dark mode', config.Model1_1500x1500Banner || 'https://img5.pic.in.th/file/secure-sv1/1500x1500232d3d161739dfd2.png']
        );
        console.log(`Inserted config for customer_id: ${customerId}`);

        console.log(`Successfully inserted additional data for customer_id: ${customerId}`);

      } catch (insertError) {
        console.error('Error inserting additional data:', insertError);
        // Don't fail the transaction if additional data insertion fails
        // Just log the error and continue
      }

      // Commit transaction
      await connection.commit();
      connection.release();

      res.json({
        success: true,
        message: 'Site purchased successfully',
        data: {
          customer_id: customerId,
          website_name,
          admin_user,
          method,
          expiredDay: expiredDay.toISOString().split('T')[0],
          amount_deducted: sitePrice,
          remaining_balance: newBalance
        }
      });

    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Purchase site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Renew website endpoint
app.post('/api/resell/renew-site', authenticateToken, async (req, res) => {
  try {
    const { website_name } = req.body;
    const userId = req.user.user_id;

    // Validate required fields
    if (!website_name) {
      return res.status(400).json({
        success: false,
        message: 'Website name is required'
      });
    }

    // Start database transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Get user balance
      const [users] = await connection.execute(
        'SELECT balance FROM resell_users WHERE user_id = ?',
        [userId]
      );

      if (users.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const userBalance = parseFloat(users[0].balance);

      // Get config data for resell pricing
      const [configs] = await connection.execute(
        'SELECT Model1_resell_price FROM resell_config ORDER BY id ASC LIMIT 1'
      );

      if (configs.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(500).json({
          success: false,
          message: 'Config not found'
        });
      }

      const config = configs[0];
      const sitePrice = parseFloat(config.Model1_resell_price);

      // Check if user has enough balance
      if (userBalance < sitePrice) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({
          success: false,
          message: 'Insufficient balance',
          required: sitePrice,
          current: userBalance
        });
      }

      // Check if website exists
      const [existingSites] = await connection.execute(
        'SELECT customer_id, expiredDay FROM auth_sites WHERE website_name = ?',
        [website_name]
      );

      if (existingSites.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({
          success: false,
          message: 'Website not found'
        });
      }

      // Calculate new expiry date
      const existingExpiredDay = new Date(existingSites[0].expiredDay);
      const today = new Date();
      let newExpiredDay;

      // If expired day is in the past, add 30 days from today
      if (existingExpiredDay < today) {
        newExpiredDay = new Date();
        newExpiredDay.setDate(newExpiredDay.getDate() + 30);
      } else {
        // Add 30 days from existing expired day
        newExpiredDay = new Date(existingExpiredDay);
        newExpiredDay.setDate(newExpiredDay.getDate() + 30);
      }

      // Update expired day in auth_sites
      await connection.execute(
        'UPDATE auth_sites SET expiredDay = ? WHERE website_name = ?',
        [newExpiredDay.toISOString().split('T')[0], website_name]
      );

      // Deduct money from user balance
      const newBalance = userBalance - sitePrice;
      await connection.execute(
        'UPDATE resell_users SET balance = ? WHERE user_id = ?',
        [newBalance, userId]
      );

      // Record transaction
      const transactionDescription = `${website_name};ต่ออายุ`;
      await connection.execute(
        'INSERT INTO resell_transactions (user_id, type, amount, description, status) VALUES (?, ?, ?, ?, ?)',
        [userId, 'purchase', sitePrice, transactionDescription, 'success']
      );

      // Commit transaction
      await connection.commit();
      connection.release();

      res.json({
        success: true,
        message: 'Website renewed successfully',
        data: {
          website_name,
          old_expired_day: existingExpiredDay.toISOString().split('T')[0],
          new_expired_day: newExpiredDay.toISOString().split('T')[0],
          amount_deducted: sitePrice,
          remaining_balance: newBalance
        }
      });

    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Renew site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get transaction history
app.get('/api/resell/transactions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    const [transactions] = await pool.execute(
      'SELECT transac_id, type, amount, description, status, created_at FROM resell_transactions WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    res.json({
      success: true,
      message: 'Transaction history retrieved successfully',
      data: transactions
    });

  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get topup history
app.get('/api/resell/topup-history', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    const [topups] = await pool.execute(
      'SELECT topup_id, method, amount, slip_url, status, created_at FROM resell_topup_history WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    res.json({
      success: true,
      message: 'Topup history retrieved successfully',
      data: topups
    });

  } catch (error) {
    console.error('Get topup history error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Topup balance
app.post('/api/resell/topup', authenticateToken, async (req, res) => {
  try {
    const { method, amount, slip_url } = req.body;
    const userId = req.user.user_id;

    // Validate required fields
    if (!method || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Method and amount are required'
      });
    }

    // Validate method
    const validMethods = ['bank', 'wallet', 'card'];
    if (!validMethods.includes(method)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid method. Must be one of: bank, wallet, card'
      });
    }

    // Validate amount
    const topupAmount = parseFloat(amount);
    if (isNaN(topupAmount) || topupAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be a positive number'
      });
    }

    // Insert topup request
    const [result] = await pool.execute(
      'INSERT INTO resell_topup_history (user_id, method, amount, slip_url, status) VALUES (?, ?, ?, ?, ?)',
      [userId, method, topupAmount, slip_url || null, 'pending']
    );

    res.status(201).json({
      success: true,
      message: 'Topup request submitted successfully',
      data: {
        topup_id: result.insertId,
        method,
        amount: topupAmount,
        slip_url,
        status: 'pending'
      }
    });

  } catch (error) {
    console.error('Topup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Admin: Approve topup and add balance to user
app.post('/api/resell/admin/approve-topup/:topup_id', authenticateToken, async (req, res) => {
  try {
    const { topup_id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Start database transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Get topup details
      const [topups] = await connection.execute(
        'SELECT user_id, amount, status FROM resell_topup_history WHERE topup_id = ?',
        [topup_id]
      );

      if (topups.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({
          success: false,
          message: 'Topup request not found'
        });
      }

      const topup = topups[0];

      if (topup.status !== 'pending') {
        await connection.rollback();
        connection.release();
        return res.status(400).json({
          success: false,
          message: 'Topup request already processed'
        });
      }

      // Update topup status to success
      await connection.execute(
        'UPDATE resell_topup_history SET status = ? WHERE topup_id = ?',
        ['success', topup_id]
      );

      // Add balance to user
      await connection.execute(
        'UPDATE resell_users SET balance = balance + ? WHERE user_id = ?',
        [topup.amount, topup.user_id]
      );

      // Record transaction
      await connection.execute(
        'INSERT INTO resell_transactions (user_id, type, amount, description, status) VALUES (?, ?, ?, ?, ?)',
        [topup.user_id, 'purchase', topup.amount, `Topup approved - Topup ID: ${topup_id}`, 'success']
      );

      // Commit transaction
      await connection.commit();
      connection.release();

      res.json({
        success: true,
        message: 'Topup approved successfully',
        data: {
          topup_id: parseInt(topup_id),
          user_id: topup.user_id,
          amount: topup.amount,
          status: 'success'
        }
      });

    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Approve topup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Redeem angpao endpoint
app.post('/api/resell/redeem-angpao', authenticateToken, async (req, res) => {
  let campaignId; // Declare campaignId at function scope

  try {
    const { link } = req.body;
    const userId = req.user.user_id;

    if (!link) {
      return res.status(400).json({ success: false, error: 'กรุณาระบุ link' });
    }

    // ดึงข้อมูลผู้ใช้ปัจจุบันจาก resell_users
    const [users] = await pool.execute(
      "SELECT user_id, balance FROM resell_users WHERE user_id = ?",
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ success: false, error: 'ไม่พบผู้ใช้' });
    }

    // ดึง campaign ID จาก link
    campaignId = link;
    const phone = '0843460416'; // เบอร์โทรที่กำหนด

    if (link.includes('gift.truemoney.com/campaign/?v=')) {
      const urlParams = new URL(link).searchParams;
      campaignId = urlParams.get('v');
    } else if (link.includes('v=')) {
      const match = link.match(/[?&]v=([^&]+)/);
      if (match) {
        campaignId = match[1];
      }
    }

    if (!campaignId) {
      return res.status(400).json({ success: false, error: 'ไม่พบ campaign ID ในลิงก์' });
    }

    // เรียก API TrueMoney พร้อม retry
    let data;
    let lastError;
    const maxRetries = 3;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`Calling TrueMoney API (attempt ${attempt}/${maxRetries}): https://api.xpluem.com/${campaignId}/${phone}`);

        const response = await fetch(`https://api.xpluem.com/${campaignId}/${phone}`, {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache'
          },
          timeout: 15000
        });

        data = await response.json();
        console.log(`TrueMoney API Response (attempt ${attempt}):`, data);

        // ถ้าได้ response แล้วให้ break ออกจาก loop
        break;

      } catch (error) {
        lastError = error;
        console.error(`TrueMoney API attempt ${attempt} failed:`, error.message);

        // ถ้าเป็น attempt สุดท้ายให้ throw error
        if (attempt === maxRetries) {
          throw error;
        }

        // รอ 2 วินาทีก่อนลองใหม่
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    // เริ่ม transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // ตรวจสอบ response data
      if (!data) {
        throw new Error('ไม่ได้รับข้อมูลจาก API');
      }

      const amount = data.data ? parseFloat(data.data.amount) : 0;
      const status = data.success ? 'success' : 'failed';

      // ตรวจสอบจำนวนเงิน
      if (amount <= 0) {
        throw new Error('จำนวนเงินไม่ถูกต้อง');
      }

      // ตรวจสอบว่ามีการเติมเงินซ้ำหรือไม่ (ตรวจสอบ campaign ID ใน 24 ชั่วโมงที่ผ่านมา)
      const [existingTopup] = await connection.execute(
        'SELECT topup_id FROM resell_topup_history WHERE user_id = ? AND method = ? AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND slip_url = ?',
        [userId, 'wallet', `Campaign: ${campaignId}`]
      );

      if (existingTopup.length > 0) {
        throw new Error('ลิงก์นี้ถูกใช้แล้วใน 24 ชั่วโมงที่ผ่านมา');
      }

      // บันทึกลงตาราง resell_topup_history
      const [topupResult] = await connection.execute(
        'INSERT INTO resell_topup_history (user_id, method, amount, slip_url, status) VALUES (?, ?, ?, ?, ?)',
        [userId, 'wallet', amount, `Campaign: ${campaignId}`, status]
      );

      // ถ้าสำเร็จ ให้บวกเงิน
      if (data.success && (data.message === 'รับเงินสำเร็จ' || data.message === 'success')) {
        const newBalance = parseFloat(users[0].balance) + amount;

        // อัปเดตเงินผู้ใช้
        const [updateResult] = await connection.execute(
          'UPDATE resell_users SET balance = ? WHERE user_id = ?',
          [newBalance, userId]
        );

        if (updateResult.affectedRows === 0) {
          throw new Error('ไม่สามารถอัปเดตเงินผู้ใช้ได้');
        }

        // อัปเดตสถานะ topup เป็น success
        await connection.execute(
          'UPDATE resell_topup_history SET status = ? WHERE topup_id = ?',
          ['success', topupResult.insertId]
        );

        // บันทึกลง transaction history
        await connection.execute(
          'INSERT INTO resell_transactions (user_id, type, amount, description, status) VALUES (?, ?, ?, ?, ?)',
          [userId, 'purchase', amount, `Redeem Angpao - Campaign: ${campaignId}`, 'success']
        );

        await connection.commit();

        console.log(`Angpao redemption successful: User ${userId}, Amount: ${amount}, New Balance: ${newBalance}`);

        res.json({
          success: true,
          message: `เติมเงินสำเร็จ: +${amount} บาท`,
          amount: amount,
          new_balance: newBalance,
          topup_id: topupResult.insertId,
          campaign_id: campaignId
        });
      } else {
        // อัปเดตสถานะ topup เป็น failed
        await connection.execute(
          'UPDATE resell_topup_history SET status = ? WHERE topup_id = ?',
          ['failed', topupResult.insertId]
        );

        await connection.commit();

        console.log(`Angpao redemption failed: User ${userId}, Campaign: ${campaignId}, Message: ${data.message}`);

        res.json({
          success: false,
          message: data.message || 'การเติมเงินไม่สำเร็จ',
          amount: amount,
          topup_id: topupResult.insertId,
          campaign_id: campaignId
        });
      }

    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }

  } catch (err) {
    console.error('Redeem angpao error:', err);

    // กรณีเรียก API ล้มเหลว
    if (err.response) {
      console.error('API Error Details:', {
        status: err.response.status,
        statusText: err.response.statusText,
        data: err.response.data,
        url: err.config?.url,
        user_id: req.user?.user_id,
        campaign_id: campaignId
      });

      let errorMessage = 'ไม่สามารถเชื่อมต่อ API ได้';

      if (err.response.status === 500) {
        errorMessage = 'API เกิดข้อผิดพลาดภายใน (500) - อาจเป็นเพราะ campaign ID ไม่ถูกต้องหรือ API มีปัญหา';
      } else if (err.response.status === 404) {
        errorMessage = 'ไม่พบ campaign ID ที่ระบุ - ลิงก์อาจหมดอายุหรือไม่ถูกต้อง';
      } else if (err.response.status === 400) {
        errorMessage = 'ข้อมูลที่ส่งไปไม่ถูกต้อง - ตรวจสอบลิงก์และเบอร์โทร';
      } else if (err.response.status === 403) {
        errorMessage = 'ไม่มีสิทธิ์เข้าถึง API - ลิงก์อาจถูกใช้แล้ว';
      } else if (err.response.status === 429) {
        errorMessage = 'เรียก API เกินขีดจำกัด - กรุณารอสักครู่แล้วลองใหม่';
      }

      return res.status(500).json({
        success: false,
        error: errorMessage,
        details: {
          status: err.response.status,
          message: err.response.data?.message || err.response.statusText,
          campaign_id: campaignId
        }
      });
    }

    // กรณี timeout หรือ network error
    if (err.code === 'ECONNABORTED') {
      return res.status(500).json({
        success: false,
        error: 'การเชื่อมต่อ API หมดเวลา - กรุณาลองใหม่อีกครั้ง',
        details: {
          code: err.code,
          campaign_id: campaignId
        }
      });
    }

    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      return res.status(500).json({
        success: false,
        error: 'ไม่สามารถเชื่อมต่อ API ได้ - ตรวจสอบการเชื่อมต่ออินเทอร์เน็ต',
        details: {
          code: err.code,
          campaign_id: campaignId
        }
      });
    }

    // กรณี error อื่นๆ
    res.status(500).json({
      success: false,
      error: err.message || 'เกิดข้อผิดพลาดที่ไม่ทราบสาเหตุ',
      details: {
        message: err.message,
        campaign_id: campaignId,
        user_id: req.user?.user_id
      }
    });
  }
});

// ==================== RESELL CONFIG API ====================

// Get resell config (first row only) - Public endpoint
app.get('/api/resell/config', async (req, res) => {
  try {
    const [configs] = await pool.execute(
      'SELECT * FROM resell_config ORDER BY id ASC LIMIT 1'
    );

    if (configs.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No config found'
      });
    }

    const config = configs[0];

    res.json({
      success: true,
      message: 'Config retrieved successfully',
      data: {
        // Public information for general users
        owner_name: config.owner_name,
        owner_bank: config.owner_bank,
        website_name: config.website_name,
        Model1_price: config.Model1_price,
        Model1_resell_price: config.Model1_resell_price,
        Model1_name: config.Model1_name,
        // Banner URLs for public use
        Model1_1500x1500Banner: config.Model1_1500x1500Banner,
        Model1_2000x500Banner: config.Model1_2000x500Banner,
        Model1_1000x500Banner: config.Model1_1000x500Banner,
        Model1_1640x500Banner: config.Model1_1640x500Banner,
        // Private information (only for internal use)
        phone_number: config.phone_number
      }
    });

  } catch (error) {
    console.error('Get resell config error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get all resell configs (Admin only)
app.get('/api/resell/admin/configs', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [configs] = await pool.execute(
      'SELECT * FROM resell_config ORDER BY id ASC'
    );

    res.json({
      success: true,
      message: 'Configs retrieved successfully',
      data: configs
    });

  } catch (error) {
    console.error('Get resell configs error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Create new resell config (Admin only)
app.post('/api/resell/admin/config', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;
    const {
      phone_number,
      owner_name,
      owner_bank,
      website_name,
      Model1_price,
      Model1_resell_price,
      Model1_name,
      Model1_1500x1500Banner,
      Model1_2000x500Banner,
      Model1_1000x500Banner,
      Model1_1640x500Banner
    } = req.body;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Validate required fields
    if (!phone_number || !owner_name || !owner_bank || !website_name ||
      !Model1_price || !Model1_resell_price || !Model1_name) {
      return res.status(400).json({
        success: false,
        message: 'Required fields: phone_number, owner_name, owner_bank, website_name, Model1_price, Model1_resell_price, Model1_name'
      });
    }

    // Insert new config
    const [result] = await pool.execute(
      'INSERT INTO resell_config (phone_number, owner_name, owner_bank, website_name, Model1_price, Model1_resell_price, Model1_name, Model1_1500x1500Banner, Model1_2000x500Banner, Model1_1000x500Banner, Model1_1640x500Banner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [phone_number, owner_name, owner_bank, website_name, Model1_price, Model1_resell_price, Model1_name, Model1_1500x1500Banner, Model1_2000x500Banner, Model1_1000x500Banner, Model1_1640x500Banner]
    );

    res.status(201).json({
      success: true,
      message: 'Config created successfully',
      data: {
        id: result.insertId,
        phone_number,
        owner_name,
        owner_bank,
        website_name,
        Model1_price,
        Model1_resell_price,
        Model1_name,
        Model1_1500x1500Banner,
        Model1_2000x500Banner,
        Model1_1000x500Banner,
        Model1_1640x500Banner
      }
    });

  } catch (error) {
    console.error('Create resell config error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Update resell config (Admin only)
app.put('/api/resell/admin/config/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;
    const {
      phone_number,
      owner_name,
      owner_bank,
      website_name,
      Model1_price,
      Model1_resell_price,
      Model1_name,
      Model1_1500x1500Banner,
      Model1_2000x500Banner,
      Model1_1000x500Banner,
      Model1_1640x500Banner
    } = req.body;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Check if config exists
    const [existingConfig] = await pool.execute(
      'SELECT id FROM resell_config WHERE id = ?',
      [id]
    );

    if (existingConfig.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Config not found'
      });
    }

    // Build update query dynamically
    const updateFields = [];
    const updateValues = [];

    if (phone_number !== undefined) {
      updateFields.push('phone_number = ?');
      updateValues.push(phone_number);
    }
    if (owner_name !== undefined) {
      updateFields.push('owner_name = ?');
      updateValues.push(owner_name);
    }
    if (owner_bank !== undefined) {
      updateFields.push('owner_bank = ?');
      updateValues.push(owner_bank);
    }
    if (website_name !== undefined) {
      updateFields.push('website_name = ?');
      updateValues.push(website_name);
    }
    if (Model1_price !== undefined) {
      updateFields.push('Model1_price = ?');
      updateValues.push(Model1_price);
    }
    if (Model1_resell_price !== undefined) {
      updateFields.push('Model1_resell_price = ?');
      updateValues.push(Model1_resell_price);
    }
    if (Model1_name !== undefined) {
      updateFields.push('Model1_name = ?');
      updateValues.push(Model1_name);
    }
    if (Model1_1500x1500Banner !== undefined) {
      updateFields.push('Model1_1500x1500Banner = ?');
      updateValues.push(Model1_1500x1500Banner);
    }
    if (Model1_2000x500Banner !== undefined) {
      updateFields.push('Model1_2000x500Banner = ?');
      updateValues.push(Model1_2000x500Banner);
    }
    if (Model1_1000x500Banner !== undefined) {
      updateFields.push('Model1_1000x500Banner = ?');
      updateValues.push(Model1_1000x500Banner);
    }
    if (Model1_1640x500Banner !== undefined) {
      updateFields.push('Model1_1640x500Banner = ?');
      updateValues.push(Model1_1640x500Banner);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    updateValues.push(id);

    // Update config
    await pool.execute(
      `UPDATE resell_config SET ${updateFields.join(', ')} WHERE id = ?`,
      updateValues
    );

    res.json({
      success: true,
      message: 'Config updated successfully',
      data: {
        id: parseInt(id),
        updated_fields: updateFields.length
      }
    });

  } catch (error) {
    console.error('Update resell config error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Delete resell config (Admin only)
app.delete('/api/resell/admin/config/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Check if config exists
    const [existingConfig] = await pool.execute(
      'SELECT id FROM resell_config WHERE id = ?',
      [id]
    );

    if (existingConfig.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Config not found'
      });
    }

    // Delete config
    await pool.execute(
      'DELETE FROM resell_config WHERE id = ?',
      [id]
    );

    res.json({
      success: true,
      message: 'Config deleted successfully',
      data: {
        id: parseInt(id)
      }
    });

  } catch (error) {
    console.error('Delete resell config error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// ==================== RESELL USERS MANAGEMENT API ====================

// Get all resell users (Admin only)
app.get('/api/resell/admin/users', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [allUsers] = await pool.execute(
      'SELECT user_id, username, email, role, balance, created_at FROM resell_users ORDER BY created_at DESC'
    );

    res.json({
      success: true,
      message: 'Users retrieved successfully',
      data: allUsers
    });

  } catch (error) {
    console.error('Get resell users error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get specific user details (Admin only)
app.get('/api/resell/admin/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [targetUsers] = await pool.execute(
      'SELECT user_id, username, email, role, balance, created_at FROM resell_users WHERE user_id = ?',
      [id]
    );

    if (targetUsers.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get user's transaction history
    const [transactions] = await pool.execute(
      'SELECT transac_id, type, amount, description, status, created_at FROM resell_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
      [id]
    );

    // Get user's topup history
    const [topups] = await pool.execute(
      'SELECT topup_id, method, amount, slip_url, status, created_at FROM resell_topup_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
      [id]
    );

    res.json({
      success: true,
      message: 'User details retrieved successfully',
      data: {
        user: targetUsers[0],
        recent_transactions: transactions,
        recent_topups: topups
      }
    });

  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Update user information (Admin only) 
app.put('/api/resell/admin/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;
    const { username, email, role, balance } = req.body;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Check if target user exists
    const [targetUsers] = await pool.execute(
      'SELECT user_id FROM resell_users WHERE user_id = ?',
      [id]
    );

    if (targetUsers.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Build update query dynamically
    const updateFields = [];
    const updateValues = [];

    if (username !== undefined) {
      // Check if username already exists (excluding current user)
      const [existingUsername] = await pool.execute(
        'SELECT user_id FROM resell_users WHERE username = ? AND user_id != ?',
        [username, id]
      );
      if (existingUsername.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Username already exists'
        });
      }
      updateFields.push('username = ?');
      updateValues.push(username);
    }

    if (email !== undefined) {
      // Check if email already exists (excluding current user)
      const [existingEmail] = await pool.execute(
        'SELECT user_id FROM resell_users WHERE email = ? AND user_id != ?',
        [email, id]
      );
      if (existingEmail.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Email already exists'
        });
      }
      updateFields.push('email = ?');
      updateValues.push(email);
    }

    if (role !== undefined) {
      const validRoles = ['admin', 'user', 'moderator'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid role. Must be one of: admin, user, moderator'
        });
      }
      updateFields.push('role = ?');
      updateValues.push(role);
    }

    if (balance !== undefined) {
      const balanceValue = parseFloat(balance);
      if (isNaN(balanceValue) || balanceValue < 0) {
        return res.status(400).json({
          success: false,
          message: 'Balance must be a positive number'
        });
      }
      updateFields.push('balance = ?');
      updateValues.push(balanceValue);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    updateValues.push(id);

    // Update user
    await pool.execute(
      `UPDATE resell_users SET ${updateFields.join(', ')} WHERE user_id = ?`,
      updateValues
    );

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        user_id: parseInt(id),
        updated_fields: updateFields.length
      }
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Add balance to user (Admin only)
app.post('/api/resell/admin/users/:id/add-balance', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;
    const { amount, description } = req.body;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Validate amount
    const addAmount = parseFloat(amount);
    if (isNaN(addAmount) || addAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be a positive number'
      });
    }

    // Check if target user exists
    const [targetUsers] = await pool.execute(
      'SELECT user_id, balance FROM resell_users WHERE user_id = ?',
      [id]
    );

    if (targetUsers.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const targetUser = targetUsers[0];
    const newBalance = parseFloat(targetUser.balance) + addAmount;

    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Update user balance
      await connection.execute(
        'UPDATE resell_users SET balance = ? WHERE user_id = ?',
        [newBalance, id]
      );

      // Record transaction
      const transactionDescription = description || `Admin added balance: +${addAmount}`;
      await connection.execute(
        'INSERT INTO resell_transactions (user_id, type, amount, description, status) VALUES (?, ?, ?, ?, ?)',
        [id, 'purchase', addAmount, transactionDescription, 'success']
      );

      await connection.commit();
      connection.release();

      res.json({
        success: true,
        message: 'Balance added successfully',
        data: {
          user_id: parseInt(id),
          amount_added: addAmount,
          old_balance: parseFloat(targetUser.balance),
          new_balance: newBalance
        }
      });

    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Add balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Delete user (Admin only)
app.delete('/api/resell/admin/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Prevent admin from deleting themselves
    if (parseInt(id) === userId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete your own account'
      });
    }

    // Check if target user exists
    const [targetUsers] = await pool.execute(
      'SELECT user_id, username FROM resell_users WHERE user_id = ?',
      [id]
    );

    if (targetUsers.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const targetUser = targetUsers[0];

    // Delete user (CASCADE will handle related records)
    await pool.execute(
      'DELETE FROM resell_users WHERE user_id = ?',
      [id]
    );

    res.json({
      success: true,
      message: 'User deleted successfully',
      data: {
        user_id: parseInt(id),
        username: targetUser.username
      }
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// ==================== REPORTS API ====================

// Get all topup history (Admin only)
app.get('/api/resell/admin/reports/topups', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [topups] = await pool.execute(
      `SELECT 
        t.topup_id,
        t.user_id,
        u.username,
        u.email,
        t.method,
        t.amount,
        t.slip_url,
        t.status,
        t.created_at
      FROM resell_topup_history t
      LEFT JOIN resell_users u ON t.user_id = u.user_id
      ORDER BY t.created_at DESC`
    );

    res.json({
      success: true,
      message: 'Topup history retrieved successfully',
      data: topups
    });

  } catch (error) {
    console.error('Get topup reports error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get all transactions (Admin only)
app.get('/api/resell/admin/reports/transactions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [transactions] = await pool.execute(
      `SELECT 
        t.transac_id,
        t.user_id,
        u.username,
        u.email,
        t.type,
        t.amount,
        t.description,
        t.status,
        t.created_at
      FROM resell_transactions t
      LEFT JOIN resell_users u ON t.user_id = u.user_id
      ORDER BY t.created_at DESC`
    );

    res.json({
      success: true,
      message: 'Transaction history retrieved successfully',
      data: transactions
    });

  } catch (error) {
    console.error('Get transaction reports error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get sales summary (Admin only)
app.get('/api/resell/admin/reports/summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Get total topup amounts by status
    const [topupSummary] = await pool.execute(
      `SELECT 
        status,
        COUNT(*) as count,
        SUM(amount) as total_amount
      FROM resell_topup_history 
      GROUP BY status`
    );

    // Get total transaction amounts by type and status
    const [transactionSummary] = await pool.execute(
      `SELECT 
        type,
        status,
        COUNT(*) as count,
        SUM(amount) as total_amount
      FROM resell_transactions 
      GROUP BY type, status`
    );

    // Get daily sales for last 30 days
    const [dailySales] = await pool.execute(
      `SELECT 
        DATE(created_at) as date,
        COUNT(*) as transaction_count,
        SUM(amount) as total_amount
      FROM resell_transactions 
      WHERE type = 'purchase' AND status = 'success'
      AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(created_at)
      ORDER BY date DESC`
    );

    // Get monthly sales for last 12 months
    const [monthlySales] = await pool.execute(
      `SELECT 
        DATE_FORMAT(created_at, '%Y-%m') as month,
        COUNT(*) as transaction_count,
        SUM(amount) as total_amount
      FROM resell_transactions 
      WHERE type = 'purchase' AND status = 'success'
      AND created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY month DESC`
    );

    // Get top users by spending
    const [topUsers] = await pool.execute(
      `SELECT 
        u.user_id,
        u.username,
        u.email,
        COUNT(t.transac_id) as transaction_count,
        SUM(t.amount) as total_spent
      FROM resell_users u
      LEFT JOIN resell_transactions t ON u.user_id = t.user_id AND t.type = 'purchase' AND t.status = 'success'
      GROUP BY u.user_id, u.username, u.email
      HAVING total_spent > 0
      ORDER BY total_spent DESC
      LIMIT 10`
    );

    // Calculate totals
    const totalTopupAmount = topupSummary.reduce((sum, item) => sum + parseFloat(item.total_amount || 0), 0);
    const totalTransactionAmount = transactionSummary.reduce((sum, item) => sum + parseFloat(item.total_amount || 0), 0);
    const totalSalesAmount = transactionSummary
      .filter(item => item.type === 'purchase' && item.status === 'success')
      .reduce((sum, item) => sum + parseFloat(item.total_amount || 0), 0);

    res.json({
      success: true,
      message: 'Sales summary retrieved successfully',
      data: {
        summary: {
          total_topup_amount: totalTopupAmount,
          total_transaction_amount: totalTransactionAmount,
          total_sales_amount: totalSalesAmount,
          total_users: topUsers.length
        },
        topup_summary: topupSummary,
        transaction_summary: transactionSummary,
        daily_sales: dailySales,
        monthly_sales: monthlySales,
        top_users: topUsers
      }
    });

  } catch (error) {
    console.error('Get sales summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get topup history with filters (Admin only)
app.get('/api/resell/admin/reports/topups/filtered', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;
    const { status, method, start_date, end_date, user_id } = req.query;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Build query with filters
    let query = `
      SELECT 
        t.topup_id,
        t.user_id,
        u.username,
        u.email,
        t.method,
        t.amount,
        t.slip_url,
        t.status,
        t.created_at
      FROM resell_topup_history t
      LEFT JOIN resell_users u ON t.user_id = u.user_id
      WHERE 1=1
    `;

    const queryParams = [];

    if (status) {
      query += ' AND t.status = ?';
      queryParams.push(status);
    }

    if (method) {
      query += ' AND t.method = ?';
      queryParams.push(method);
    }

    if (user_id) {
      query += ' AND t.user_id = ?';
      queryParams.push(user_id);
    }

    if (start_date) {
      query += ' AND DATE(t.created_at) >= ?';
      queryParams.push(start_date);
    }

    if (end_date) {
      query += ' AND DATE(t.created_at) <= ?';
      queryParams.push(end_date);
    }

    query += ' ORDER BY t.created_at DESC';

    const [topups] = await pool.execute(query, queryParams);

    res.json({
      success: true,
      message: 'Filtered topup history retrieved successfully',
      data: topups
    });

  } catch (error) {
    console.error('Get filtered topup reports error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get transactions with filters (Admin only)
app.get('/api/resell/admin/reports/transactions/filtered', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;
    const { type, status, start_date, end_date, user_id } = req.query;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Build query with filters
    let query = `
      SELECT 
        t.transac_id,
        t.user_id,
        u.username,
        u.email,
        t.type,
        t.amount,
        t.description,
        t.status,
        t.created_at
      FROM resell_transactions t
      LEFT JOIN resell_users u ON t.user_id = u.user_id
      WHERE 1=1
    `;

    const queryParams = [];

    if (type) {
      query += ' AND t.type = ?';
      queryParams.push(type);
    }

    if (status) {
      query += ' AND t.status = ?';
      queryParams.push(status);
    }

    if (user_id) {
      query += ' AND t.user_id = ?';
      queryParams.push(user_id);
    }

    if (start_date) {
      query += ' AND DATE(t.created_at) >= ?';
      queryParams.push(start_date);
    }

    if (end_date) {
      query += ' AND DATE(t.created_at) <= ?';
      queryParams.push(end_date);
    }

    query += ' ORDER BY t.created_at DESC';

    const [transactions] = await pool.execute(query, queryParams);

    res.json({
      success: true,
      message: 'Filtered transaction history retrieved successfully',
      data: transactions
    });

  } catch (error) {
    console.error('Get filtered transaction reports error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// ==================== AUTH SITES API ====================

// Get all auth sites (Admin only)
app.get('/api/auth-sites', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [sites] = await pool.execute(
      'SELECT id, customer_id, website_name, admin_user, admin_password, expiredDay, created_at FROM auth_sites ORDER BY created_at DESC'
    );

    // Decrypt passwords for admin view
    const sitesWithDecryptedPasswords = await Promise.all(
      sites.map(async (site) => ({
        ...site,
        admin_password: await decryptPassword(site.admin_password)
      }))
    );

    res.json({
      success: true,
      message: 'Auth sites retrieved successfully',
      data: sitesWithDecryptedPasswords
    });

  } catch (error) {
    console.error('Get auth sites error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get auth site by customer_id
app.get('/api/auth-sites/:customer_id', async (req, res) => {
  try {
    const { customer_id } = req.params;

    const [sites] = await pool.execute(
      'SELECT id, customer_id, website_name, admin_user, admin_password, expiredDay, created_at FROM auth_sites WHERE customer_id = ?',
      [customer_id]
    );

    if (sites.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Auth site not found'
      });
    }

    const site = sites[0];

    // Decrypt password for admin access
    const decryptedPassword = await decryptPassword(site.admin_password);

    res.json({
      success: true,
      message: 'Auth site retrieved successfully',
      data: {
        id: site.id,
        customer_id: site.customer_id,
        website_name: site.website_name,
        admin_user: site.admin_user,
        admin_password: decryptedPassword,
        expiredDay: site.expiredDay,
        created_at: site.created_at
      }
    });

  } catch (error) {
    console.error('Get auth site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Create auth site
app.post('/api/auth-sites', async (req, res) => {
  try {
    const { customer_id, website_name, admin_user, admin_password, expiredDay } = req.body;

    // Validate required fields
    if (!customer_id || !website_name || !admin_user || !admin_password || !expiredDay) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Check if customer_id already exists
    const [existingSite] = await pool.execute(
      'SELECT id FROM auth_sites WHERE customer_id = ?',
      [customer_id]
    );

    if (existingSite.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Customer ID already exists'
      });
    }

    // Insert new auth site
    const [result] = await pool.execute(
      'INSERT INTO auth_sites (customer_id, website_name, admin_user, admin_password, expiredDay) VALUES (?, ?, ?, ?, ?)',
      [customer_id, website_name, admin_user, admin_password, expiredDay]
    );

    res.status(201).json({
      success: true,
      message: 'Auth site created successfully',
      data: {
        id: result.insertId,
        customer_id,
        website_name,
        admin_user,
        expiredDay
      }
    });

  } catch (error) {
    console.error('Create auth site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Delete auth site (Admin only)
app.delete('/api/auth-sites/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Check if site exists
    const [existingSite] = await pool.execute(
      'SELECT id, customer_id, website_name FROM auth_sites WHERE id = ?',
      [id]
    );

    if (existingSite.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Auth site not found'
      });
    }

    const site = existingSite[0];
    const customerId = site.customer_id;

    // Start database transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Delete all related data for this customer_id
      // Order matters: delete child tables first, then parent tables

      // 1. Delete from products first (has foreign key to categories)
      await connection.execute(
        'DELETE FROM products WHERE customer_id = ?',
        [customerId]
      );

      // 2. Delete from categories (has foreign key to customer_id)
      await connection.execute(
        'DELETE FROM categories WHERE customer_id = ?',
        [customerId]
      );

      // 3. Delete from users (has foreign key to customer_id)
      await connection.execute(
        'DELETE FROM users WHERE customer_id = ?',
        [customerId]
      );

      // 4. Delete from roles (has foreign key to customer_id)
      await connection.execute(
        'DELETE FROM roles WHERE customer_id = ?',
        [customerId]
      );

      // 5. Delete from theme_settings (has foreign key to customer_id)
      await connection.execute(
        'DELETE FROM theme_settings WHERE customer_id = ?',
        [customerId]
      );

      // 6. Delete from config (has foreign key to customer_id)
      await connection.execute(
        'DELETE FROM config WHERE customer_id = ?',
        [customerId]
      );

      // 7. Finally delete from auth_sites (parent table)
      await connection.execute(
        'DELETE FROM auth_sites WHERE customer_id = ?',
        [customerId]
      );

      // Commit transaction
      await connection.commit();
      connection.release();

      res.json({
        success: true,
        message: 'Auth site and all related data deleted successfully',
        data: {
          id: parseInt(id),
          customer_id: customerId,
          website_name: site.website_name,
          deleted_tables: [
            'products',
            'categories',
            'users',
            'roles',
            'theme_settings',
            'config',
            'auth_sites'
          ]
        }
      });

    } catch (error) {
      await connection.rollback();
      connection.release();
      console.error('Foreign key constraint error:', error);
      throw error;
    }

  } catch (error) {
    console.error('Delete auth site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Disable auth site by setting expiredDay to 100 days ago (Admin only)
app.put('/api/auth-sites/:id/disable', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Check if site exists
    const [existingSite] = await pool.execute(
      'SELECT id, customer_id, website_name, expiredDay FROM auth_sites WHERE id = ?',
      [id]
    );

    if (existingSite.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Auth site not found'
      });
    }

    const site = existingSite[0];

    // Calculate date 100 days ago
    const disabledDate = new Date();
    disabledDate.setDate(disabledDate.getDate() - 100);

    // Update expiredDay to 100 days ago
    await pool.execute(
      'UPDATE auth_sites SET expiredDay = ? WHERE id = ?',
      [disabledDate.toISOString().split('T')[0], id]
    );

    res.json({
      success: true,
      message: 'Auth site disabled successfully',
      data: {
        id: parseInt(id),
        customer_id: site.customer_id,
        website_name: site.website_name,
        old_expired_day: site.expiredDay,
        new_expired_day: disabledDate.toISOString().split('T')[0]
      }
    });

  } catch (error) {
    console.error('Disable auth site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Enable auth site by setting expiredDay to 30 days from now (Admin only)
app.put('/api/auth-sites/:id/enable', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.user_id;

    // Check if user is admin
    const [users] = await pool.execute(
      'SELECT role FROM resell_users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Check if site exists
    const [existingSite] = await pool.execute(
      'SELECT id, customer_id, website_name, expiredDay FROM auth_sites WHERE id = ?',
      [id]
    );

    if (existingSite.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Auth site not found'
      });
    }

    const site = existingSite[0];

    // Calculate date 30 days from now
    const enabledDate = new Date();
    enabledDate.setDate(enabledDate.getDate() + 30);

    // Update expiredDay to 30 days from now
    await pool.execute(
      'UPDATE auth_sites SET expiredDay = ? WHERE id = ?',
      [enabledDate.toISOString().split('T')[0], id]
    );

    res.json({
      success: true,
      message: 'Auth site enabled successfully',
      data: {
        id: parseInt(id),
        customer_id: site.customer_id,
        website_name: site.website_name,
        old_expired_day: site.expiredDay,
        new_expired_day: enabledDate.toISOString().split('T')[0]
      }
    });

  } catch (error) {
    console.error('Enable auth site error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Test database connection endpoint
app.get('/test-db', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    console.log('Database connected successfully!');

    // Test query
    const [rows] = await connection.execute('SELECT 1 as test');
    console.log('Test query result:', rows);

    connection.release();

    res.json({
      success: true,
      message: 'Database connection successful',
      data: rows
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({
      success: false,
      message: 'Database connection failed',
      error: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});



// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Database test: http://localhost:${PORT}/test-db`);
  console.log('\n=== API Endpoints ===');
  console.log('Resell Users:');
  console.log(`  POST /api/resell/signup - Create new user`);
  console.log(`  POST /api/resell/login - User login`);
  console.log(`  GET /api/resell/myprofile - Get user profile (requires auth)`);
  console.log(`  POST /api/resell/purchase-site/model1 - Purchase new site (requires auth)`);
  console.log(`  POST /api/resell/renew-site - Renew existing site (requires auth)`);
  console.log(`  GET /api/resell/transactions - Get transaction history (requires auth)`);
  console.log(`  GET /api/resell/topup-history - Get topup history (requires auth)`);
  console.log(`  POST /api/resell/topup - Submit topup request (requires auth)`);
  console.log(`  GET /api/resell/config - Get resell configuration`);
  console.log('Resell Config Management (Admin only):');
  console.log(`  GET /api/resell/admin/configs - Get all configs`);
  console.log(`  POST /api/resell/admin/config - Create new config`);
  console.log(`  PUT /api/resell/admin/config/:id - Update config`);
  console.log(`  DELETE /api/resell/admin/config/:id - Delete config`);
  console.log('Resell Users Management (Admin only):');
  console.log(`  GET /api/resell/admin/users - Get all users`);
  console.log(`  GET /api/resell/admin/users/:id - Get user details`);
  console.log(`  PUT /api/resell/admin/users/:id - Update user`);
  console.log(`  POST /api/resell/admin/users/:id/add-balance - Add balance to user`);
  console.log(`  DELETE /api/resell/admin/users/:id - Delete user`);
  console.log('Reports (Admin only):');
  console.log(`  GET /api/resell/admin/reports/topups - Get all topup history`);
  console.log(`  GET /api/resell/admin/reports/transactions - Get all transactions`);
  console.log(`  GET /api/resell/admin/reports/summary - Get sales summary`);
  console.log(`  GET /api/resell/admin/reports/topups/filtered - Get filtered topup history`);
  console.log(`  GET /api/resell/admin/reports/transactions/filtered - Get filtered transactions`);
  console.log('Auth Sites:');
  console.log(`  GET /api/auth-sites - Get all auth sites (Admin only)`);
  console.log(`  GET /api/auth-sites/:customer_id - Get auth site by customer_id`);
  console.log(`  POST /api/auth-sites - Create new auth site`);
  console.log(`  DELETE /api/auth-sites/:id - Delete auth site (Admin only)`);
  console.log(`  PUT /api/auth-sites/:id/disable - Disable auth site (Admin only)`);
  console.log(`  PUT /api/auth-sites/:id/enable - Enable auth site (Admin only)`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  await pool.end();
  process.exit(0);
});