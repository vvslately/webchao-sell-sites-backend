import express from 'express';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = '91bbc8a7d1dab1b0604d9b91c89f2646';

// Database configuration
const dbConfig = {
  host: 'gondola.proxy.rlwy.net',
  port: 11555,
  user: 'root',
  password: 'tzspZOlqqEvABEgEeCCbDbAFdkGiQSYQ',
  database: 'railway',
  ssl: {
    rejectUnauthorized: false
  }
};

// Create database connection pool
const pool = mysql.createPool(dbConfig);

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000' , 'https://vhouse.space' ,'https://web-rental-frontend.vercel.app' ,'https://www.vhouse.space'],
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
app.post('/api/resell/purchase-site', authenticateToken, async (req, res) => {
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
      const sitePrice = 200.00; // ราคา site (สามารถปรับได้)

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
            [customerId.toString(), `${website_name} Category`, `Category for ${website_name}`, `https://img2.pic.in.th/pic/1640x500ebe7d18bc84a1cf6.png`, `${website_name.toLowerCase()}_category`, 0, 1, 0]
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
            [customerId.toString(), categoryId, 'Sample Product', 'This is a sample product for your new site', 10.00, 8.00, 100, '30 days', `https://img5.pic.in.th/file/secure-sv1/1500x1500232d3d161739dfd2.png`, null, 0, 1, 1, 0, null, '#ff0000', '#b3ffc7', 0, 0]
          );
          console.log(`Inserted sample product for customer_id: ${customerId}`);

          // Insert config data
          await connection.execute(
            'INSERT INTO config (customer_id, owner_phone, site_name, site_logo, meta_title, meta_description, meta_keywords, meta_author, discord_link, discord_webhook, banner_link, banner2_link, banner3_link, navigation_banner_1, navigation_link_1, navigation_banner_2, navigation_link_2, navigation_banner_3, navigation_link_3, navigation_banner_4, navigation_link_4, background_image, footer_image, load_logo, footer_logo, theme, ad_banner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [customerId.toString(), '0000000000', website_name, `https://img5.pic.in.th/file/secure-sv1/1500x1500232d3d161739dfd2.png`, `(⭐) ${website_name} - Digital Store`, `Welcome to ${website_name} - Your trusted digital products store`, 'digital, products, store, gaming', `${website_name} Admin`, null, null, 'https://img2.pic.in.th/pic/2000x500172fb60914209eb0.png', 'https://img2.pic.in.th/pic/2000x500172fb60914209eb0.png', 'https://img2.pic.in.th/pic/2000x500172fb60914209eb0.png', 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, 'https://img5.pic.in.th/file/secure-sv1/1000x500.png', null, null, null, null, null, 'Dark mode', 'https://img5.pic.in.th/file/secure-sv1/1500x1500232d3d161739dfd2.png']
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
      const sitePrice = 200.00; // ราคา site (สามารถปรับได้)

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

// ==================== AUTH SITES API ====================

// Get all auth sites
app.get('/api/auth-sites', async (req, res) => {
  try {
    const [sites] = await pool.execute(
      'SELECT id, customer_id, website_name, admin_user, expiredDay, created_at FROM auth_sites'
    );

    res.json({
      success: true,
      message: 'Auth sites retrieved successfully',
      data: sites
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
  console.log(`  POST /api/resell/purchase-site - Purchase new site (requires auth)`);
  console.log(`  POST /api/resell/renew-site - Renew existing site (requires auth)`);
  console.log(`  GET /api/resell/transactions - Get transaction history (requires auth)`);
  console.log(`  GET /api/resell/topup-history - Get topup history (requires auth)`);
  console.log(`  POST /api/resell/topup - Submit topup request (requires auth)`);
  console.log('Auth Sites:');
  console.log(`  GET /api/auth-sites - Get all auth sites`);
  console.log(`  GET /api/auth-sites/:customer_id - Get auth site by customer_id`);
  console.log(`  POST /api/auth-sites - Create new auth site`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  await pool.end();
  process.exit(0);
});