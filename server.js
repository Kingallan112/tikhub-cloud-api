const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy - Required for rate limiting behind Render.com reverse proxy
app.set('trust proxy', 1);

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'tikhub-session-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(passport.initialize());
app.use(passport.session());

// Rate limiting - prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again after 15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 login attempts per windowMs
  message: {
    error: 'Too many login attempts, please try again after 15 minutes'
  }
});

// Apply general rate limiter to all API routes
app.use('/api/', limiter);

// Apply stricter limiter to authentication routes
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Database connection (Render PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'tikhub-secret-key-2024';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'tikhub-admin-secret-2024';

// Test database connection
pool.connect((err, client, done) => {
  if (err) {
    console.error('❌ Database connection error:', err);
  } else {
    console.log('✅ Connected to PostgreSQL database');
    done();
  }
});

// ==================== PASSPORT OAUTH CONFIGURATION ====================

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, result.rows[0]);
  } catch (error) {
    done(error, null);
  }
});

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL || 'http://localhost:3000'}/api/auth/google/callback`,
      scope: ['profile', 'email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('🔐 Google OAuth callback:', profile.emails[0].value);
        
        const email = profile.emails[0].value;
        const username = profile.displayName || email.split('@')[0];
        const providerId = profile.id;
        const avatarUrl = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
        
        // Check if user exists
        let user = await pool.query(
          'SELECT * FROM users WHERE provider = $1 AND provider_id = $2',
          ['google', providerId]
        );
        
        if (user.rows.length === 0) {
          // Check if email exists with different provider
          const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
          
          if (emailCheck.rows.length > 0) {
            // Email exists - link accounts
            user = await pool.query(
              `UPDATE users SET provider = $1, provider_id = $2, avatar_url = $3, last_login = NOW() 
               WHERE email = $4 RETURNING *`,
              ['google', providerId, avatarUrl, email]
            );
          } else {
            // Create new user
            const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            user = await pool.query(
              `INSERT INTO users (id, username, email, provider, provider_id, avatar_url, last_login, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, NOW(), true) RETURNING *`,
              [userId, username, email, 'google', providerId, avatarUrl]
            );
            
            // Create free subscription
            await pool.query(
              `INSERT INTO subscriptions (user_id, tier, status, start_date, end_date)
               VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '1 year')`,
              [userId]
            );
          }
        } else {
          // Update last login and avatar
          user = await pool.query(
            `UPDATE users SET last_login = NOW(), avatar_url = $1 WHERE id = $2 RETURNING *`,
            [avatarUrl, user.rows[0].id]
          );
        }
        
        console.log('✅ Google OAuth success:', user.rows[0].email);
        return done(null, user.rows[0]);
      } catch (error) {
        console.error('❌ Google OAuth error:', error);
        return done(error, null);
      }
    }
  ));
  console.log('✅ Google OAuth strategy configured');
} else {
  console.log('⚠️  Google OAuth not configured (missing credentials)');
}

// Discord OAuth Strategy
if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET) {
  passport.use(new DiscordStrategy({
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: `${process.env.API_URL || 'http://localhost:3000'}/api/auth/discord/callback`,
      scope: ['identify', 'email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('🔐 Discord OAuth callback:', profile.email);
        
        const email = profile.email;
        const username = profile.username || email.split('@')[0];
        const providerId = profile.id;
        const avatarUrl = profile.avatar 
          ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
          : null;
        
        // Check if user exists
        let user = await pool.query(
          'SELECT * FROM users WHERE provider = $1 AND provider_id = $2',
          ['discord', providerId]
        );
        
        if (user.rows.length === 0) {
          // Check if email exists with different provider
          const emailCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
          
          if (emailCheck.rows.length > 0) {
            // Email exists - link accounts
            user = await pool.query(
              `UPDATE users SET provider = $1, provider_id = $2, avatar_url = $3, last_login = NOW() 
               WHERE email = $4 RETURNING *`,
              ['discord', providerId, avatarUrl, email]
            );
          } else {
            // Create new user
            const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            user = await pool.query(
              `INSERT INTO users (id, username, email, provider, provider_id, avatar_url, last_login, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, NOW(), true) RETURNING *`,
              [userId, username, email, 'discord', providerId, avatarUrl]
            );
            
            // Create free subscription
            await pool.query(
              `INSERT INTO subscriptions (user_id, tier, status, start_date, end_date)
               VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '1 year')`,
              [userId]
            );
          }
        } else {
          // Update last login and avatar
          user = await pool.query(
            `UPDATE users SET last_login = NOW(), avatar_url = $1 WHERE id = $2 RETURNING *`,
            [avatarUrl, user.rows[0].id]
          );
        }
        
        console.log('✅ Discord OAuth success:', user.rows[0].email);
        return done(null, user.rows[0]);
      } catch (error) {
        console.error('❌ Discord OAuth error:', error);
        return done(error, null);
      }
    }
  ));
  console.log('✅ Discord OAuth strategy configured');
} else {
  console.log('⚠️  Discord OAuth not configured (missing credentials)');
}

// ==================== MIDDLEWARE ====================

// Authentication middleware for users
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Authentication middleware for admin
const authenticateAdmin = (req, res, next) => {
  const adminKey = req.headers['x-admin-key'];
  
  if (!adminKey || adminKey !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Admin authentication required' });
  }
  
  next();
};

// ==================== PUBLIC ENDPOINTS ====================

// Root endpoint - Welcome page
app.get('/', (req, res) => {
  res.json({
    name: 'TikHub Cloud API',
    version: '1.0.0',
    status: 'online',
    description: 'Cloud-based User Management & Authentication System for TikHub',
    endpoints: {
      public: {
        'GET /': 'This page',
        'GET /api/health': 'Health check',
        'GET /ping': 'Ping test',
        'POST /api/auth/register': 'Register new user',
        'POST /api/auth/login': 'Login user'
      },
      authenticated: {
        'GET /api/auth/verify': 'Verify JWT token',
        'GET /api/subscription/status': 'Get subscription status',
        'GET /api/users/me': 'Get user profile'
      },
      admin: {
        'GET /api/admin/users': 'Get all users',
        'POST /api/admin/update-subscription': 'Update user subscription',
        'GET /api/admin/stats': 'Get statistics',
        'POST /api/admin/init-db': 'Initialize database'
      }
    },
    documentation: 'https://github.com/Kingallan112/tikhub-cloud-api',
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'TikHub Cloud API',
    version: '1.0.0'
  });
});

// Ping endpoint
app.get('/ping', (req, res) => {
  res.json({ success: true, message: 'TikHub Cloud API is running!' });
});

// ==================== USER AUTH ENDPOINTS ====================

// Verify JWT token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ 
    valid: true, 
    user: req.user 
  });
});

// Get subscription status
app.get('/api/subscription/status', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.json({
        subscription: {
          tier: 'free',
          status: 'active',
          startDate: new Date().toISOString(),
          endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
          autoRenew: false
        }
      });
    }

    let subscription = result.rows[0];

    // Check if subscription has expired and auto-downgrade
    if (subscription.tier !== 'free' && subscription.end_date) {
      const endDate = new Date(subscription.end_date);
      const now = new Date();
      
      if (now > endDate && subscription.status === 'active') {
        console.log(`⏰ Subscription expired for user ${req.user.userId}, downgrading to free tier`);
        
        // Update to free tier in database
        await pool.query(
          `UPDATE subscriptions 
           SET tier = 'free', status = 'expired', last_updated = NOW()
           WHERE user_id = $1`,
          [req.user.userId]
        );
        
        // Return updated subscription
        subscription = {
          ...subscription,
          tier: 'free',
          status: 'expired'
        };
      }
    }

    // Convert snake_case to camelCase for frontend compatibility
    const formattedSubscription = {
      tier: subscription.tier,
      status: subscription.status,
      startDate: subscription.start_date ? new Date(subscription.start_date).toISOString() : new Date().toISOString(),
      endDate: subscription.end_date ? new Date(subscription.end_date).toISOString() : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      autoRenew: subscription.auto_renew || false
    };

    res.json({ subscription: formattedSubscription });
  } catch (error) {
    console.error('Error fetching subscription:', error);
    res.status(500).json({ error: 'Failed to fetch subscription' });
  }
});

// User registration (alias for /api/users/register)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, deviceInfo } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Username, email, and password are required' });
    }

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate user ID
    const userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (id, username, email, password_hash, device_info, created_at, last_activity)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
       RETURNING id, username, email, created_at`,
      [userId, username, email, hashedPassword, JSON.stringify(deviceInfo || {})]
    );

    const user = result.rows[0];

    // Create default free subscription
    const subResult = await pool.query(
      `INSERT INTO subscriptions (user_id, tier, status, start_date, end_date)
       VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '1 year')
       RETURNING *`,
      [user.id]
    );

    const subscription = subResult.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log('✅ New user registered:', user.username);

    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.created_at,
        subscription: subscription
      }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ success: false, error: 'Failed to register user' });
  }
});

// User login (alias for /api/users/login)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, deviceInfo } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, username, email, password_hash FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Check password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    // Update last login
    await pool.query(
      `UPDATE users 
       SET last_login = NOW(), last_activity = NOW(), device_info = $2
       WHERE id = $1`,
      [user.id, JSON.stringify(deviceInfo || {})]
    );

    // Get subscription
    const subResult = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1',
      [user.id]
    );

    let subscription = subResult.rows[0] || {
      tier: 'free',
      status: 'active'
    };

    // Check if subscription has expired and auto-downgrade
    if (subscription.tier !== 'free' && subscription.end_date) {
      const endDate = new Date(subscription.end_date);
      const now = new Date();
      
      if (now > endDate && subscription.status === 'active') {
        console.log(`⏰ Subscription expired for user ${user.username}, downgrading to free tier`);
        
        // Update to free tier in database
        await pool.query(
          `UPDATE subscriptions 
           SET tier = 'free', status = 'expired', last_updated = NOW()
           WHERE user_id = $1`,
          [user.id]
        );
        
        // Return updated subscription
        subscription = {
          ...subscription,
          tier: 'free',
          status: 'expired'
        };
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log('✅ User logged in:', user.username);

    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        subscription: subscription
      }
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ success: false, error: 'Failed to login' });
  }
});

// ==================== OAUTH ENDPOINTS ====================

// Google OAuth - Initiate
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google OAuth - Callback
app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/api/auth/oauth-error' }),
  async (req, res) => {
    try {
      // Get subscription info
      const subResult = await pool.query(
        'SELECT * FROM subscriptions WHERE user_id = $1',
        [req.user.id]
      );

      let subscription = subResult.rows[0] || {
        tier: 'free',
        status: 'active'
      };

      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: req.user.id,
          email: req.user.email,
          username: req.user.username
        },
        JWT_SECRET,
        { expiresIn: '30d' }
      );

      // Redirect to app with token
      const redirectUrl = `tikhub://oauth-success?token=${token}&username=${encodeURIComponent(req.user.username)}&email=${encodeURIComponent(req.user.email)}&tier=${subscription.tier}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('❌ Google OAuth callback error:', error);
      res.redirect('tikhub://oauth-error?error=callback_failed');
    }
  }
);

// Discord OAuth - Initiate
app.get('/api/auth/discord',
  passport.authenticate('discord', { scope: ['identify', 'email'] })
);

// Discord OAuth - Callback
app.get('/api/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/api/auth/oauth-error' }),
  async (req, res) => {
    try {
      // Get subscription info
      const subResult = await pool.query(
        'SELECT * FROM subscriptions WHERE user_id = $1',
        [req.user.id]
      );

      let subscription = subResult.rows[0] || {
        tier: 'free',
        status: 'active'
      };

      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: req.user.id,
          email: req.user.email,
          username: req.user.username
        },
        JWT_SECRET,
        { expiresIn: '30d' }
      );

      // Redirect to app with token
      const redirectUrl = `tikhub://oauth-success?token=${token}&username=${encodeURIComponent(req.user.username)}&email=${encodeURIComponent(req.user.email)}&tier=${subscription.tier}`;
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('❌ Discord OAuth callback error:', error);
      res.redirect('tikhub://oauth-error?error=callback_failed');
    }
  }
);

// OAuth Error Handler
app.get('/api/auth/oauth-error', (req, res) => {
  res.redirect('tikhub://oauth-error?error=authentication_failed');
});

// User registration
app.post('/api/users/register', async (req, res) => {
  try {
    const { username, email, password, deviceInfo } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate user ID
    const userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (id, username, email, password_hash, device_info, created_at, last_activity)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
       RETURNING id, username, email, created_at`,
      [userId, username, email, hashedPassword, JSON.stringify(deviceInfo || {})]
    );

    const user = result.rows[0];

    // Create default free subscription
    await pool.query(
      `INSERT INTO subscriptions (user_id, tier, status, start_date, end_date)
       VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '1 year')`,
      [user.id]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log('✅ New user registered:', user.username);

    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// User login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password, deviceInfo } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, username, email, password_hash FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Check password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last login
    await pool.query(
      `UPDATE users 
       SET last_login = NOW(), last_activity = NOW(), device_info = $2
       WHERE id = $1`,
      [user.id, JSON.stringify(deviceInfo || {})]
    );

    // Get subscription
    const subResult = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1',
      [user.id]
    );

    let subscription = subResult.rows[0] || {
      tier: 'free',
      status: 'active'
    };

    // Check if subscription has expired and auto-downgrade
    if (subscription.tier !== 'free' && subscription.end_date) {
      const endDate = new Date(subscription.end_date);
      const now = new Date();
      
      if (now > endDate && subscription.status === 'active') {
        console.log(`⏰ Subscription expired for user ${user.username}, downgrading to free tier`);
        
        // Update to free tier in database
        await pool.query(
          `UPDATE subscriptions 
           SET tier = 'free', status = 'expired', last_updated = NOW()
           WHERE user_id = $1`,
          [user.id]
        );
        
        // Return updated subscription
        subscription = {
          ...subscription,
          tier: 'free',
          status: 'expired'
        };
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log('✅ User logged in:', user.username);

    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        subscription: subscription
      }
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// ==================== USER DATA ENDPOINTS ====================

// Get user profile (requires authentication)
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.email, u.created_at, u.last_login,
              s.tier, s.status, s.start_date, s.end_date
       FROM users u
       LEFT JOIN subscriptions s ON u.id = s.user_id
       WHERE u.id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Check for subscription updates (for auto-sync)
app.get('/api/users/check-updates', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get pending updates
    const updates = await pool.query(
      `SELECT subscription_data, updated_by, updated_at
       FROM subscription_updates
       WHERE user_id = $1 AND status = 'pending'
       ORDER BY updated_at DESC`,
      [userId]
    );

    // Mark as delivered
    if (updates.rows.length > 0) {
      await pool.query(
        `UPDATE subscription_updates 
         SET status = 'delivered', delivered_at = NOW()
         WHERE user_id = $1 AND status = 'pending'`,
        [userId]
      );
    }

    res.json({
      hasUpdates: updates.rows.length > 0,
      updates: updates.rows
    });
  } catch (error) {
    console.error('Error checking updates:', error);
    res.status(500).json({ error: 'Failed to check updates' });
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Get all users (admin only) with search and filter
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    // Get search and filter parameters
    const { search, tier, status, sortBy, sortOrder } = req.query;
    
    // Build dynamic query
    let query = `
      SELECT u.id, u.username, u.email, u.created_at, u.last_login, u.last_activity,
             u.device_info, u.is_active,
             s.tier, s.status, s.start_date, s.end_date, s.auto_renew, s.admin_notes
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.user_id
      WHERE 1=1
    `;
    
    const params = [];
    let paramCount = 0;
    
    // Add search filter (username or email)
    if (search && search.trim()) {
      paramCount++;
      query += ` AND (LOWER(u.username) LIKE LOWER($${paramCount}) OR LOWER(u.email) LIKE LOWER($${paramCount}))`;
      params.push(`%${search.trim()}%`);
    }
    
    // Add tier filter
    if (tier && tier !== 'all') {
      paramCount++;
      query += ` AND s.tier = $${paramCount}`;
      params.push(tier);
    }
    
    // Add status filter
    if (status && status !== 'all') {
      paramCount++;
      query += ` AND s.status = $${paramCount}`;
      params.push(status);
    }
    
    // Add sorting
    const validSortFields = ['username', 'email', 'created_at', 'last_login', 'tier'];
    const sortField = validSortFields.includes(sortBy) ? sortBy : 'created_at';
    const order = sortOrder === 'asc' ? 'ASC' : 'DESC';
    query += ` ORDER BY ${sortField === 'username' || sortField === 'email' ? 'u.' : sortField === 'tier' ? 's.' : 'u.'}${sortField} ${order}`;
    
    const result = await pool.query(query, params);

    console.log(`📊 Admin fetched ${result.rows.length} users (filtered: ${search || tier || status ? 'yes' : 'no'})`);

    // Check each user's subscription for expiration and auto-downgrade
    const now = new Date();
    const users = result.rows;
    const expiredUsers = [];
    
    for (const user of users) {
      if (user.tier && user.tier !== 'free' && user.end_date) {
        const endDate = new Date(user.end_date);
        
        if (now > endDate && user.status === 'active') {
          console.log(`⏰ [Admin] Subscription expired for user ${user.username}, downgrading to free tier`);
          
          // Update to free tier in database
          await pool.query(
            `UPDATE subscriptions 
             SET tier = 'free', status = 'expired', last_updated = NOW()
             WHERE user_id = $1`,
            [user.id]
          );
          
          // Update the user object to reflect the change
          user.tier = 'free';
          user.status = 'expired';
          expiredUsers.push(user.username);
        }
      }
    }
    
    if (expiredUsers.length > 0) {
      console.log(`⏰ [Admin] Auto-downgraded ${expiredUsers.length} expired subscriptions:`, expiredUsers.join(', '));
    }

    res.json({
      success: true,
      users: users,
      total: users.length,
      expiredCount: expiredUsers.length
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update user subscription (admin only)
app.post('/api/admin/update-subscription', authenticateAdmin, async (req, res) => {
  try {
    const { userId, subscription } = req.body;
    let { tier, status, endDate, autoRenew, adminNotes } = subscription;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // If downgrading to free tier, set end date to far future (1 year from now)
    if (tier === 'free') {
      const oneYearFromNow = new Date();
      oneYearFromNow.setFullYear(oneYearFromNow.getFullYear() + 1);
      endDate = oneYearFromNow.toISOString();
      status = 'active'; // Free tier is always active
      console.log(`📊 [Admin] Setting free tier with 1 year duration (no actual expiration)`);
    }

    // Update subscription
    await pool.query(
      `UPDATE subscriptions
       SET tier = $1, status = $2, end_date = $3, auto_renew = $4, 
           admin_notes = $5, last_updated = NOW(), updated_by = 'admin'
       WHERE user_id = $6`,
      [tier, status, endDate, autoRenew || false, adminNotes || '', userId]
    );

    // Create update record for sync
    await pool.query(
      `INSERT INTO subscription_updates (user_id, subscription_data, updated_by, status)
       VALUES ($1, $2, 'admin', 'pending')`,
      [userId, JSON.stringify(subscription)]
    );

    console.log(`✅ Admin updated subscription for user: ${userId}`);

    res.json({
      success: true,
      message: 'Subscription updated successfully'
    });
  } catch (error) {
    console.error('Error updating subscription:', error);
    res.status(500).json({ error: 'Failed to update subscription' });
  }
});

// Get admin stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
    const activeUsers = await pool.query('SELECT COUNT(*) FROM users WHERE is_active = true');
    const freeUsers = await pool.query('SELECT COUNT(*) FROM subscriptions WHERE tier = $1', ['free']);
    const proUsers = await pool.query('SELECT COUNT(*) FROM subscriptions WHERE tier = $1', ['pro']);
    const legendUsers = await pool.query('SELECT COUNT(*) FROM subscriptions WHERE tier = $1', ['legend']);

    res.json({
      success: true,
      stats: {
        totalUsers: parseInt(totalUsers.rows[0].count),
        activeUsers: parseInt(activeUsers.rows[0].count),
        freeUsers: parseInt(freeUsers.rows[0].count),
        proUsers: parseInt(proUsers.rows[0].count),
        legendUsers: parseInt(legendUsers.rows[0].count)
      }
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Backup database (export all data as JSON)
app.get('/api/admin/backup', authenticateAdmin, async (req, res) => {
  try {
    console.log('💾 Creating database backup...');
    
    // Export all tables
    const users = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    const subscriptions = await pool.query('SELECT * FROM subscriptions ORDER BY user_id');
    const updates = await pool.query('SELECT * FROM subscription_updates ORDER BY updated_at DESC');
    
    const backup = {
      metadata: {
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        totalUsers: users.rows.length,
        totalSubscriptions: subscriptions.rows.length,
        totalUpdates: updates.rows.length
      },
      data: {
        users: users.rows,
        subscriptions: subscriptions.rows,
        subscription_updates: updates.rows
      }
    };
    
    console.log(`💾 Backup created: ${users.rows.length} users, ${subscriptions.rows.length} subscriptions`);
    
    // Set headers for file download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="tikhub-backup-${Date.now()}.json"`);
    res.json(backup);
  } catch (error) {
    console.error('Error creating backup:', error);
    res.status(500).json({ error: 'Failed to create backup' });
  }
});

// Restore database from backup (WARNING: This will overwrite existing data!)
app.post('/api/admin/restore', authenticateAdmin, async (req, res) => {
  try {
    const { backup, mode } = req.body; // mode: 'replace' or 'merge'
    
    if (!backup || !backup.data) {
      return res.status(400).json({ error: 'Invalid backup data' });
    }
    
    console.log(`💾 Restoring database backup (mode: ${mode})...`);
    
    let usersRestored = 0;
    let subscriptionsRestored = 0;
    
    // Begin transaction
    await pool.query('BEGIN');
    
    try {
      if (mode === 'replace') {
        // Clear existing data (dangerous!)
        await pool.query('DELETE FROM subscription_updates');
        await pool.query('DELETE FROM subscriptions');
        await pool.query('DELETE FROM users');
        console.log('⚠️  Cleared existing data');
      }
      
      // Restore users
      for (const user of backup.data.users) {
        await pool.query(
          `INSERT INTO users (id, username, email, password_hash, created_at, last_login, last_activity, is_active, device_info)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (id) DO ${mode === 'merge' ? 'NOTHING' : 'UPDATE SET username = EXCLUDED.username'}`,
          [user.id, user.username, user.email, user.password_hash, user.created_at, user.last_login, user.last_activity, user.is_active, user.device_info]
        );
        usersRestored++;
      }
      
      // Restore subscriptions
      for (const sub of backup.data.subscriptions) {
        await pool.query(
          `INSERT INTO subscriptions (user_id, tier, status, start_date, end_date, auto_renew, payment_method, next_billing_date, admin_notes, last_updated, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (user_id) DO ${mode === 'merge' ? 'NOTHING' : 'UPDATE SET tier = EXCLUDED.tier, status = EXCLUDED.status'}`,
          [sub.user_id, sub.tier, sub.status, sub.start_date, sub.end_date, sub.auto_renew, sub.payment_method, sub.next_billing_date, sub.admin_notes, sub.last_updated, sub.updated_by]
        );
        subscriptionsRestored++;
      }
      
      await pool.query('COMMIT');
      
      console.log(`✅ Backup restored: ${usersRestored} users, ${subscriptionsRestored} subscriptions`);
      
      res.json({
        success: true,
        message: 'Backup restored successfully',
        usersRestored,
        subscriptionsRestored
      });
    } catch (error) {
      await pool.query('ROLLBACK');
      throw error;
    }
  } catch (error) {
    console.error('Error restoring backup:', error);
    res.status(500).json({ error: 'Failed to restore backup' });
  }
});

// ==================== DATABASE INITIALIZATION ====================

// Initialize database tables (run once)
app.post('/api/admin/init-db', authenticateAdmin, async (req, res) => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        provider VARCHAR(50) DEFAULT 'local',
        provider_id VARCHAR(255),
        avatar_url TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP,
        last_activity TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        device_info JSONB
      )
    `);
    
    // Add columns to existing users table if they don't exist (migration)
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS provider VARCHAR(50) DEFAULT 'local',
      ADD COLUMN IF NOT EXISTS provider_id VARCHAR(255),
      ADD COLUMN IF NOT EXISTS avatar_url TEXT
    `);

    // Create subscriptions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        user_id VARCHAR(255) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        tier VARCHAR(50) DEFAULT 'free',
        status VARCHAR(50) DEFAULT 'active',
        start_date TIMESTAMP,
        end_date TIMESTAMP,
        auto_renew BOOLEAN DEFAULT false,
        payment_method VARCHAR(100),
        next_billing_date TIMESTAMP,
        admin_notes TEXT,
        last_updated TIMESTAMP DEFAULT NOW(),
        updated_by VARCHAR(255)
      )
    `);

    // Create subscription_updates table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscription_updates (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
        subscription_data JSONB NOT NULL,
        updated_by VARCHAR(255) NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW(),
        status VARCHAR(50) DEFAULT 'pending',
        delivered_at TIMESTAMP
      )
    `);

    // Create password_reset_tokens table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP,
        created_by VARCHAR(255) DEFAULT 'admin'
      )
    `);

    // Create indexes
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_subscription_updates_user ON subscription_updates(user_id, status)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_reset_tokens_token ON password_reset_tokens(token)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON password_reset_tokens(user_id)');

    console.log('✅ Database tables created successfully');

    res.json({
      success: true,
      message: 'Database initialized successfully'
    });
  } catch (error) {
    console.error('Error initializing database:', error);
    res.status(500).json({ error: 'Failed to initialize database' });
  }
});

// ==================== PASSWORD RESET ENDPOINTS ====================

// Generate password reset token (Admin only)
app.post('/api/admin/generate-reset-token', authenticateAdmin, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    console.log('🔑 Generating password reset token for:', email);

    // Check if user exists
    const userResult = await pool.query('SELECT id, username, email FROM users WHERE email = $1', [email]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found with this email' });
    }

    const user = userResult.rows[0];

    // Generate secure token (valid for 1 hour)
    const tokenPayload = {
      userId: user.id,
      email: user.email,
      type: 'password_reset'
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

    // Calculate expiry time (1 hour from now)
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    // Save token to database
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at, created_by) VALUES ($1, $2, $3, $4)',
      [user.id, token, expiresAt, 'admin']
    );

    console.log('✅ Password reset token generated successfully');

    // Generate deep link
    const resetLink = `tikhub://reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;

    res.json({
      success: true,
      token: token,
      resetLink: resetLink,
      expiresAt: expiresAt.toISOString(),
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('❌ Error generating reset token:', error);
    res.status(500).json({ error: 'Failed to generate reset token' });
  }
});

// Reset password (Public endpoint, token-protected)
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    console.log('🔒 Processing password reset request...');

    // Verify JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      console.log('❌ Invalid or expired token');
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    if (decoded.type !== 'password_reset') {
      return res.status(400).json({ error: 'Invalid token type' });
    }

    // Check if token exists in database and hasn't been used
    const tokenResult = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1 AND used_at IS NULL',
      [token]
    );

    if (tokenResult.rows.length === 0) {
      console.log('❌ Token not found or already used');
      return res.status(400).json({ error: 'This reset link has already been used or is invalid' });
    }

    const tokenData = tokenResult.rows[0];

    // Check if token has expired (double-check even though JWT validates this)
    if (new Date() > new Date(tokenData.expires_at)) {
      console.log('❌ Token expired');
      return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' });
    }

    // Validate password strength
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [hashedPassword, decoded.userId]
    );

    // Mark token as used
    await pool.query(
      'UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1',
      [tokenData.id]
    );

    console.log('✅ Password reset successfully for user:', decoded.email);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('❌ Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
  console.log(`🚀 TikHub Cloud API running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
  console.log(`🔑 Admin Secret: ${ADMIN_SECRET.substring(0, 10)}...`);
});

// Error handling
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Promise Rejection:', err);
});

