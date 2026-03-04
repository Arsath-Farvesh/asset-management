require('dotenv').config();

const express = require("express");
const { Pool } = require("pg");
const bodyParser = require("body-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");
const QRCode = require("qrcode");
const bwipjs = require("bwip-js");
const path = require("path");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const MicrosoftStrategy = require("passport-microsoft").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;

const app = express();
const PORT = process.env.PORT || 3000;

// ===== CORS CONFIGURATION =====
app.use(cors({
  origin: "*",
  credentials: true
}));

app.set('trust proxy', 1);

// ===== REQUEST LOGGING (for debugging) =====
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// ===== BODY PARSERS =====
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// ===== STATIC FILES - CORRECT (HTML files are in public/) =====
app.use(express.static(path.join(__dirname, "public")));

// ===== SESSION CONFIGURATION =====
app.use(session({
  secret: process.env.SESSION_SECRET || "change_this_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 2,
    domain: process.env.NODE_ENV === 'production' ? undefined : 'localhost'
  }
}));

// ===== PASSPORT INITIALIZATION =====
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// ===== GOOGLE OAUTH STRATEGY =====
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET',
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = {
      id: profile.id,
      username: profile.displayName || profile.emails[0].value.split('@')[0],
      email: profile.emails[0].value,
      provider: 'google',
      avatar: profile.photos[0]?.value,
      role: 'user'
    };
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// ===== MICROSOFT OAUTH STRATEGY =====
passport.use(new MicrosoftStrategy({
  clientID: process.env.MICROSOFT_CLIENT_ID || 'YOUR_MICROSOFT_CLIENT_ID',
  clientSecret: process.env.MICROSOFT_CLIENT_SECRET || 'YOUR_MICROSOFT_CLIENT_SECRET',
  callbackURL: process.env.MICROSOFT_CALLBACK_URL || 'http://localhost:3000/auth/microsoft/callback',
  tenant: process.env.MICROSOFT_TENANT || 'common'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = {
      id: profile.id,
      username: profile.displayName || profile.upn.split('@')[0],
      email: profile.upn,
      provider: 'microsoft',
      avatar: null,
      role: 'user'
    };
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// ===== GITHUB OAUTH STRATEGY =====
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID || 'YOUR_GITHUB_CLIENT_ID',
  clientSecret: process.env.GITHUB_CLIENT_SECRET || 'YOUR_GITHUB_CLIENT_SECRET',
  callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = {
      id: profile.id,
      username: profile.login || profile.displayName,
      email: profile.emails?.[0]?.value || 'no-email@github.com',
      provider: 'github',
      avatar: profile.photos[0]?.value,
      role: 'user'
    };
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// ===== DATABASE CONNECTION - SUPPORTS BOTH URL AND ENV VARS =====
const dbUrl = process.env.DATABASE_URL;
let poolConfig = {
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000,
  max: 20
};

// Determine SSL configuration  
// Railway connections need SSL
let sslConfig = false;
if (process.env.NODE_ENV === 'production' || process.env.PGHOST?.includes('railway') || process.env.PGHOST?.includes('proxy') || dbUrl?.includes('railway')) {
  sslConfig = { rejectUnauthorized: false };
}

// Use DATABASE_URL if available, otherwise pg will use PG* env vars
if (dbUrl) {
  poolConfig.connectionString = dbUrl;
  poolConfig.ssl = sslConfig;
  console.log('🔗 Using DATABASE_URL for connection');
} else {
  // Using individual PG* variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE)
  poolConfig.ssl = sslConfig;
  console.log('🔗 Using PG* environment variables for connection');
  console.log(`   Host: ${process.env.PGHOST}:${process.env.PGPORT}`);
  console.log(`   SSL: ${sslConfig ? 'enabled' : 'disabled'}`);
}

const pool = new Pool(poolConfig);

pool.on("connect", () => console.log("✅ PostgreSQL connected"));
pool.on("error", (err) => console.error("❌ PostgreSQL error:", err.message));

// ===== ROOT ROUTE - REDIRECT TO LOGIN =====
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// ===== SIMPLE HEALTH CHECK - FOR RAILWAY (No DB dependency) =====
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ===== DETAILED HEALTH CHECK - WITH DATABASE =====
app.get('/health/detailed', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as now');
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      time: result.rows[0].now,
      uptime: process.uptime()
    });
  } catch (err) {
    res.status(503).json({ 
      status: 'unhealthy', 
      database: 'disconnected',
      error: err.message,
      uptime: process.uptime()
    });
  }
});

// ===== VALID TABLES =====
const validTables = [
  "assets","employees","maintenance_logs","documents","depreciation_history",
  "it_hardware","software_license","locations","machinery_equipment","digital_media",
  "vehicles","real_estate","furniture","financial_assets","infrastructure",
  "tools","leased_assets","intellectual_property",
  "keys","case_details"
];

function normalizeCategory(category) {
  if (category === 'equipments_assets') return 'keys';
  return category;
}

async function generateCodes(category, payload) {
  let qrText;
  let barcodeText;

  if (category === 'case_details') {
    const customerName = (payload.customer_name || '').toString().trim();
    const caseNumber = (payload.case_number || '').toString().trim();
    qrText = `${customerName}-${caseNumber}`;
    barcodeText = caseNumber || customerName || 'CASE';
  } else {
    const name = (payload.name || '').toString().trim();
    const serialNumber = (payload.serial_number || '').toString().trim();
    qrText = `${name}-${category}-${serialNumber}`;
    barcodeText = serialNumber || name || 'ASSET';
  }

  const safeQrText = (qrText || 'Takhlees').toString().slice(0, 512);
  const safeBarcodeText = (barcodeText || 'Takhlees').toString().slice(0, 120);

  const qrImage = await QRCode.toDataURL(safeQrText);
  const barcodePng = await bwipjs.toBuffer({
    bcid: "code128",
    text: safeBarcodeText,
    scale: 3,
    height: 10,
    includetext: true,
    textxalign: "center"
  });

  return {
    qrText: safeQrText,
    barcodeText: safeBarcodeText,
    qrImage,
    barcodeImage: `data:image/png;base64,${barcodePng.toString("base64")}`
  };
}

// ===== DATABASE INITIALIZATION WITH RETRY =====
async function waitForDatabase(maxRetries = 10, delay = 3000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log('✅ Database connection verified');
      return true;
    } catch (err) {
      console.log(`⏳ Waiting for database... (attempt ${i + 1}/${maxRetries})`);
      if (i === maxRetries - 1) throw err;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

async function initDatabase() {
  console.log('🔄 Initializing database...');
  
  try {
    // Wait for database to be ready with retry
    await waitForDatabase();

    // Create updated_at function
    await pool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Initialize tables
    await createUsersTable();
    await updateUsersTableSchema();
    await createTables();
    await addKeysColumns();
    await createCaseDetailsTable();
    
    // Create default users (ignore if exist)
    await createDefaultUsers().catch(err => {
      console.log('⚠️ Default users may exist:', err.message);
    });

    console.log('✅ Database initialization complete');
  } catch (err) {
    console.error('❌ Database initialization failed:', err.message);
    console.error('Full error:', err);
    // Don't throw - let server start anyway for debugging
  }
}

async function createUsersTable() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        email TEXT,
        phone TEXT,
        department TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);
    console.log("✅ Users table ready");
  } finally {
    client.release();
  }
}

async function updateUsersTableSchema() {
  const client = await pool.connect();
  try {
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expire TIMESTAMP`);
    
    try {
      await client.query(`
        DROP TRIGGER IF EXISTS update_users_updated_at ON users;
        CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
      `);
    } catch (e) { /* Trigger may exist */ }
    
    console.log("✅ Users schema updated");
  } finally {
    client.release();
  }
}

async function createDefaultUsers() {
  const users = [
    { username: "admin", password: "TakhleeAdmin@2024!", role: "admin", email: "arsathfarvesh02@gmail.com" },
    { username: "admin2", password: "TakhleeAdmin@2024!", role: "admin", email: "Shahulofficial16@gmail.com" },
    { username: "user1", password: "TakhleeUser@2024!", role: "user", email: "developerf07@gmail.com" }
  ];
  
  for (const user of users) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    await pool.query(
      `INSERT INTO users (username, password, role, email) 
       VALUES ($1, $2, $3, $4) 
       ON CONFLICT (username) DO NOTHING`,
      [user.username, hashedPassword, user.role, user.email]
    );
  }
  console.log("✅ Default users created");
}

async function createTables() {
  const client = await pool.connect();
  try {
    for (const table of validTables) {
      if (table === 'case_details') continue;
      
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${table} (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          serial_number TEXT,
          employee_name TEXT,
          qr_code TEXT,
          qr_text TEXT,
          barcode TEXT,
          submitted_by TEXT,
          location TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      
      await client.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS location TEXT`);
      await client.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS qr_text TEXT`);
      
      try {
        await client.query(`
          DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table};
          CREATE TRIGGER update_${table}_updated_at
          BEFORE UPDATE ON ${table}
          FOR EACH ROW
          EXECUTE PROCEDURE update_updated_at_column();
        `);
      } catch (e) { /* Trigger exists */ }
      
      console.log(`✅ Table ${table} ready`);
    }
  } finally {
    client.release();
  }
}

async function addKeysColumns() {
  await pool.query(`
    ALTER TABLE keys 
    ADD COLUMN IF NOT EXISTS date DATE,
    ADD COLUMN IF NOT EXISTS keys INTEGER;
  `);
  console.log("✅ keys columns ready");
}

async function createCaseDetailsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS case_details (
      id SERIAL PRIMARY KEY,
      customer_name TEXT NOT NULL,
      customer_phone TEXT,
      case_date DATE,
      case_number TEXT,
      case_type TEXT,
      qr_code TEXT,
      qr_text TEXT,
      barcode TEXT,
      submitted_by TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  try {
    await pool.query(`
      DROP TRIGGER IF EXISTS update_case_details_updated_at ON case_details;
      CREATE TRIGGER update_case_details_updated_at
      BEFORE UPDATE ON case_details
      FOR EACH ROW
      EXECUTE PROCEDURE update_updated_at_column();
    `);
  } catch (e) { /* Trigger exists */ }
  
  console.log("✅ case_details table ready");
}

// ===== PASSWORD STRENGTH VALIDATION =====
function validatePasswordStrength(password) {
  if (!password || password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character (!@#$%^&* etc)' };
  }
  return { valid: true, message: 'Strong password' };
}

// ===== MIDDLEWARE =====
function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.status(401).json({ success: false, error: "Unauthorized" });
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") return next();
  return res.status(403).json({ success: false, error: "Admin only" });
}

// ===== AUTH ROUTES =====
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Credentials required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1 AND (is_active=TRUE OR is_active IS NULL)", 
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.json({ success: false, error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      return res.json({ success: false, error: "Invalid credentials" });
    }

    await pool.query("UPDATE users SET last_login=NOW() WHERE id=$1", [user.id]);

    // Check if password strength compliance is needed
    const passwordCheck = validatePasswordStrength(password);
    const needsPasswordChange = !passwordCheck.valid;

    req.session.user = { 
      id: user.id,
      username: user.username, 
      role: user.role,
      email: user.email,
      department: user.department,
      needsPasswordChange: needsPasswordChange
    };
    
    res.json({ success: true, user: req.session.user, needsPasswordChange });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/api/auth-status", (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.status(401).json({ authenticated: false });
  }
});

// ===== OAUTH ROUTES =====
// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login.html' }), (req, res) => {
  req.session.user = {
    id: req.user.id,
    username: req.user.username,
    email: req.user.email,
    role: req.user.role,
    provider: 'google',
    avatar: req.user.avatar
  };
  res.redirect('/index.html');
});

// Microsoft OAuth
app.get('/auth/microsoft', passport.authenticate('microsoft', { scope: ['user.read'] }));

app.get('/auth/microsoft/callback', passport.authenticate('microsoft', { failureRedirect: '/login.html' }), (req, res) => {
  req.session.user = {
    id: req.user.id,
    username: req.user.username,
    email: req.user.email,
    role: req.user.role,
    provider: 'microsoft',
    avatar: req.user.avatar
  };
  res.redirect('/index.html');
});

// GitHub OAuth
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login.html' }), (req, res) => {
  req.session.user = {
    id: req.user.id,
    username: req.user.username,
    email: req.user.email,
    role: req.user.role,
    provider: 'github',
    avatar: req.user.avatar
  };
  res.redirect('/index.html');
});

app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.json({ authenticated: false });
  }
});

app.get("/me", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// ===== USER MANAGEMENT =====
app.get("/api/users", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, role, email, phone, department, created_at, updated_at, last_login, is_active 
      FROM users ORDER BY created_at DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== ASSET ROUTES =====
app.post("/api/assets/:category", isAuthenticated, async (req, res) => {
  const category = normalizeCategory(req.params.category);
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  const { name, serial_number, employee_name, location, ...extraFields } = req.body;
  
  if (category === 'case_details' && !extraFields.customer_name) {
    return res.status(400).json({ success: false, error: "Customer name required" });
  }
  if (category !== 'case_details' && !name) {
    return res.status(400).json({ success: false, error: "Name required" });
  }

  try {
    const codes = await generateCodes(
      category,
      category === 'case_details'
        ? { customer_name: extraFields.customer_name, case_number: extraFields.case_number }
        : { name, serial_number }
    );

    const submittedBy = req.session.user.username;

    let columns, values, placeholders;
    
    if (category === 'case_details') {
      columns = ['customer_name', 'customer_phone', 'case_date', 'case_number', 'case_type', 'qr_code', 'qr_text', 'barcode', 'submitted_by'];
      values = [
        extraFields.customer_name, extraFields.customer_phone || null,
        extraFields.case_date || null, extraFields.case_number || null,
        extraFields.case_type || null, codes.qrImage, codes.qrText, codes.barcodeImage, submittedBy
      ];
      placeholders = ['$1','$2','$3','$4','$5','$6','$7','$8','$9'];
    } else {
      columns = ['name', 'serial_number', 'employee_name', 'qr_code', 'qr_text', 'barcode', 'submitted_by', 'location'];
      values = [name, serial_number || null, employee_name || null, codes.qrImage, codes.qrText, codes.barcodeImage, submittedBy, location || null];
      placeholders = ['$1','$2','$3','$4','$5','$6','$7','$8'];

      Object.keys(extraFields).forEach((key) => {
        columns.push(key);
        values.push(extraFields[key] || null);
        placeholders.push(`$${values.length}`);
      });
    }

    const query = `INSERT INTO ${category} (${columns.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING *`;
    const result = await pool.query(query, values);
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Create asset error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/assets/:category", isAuthenticated, async (req, res) => {
  const category = normalizeCategory(req.params.category);
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  try {
    const result = await pool.query(`SELECT * FROM ${category} ORDER BY created_at DESC`);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/assets/:category/:id", isAuthenticated, async (req, res) => {
  const category = normalizeCategory(req.params.category);
  const { id } = req.params;
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  try {
    const result = await pool.query(`SELECT * FROM ${category} WHERE id=$1`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put("/api/assets/:category/:id", isAuthenticated, isAdmin, async (req, res) => {
  const category = normalizeCategory(req.params.category);
  const { id } = req.params;
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  const { name, serial_number, employee_name, location, ...extraFields } = req.body;
  
  try {
    let updates, values;
    const codes = await generateCodes(
      category,
      category === 'case_details'
        ? { customer_name: extraFields.customer_name, case_number: extraFields.case_number }
        : { name, serial_number }
    );
    
    if (category === 'case_details') {
      updates = ['customer_name=$1', 'customer_phone=$2', 'case_date=$3', 'case_number=$4', 'case_type=$5', 'qr_code=$6', 'qr_text=$7', 'barcode=$8', 'updated_at=NOW()'];
      values = [
        extraFields.customer_name,
        extraFields.customer_phone || null,
        extraFields.case_date || null,
        extraFields.case_number || null,
        extraFields.case_type || null,
        codes.qrImage,
        codes.qrText,
        codes.barcodeImage
      ];
    } else {
      updates = ['name=$1', 'serial_number=$2', 'employee_name=$3', 'location=$4', 'qr_code=$5', 'qr_text=$6', 'barcode=$7', 'updated_at=NOW()'];
      values = [name, serial_number || null, employee_name || null, location || null, codes.qrImage, codes.qrText, codes.barcodeImage];
      let paramIndex = 8;
      Object.keys(extraFields).forEach(key => {
        updates.push(`${key}=$${paramIndex++}`);
        values.push(extraFields[key] || null);
      });
    }

    values.push(id);
    const query = `UPDATE ${category} SET ${updates.join(', ')} WHERE id=$${values.length} RETURNING *`;
    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete("/api/assets/:category/:id", isAuthenticated, async (req, res) => {
  const category = normalizeCategory(req.params.category);
  const { id } = req.params;
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  try {
    const result = await pool.query(`DELETE FROM ${category} WHERE id=$1 RETURNING *`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== QR LOOKUP =====
app.get("/api/qr/:code", isAuthenticated, async (req, res) => {
  const code = req.params.code;
  
  try {
    for (const table of validTables) {
      const result = await pool.query(
        `SELECT * FROM ${table} WHERE qr_text = $1 OR qr_code = $1`,
        [code]
      );
      if (result.rows.length > 0) {
        return res.json({ success: true, category: table, data: result.rows[0] });
      }
    }
    res.status(404).json({ success: false, error: "QR not found" });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== HISTORY =====
app.get("/api/history", isAuthenticated, async (req, res) => {
  try {
    let history = [];
    const assetTables = validTables;
    
    for (const table of assetTables) {
      try {
        let query;
        if (table === 'case_details') {
          query = `
            SELECT id,
                   customer_name AS name,
                   case_number AS serial_number,
                   customer_phone AS employee_name,
                   submitted_by,
                   NULL::text AS location,
                   created_at
            FROM case_details
          `;
        } else {
          query = `SELECT id, name, serial_number, employee_name, submitted_by, location, created_at FROM ${table}`;
        }
        const result = await pool.query(query);
        result.rows.forEach(row => row.category = table);
        history = history.concat(result.rows);
      } catch (e) { /* Skip failed tables */ }
    }
    history.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ success: true, data: history });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== PDF EXPORT =====
app.get("/api/history/pdf", isAuthenticated, async (req, res) => {
  try {
    let history = [];
    const assetTables = validTables;
    
    for (const table of assetTables) {
      try {
        let query;
        if (table === 'case_details') {
          query = `
            SELECT id,
                   customer_name AS name,
                   case_number AS serial_number,
                   customer_phone AS employee_name,
                   submitted_by,
                   NULL::text AS location,
                   created_at
            FROM case_details
          `;
        } else {
          query = `SELECT id, name, serial_number, employee_name, submitted_by, location, created_at FROM ${table}`;
        }
        const result = await pool.query(query);
        result.rows.forEach(row => row.category = table);
        history = history.concat(result.rows);
      } catch (e) { /* Skip failed tables */ }
    }
    history.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const doc = new PDFDocument({ margin: 30, size: "A4", layout: "landscape" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=history.pdf");
    doc.pipe(res);

    doc.fontSize(18).font("Helvetica-Bold").text("Asset History Report", { align: "center" });
    doc.moveDown(1);

    // Table headers
    const headers = ["ID","Category","Name","Serial","Employee","Submitted By","Location","Created At"];
    const colWidths = [40, 100, 120, 100, 120, 100, 120, 120];
    const startX = doc.page.margins.left;
    let x = startX;
    let y = doc.y;

    doc.fontSize(10).font("Helvetica-Bold");
    headers.forEach((header, i) => {
      doc.text(header, x, y, { width: colWidths[i], align: "left" });
      x += colWidths[i];
    });

    doc.font("Helvetica");
    y += 20;

    history.forEach((row) => {
      x = startX;
      const values = [
        row.id, row.category, row.name || "-", row.serial_number || "-",
        row.employee_name || "-", row.submitted_by || "-",
        row.location || "-", new Date(row.created_at).toLocaleString()
      ];
      values.forEach((text, i) => {
        doc.text(String(text), x, y, { width: colWidths[i], align: "left" });
        x += colWidths[i];
      });
      y += 20;
    });

    doc.end();
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== CHANGE PASSWORD (Authenticated) =====
app.post("/api/change-password", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, error: "Current and new password required" });
  }

  const strengthCheck = validatePasswordStrength(newPassword);
  if (!strengthCheck.valid) {
    return res.status(400).json({ success: false, error: strengthCheck.message });
  }

  try {
    const result = await pool.query("SELECT password FROM users WHERE id=$1", [req.session.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) {
      return res.status(400).json({ success: false, error: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hashedPassword, req.session.user.id]);

    res.json({ success: true, message: "Password changed successfully" });
  } catch (err) {
    console.error("Change password error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ===== PASSWORD RESET REQUEST (Send reset link) =====
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, error: "Email required" });
  }

  try {
    const result = await pool.query("SELECT id, username FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0) {
      // Don't reveal if email exists for security
      return res.json({ success: true, message: "If email exists, reset link sent" });
    }

    const user = result.rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = await bcrypt.hash(resetToken, 10);
    const resetTokenExpire = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(
      "UPDATE users SET reset_token=$1, reset_token_expire=$2 WHERE id=$3",
      [resetTokenHash, resetTokenExpire, user.id]
    );

    // In production, send email. For now, log the token
    console.log(`✅ Password reset token for ${user.username}: ${resetToken}`);
    console.log(`   Reset link: /reset-password.html?token=${resetToken}`);

    res.json({ success: true, message: "If email exists, reset link sent" });
  } catch (err) {
    console.error("Forgot password error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ===== RESET PASSWORD (With token validation) =====
app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ success: false, error: "Token and password required" });
  }

  const strengthCheck = validatePasswordStrength(newPassword);
  if (!strengthCheck.valid) {
    return res.status(400).json({ success: false, error: strengthCheck.message });
  }

  try {
    // First, find users with valid reset tokens
    const result = await pool.query(
      "SELECT id, reset_token FROM users WHERE reset_token IS NOT NULL AND reset_token_expire > NOW()"
    );

    let userFound = false;
    let userId = null;

    for (const row of result.rows) {
      const match = await bcrypt.compare(token, row.reset_token);
      if (match) {
        userFound = true;
        userId = row.id;
        break;
      }
    }

    if (!userFound) {
      return res.status(400).json({ success: false, error: "Invalid or expired reset token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE users SET password=$1, reset_token=NULL, reset_token_expire=NULL WHERE id=$2",
      [hashedPassword, userId]
    );

    res.json({ success: true, message: "Password reset successfully. Please login." });
  } catch (err) {
    console.error("Reset password error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ===== VALIDATE RESET TOKEN =====
app.post("/api/validate-reset-token", async (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ success: false, error: "Token required" });
  }

  try {
    const result = await pool.query(
      "SELECT id FROM users WHERE reset_token IS NOT NULL AND reset_token_expire > NOW()"
    );

    for (const row of result.rows) {
      const match = await bcrypt.compare(token, row.reset_token);
      if (match) {
        return res.json({ success: true, message: "Valid token" });
      }
    }

    res.status(400).json({ success: false, error: "Invalid or expired token" });
  } catch (err) {
    console.error("Validate token error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ===== PASSWORD RESET (Placeholder) =====
app.post("/forgot-password", async (req, res) => {
  res.json({ success: false, message: "Password reset not configured" });
});

app.post("/reset-password", async (req, res) => {
  res.json({ success: false, message: "Password reset not configured" });
});

// ===== CATEGORIES =====
app.get("/api/categories", (req, res) => {
  res.json({ success: true, data: validTables });
});

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ===== START SERVER =====
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Serving static files from: ${path.join(__dirname, 'public')}`);
  console.log(`🌐 Server bound to 0.0.0.0:${PORT}`);
  
  // Initialize database after server starts
  initDatabase().catch(err => {
    console.error('Database init error:', err.message);
  });
});
