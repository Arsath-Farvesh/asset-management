require('dotenv').config();

// Validate critical environment variables in production
if (process.env.NODE_ENV === 'production') {
  if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET must be set in production environment');
  }
  if (!process.env.DATABASE_URL) {
    console.warn('⚠️  DATABASE_URL not set in production - database operations will fail');
  }
}

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
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

const cors = require("cors");

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"]
    }
  }
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true
}));

app.set('trust proxy', 1);

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Rate limiting middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: "Too many login attempts, please try again later"
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts
  message: "Too many password reset attempts, please try again later"
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use("/api/", apiLimiter);

app.use(session({
  secret: process.env.SESSION_SECRET || "change_this_in_production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60
  }
}));

let dbConnected = false;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on("connect", () => {
  console.log("✅ Connected to PostgreSQL");
  dbConnected = true;
});

pool.on("error", (err) => {
  console.error("DB connection error:", err);
  dbConnected = false;
});

// --- Users table setup ---
async function createUsersTable() {
  if (!dbConnected) return;
  
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
  } catch (err) {
    console.error("Error creating users table:", err.message);
  } finally {
    client.release();
  }
}

// --- Update existing users table schema ---
async function updateUsersTableSchema() {
  if (!dbConnected) return;
  
  const client = await pool.connect();
  try {
    // Add new columns to existing table
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE`);
    
    console.log("✅ Users table schema updated");
  } catch (err) {
    console.error("Error updating users table schema:", err.message);
  } finally {
    client.release();
  }
}

// Initialize tables in sequence
async function initUsers() {
  try {
    await createUsersTable();
    await updateUsersTableSchema();
  } catch (err) {
    console.error("Error initializing users:", err.message);
  }
}

// Initialize users table
initUsers().catch(err => console.error("Failed to initialize users table:", err));

async function createUser(username, password, role = 'user', email = null, phone = null, department = null) {
  if (!dbConnected) return;
  
  const client = await pool.connect();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query(
      "INSERT INTO users (username, password, role, email, phone, department) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
      [username, hashedPassword, role, email, phone, department]
    );
  } catch (err) {
    console.error("Error creating user:", err.message);
  } finally {
    client.release();
  }
}

// Create default users after schema is ready
setTimeout(() => {
  createUser("admin", "admin123456", "admin", "arsathfarvesh02@gmail.com", "1234567890", "IT");
  createUser("user1", "user123456", "user", "developerf07@gmail.com", "0987654321", "Operations");
  createUser("user2", "user456789", "user", "user2@company.com", "1122334455", "Finance");
}, 3000);

// --- Assets tables setup ---
const validTables = [
  "assets","employees","maintenance_logs","documents","depreciation_history",
  "it_hardware","software_license","locations","machinery_equipment","digital_media",
  "vehicles","real_estate","furniture","financial_assets","infrastructure",
  "tools","leased_assets","intellectual_property",
  "equipments_assets",
  "customer_details"
];

async function createTables() {
  if (!dbConnected) return;
  
  const client = await pool.connect();
  try {
    for (const table of validTables) {
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${table} (
          id SERIAL PRIMARY KEY,
          asset_name VARCHAR(255),
          description TEXT,
          qr_code TEXT UNIQUE,
          barcode TEXT UNIQUE,
          category VARCHAR(100),
          location VARCHAR(255),
          status VARCHAR(50) DEFAULT 'active',
          purchase_date DATE,
          purchase_price DECIMAL(15,2),
          current_value DECIMAL(15,2),
          depreciation_rate DECIMAL(5,2),
          depreciation_amount DECIMAL(15,2),
          remaining_value DECIMAL(15,2),
          supplier VARCHAR(255),
          warranty_expiry DATE,
          created_by INT REFERENCES users(id),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
    }
    console.log("✅ All asset tables created");
  } catch (err) {
    console.error("Error creating tables:", err.message);
  } finally {
    client.release();
  }
}

// --- Add extra columns for equipments_assets ---
async function addEquipmentsAssetsColumns() {
  if (!dbConnected) return;
  
  const client = await pool.connect();
  try {
    await client.query(`ALTER TABLE equipments_assets ADD COLUMN IF NOT EXISTS equipment_type VARCHAR(100)`);
    await client.query(`ALTER TABLE equipments_assets ADD COLUMN IF NOT EXISTS model VARCHAR(100)`);
    await client.query(`ALTER TABLE equipments_assets ADD COLUMN IF NOT EXISTS serial_number VARCHAR(100)`);
    console.log("✅ Equipment assets columns added");
  } catch (err) {
    console.error("Error adding equipments columns:", err.message);
  } finally {
    client.release();
  }
}

// --- Create customer_details table ---
async function createCustomerDetailsTable() {
  if (!dbConnected) return;
  
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS customer_details (
        id SERIAL PRIMARY KEY,
        customer_name VARCHAR(255) NOT NULL,
        customer_email VARCHAR(255),
        customer_phone VARCHAR(20),
        company_name VARCHAR(255),
        address TEXT,
        city VARCHAR(100),
        state VARCHAR(100),
        postal_code VARCHAR(20),
        country VARCHAR(100),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("✅ Customer details table created");
  } catch (err) {
    console.error("Error creating customer_details table:", err.message);
  } finally {
    client.release();
  }
}

// --- Initialize database with graceful error handling ---
async function initializeDatabase() {
  try {
    await createTables();
    await addEquipmentsAssetsColumns();
    await createCustomerDetailsTable();
    console.log("✅ Database initialized successfully");
  } catch (err) {
    console.warn("⚠️  Database initialization error: " + err.message);
  }
}

// Initialize database
initializeDatabase().catch(err => console.error("Failed to initialize database:", err));

// --- Middleware ---
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  return res.status(401).json({ success: false, error: "Not authenticated" });
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") {
    return next();
  }
  return res.status(403).json({ success: false, error: "Admin access required" });
}

// --- Login API ---
app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password required" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database connection unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }

    if (!user.is_active) {
      return res.status(403).json({ success: false, error: "User account is inactive" });
    }

    // Update last login
    await client.query("UPDATE users SET last_login = NOW() WHERE id = $1", [user.id]);

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
      department: user.department
    };

    res.json({ 
      success: true, 
      message: "Login successful",
      user: req.session.user
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Server error during login" });
  } finally {
    client.release();
  }
});

// --- Logout API ---
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, error: "Logout failed" });
    }
    res.json({ success: true, message: "Logged out successfully" });
  });
});

// --- USER MANAGEMENT APIs (Admin Only) ---

// Get all users
app.get("/api/users", isAuthenticated, isAdmin, async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("SELECT id, username, role, email, phone, department, is_active, created_at FROM users ORDER BY created_at DESC");
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ success: false, error: "Failed to fetch users" });
  } finally {
    client.release();
  }
});

// Get single user
app.get("/api/users/:id", isAuthenticated, async (req, res) => {
  const { id } = req.params;
  
  // Users can view their own profile, admins can view any
  if (req.session.user.id != id && req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: "Unauthorized" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("SELECT id, username, role, email, phone, department, is_active, created_at, last_login FROM users WHERE id = $1", [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ success: false, error: "Failed to fetch user" });
  } finally {
    client.release();
  }
});

// Create new user (Admin only)
app.post("/api/users", isAuthenticated, isAdmin, async (req, res) => {
  const { username, password, role = 'user', email, phone, department } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password required" });
  }

  if (password.length < 8) {
    return res.status(400).json({ success: false, error: "Password must be at least 8 characters" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
      "INSERT INTO users (username, password, role, email, phone, department) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, role",
      [username, hashedPassword, role, email, phone, department]
    );
    res.json({ success: true, message: "User created", user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') { // Unique violation
      res.status(409).json({ success: false, error: "Username already exists" });
    } else {
      console.error("Error creating user:", err);
      res.status(500).json({ success: false, error: "Failed to create user" });
    }
  } finally {
    client.release();
  }
});

// Update user
app.put("/api/users/:id", isAuthenticated, async (req, res) => {
  const { id } = req.params;
  const { username, role, email, phone, department, is_active } = req.body;
  
  // Users can update their own profile (except role), admins can update any
  if (req.session.user.id != id && req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: "Unauthorized" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const userResult = await client.query("SELECT * FROM users WHERE id = $1", [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const user = userResult.rows[0];
    
    // Only admins can change roles or is_active status
    const finalRole = req.session.user.role === 'admin' ? (role || user.role) : user.role;
    const finalIsActive = req.session.user.role === 'admin' ? (is_active !== undefined ? is_active : user.is_active) : user.is_active;

    const result = await client.query(
      "UPDATE users SET username = COALESCE($2, username), role = $3, email = COALESCE($4, email), phone = COALESCE($5, phone), department = COALESCE($6, department), is_active = $7, updated_at = NOW() WHERE id = $1 RETURNING id, username, role, email, phone, department, is_active",
      [id, username, finalRole, email, phone, department, finalIsActive]
    );

    res.json({ success: true, message: "User updated", user: result.rows[0] });
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ success: false, error: "Failed to update user" });
  } finally {
    client.release();
  }
});

// Change password
app.put("/api/users/:id/password", isAuthenticated, async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ success: false, error: "All password fields required" });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ success: false, error: "New passwords do not match" });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, error: "Password must be at least 8 characters" });
  }

  if (req.session.user.id != id && req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: "Unauthorized" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const userResult = await client.query("SELECT password FROM users WHERE id = $1", [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordValid && req.session.user.role !== 'admin') {
      return res.status(401).json({ success: false, error: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query("UPDATE users SET password = $2, updated_at = NOW() WHERE id = $1", [id, hashedPassword]);

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).json({ success: false, error: "Failed to change password" });
  } finally {
    client.release();
  }
});

// Delete user (Admin only)
app.delete("/api/users/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { id } = req.params;

  // Prevent deleting own account
  if (req.session.user.id == id) {
    return res.status(400).json({ success: false, error: "Cannot delete your own account" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("DELETE FROM users WHERE id = $1 RETURNING id", [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    res.json({ success: true, message: "User deleted" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ success: false, error: "Failed to delete user" });
  } finally {
    client.release();
  }
});

// Get current user profile
app.get("/api/profile", isAuthenticated, async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("SELECT id, username, role, email, phone, department, is_active, created_at, last_login FROM users WHERE id = $1", [req.session.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ success: false, error: "Failed to fetch profile" });
  } finally {
    client.release();
  }
});

// --- Forgot Password/Reset ---
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER || "noreply@example.com",
    pass: process.env.EMAIL_PASS || "placeholder",
  },
});

app.post("/forgot-password", passwordResetLimiter, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: "Username is required" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, message: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("SELECT id, email FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      // Don't reveal if user exists
      return res.json({ success: true, message: "If account exists, reset link has been sent" });
    }

    const user = result.rows[0];
    if (!user.email) {
      return res.json({ success: true, message: "If account exists, reset link has been sent" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");
    
    // Store token hash (in production, use a separate table with expiry)
    const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    // For now, use simple approach - in production use a password_reset_tokens table
    const resetLink = `${process.env.FRONTEND_URL || "http://localhost:3000"}/reset-password.html?token=${resetToken}`;

    await transporter.sendMail({
      to: user.email,
      subject: "Password Reset Request",
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`
    });

    res.json({ success: true, message: "If account exists, reset link has been sent" });
  } catch (err) {
    console.error("Error sending reset email:", err);
    res.status(500).json({ success: false, message: "Failed to send reset email" });
  } finally {
    client.release();
  }
});

app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ success: false, message: "Token and password required" });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: "Password must be at least 8 characters" });
  }

  // In production, verify token against database with expiry check
  // For now, use simple hash verification
  res.status(404).json({ success: false, message: "Reset token system requires database implementation" });
});

// --- History API ---
app.get("/api/history", isAuthenticated, async (req, res) => {
  const { category, limit = 50, offset = 0 } = req.query;

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT * FROM ${category} ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [parseInt(limit), parseInt(offset)]
    );
    const countResult = await client.query(`SELECT COUNT(*) as total FROM ${category}`);
    
    res.json({ 
      success: true, 
      data: result.rows,
      total: countResult.rows[0].total,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({ success: false, error: "Failed to fetch history" });
  } finally {
    client.release();
  }
});

// --- Download History as PDF ---
app.get("/api/history/pdf", isAuthenticated, async (req, res) => {
  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    // Fetch all data from all tables
    const historyQueries = validTables.map(table =>
      client.query(`SELECT *, '${table}' as table_name FROM ${table} ORDER BY created_at DESC LIMIT 1000`)
    );

    const results = await Promise.all(historyQueries);
    const allData = results.flatMap(r => r.rows);

    // Create PDF
    const doc = new PDFDocument();
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=asset-history.pdf");

    doc.pipe(res);
    doc.fontSize(20).text("Asset History Report", 100, 50);
    doc.fontSize(10).text(`Generated: ${new Date().toLocaleString()}`);
    doc.moveDown();

    allData.forEach((item, index) => {
      doc.fontSize(12).text(`Asset ${index + 1} (${item.table_name})`);
      Object.entries(item).forEach(([key, value]) => {
        if (key !== 'table_name') {
          doc.fontSize(9).text(`${key}: ${value || 'N/A'}`);
        }
      });
      doc.moveDown();
    });

    doc.end();
  } catch (err) {
    console.error("Error generating PDF:", err);
    res.status(500).json({ success: false, error: "Failed to generate PDF" });
  } finally {
    client.release();
  }
});

// --- Categories endpoint ---
app.get("/api/categories", (req, res) => {
  res.json({ success: true, categories: validTables });
});

// --- Create asset (DYNAMIC - supports extra fields) ---
app.post("/api/assets/:category", isAuthenticated, async (req, res) => {
  const { category } = req.params;
  const data = req.body;

  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  try {
    // Generate QR Code
    const qrCode = await QRCode.toDataURL(JSON.stringify(data));
    
    // Generate Barcode
    let barcode = "";
    try {
      barcode = await bwipjs.toBuffer({
        bcid: "code128",
        text: data.asset_name || `${category}-${Date.now()}`,
        scale: 3,
        height: 10,
        includetext: true,
        textxalign: "center"
      });
    } catch (err) {
      console.warn("Barcode generation warning:", err.message);
    }

    const keys = Object.keys(data);
    const values = Object.values(data);
    keys.push("qr_code", "barcode", "created_by");
    values.push(qrCode, barcode?.toString() || null, req.session.user.id);

    const placeholders = keys.map((_, i) => `$${i + 1}`).join(",");
    const query = `INSERT INTO ${category} (${keys.join(",")}) VALUES (${placeholders}) RETURNING id, asset_name, category`;

    const client = await pool.connect();
    try {
      const result = await client.query(query, values);
      res.json({ success: true, message: "Asset created", asset: result.rows[0], qrCode });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Error creating asset:", err);
    res.status(500).json({ success: false, error: "Failed to create asset" });
  }
});

// --- List assets in a category ---
app.get("/api/assets/:category", isAuthenticated, async (req, res) => {
  const { category } = req.params;
  const { limit = 50, offset = 0 } = req.query;

  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(
      `SELECT * FROM ${category} ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [parseInt(limit), parseInt(offset)]
    );
    const countResult = await client.query(`SELECT COUNT(*) as total FROM ${category}`);
    
    res.json({ 
      success: true, 
      assets: result.rows,
      total: countResult.rows[0].total
    });
  } catch (err) {
    console.error("Error fetching assets:", err);
    res.status(500).json({ success: false, error: "Failed to fetch assets" });
  } finally {
    client.release();
  }
});

// --- Get single asset by category + id ---
app.get("/api/assets/:category/:id", isAuthenticated, async (req, res) => {
  const { category, id } = req.params;

  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(`SELECT * FROM ${category} WHERE id = $1`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Asset not found" });
    }
    res.json({ success: true, asset: result.rows[0] });
  } catch (err) {
    console.error("Error fetching asset:", err);
    res.status(500).json({ success: false, error: "Failed to fetch asset" });
  } finally {
    client.release();
  }
});

// --- Update asset (admin only, DYNAMIC) ---
app.put("/api/assets/:category/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { category, id } = req.params;
  const data = req.body;

  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  try {
    const keys = Object.keys(data);
    const values = Object.values(data);
    const setClause = keys.map((key, i) => `${key} = $${i + 1}`).join(", ");
    values.push(id);

    const query = `UPDATE ${category} SET ${setClause}, updated_at = NOW() WHERE id = $${keys.length + 1} RETURNING *`;

    const client = await pool.connect();
    try {
      const result = await client.query(query, values);
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, error: "Asset not found" });
      }
      res.json({ success: true, message: "Asset updated", asset: result.rows[0] });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Error updating asset:", err);
    res.status(500).json({ success: false, error: "Failed to update asset" });
  }
});

// --- Delete asset (admin only) ---
app.delete("/api/assets/:category/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { category, id } = req.params;

  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(`DELETE FROM ${category} WHERE id = $1 RETURNING id`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Asset not found" });
    }
    res.json({ success: true, message: "Asset deleted" });
  } catch (err) {
    console.error("Error deleting asset:", err);
    res.status(500).json({ success: false, error: "Failed to delete asset" });
  } finally {
    client.release();
  }
});

// --- Find asset by QR code ---
app.get("/api/qr/:code", isAuthenticated, async (req, res) => {
  const { code } = req.params;

  if (!dbConnected) {
    return res.status(503).json({ success: false, error: "Database unavailable" });
  }

  const client = await pool.connect();
  try {
    for (const table of validTables) {
      const result = await client.query(`SELECT * FROM ${table} WHERE qr_code = $1 OR barcode = $1 LIMIT 1`, [code]);
      if (result.rows.length > 0) {
        return res.json({ success: true, category: table, asset: result.rows[0] });
      }
    }
    res.status(404).json({ success: false, error: "Asset not found" });
  } catch (err) {
    console.error("Error searching QR code:", err);
    res.status(500).json({ success: false, error: "Failed to search asset" });
  } finally {
    client.release();
  }
});

// --- Current user info ---
app.get("/me", (req, res) => {
  if (req.session.user) {
    return res.json(req.session.user);
  }
  res.status(401).json({ error: "Not authenticated" });
});

// --- Health check ---
app.get('/health', (req, res) => {
  res.json({ 
    status: "ok",
    timestamp: new Date().toISOString(),
    database: dbConnected ? "connected" : "disconnected"
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Access at http://localhost:${PORT}`);
  console.log(`🔐 Node Environment: ${process.env.NODE_ENV || 'development'}`);
});
