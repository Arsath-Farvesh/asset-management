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

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true
}));

app.set('trust proxy', 1);

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: process.env.SESSION_SECRET || "change_this",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 1000 * 60 * 60
  }
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway')
    ? { rejectUnauthorized: false }
    : false,
});

pool.on("connect", () => console.log("✅ Connected to PostgreSQL"));
pool.on("error", (err) => console.error("❌ DB error:", err));

// --- Users table setup ---
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
    console.log("Users table ready");
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

// --- FIX: Update existing users table schema ---
async function updateUsersTableSchema() {
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
    
    // Create trigger for updated_at
    await client.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
      BEFORE UPDATE ON users
      FOR EACH ROW
      EXECUTE PROCEDURE update_updated_at_column();
    `);
    
    console.log("✅ Users table schema updated");
  } catch (err) {
    console.error("Error updating users table schema:", err);
  } finally {
    client.release();
  }
}

// Initialize tables in sequence
async function initUsers() {
  await createUsersTable();
  await updateUsersTableSchema();
}

async function createUser(username, password, role = 'user', email = null, phone = null, department = null) {
  const client = await pool.connect();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query(
      `INSERT INTO users (username, password, role, email, phone, department) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       ON CONFLICT (username) DO NOTHING`,
      [username, hashedPassword, role, email, phone, department]
    );
    console.log(`User ${username} created`);
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

// --- Create default users ---
async function createDefaultUsers() {
  await createUser("admin", "admin123", "admin", "arsathfarvesh02@gmail.com", "1234567890", "IT");
  await createUser("user1", "user123", "user", "developerf07@gmail.com", "0987654321", "Operations");
  await createUser("user2", "user456", "user", "user2@company.com", "1122334455", "Finance");
}

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
  const client = await pool.connect();
  try {
    // create function once
    await client.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    for (const table of validTables) {
      if (table === 'customer_details') continue;
      
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

      await client.query(`
        DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table};
        CREATE TRIGGER update_${table}_updated_at
        BEFORE UPDATE ON ${table}
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
      `);

      await client.query(`
        ALTER TABLE ${table}
        ADD COLUMN IF NOT EXISTS location TEXT;
      `);

      await client.query(`
        ALTER TABLE ${table}
        ADD COLUMN IF NOT EXISTS qr_text TEXT;
      `);

      console.log(`Table ${table} ready`);
    }
  } catch (err) {
    console.error(err);
  } finally {
    client.release();
  }
}

// --- Add extra columns for equipments_assets ---
async function addEquipmentsAssetsColumns() {
  const client = await pool.connect();
  try {
    await client.query(`
      ALTER TABLE equipments_assets 
      ADD COLUMN IF NOT EXISTS date DATE,
      ADD COLUMN IF NOT EXISTS keys INTEGER;
    `);
    console.log("✅ equipments_assets columns (date, keys) ready");
  } catch (err) {
    console.error("Error adding columns:", err);
  } finally {
    client.release();
  }
}

// --- Create customer_details table ---
async function createCustomerDetailsTable() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS customer_details (
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
    
    await client.query(`
      DROP TRIGGER IF EXISTS update_customer_details_updated_at ON customer_details;
      CREATE TRIGGER update_customer_details_updated_at
      BEFORE UPDATE ON customer_details
      FOR EACH ROW
      EXECUTE PROCEDURE update_updated_at_column();
    `);

    console.log("✅ customer_details table ready");
  } catch (err) {
    console.error("Error creating customer_details table:", err);
  } finally {
    client.release();
  }
}

// --- Initialize tables ---
async function initializeDatabase() {
  await createTables();
  await addEquipmentsAssetsColumns();
  await createCustomerDetailsTable();
}

// --- Middleware ---
function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.status(401).json({ success: false, error: "Unauthorized" });
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") return next();
  return res.status(403).json({ success: false, error: "Admin only" });
}

// --- Login API ---
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, error: "Username and password required" });

  const client = await pool.connect();
  try {
    // FIX: Handle both old and new schema (is_active might be NULL)
    const result = await client.query(
      "SELECT * FROM users WHERE username=$1 AND (is_active=TRUE OR is_active IS NULL)", 
      [username]
    );
    
    if (result.rows.length === 0) return res.json({ success: false, error: "Invalid username or password" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, error: "Invalid username or password" });

    // Update last login
    await client.query("UPDATE users SET last_login=NOW() WHERE id=$1", [user.id]);

    req.session.user = { 
      id: user.id,
      username: user.username, 
      role: user.role,
      email: user.email,
      department: user.department
    };
    
    res.json({ 
      success: true, 
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        email: user.email,
        phone: user.phone,
        department: user.department
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Logout API ---
app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// --- USER MANAGEMENT APIs (Admin Only) ---

// Get all users
app.get("/api/users", isAuthenticated, isAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT id, username, role, email, phone, department, created_at, updated_at, last_login, is_active 
      FROM users 
      ORDER BY created_at DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Get single user
app.get("/api/users/:id", isAuthenticated, async (req, res) => {
  const { id } = req.params;
  
  // Users can view their own profile, admins can view any
  if (req.session.user.id != id && req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT id, username, role, email, phone, department, created_at, updated_at, last_login, is_active 
      FROM users 
      WHERE id=$1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
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

  const client = await pool.connect();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(`
      INSERT INTO users (username, password, role, email, phone, department) 
      VALUES ($1, $2, $3, $4, $5, $6) 
      RETURNING id, username, role, email, phone, department, created_at, is_active
    `, [username, hashedPassword, role, email, phone, department]);
    
    res.json({ success: true, data: result.rows[0], message: "User created successfully" });
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ success: false, error: "Username already exists" });
    } else {
      console.error(err);
      res.status(500).json({ success: false, error: err.message });
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
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  const client = await pool.connect();
  try {
    let updates = [];
    let values = [];
    let paramIndex = 1;

    if (username) {
      updates.push(`username=$${paramIndex++}`);
      values.push(username);
    }
    if (email !== undefined) {
      updates.push(`email=$${paramIndex++}`);
      values.push(email);
    }
    if (phone !== undefined) {
      updates.push(`phone=$${paramIndex++}`);
      values.push(phone);
    }
    if (department !== undefined) {
      updates.push(`department=$${paramIndex++}`);
      values.push(department);
    }
    
    // Only admin can change role and is_active
    if (req.session.user.role === 'admin') {
      if (role) {
        updates.push(`role=$${paramIndex++}`);
        values.push(role);
      }
      if (is_active !== undefined) {
        updates.push(`is_active=$${paramIndex++}`);
        values.push(is_active);
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: "No fields to update" });
    }

    values.push(id);
    const query = `UPDATE users SET ${updates.join(', ')}, updated_at=NOW() WHERE id=$${paramIndex} RETURNING id, username, role, email, phone, department, is_active, updated_at`;
    
    const result = await client.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    res.json({ success: true, data: result.rows[0], message: "User updated successfully" });
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ success: false, error: "Username already exists" });
    } else {
      console.error(err);
      res.status(500).json({ success: false, error: err.message });
    }
  } finally {
    client.release();
  }
});

// Change password
app.put("/api/users/:id/password", isAuthenticated, async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;
  
  // Users can only change their own password
  if (req.session.user.id != id) {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ success: false, error: "Password must be at least 6 characters" });
  }

  const client = await pool.connect();
  try {
    // Verify current password
    const userResult = await client.query("SELECT password FROM users WHERE id=$1", [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    const match = await bcrypt.compare(currentPassword, userResult.rows[0].password);
    if (!match) {
      return res.status(400).json({ success: false, error: "Current password is incorrect" });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query("UPDATE users SET password=$1, updated_at=NOW() WHERE id=$2", [hashedPassword, id]);
    
    res.json({ success: true, message: "Password changed successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Delete user (Admin only)
app.delete("/api/users/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { id } = req.params;
  
  // Prevent deleting yourself
  if (req.session.user.id == id) {
    return res.status(400).json({ success: false, error: "Cannot delete your own account" });
  }

  const client = await pool.connect();
  try {
    const result = await client.query("DELETE FROM users WHERE id=$1 RETURNING id, username", [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    res.json({ success: true, data: result.rows[0], message: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Get current user profile
app.get("/api/profile", isAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT id, username, role, email, phone, department, created_at, last_login 
      FROM users 
      WHERE id=$1
    `, [req.session.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Forgot Password/Reset ---
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.post("/forgot-password", async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ success: false, message: "Username is required" });

  const client = await pool.connect();
  try {
    const userRes = await client.query("SELECT * FROM users WHERE username=$1", [username]);
    if (userRes.rows.length === 0)
      return res.status(404).json({ success: false, message: "User not found" });

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + (parseInt(process.env.RESET_TOKEN_EXPIRY) || 3600);

    await client.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        username TEXT,
        token TEXT,
        expires_at INTEGER
      )
    `);

    await client.query("DELETE FROM password_resets WHERE username=$1", [username]);
    await client.query("INSERT INTO password_resets (username, token, expires_at) VALUES ($1,$2,$3)", [username, token, expiresAt]);

    const resetLink = `${process.env.NODE_ENV === 'production' ? 'https' : 'http'}://${req.headers.host}/reset-password.html?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: "Password Reset Request",
      html: `<p>You requested a password reset for your Asset Management account.</p>
             <p>Click the link below to reset your password (valid for 1 hour):</p>
             <a href="${resetLink}">${resetLink}</a>`
    });

    res.json({ success: true, message: "Reset link sent to your email." });
  } catch (err) {
    console.error("Forgot Password Error:", err);
    res.status(500).json({ success: false, message: "Error sending reset link." });
  } finally {
    client.release();
  }
});

app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ success: false, message: "Token and new password required" });

  const client = await pool.connect();
  try {
    const tokenRes = await client.query("SELECT * FROM password_resets WHERE token=$1", [token]);
    if (tokenRes.rows.length === 0)
      return res.status(400).json({ success: false, message: "Invalid or expired token" });

    const resetEntry = tokenRes.rows[0];
    if (Math.floor(Date.now() / 1000) > resetEntry.expires_at)
      return res.status(400).json({ success: false, message: "Token expired" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query("UPDATE users SET password=$1 WHERE username=$2", [hashedPassword, resetEntry.username]);
    await client.query("DELETE FROM password_resets WHERE username=$1", [resetEntry.username]);

    res.json({ success: true, message: "Password successfully reset" });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ success: false, message: "Error resetting password" });
  } finally {
    client.release();
  } 
});

// --- History API ---
app.get("/api/history", isAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    let history = [];
    // Skip customer_details - it has different schema
    const assetTables = validTables.filter(t => t !== 'customer_details');
    
    for (const table of assetTables) {
      try {
        const result = await client.query(
          `SELECT id, name, serial_number, employee_name, submitted_by, location, created_at FROM ${table}`
        );
        result.rows.forEach(row => row.category = table);
        history = history.concat(result.rows);
      } catch (tableErr) {
        console.error(`Error fetching from ${table}:`, tableErr.message);
      }
    }
    history.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ success: true, data: history });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Download History as PDF ---
app.get("/api/history/pdf", isAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    let history = [];
    // Skip customer_details - it has different schema
    const assetTables = validTables.filter(t => t !== 'customer_details');
    
    for (const table of assetTables) {
      try {
        const result = await client.query(
          `SELECT id, name, serial_number, employee_name, submitted_by, location, created_at FROM ${table}`
        );
        result.rows.forEach(row => row.category = table);
        history = history.concat(result.rows);
      } catch (tableErr) {
        console.error(`Error fetching from ${table} for PDF:`, tableErr.message);
      }
    }
    history.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    const doc = new PDFDocument({ margin: 30, size: "A4", layout: "landscape" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=history.pdf");
    doc.pipe(res);

    doc.fontSize(18).font("Helvetica-Bold").text("Asset History Report", { align: "center" });
    doc.moveDown(1);

    const tableTop = doc.y;
    const rowHeight = 20;
    const colWidths = {
      id: 40, category: 100, name: 120, serial_number: 100,
      employee_name: 120, submitted_by: 100, location: 120, created_at: 120
    };
    const startX = doc.page.margins.left;

    doc.fontSize(10).font("Helvetica-Bold");
    let x = startX;
    ["ID","Category","Name","Serial Number","Employee Name","Submitted By","Location","Created At"].forEach((header, i) => {
      doc.text(header, x, tableTop, { width: Object.values(colWidths)[i], align: "left" });
      x += Object.values(colWidths)[i];
    });

    doc.font("Helvetica");
    let y = tableTop + rowHeight;

    history.forEach((row) => {
      x = startX;
      [
        row.id, row.category, row.name || "-", row.serial_number || "-",
        row.employee_name || "-", row.submitted_by || "-",
        row.location || "-", new Date(row.created_at).toLocaleString()
      ].forEach((text, i) => {
        doc.text(text.toString(), x, y, { width: Object.values(colWidths)[i], align: "left" });
        x += Object.values(colWidths)[i];
      });
      y += rowHeight;

      if (y + rowHeight > doc.page.height - doc.page.margins.bottom) {
        doc.addPage({ layout: "landscape" });
        y = doc.page.margins.top;
      }
    });

    doc.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Categories endpoint ---
app.get("/api/categories", (req, res) => {
  res.json({ success: true, data: validTables });
});

// --- Create asset (DYNAMIC - supports extra fields) ---
app.post("/api/assets/:category", isAuthenticated, async (req, res) => {
  const category = req.params.category;
  if (!validTables.includes(category)) return res.status(400).json({ success:false, error: "Invalid category" });

  const { name, serial_number, employee_name, location, ...extraFields } = req.body;
  
  if (category === 'customer_details') {
    if (!extraFields.customer_name) return res.status(400).json({ success:false, error: "Customer name required" });
  } else {
    if (!name) return res.status(400).json({ success:false, error: "Name required" });
  }

  const client = await pool.connect();
  try {
    let qrText, barcodeText;
    if (category === 'customer_details') {
      qrText = `${extraFields.customer_name}-${extraFields.case_number || ''}-${extraFields.case_type || ''}`;
      barcodeText = extraFields.case_number || extraFields.customer_name;
    } else {
      qrText = `${name}-${category}-${serial_number || ""}-${employee_name || ""}`;
      barcodeText = serial_number || name;
    }
    
    const qrImage = await QRCode.toDataURL(qrText);
    const barcodePng = await bwipjs.toBuffer({
      bcid: "code128", text: barcodeText, scale: 3, height: 10,
      includetext: true, textxalign: "center"
    });
    const barcodeImage = `data:image/png;base64,${barcodePng.toString("base64")}`;

    const submittedBy = req.session.user.username;

    let columns, values, placeholders;
    
    if (category === 'customer_details') {
      columns = ['customer_name', 'customer_phone', 'case_date', 'case_number', 'case_type', 'qr_code', 'qr_text', 'barcode', 'submitted_by'];
      values = [
        extraFields.customer_name,
        extraFields.customer_phone || null,
        extraFields.case_date || null,
        extraFields.case_number || null,
        extraFields.case_type || null,
        qrImage, qrText, barcodeImage, submittedBy
      ];
      placeholders = ['$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8', '$9'];
    } else {
      columns = ['name', 'serial_number', 'employee_name', 'qr_code', 'qr_text', 'barcode', 'submitted_by', 'location'];
      values = [name, serial_number || null, employee_name || null, qrImage, qrText, barcodeImage, submittedBy, location || null];
      placeholders = ['$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8'];

      Object.keys(extraFields).forEach((key) => {
        columns.push(key);
        values.push(extraFields[key] || null);
        placeholders.push(`$${values.length}`);
      });
    }

    const query = `INSERT INTO ${category} (${columns.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING *`;
    
    const result = await client.query(query, values);
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- List assets in a category ---
app.get("/api/assets/:category", isAuthenticated, async (req, res) => {
  const category = req.params.category;
  if (!validTables.includes(category)) return res.status(400).json({ success:false, error: "Invalid category" });

  const client = await pool.connect();
  try {
    const result = await client.query(`SELECT * FROM ${category} ORDER BY created_at DESC`);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Get single asset by category + id ---
app.get("/api/assets/:category/:id", isAuthenticated, async (req, res) => {
  const { category, id } = req.params;
  if (!validTables.includes(category)) return res.status(400).json({ success:false, error: "Invalid category" });

  const client = await pool.connect();
  try {
    const result = await client.query(`SELECT * FROM ${category} WHERE id=$1`, [id]);
    if (result.rows.length === 0) return res.status(404).json({ success:false, error: "Not found" });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Update asset (admin only, DYNAMIC) ---
app.put("/api/assets/:category/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { category, id } = req.params;
  if (!validTables.includes(category)) return res.status(400).json({ success:false, error: "Invalid category" });

  const { name, serial_number, employee_name, location, ...extraFields } = req.body;
  const client = await pool.connect();
  try {
    let updates, values;
    
    if (category === 'customer_details') {
      updates = ['customer_name=$1', 'customer_phone=$2', 'case_date=$3', 'case_number=$4', 'case_type=$5', 'updated_at=NOW()'];
      values = [
        extraFields.customer_name,
        extraFields.customer_phone || null,
        extraFields.case_date || null,
        extraFields.case_number || null,
        extraFields.case_type || null
      ];
    } else {
      updates = ['name=$1', 'serial_number=$2', 'employee_name=$3', 'location=$4', 'updated_at=NOW()'];
      values = [name, serial_number || null, employee_name || null, location || null];
      let paramIndex = 5;

      Object.keys(extraFields).forEach(key => {
        updates.push(`${key}=$${paramIndex}`);
        values.push(extraFields[key] || null);
        paramIndex++;
      });
    }

    values.push(id);

    const query = `UPDATE ${category} SET ${updates.join(', ')} WHERE id=$${values.length} RETURNING *`;
    
    const result = await client.query(query, values);
    if (result.rows.length === 0) return res.status(404).json({ success:false, error: "Not found" });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Delete asset (admin only) ---
app.delete("/api/assets/:category/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { category, id } = req.params;
  if (!validTables.includes(category)) return res.status(400).json({ success:false, error: "Invalid category" });

  const client = await pool.connect();
  try {
    const result = await client.query(`DELETE FROM ${category} WHERE id=$1 RETURNING *`, [id]);
    if (result.rows.length === 0) return res.status(404).json({ success:false, error: "Not found" });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Find asset by QR code ---
app.get("/api/qr/:code", isAuthenticated, async (req, res) => {
  const code = req.params.code;
  const client = await pool.connect();
  try {
    for (const table of validTables) {
      const result = await client.query(
        `SELECT * FROM ${table} WHERE qr_text = $1 OR qr_code = $1`,
        [code]
      );
      if (result.rows.length > 0) {
        return res.json({ success: true, category: table, data: result.rows[0] });
      }
    }
    res.status(404).json({ success:false, error: "QR not found" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success:false, error: err.message });
  } finally {
    client.release();
  }
});

// --- Current user info ---
app.get("/me", (req, res) => {
  if (req.session.user) res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role });
  else res.json({ loggedIn: false });
});

// --- Health ---
app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as now');
    res.json({ status: 'ok', time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// --- Start server after DB initialization ---
async function startServer() {
  try {
    console.log('🔄 Initializing database...');
    await initUsers();
    await initializeDatabase();
    await createDefaultUsers();
    console.log('✅ Database and users initialized');

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('❌ Startup error:', err);
    process.exit(1);
  }
}

startServer();
