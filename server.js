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

// ===== CORS CONFIGURATION =====
app.use(cors({
  origin: "*",
  credentials: true
}));

app.set('trust proxy', 1);

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
    sameSite: "none",
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// ===== DATABASE CONNECTION - FIXED =====
const dbUrl = process.env.DATABASE_URL;
let sslConfig = false;

if (dbUrl) {
  // Enable SSL for Railway, AWS, or any production environment
  if (dbUrl.includes('railway.app') || dbUrl.includes('amazonaws.com') || process.env.NODE_ENV === 'production') {
    sslConfig = { rejectUnauthorized: false };
  }
}

const pool = new Pool({
  connectionString: dbUrl,
  ssl: sslConfig,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

pool.on("connect", () => console.log("✅ PostgreSQL connected"));
pool.on("error", (err) => console.error("❌ PostgreSQL error:", err.message));

// ===== ROOT ROUTE - REDIRECT TO LOGIN =====
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// ===== HEALTH CHECK - FOR RAILWAY =====
app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as now');
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      time: result.rows[0].now 
    });
  } catch (err) {
    res.status(503).json({ 
      status: 'unhealthy', 
      database: 'disconnected',
      error: err.message 
    });
  }
});

// ===== VALID TABLES =====
const validTables = [
  "assets","employees","maintenance_logs","documents","depreciation_history",
  "it_hardware","software_license","locations","machinery_equipment","digital_media",
  "vehicles","real_estate","furniture","financial_assets","infrastructure",
  "tools","leased_assets","intellectual_property",
  "equipments_assets","customer_details"
];

// ===== DATABASE INITIALIZATION =====
async function initDatabase() {
  console.log('🔄 Initializing database...');
  
  try {
    // Test connection
    await pool.query('SELECT 1');
    console.log('✅ Database connection verified');

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
    await addEquipmentsAssetsColumns();
    await createCustomerDetailsTable();
    
    // Create default users (ignore if exist)
    await createDefaultUsers().catch(err => {
      console.log('⚠️ Default users may exist:', err.message);
    });

    console.log('✅ Database initialization complete');
  } catch (err) {
    console.error('❌ Database initialization failed:', err.message);
    // Don't throw - let server start anyway
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
    { username: "admin", password: "admin123", role: "admin", email: "arsathfarvesh02@gmail.com" },
    { username: "user1", password: "user123", role: "user", email: "developerf07@gmail.com" }
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

async function addEquipmentsAssetsColumns() {
  await pool.query(`
    ALTER TABLE equipments_assets 
    ADD COLUMN IF NOT EXISTS date DATE,
    ADD COLUMN IF NOT EXISTS keys INTEGER;
  `);
  console.log("✅ equipments_assets columns ready");
}

async function createCustomerDetailsTable() {
  await pool.query(`
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
  
  try {
    await pool.query(`
      DROP TRIGGER IF EXISTS update_customer_details_updated_at ON customer_details;
      CREATE TRIGGER update_customer_details_updated_at
      BEFORE UPDATE ON customer_details
      FOR EACH ROW
      EXECUTE PROCEDURE update_updated_at_column();
    `);
  } catch (e) { /* Trigger exists */ }
  
  console.log("✅ customer_details table ready");
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

    req.session.user = { 
      id: user.id,
      username: user.username, 
      role: user.role,
      email: user.email,
      department: user.department
    };
    
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/me", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role });
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
  const category = req.params.category;
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  const { name, serial_number, employee_name, location, ...extraFields } = req.body;
  
  if (category === 'customer_details' && !extraFields.customer_name) {
    return res.status(400).json({ success: false, error: "Customer name required" });
  }
  if (category !== 'customer_details' && !name) {
    return res.status(400).json({ success: false, error: "Name required" });
  }

  try {
    let qrText, barcodeText;
    if (category === 'customer_details') {
      qrText = `${extraFields.customer_name}-${extraFields.case_number || ''}`;
      barcodeText = extraFields.case_number || extraFields.customer_name;
    } else {
      qrText = `${name}-${category}-${serial_number || ""}`;
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
        extraFields.customer_name, extraFields.customer_phone || null,
        extraFields.case_date || null, extraFields.case_number || null,
        extraFields.case_type || null, qrImage, qrText, barcodeImage, submittedBy
      ];
      placeholders = ['$1','$2','$3','$4','$5','$6','$7','$8','$9'];
    } else {
      columns = ['name', 'serial_number', 'employee_name', 'qr_code', 'qr_text', 'barcode', 'submitted_by', 'location'];
      values = [name, serial_number || null, employee_name || null, qrImage, qrText, barcodeImage, submittedBy, location || null];
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
  const category = req.params.category;
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
  const { category, id } = req.params;
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
  const { category, id } = req.params;
  if (!validTables.includes(category)) {
    return res.status(400).json({ success: false, error: "Invalid category" });
  }

  const { name, serial_number, employee_name, location, ...extraFields } = req.body;
  
  try {
    let updates, values;
    
    if (category === 'customer_details') {
      updates = ['customer_name=$1', 'customer_phone=$2', 'case_date=$3', 'case_number=$4', 'case_type=$5', 'updated_at=NOW()'];
      values = [extraFields.customer_name, extraFields.customer_phone || null, extraFields.case_date || null, extraFields.case_number || null, extraFields.case_type || null];
    } else {
      updates = ['name=$1', 'serial_number=$2', 'employee_name=$3', 'location=$4', 'updated_at=NOW()'];
      values = [name, serial_number || null, employee_name || null, location || null];
      let paramIndex = 5;
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

app.delete("/api/assets/:category/:id", isAuthenticated, isAdmin, async (req, res) => {
  const { category, id } = req.params;
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
    const assetTables = validTables.filter(t => t !== 'customer_details');
    
    for (const table of assetTables) {
      try {
        const result = await pool.query(
          `SELECT id, name, serial_number, employee_name, submitted_by, location, created_at FROM ${table}`
        );
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
    const assetTables = validTables.filter(t => t !== 'customer_details');
    
    for (const table of assetTables) {
      try {
        const result = await pool.query(
          `SELECT id, name, serial_number, employee_name, submitted_by, location, created_at FROM ${table}`
        );
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
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Serving static files from: ${path.join(__dirname, 'public')}`);
  
  // Initialize database after server starts
  initDatabase().catch(err => {
    console.error('Database init error:', err.message);
  });
});
