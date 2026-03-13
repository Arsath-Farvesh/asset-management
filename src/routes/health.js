const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const { isAuthenticated, isAdmin } = require('../middleware/auth');

const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT_NAME === 'production';
const allowDebugEndpoints = process.env.ENABLE_DEBUG_ENDPOINTS === 'true' || !isProduction;

// Health check route (no dependencies)
router.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.status(200).json({
      status: 'ok',
      database: 'connected',
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      status: 'degraded',
      database: 'disconnected',
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  }
});

// CSRF token endpoint
router.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Session timeout configuration endpoint
router.get('/session-config', (req, res) => {
  // 30 minutes inactivity timeout and 24 hours max session
  const inactivityTimeout = Number.parseInt(process.env.SESSION_INACTIVITY_TIMEOUT, 10) || 30 * 60 * 1000;
  const maxSessionAge = Number.parseInt(process.env.SESSION_MAX_AGE, 10) || 24 * 60 * 60 * 1000;
  const warningTimeout = Math.max(inactivityTimeout - 5 * 60 * 1000, 5 * 60 * 1000); // Show warning 5 min before logout
  
  res.json({
    inactivityTimeout,  // milliseconds until auto-logout
    maxSessionAge,      // milliseconds until max session age
    warningTimeout,     // milliseconds until warning shown
    inactivityTimeoutMin: Math.round(inactivityTimeout / 60000), // minutes
    warningTimeoutMin: Math.round(warningTimeout / 60000)
  });
});

// Database schema check endpoint (for debugging)
router.get('/db-schema', isAuthenticated, isAdmin, async (req, res) => {
  if (!allowDebugEndpoints) {
    return res.status(404).json({
      success: false,
      error: 'Not found'
    });
  }

  try {
    const result = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    const tables = result.rows.map(r => r.table_name);
    const hasCaseDetails = tables.includes('case_details');
    
    res.json({
      status: 'ok',
      tables,
      hasCaseDetails,
      caseDetailsColumns: hasCaseDetails ? await getCaseDetailsColumns() : null
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

async function getCaseDetailsColumns() {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'case_details'
      ORDER BY ordinal_position
    `);
    return result.rows;
  } catch (err) {
    return null;
  }
}

module.exports = router;
