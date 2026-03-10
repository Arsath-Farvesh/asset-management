const express = require('express');
const router = express.Router();
const pool = require('../config/database');

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

// Database schema check endpoint (for debugging)
router.get('/db-schema', async (req, res) => {
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
