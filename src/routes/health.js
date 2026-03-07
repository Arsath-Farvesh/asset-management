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

module.exports = router;
