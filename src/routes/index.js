const express = require('express');
const router = express.Router();

// Mount all route modules
const authRoutes = require('./auth');
const assetRoutes = require('./assets');
const healthRoutes = require('./health');

// API routes
router.use('/api', authRoutes);
router.use('/api', assetRoutes);
router.use('/api', healthRoutes);

module.exports = router;
