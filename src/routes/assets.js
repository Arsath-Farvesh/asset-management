const express = require('express');
const router = express.Router();
const assetController = require('../controllers/assetController');
const { isAuthenticated, isAdmin } = require('../middleware/auth');

// Routes
router.post('/assets/:category', isAuthenticated, assetController.createAsset);
router.get('/assets/:category', isAuthenticated, assetController.getAssets);
router.get('/assets/:category/:id', isAuthenticated, assetController.getAssetById);
router.put('/assets/:category/:id', isAuthenticated, isAdmin, assetController.updateAsset);
router.delete('/assets/:category/:id', isAuthenticated, assetController.deleteAsset);
router.post('/assets/bulk-delete', isAuthenticated, assetController.bulkDelete);
router.get('/history', isAuthenticated, assetController.getHistory);

module.exports = router;
