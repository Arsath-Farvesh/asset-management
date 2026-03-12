const express = require('express');
const router = express.Router();
const assetController = require('../controllers/assetController');
const { isAuthenticated, isAdmin } = require('../middleware/auth');

/**
 * @swagger
 * /api/assets/{category}:
 *   post:
 *     tags: [Assets]
 *     summary: Create a new asset
 *     security:
 *       - sessionAuth: []
 *       - csrfToken: []
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *           enum: [keys, laptops, monitors, accessories, id_cards]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             oneOf:
 *               - $ref: '#/components/schemas/Key'
 *               - $ref: '#/components/schemas/Laptop'
 *               - $ref: '#/components/schemas/Monitor'
 *               - $ref: '#/components/schemas/Accessory'
 *               - $ref: '#/components/schemas/IDCard'
 *     responses:
 *       200:
 *         description: Asset created successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.post('/assets/bulk-delete', isAuthenticated, isAdmin, assetController.bulkDelete);
router.post('/assets/:category', isAuthenticated, assetController.createAsset);

/**
 * @swagger
 * /api/assets/{category}:
 *   get:
 *     tags: [Assets]
 *     summary: Get all assets from a category
 *     security:
 *       - sessionAuth: []
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *           enum: [keys, laptops, monitors, accessories, id_cards]
 *     responses:
 *       200:
 *         description: List of assets
 */
router.get('/assets/:category', isAuthenticated, assetController.getAssets);

/**
 * @swagger
 * /api/assets/{category}/{id}:
 *   get:
 *     tags: [Assets]
 *     summary: Get single asset by ID
 *     security:
 *       - sessionAuth: []
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Asset details
 *       404:
 *         description: Asset not found
 */
router.get('/assets/:category/:id', isAuthenticated, assetController.getAssetById);

/**
 * @swagger
 * /api/assets/{category}/{id}:
 *   put:
 *     tags: [Assets]
 *     summary: Update an asset (Admin only)
 *     security:
 *       - sessionAuth: []
 *       - csrfToken: []
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Asset updated
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         description: Admin access required
 */
router.put('/assets/:category/:id', isAuthenticated, isAdmin, assetController.updateAsset);

/**
 * @swagger
 * /api/assets/{category}/{id}:
 *   delete:
 *     tags: [Assets]
 *     summary: Delete an asset (Admin only)
 *     security:
 *       - sessionAuth: []
 *       - csrfToken: []
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Asset deleted
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         description: Admin access required
 */
router.delete('/assets/:category/:id', isAuthenticated, isAdmin, assetController.deleteAsset);

/**
 * @swagger
 * /api/assets/bulk-delete:
 *   post:
 *     tags: [Assets]
 *     summary: Bulk delete assets (Admin only)
 *     security:
 *       - sessionAuth: []
 *       - csrfToken: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               ids:
 *                 type: array
 *                 items:
 *                   type: integer
 *     responses:
 *       200:
 *         description: Assets deleted
 *       403:
 *         description: Admin access required
 */
/**
 * @swagger
 * /api/history:
 *   get:
 *     tags: [Assets]
 *     summary: Get asset collection history
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Asset history
 */
router.get('/history', isAuthenticated, assetController.getHistory);
router.get('/history/pdf', isAuthenticated, assetController.getHistoryPdf);

module.exports = router;
