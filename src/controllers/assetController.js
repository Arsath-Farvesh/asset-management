const assetService = require('../services/assetService');
const logger = require('../config/logger');

class AssetController {
  // Create asset
  async createAsset(req, res) {
    const { category } = req.params;
    const data = req.body;

    const result = await assetService.createAsset(category, data);

    if (!result.success) {
      return res.status(500).json(result);
    }

    res.status(201).json(result);
  }

  // Get all assets from category
  async getAssets(req, res) {
    const { category } = req.params;

    const result = await assetService.getAssets(category);

    if (!result.success) {
      return res.status(500).json(result);
    }

    res.json(result);
  }

  // Get single asset by ID
  async getAssetById(req, res) {
    const { category, id } = req.params;

    const result = await assetService.getAssetById(category, id);

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json(result);
  }

  // Update asset
  async updateAsset(req, res) {
    const { category, id } = req.params;
    const data = req.body;

    const result = await assetService.updateAsset(category, id, data);

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json(result);
  }

  // Delete asset
  async deleteAsset(req, res) {
    const { category, id } = req.params;

    const result = await assetService.deleteAsset(category, id);

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json(result);
  }

  // Bulk delete assets
  async bulkDelete(req, res) {
    const { ids, category } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'No IDs provided' });
    }

    if (!category) {
      return res.status(400).json({ success: false, error: 'Category is required' });
    }

    const result = await assetService.bulkDeleteAssets(category, ids);

    if (!result.success) {
      return res.status(500).json(result);
    }

    res.json(result);
  }

  // Get asset history
  async getHistory(req, res) {
    const result = await assetService.getHistory();

    if (!result.success) {
      return res.status(500).json(result);
    }

    res.json(result);
  }
}

module.exports = new AssetController();
