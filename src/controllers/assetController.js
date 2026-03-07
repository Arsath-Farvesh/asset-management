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
    const { ids, category, items } = req.body || {};

    if (Array.isArray(items) && items.length > 0) {
      const grouped = items.reduce((acc, item) => {
        if (!item || !item.category || item.id === undefined || item.id === null) {
          return acc;
        }

        if (!acc[item.category]) {
          acc[item.category] = [];
        }

        acc[item.category].push(item.id);
        return acc;
      }, {});

      const categories = Object.keys(grouped);
      if (categories.length === 0) {
        return res.status(400).json({ success: false, error: 'No valid items provided' });
      }

      let deletedCount = 0;
      const deletedIdsByCategory = {};

      for (const groupedCategory of categories) {
        const result = await assetService.bulkDeleteAssets(groupedCategory, grouped[groupedCategory]);

        if (!result.success) {
          return res.status(400).json(result);
        }

        deletedCount += result.deletedCount || 0;
        deletedIdsByCategory[groupedCategory] = result.deletedIds || [];
      }

      return res.json({
        success: true,
        deletedCount,
        deletedIdsByCategory
      });
    }

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'No IDs provided' });
    }

    if (!category) {
      return res.status(400).json({ success: false, error: 'Category is required' });
    }

    const result = await assetService.bulkDeleteAssets(category, ids);

    if (!result.success) {
      return res.status(400).json(result);
    }

    return res.json(result);
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
