const assetService = require('../services/assetService');
const logger = require('../config/logger');
const PDFDocument = require('pdfkit');

class AssetController {
  // Create asset
  async createAsset(req, res) {
    try {
      const { category } = req.params;
      // Inject the logged-in user's username so history shows who submitted it
      const data = {
        ...req.body,
        submitted_by: req.session?.user?.username || null
      };

      const result = await assetService.createAsset(category, data);

      if (!result.success) {
        return res.status(500).json(result);
      }

      res.status(201).json(result);
    } catch (err) {
      logger.error('Asset controller createAsset error:', err);
      res.status(500).json({ success: false, error: err.message || 'Failed to create asset' });
    }
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

  // Download asset history as PDF
  async getHistoryPdf(req, res) {
    const result = await assetService.getHistory();

    if (!result.success) {
      return res.status(500).json(result);
    }

    const rows = result.data || [];
    const doc = new PDFDocument({ margin: 40, size: 'A4' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="asset-history-${Date.now()}.pdf"`);

    doc.pipe(res);

    doc.fontSize(18).text('Takhlees Asset History Report', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(10).text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
    doc.moveDown(1.2);

    const headers = ['ID', 'Category', 'Name', 'Serial', 'Employee', 'Location', 'Created At'];
    const widths = [40, 80, 90, 65, 75, 80, 90];

    const drawHeader = () => {
      let x = doc.page.margins.left;
      const y = doc.y;
      doc.font('Helvetica-Bold').fontSize(9);
      headers.forEach((h, i) => {
        doc.text(h, x, y, { width: widths[i], lineBreak: false });
        x += widths[i];
      });
      doc.moveDown(0.8);
      doc.moveTo(doc.page.margins.left, doc.y)
        .lineTo(doc.page.width - doc.page.margins.right, doc.y)
        .strokeColor('#cccccc')
        .stroke();
      doc.moveDown(0.4);
    };

    drawHeader();
    doc.font('Helvetica').fontSize(8.5);

    rows.forEach((row) => {
      if (doc.y > doc.page.height - 60) {
        doc.addPage();
        drawHeader();
        doc.font('Helvetica').fontSize(8.5);
      }

      const values = [
        String(row.id || '-'),
        String(row.category || '-').replace(/_/g, ' '),
        String(row.name || '-'),
        String(row.serial_number || '-'),
        String(row.employee_name || '-'),
        String(row.location || '-'),
        row.created_at ? new Date(row.created_at).toLocaleString() : '-'
      ];

      let x = doc.page.margins.left;
      const y = doc.y;
      values.forEach((v, i) => {
        doc.text(v, x, y, { width: widths[i], lineBreak: false, ellipsis: true });
        x += widths[i];
      });
      doc.moveDown(1);
    });

    doc.end();
  }
}

module.exports = new AssetController();
