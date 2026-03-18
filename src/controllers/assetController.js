const assetService = require('../services/assetService');
const logger = require('../config/logger');
const PDFDocument = require('pdfkit');

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeCategoryLabel(category) {
  if (category === 'case_details') {
    return 'Case Details';
  }
  if (category === 'keys' || category === 'equipments_assets') {
    return 'Keys';
  }
  return String(category || '').replace(/_/g, ' ').toUpperCase();
}

class AssetController {
  // Create asset
  async createAsset(req, res) {
    try {
      const { category } = req.params;
      const actor = {
        userId: req.session?.user?.id || null,
        username: req.session?.user?.username || null,
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || null
      };
      // Inject the logged-in user's username so history shows who submitted it
      const data = {
        ...req.body,
        submitted_by: req.session?.user?.username || null
      };

      const result = await assetService.createAsset(category, data, actor);

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
    const actor = {
      userId: req.session?.user?.id || null,
      username: req.session?.user?.username || null,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || null
    };

    const result = await assetService.updateAsset(category, id, data, actor);

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json(result);
  }

  // Delete asset
  async deleteAsset(req, res) {
    const { category, id } = req.params;
    const actor = {
      userId: req.session?.user?.id || null,
      username: req.session?.user?.username || null,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || null
    };

    const result = await assetService.deleteAsset(category, id, actor);

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json(result);
  }

  // Bulk delete assets
  async bulkDelete(req, res) {
    const { ids, category, items } = req.body || {};
    const actor = {
      userId: req.session?.user?.id || null,
      username: req.session?.user?.username || null,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || null
    };

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
        const result = await assetService.bulkDeleteAssets(groupedCategory, grouped[groupedCategory], actor);

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

    const result = await assetService.bulkDeleteAssets(category, ids, actor);

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

    const headers = ['ID', 'Category', 'Name', 'Serial', 'Employee', 'Location', 'Submitted By', 'Created At'];
    const widths = [35, 75, 85, 60, 70, 70, 65, 55];

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
        String(row.submitted_by || '-'),
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

  async getHistoryCodesReport(req, res) {
    const result = await assetService.getHistory();

    if (!result.success) {
      return res.status(500).json(result);
    }

    const rows = result.data || [];
    const autoPrint = req.query.autoprint === 'true';
    const createdAt = new Date().toLocaleString();

    const cards = rows.map((row) => {
      const rowLabel = row.serial_number || row.case_number || row.id || '-';
      const qrPayload = encodeURIComponent(`${row.category || ''}|${row.id || ''}|${row.name || ''}|${rowLabel}`);
      const barcodePayload = encodeURIComponent(String(rowLabel || row.name || row.id || 'NA'));

      return `
        <article class="label-card">
          <header>
            <h3>${escapeHtml(normalizeCategoryLabel(row.category))}</h3>
            <p>#${escapeHtml(row.id || '-')}</p>
          </header>
          <p><strong>Name:</strong> ${escapeHtml(row.name || '-')}</p>
          <p><strong>Serial/Case:</strong> ${escapeHtml(rowLabel)}</p>
          <p><strong>Location:</strong> ${escapeHtml(row.location || '-')}</p>
          <div class="codes-grid">
            <div>
              <h4>QR</h4>
              <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${qrPayload}" alt="QR ${escapeHtml(row.id || '-')}">
            </div>
            <div>
              <h4>Barcode</h4>
              <img class="barcode-image" src="https://bwipjs-api.metafloor.com/?bcid=code128&text=${barcodePayload}&scale=3&height=58&includetext&paddingwidth=24&paddingheight=10" alt="Barcode ${escapeHtml(row.id || '-')}">
            </div>
          </div>
        </article>
      `;
    }).join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QR & Barcode Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #111827; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .print-btn { padding: 10px 16px; border: none; border-radius: 8px; background: #88010e; color: #fff; cursor: pointer; }
    .labels { display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 14px; }
    .label-card { border: 1px solid #d1d5db; border-radius: 10px; padding: 12px; break-inside: avoid; }
    .label-card header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px; }
    .label-card h3 { margin: 0; font-size: 16px; }
    .label-card p { margin: 4px 0; font-size: 13px; }
    .codes-grid { display: grid; grid-template-columns: 180px 1fr; gap: 14px; margin-top: 10px; align-items: center; }
    .codes-grid h4 { margin: 0 0 4px 0; font-size: 12px; text-transform: uppercase; color: #4b5563; }
    .codes-grid img { max-width: 100%; border: 1px solid #e5e7eb; border-radius: 6px; background: #fff; }
    .barcode-image { min-width: 280px; }
    @media (max-width: 900px) {
      .labels { grid-template-columns: 1fr; }
      .codes-grid { grid-template-columns: 1fr; }
      .barcode-image { min-width: 0; }
    }
    @media print {
      .print-btn { display: none; }
      body { margin: 10px; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin:0;font-size:20px;">QR & Barcode Sticker Report</h1>
      <p style="margin:4px 0 0 0;color:#4b5563;">Generated: ${escapeHtml(createdAt)} | Total: ${rows.length}</p>
    </div>
    <button class="print-btn" onclick="window.print()">Print</button>
  </div>
  <section class="labels">${cards}</section>
  ${autoPrint ? '<script>window.addEventListener(\'load\', () => window.print());<\/script>' : ''}
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="asset-codes-${Date.now()}.html"`);
    return res.send(html);
  }
}

module.exports = new AssetController();
