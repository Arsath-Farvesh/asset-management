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
    doc.text(`Total Records: ${rows.length}`, { align: 'center' });
    doc.moveDown(1.2);

    const columns = [
      { key: 'id', label: 'ID', width: 35 },
      { key: 'category', label: 'Category', width: 72 },
      { key: 'name', label: 'Name', width: 85 },
      { key: 'serial_number', label: 'Serial/Case', width: 66 },
      { key: 'employee_name', label: 'Employee', width: 70 },
      { key: 'location', label: 'Location', width: 70 },
      { key: 'submitted_by', label: 'Submitted By', width: 62 },
      { key: 'created_at', label: 'Created At', width: 55 }
    ];
    const tableLeft = doc.page.margins.left;
    const tableWidth = columns.reduce((sum, col) => sum + col.width, 0);
    const headerHeight = 20;
    const rowHeight = 18;

    const formatCell = (row, key) => {
      if (key === 'category') return String(row.category || '-').replace(/_/g, ' ');
      if (key === 'created_at') return row.created_at ? new Date(row.created_at).toLocaleString() : '-';
      return String(row[key] || '-');
    };

    const drawTableHeader = () => {
      if (doc.y + headerHeight > doc.page.height - 50) {
        doc.addPage();
      }

      const headerY = doc.y;
      doc.save();
      doc.rect(tableLeft, headerY, tableWidth, headerHeight).fill('#0f172a');
      doc.restore();

      let x = tableLeft;
      doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(8.5);
      columns.forEach((col) => {
        doc.text(col.label, x + 4, headerY + 6, {
          width: col.width - 8,
          lineBreak: false,
          ellipsis: true
        });
        x += col.width;
      });

      doc.fillColor('#111827');
      doc.y = headerY + headerHeight;
    };

    drawTableHeader();

    rows.forEach((row, index) => {
      if (doc.y + rowHeight > doc.page.height - 45) {
        doc.addPage();
        drawTableHeader();
      }

      const y = doc.y;
      if (index % 2 === 0) {
        doc.save();
        doc.rect(tableLeft, y, tableWidth, rowHeight).fill('#f8fafc');
        doc.restore();
      }

      let x = tableLeft;
      columns.forEach((col) => {
        doc.rect(x, y, col.width, rowHeight).lineWidth(0.4).strokeColor('#e5e7eb').stroke();
        doc.fillColor('#111827').font('Helvetica').fontSize(8).text(formatCell(row, col.key), x + 4, y + 5, {
          width: col.width - 8,
          lineBreak: false,
          ellipsis: true
        });
        x += col.width;
      });

      doc.y = y + rowHeight;
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
    const asDownload = req.query.download === 'true';
    const paper = String(req.query.paper || 'a4').toLowerCase() === 'letter' ? 'Letter' : 'A4';
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
              <img src="https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${qrPayload}" alt="QR ${escapeHtml(row.id || '-')}">
            </div>
            <div>
              <h4>Barcode</h4>
              <img class="barcode-image" src="https://bwipjs-api.metafloor.com/?bcid=code128&text=${barcodePayload}&scale=2.5&height=54&includetext&paddingwidth=20&paddingheight=8" alt="Barcode ${escapeHtml(row.id || '-')}">
            </div>
          </div>
          <p class="sticker-note">Please do not remove the sticker</p>
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
    @page { size: ${paper} portrait; margin: 10mm; }
    body { font-family: Arial, sans-serif; margin: 16px; color: #111827; background: #f8fafc; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .print-btn { padding: 10px 16px; border: none; border-radius: 8px; background: #88010e; color: #fff; cursor: pointer; }
    .labels { display: grid; grid-template-columns: repeat(auto-fit, minmax(480px, 1fr)); gap: 12px; }
    .label-card { border: 1px solid #d1d5db; border-radius: 10px; padding: 12px; break-inside: avoid; background: #ffffff; overflow: hidden; }
    .label-card header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px; }
    .label-card h3 { margin: 0; font-size: 16px; }
    .label-card p { margin: 4px 0; font-size: 13px; }
    .codes-grid { display: grid; grid-template-columns: 160px minmax(0, 1fr); gap: 12px; margin-top: 10px; align-items: center; }
    .codes-grid > div { min-width: 0; }
    .codes-grid h4 { margin: 0 0 4px 0; font-size: 12px; text-transform: uppercase; color: #4b5563; }
    .codes-grid img { width: 100%; max-width: 100%; height: auto; border: 1px solid #e5e7eb; border-radius: 6px; background: #fff; }
    .barcode-image { min-width: 0; max-width: 340px; }
    .sticker-note { margin: 10px 0 0 0; padding: 6px 8px; border: 1px dashed #ef4444; border-radius: 6px; text-align: center; font-size: 12px; font-weight: 700; color: #b91c1c; letter-spacing: 0.2px; }
    @media (max-width: 1100px) {
      .labels { grid-template-columns: 1fr; }
      .codes-grid { grid-template-columns: 1fr; }
      .barcode-image { max-width: 100%; }
    }
    @media print {
      .print-btn { display: none; }
      body { margin: 0; background: #fff; font-size: 11px; }
      .header { margin-bottom: 8px; }
      .labels { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
      .label-card { border-color: #cbd5e1; page-break-inside: avoid; break-inside: avoid-page; }
      .codes-grid { grid-template-columns: 1fr 1fr; }
      .barcode-image { max-width: 100%; }
      .label-card p { margin: 2px 0; }
      .sticker-note { margin-top: 8px; padding: 5px 6px; font-size: 11px; border-width: 1px; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin:0;font-size:20px;">QR & Barcode Sticker Report</h1>
      <p style="margin:4px 0 0 0;color:#4b5563;">Generated: ${escapeHtml(createdAt)} | Total: ${rows.length} | Paper: ${paper}</p>
    </div>
    <button class="print-btn" onclick="window.print()">Print</button>
  </div>
  <section class="labels">${cards}</section>
  ${autoPrint ? '<script>window.addEventListener(\'load\', () => window.print());<\/script>' : ''}
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `${asDownload ? 'attachment' : 'inline'}; filename="asset-codes-${Date.now()}.html"`);
    return res.send(html);
  }
}

module.exports = new AssetController();
