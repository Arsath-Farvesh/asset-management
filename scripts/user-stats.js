#!/usr/bin/env node
/**
 * Run with your Railway DATABASE_URL:
 *   DATABASE_URL="postgresql://..." node scripts/user-stats.js
 */
require('dotenv').config();
const { Pool } = require('pg');

const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error('\nERROR: No DATABASE_URL set.');
  console.error('Run: DATABASE_URL="postgresql://..." node scripts/user-stats.js\n');
  process.exit(1);
}

const pool = new Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });

(async () => {
  try {
    const [totals, detail] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(*)                                              AS total_users,
          COUNT(*) FILTER (WHERE role = 'admin')               AS admins,
          COUNT(*) FILTER (WHERE role = 'user')                AS normal_users,
          COUNT(*) FILTER (WHERE role = 'guest')               AS guests,
          COUNT(*) FILTER (WHERE email    IS NOT NULL AND email    <> '') AS has_email,
          COUNT(*) FILTER (WHERE department IS NOT NULL AND department <> '') AS has_department,
          COUNT(*) FILTER (
            WHERE email IS NOT NULL AND email <> ''
              AND department IS NOT NULL AND department <> ''
          ) AS fully_complete
        FROM users
      `),
      pool.query(`
        SELECT id, username, email, role, department,
               first_name, last_name, office_location, phone,
               created_at
        FROM users
        ORDER BY created_at ASC
      `)
    ]);

    const s = totals.rows[0];

    console.log('\n╔══════════════════════════════╗');
    console.log('║       USER SUMMARY           ║');
    console.log('╚══════════════════════════════╝');
    console.log(`  Total users     : ${s.total_users}`);
    console.log(`  Admins          : ${s.admins}`);
    console.log(`  Normal users    : ${s.normal_users}`);
    console.log(`  Guests          : ${s.guests}`);
    console.log(`  Has email       : ${s.has_email}`);
    console.log(`  Has department  : ${s.has_department}`);
    console.log(`  Fully complete  : ${s.fully_complete}  (email + dept filled)`);

    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║  ID   STATUS     USERNAME         ROLE    EMAIL / DEPT / NAME  ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');

    detail.rows.forEach((u) => {
      const fields = [u.email, u.department].filter(Boolean).length;
      const tag = fields === 2 ? ' [FULL]   ' : fields === 0 ? ' [EMPTY]  ' : ' [PARTIAL]';
      const name = [u.first_name, u.last_name].filter(Boolean).join(' ') || '-';
      console.log(
        `  #${String(u.id).padEnd(4)}${tag} ` +
        `${(u.username || '').padEnd(16)} ` +
        `${(u.role || '').padEnd(7)} ` +
        `email=${u.email || '-'} | dept=${u.department || '-'} | name=${name}`
      );
    });

    console.log('');
  } catch (err) {
    console.error('Query failed:', err.message);
  } finally {
    await pool.end();
  }
})();
