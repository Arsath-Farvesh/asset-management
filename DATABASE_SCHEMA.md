# Database Schema Documentation

## Overview
Asset Management System uses PostgreSQL database with the following structure:

## Core Tables

### users
User accounts and authentication
- `id` (PK): Auto-increment primary key
- `username`: Unique username (indexed)
- `email`: User email (indexed)
- `password`: Bcrypt hashed password
- `role`: User role ('user', 'admin') - indexed
- `department`: User department
- `oauth_provider`: OAuth provider ('google', 'microsoft', 'github')
- `oauth_id`: OAuth provider user ID
- `created_at`, `updated_at`: Timestamps

**Indexes:** username, email, role

---

### keys
Key asset tracking
- `id` (PK): Auto-increment primary key
- `case_name`: Case/Project name (indexed)
- `key_reference`: Key identifier
- `location`: Storage location (indexed)
  - Options: EJARI, RDC, RDC General Services, RERA, Rera General Services, RDC Electrical Enforcement
- `employee_name`: Person holding the key (indexed)
- `collection_date`: Date key was collected (indexed)
- `remarks`: Additional notes
- `created_at`, `updated_at`: Timestamps

**Indexes:** case_name, location, employee_name, collection_date

**Business Rules:**
- "Asset Name" field displays as "Case Name" in UI for Keys category
- All fields required except remarks

---

### laptops
Laptop asset tracking
- `id` (PK): Auto-increment primary key
- `asset_name`: Laptop model/name (indexed)
- `asset_tag`: Unique asset tag (indexed, unique)
- `location`: Current location (indexed)
- `employee_name`: Assigned employee (indexed)
- `collection_date`: Assignment date
- `remarks`: Additional notes
- `created_at`, `updated_at`: Timestamps

**Indexes:** asset_name, asset_tag (unique), location, employee_name

---

### monitors
Monitor asset tracking
- `id` (PK): Auto-increment primary key
- `asset_name`: Monitor model/name
- `asset_tag`: Unique asset tag (indexed, unique)
- `location`: Current location (indexed)
- `employee_name`: Assigned employee (indexed)
- `collection_date`: Assignment date
- `remarks`: Additional notes
- `created_at`, `updated_at`: Timestamps

**Indexes:** asset_tag (unique), location, employee_name

---

### accessories
Miscellaneous accessories tracking
- `id` (PK): Auto-increment primary key
- `asset_name`: Accessory description (indexed)
- `asset_tag`: Asset tag (optional)
- `location`: Current location (indexed)
- `employee_name`: Assigned employee (indexed)
- `collection_date`: Assignment date
- `remarks`: Additional notes
- `created_at`, `updated_at`: Timestamps

**Indexes:** asset_name, location, employee_name

---

### id_cards
ID card tracking
- `id` (PK): Auto-increment primary key
- `asset_name`: ID card type
- `employee_id`: Employee ID number (indexed)
- `location`: Issue location (indexed)
- `employee_name`: Cardholder name (indexed)
- `collection_date`: Issue date
- `remarks`: Additional notes
- `created_at`, `updated_at`: Timestamps

**Indexes:** employee_id, employee_name, location

---

### audit_logs
Audit trail for all asset operations
- `id` (PK): Auto-increment primary key
- `table_name`: Table affected (indexed)
- `record_id`: Record ID in target table (indexed)
- `action`: Operation type ('CREATE', 'UPDATE', 'DELETE') - indexed
- `user_id` (FK): References users(id) - indexed
- `username`: Username snapshot
- `old_data`: JSON snapshot before change
- `new_data`: JSON snapshot after change
- `ip_address`: Client IP address
- `user_agent`: Client user agent
- `created_at`: Timestamp (indexed)

**Indexes:** table_name, record_id, action, user_id, created_at, (table_name + record_id composite)

**Retention:** Recommend archiving logs older than 1 year

---

## Sessions
Managed by express-session with connect-pg-simple

### session
- `sid` (PK): Session ID
- `sess`: Session data (JSONB)
- `expire`: Expiration timestamp (indexed)

**Cleanup:** Automatic cleanup via pg-simple prune job

---

## Database Relationships

```
users (1) ──> (N) audit_logs
   │
   └──> Session management via express-session
```

---

## Performance Optimization

### Indexing Strategy
All foreign keys and frequently queried fields are indexed:
- **Lookup fields:** location, employee_name, asset_tag, employee_id
- **Search fields:** case_name, asset_name
- **Filter fields:** role, collection_date, action
- **Join keys:** user_id, record_id

### Query Patterns
1. **Asset Retrieval:** `SELECT * FROM {category} ORDER BY id DESC`
2. **User Lookup:** `SELECT * FROM users WHERE username = ?`
3. **Audit Trail:** `SELECT * FROM audit_logs WHERE table_name = ? AND record_id = ?`

---

## Backup & Recovery
- **Backup Frequency:** Daily full backups recommended
- **Retention:** 30 days minimum
- **Point-in-Time Recovery:** Enable WAL archiving

---

## Migrations
Managed by Knex.js

### Run Migrations
```bash
npx knex migrate:latest
```

### Rollback
```bash
npx knex migrate:rollback
```

### Check Status
```bash
npx knex migrate:currentVersion
```

---

## Connection Pooling
- **Min Connections:** 2
- **Max Connections:** 20 (development), 10 (production)
- **Idle Timeout:** 30 seconds
- **Connection Timeout:** 5 seconds

---

## Security
- **SSL:** Enabled in production
- **Password Storage:** Bcrypt hashing (10 rounds)
- **SQL Injection:** Parameterized queries only
- **Access Control:** Role-based (user/admin)
