# Visiting Airmen Record System (VARS)
## Multi-Camp Gate Operations, Inter-Camp Movement & Temporary Accommodation

The **Visiting Airmen Record System (VARS)** is a secure, role-based PHP & MySQL application engineered for military camp gate security police and administrative stakeholders.

---

## Key Capabilities

1. **External Visitor Management (Preserved & Isolated)**
   - External visitor check-in, tracking, and check-out.
   - Real-time search, camp filtering, and duration tracking.
   - Comprehensive CSV reports.

2. **Two-Sided Inter-Camp Movement Tracking**
   - **Stage A (Origin OUT):** Dispatches airman from parent base with unique reference number (e.g. `MOV-20261113-DB04A`), destination base, purpose, and authorizing officer details.
   - **Stage B (Destination IN):** Destination gate verifies incoming airman and confirms check-in. Automatically activates a 24-hour temporary accommodation validity window.
   - **Stage D (Destination OUT):** Destination gate confirms departure. Closes temporary accommodation record.
   - **Stage E (Origin Return IN):** Parent base gate confirms airman's return home. Finalizes movement lifecycle as `COMPLETED`.

3. **Temporary Accommodation Management**
   - Default 24-hour validity starting from the exact Destination IN timestamp.
   - Live visual countdown and threshold alerts:
     - **Active** (Emerald badge)
     - **Expiring Soon** (&lt; 4 hours remaining, pulsing Amber badge)
     - **Expired / Overdue** (Pulsing Red badge)
   - Authorized validity extensions with reason, approving officer credentials, and complete audit history.

4. **Personnel Master Directory & Instant Gate Lookup**
   - Central directory of airmen (`personnel` table).
   - Real-time lookup by Service Number at the gate to auto-fill rank, name, and NIC.

5. **Advanced Personnel & Movement Inquiry**
   - Multi-parameter investigation across Service Number, Name, Rank, Dates, and Base.
   - Interactive visual journey timeline drawer for inspecting chronological events.

6. **Security & System Audit Trail**
   - Append-only compliance log of gate check-ins, check-outs, extensions, logins, and administrative actions.
   - CSRF protection on every transaction, rate-limiting brute-force guard, and secure session management.

---

## Installation & Deployment

### 1. Requirements
- PHP 8.1+ with `pdo_mysql`, `mbstring`, `openssl`, `session` extensions.
- MySQL 8.0+ or MariaDB 10.4+.
- Web server (Apache, Nginx, or PHP Built-in Server).

### 2. Database Setup
1. Create a MySQL database (e.g. `vars`).
2. Import base schema: `database.sql`.
3. Run the incremental migration: `migrations/001_inter_camp_movements_schema.sql` (or let `db.php` auto-migrate on first launch).
4. Configure database connection in `.env`:
   ```ini
   DB_HOST=127.0.0.1
   DB_PORT=3306
   DB_NAME=vars
   DB_USER=varsdb
   DB_PASS=YourSecurePassword
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=YourAdminPassword
   ADMIN_FULL_NAME="System Administrator"
   ADMIN_LOCATION=SJP
   ```
5. Seed initial admin account:
   ```bash
   php seed.php
   ```

### 3. Launching
Access `index.php` in your web browser. Sign in using your credentials and assigned camp location.

