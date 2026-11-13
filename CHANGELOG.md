# Changelog
All notable changes to the VARS project are documented in this file.

## [2.0.0] - 2026-11-13
### Added
- **Inter-Camp Personnel Movement Tracking**:
  - Implemented 5-stage movement lifecycle (Origin OUT &rarr; Destination IN &rarr; Temporary Accommodation &rarr; Destination OUT &rarr; Origin Return IN).
  - Added unique movement reference generator (`MOV-YYYYMMDD-XXXXX`).
  - Added `inter_camp_movements` and `movement_events` relational tables.
- **24-Hour Temporary Accommodation Module**:
  - Implemented 24-hour default temporary accommodation activated on Host Base IN.
  - Added dynamic status calculation (`ACTIVE`, `EXPIRING_SOON`, `EXPIRED`, `EXTENDED`, `CLOSED`).
  - Implemented authorized accommodation extension with audit history in `accommodation_extensions`.
- **Personnel Master Directory**:
  - Added `personnel` master table with fast lookup by Service Number.
  - Added real-time AJAX auto-fill of personnel details at Origin OUT gate.
- **Personnel & Movement Inquiry**:
  - Added dedicated multi-parameter search tab (`activeTab = 'inquiry'`).
  - Added chronological journey timeline modal (`modal = 'movementTimeline'`).
- **Audit Logging**:
  - Added append-only `audit_logs` table tracking user actions, IP addresses, timestamps, and before/after details.
  - Added dedicated Audit Trail dashboard tab for Administrators and OC Provost.
- **Migration & Automation**:
  - Created `migrations/001_inter_camp_movements_schema.sql`.
  - Added automatic schema verification and migration trigger to `ensureSchema()` in `db.php`.
- **Security Enhancements**:
  - Expanded `ALLOWED_ACTIONS` in `security.php` for movement actions.
  - Added `require_camp_access()` and `has_camp_access()` guards to enforce camp boundary integrity on all operations.

### Changed
- Preserved existing `visitors`, `users`, and `locations` database tables with zero data loss or breaking changes.
- Extended `users.role` ENUM backward-compatibly (`admin`, `camp_admin`, `user`, `oc_provost`, `stakeholder`).
- Enhanced `dashboard.php` with new tabs while preserving the visual identity, Tailwind styling, and dark mode palette.

### Fixed
- Fixed MySQL 8.0+ reserved keyword collision on `rank` column by ensuring backtick escaping (`` `rank` ``) across all DDL and DML queries.
