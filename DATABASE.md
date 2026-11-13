# Database Architecture & Schema Documentation

The Visiting Airmen Record System uses MySQL/MariaDB with `InnoDB` storage engines and `utf8mb4` character encoding.

---

## Entity Relationship Overview

```
[locations] (camp codes & names)
    ├── [users] (security police and admin accounts)
    ├── [visitors] (external visitors check-in / check-out)
    ├── [personnel] (airmen master directory)
    ├── [inter_camp_movements] (movement journeys: origin & destination)
    │       ├── [movement_events] (chronological immutable event stream)
    │       └── [temporary_accommodations] (24h accommodation tracker)
    │               └── [accommodation_extensions] (authorized extension history)
    └── [audit_logs] (append-only system compliance audit trail)
```

---

## Table Definitions

### 1. `locations` (Camp / Base Locations)
Stores registered SLAF bases and camps.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `code` VARCHAR(60) UNIQUE NOT NULL (e.g., 'SJP', 'KAT', 'EKL')
- `name` VARCHAR(120) NOT NULL
- `is_active` TINYINT(1) DEFAULT 1
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP

### 2. `users` (Operator & Administrator Accounts)
Stores user credentials and camp assignments.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `username` VARCHAR(60) UNIQUE NOT NULL
- `password` VARCHAR(255) NOT NULL (bcrypt hash)
- `svs_no` VARCHAR(40) NOT NULL DEFAULT ''
- `` `rank` `` VARCHAR(60) NOT NULL DEFAULT ''
- `name` VARCHAR(120) NOT NULL DEFAULT ''
- `role` ENUM('admin','camp_admin','user','oc_provost','stakeholder') NOT NULL DEFAULT 'user'
- `location` VARCHAR(60) NOT NULL DEFAULT 'SJP'
- `is_active` TINYINT(1) DEFAULT 1
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP

### 3. `visitors` (External Visitor Records)
Maintains external non-servicemen visitors. Unchanged from v1.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `svs_no` VARCHAR(40) NOT NULL
- `` `rank` `` VARCHAR(60) NOT NULL
- `name` VARCHAR(120) NOT NULL
- `nic_no` VARCHAR(30) NOT NULL
- `parent_camp` VARCHAR(120) NOT NULL
- `location` VARCHAR(60) NOT NULL DEFAULT 'SJP'
- `remarks` TEXT
- `authority_by` VARCHAR(120) NOT NULL DEFAULT ''
- `in_datetime` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
- `out_datetime` DATETIME NULL DEFAULT NULL
- `created_by` INT UNSIGNED NULL

### 4. `personnel` (Airmen Master Directory)
Fast gate lookup directory for servicemen.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `svs_no` VARCHAR(40) UNIQUE NOT NULL
- `` `rank` `` VARCHAR(60) NOT NULL DEFAULT ''
- `name` VARCHAR(120) NOT NULL DEFAULT ''
- `nic_no` VARCHAR(30) NOT NULL DEFAULT ''
- `parent_camp` VARCHAR(60) NOT NULL DEFAULT 'SJP'
- `contact_no` VARCHAR(40) NOT NULL DEFAULT ''
- `is_active` TINYINT(1) DEFAULT 1
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
- `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

### 5. `inter_camp_movements` (Movement Journeys)
Core lifecycle record for inter-camp travel.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `movement_ref` VARCHAR(40) UNIQUE NOT NULL
- `svs_no` VARCHAR(40) NOT NULL
- `` `rank` `` VARCHAR(60) NOT NULL DEFAULT ''
- `name` VARCHAR(120) NOT NULL DEFAULT ''
- `nic_no` VARCHAR(30) NOT NULL DEFAULT ''
- `origin_camp` VARCHAR(60) NOT NULL
- `destination_camp` VARCHAR(60) NOT NULL
- `purpose_of_visit` TEXT NOT NULL
- `authority_name` VARCHAR(120) NOT NULL DEFAULT ''
- `authority_svs` VARCHAR(40) NOT NULL DEFAULT ''
- `authority_rank` VARCHAR(60) NOT NULL DEFAULT ''
- `authority_designation` VARCHAR(120) NOT NULL DEFAULT ''
- `authority_ref` VARCHAR(120) NOT NULL DEFAULT ''
- `approval_status` ENUM('NOT_VERIFIED','VERIFIED','WAIVED') DEFAULT 'NOT_VERIFIED'
- `movement_status` ENUM('PENDING_OUT','DEPARTED_ORIGIN','ARRIVED_DESTINATION','DEPARTED_DESTINATION','RETURNED_ORIGIN','COMPLETED','OVERDUE','CANCELLED') DEFAULT 'DEPARTED_ORIGIN'
- `expected_arrival` DATETIME NULL
- `expected_return` DATETIME NULL
- `actual_out_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
- `actual_in_at` DATETIME NULL
- `actual_dest_out_at` DATETIME NULL
- `actual_return_in_at` DATETIME NULL
- `created_by` INT UNSIGNED NULL
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
- `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

### 6. `movement_events` (Chronological Audit Stream)
Append-only log of every gate transaction in the movement lifecycle.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `movement_id` INT UNSIGNED NOT NULL
- `movement_ref` VARCHAR(40) NOT NULL
- `event_type` ENUM('ORIGIN_OUT','DESTINATION_IN','DESTINATION_OUT','ORIGIN_RETURN_IN','EXTENSION_GRANTED','CANCELLED','REMARKS_ADDED') NOT NULL
- `camp_code` VARCHAR(60) NOT NULL
- `operator_id` INT UNSIGNED NULL
- `event_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
- `remarks` TEXT NULL
- `ip_address` VARCHAR(45) NOT NULL DEFAULT ''
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP

### 7. `temporary_accommodations` (24h Accommodation Tracker)
Manages 24-hour default validity from actual Host IN timestamp.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `movement_id` INT UNSIGNED UNIQUE NOT NULL
- `movement_ref` VARCHAR(40) NOT NULL
- `camp_code` VARCHAR(60) NOT NULL
- `svs_no` VARCHAR(40) NOT NULL
- `` `rank` `` VARCHAR(60) NOT NULL DEFAULT ''
- `name` VARCHAR(120) NOT NULL DEFAULT ''
- `checkin_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
- `original_expires_at` DATETIME NOT NULL
- `current_expires_at` DATETIME NOT NULL
- `accommodation_status` ENUM('NOT_STARTED','ACTIVE','EXPIRING_SOON','EXPIRED','EXTENDED','CLOSED') DEFAULT 'ACTIVE'
- `billet_location` VARCHAR(120) NOT NULL DEFAULT ''
- `checkout_at` DATETIME NULL
- `checkin_operator_id` INT UNSIGNED NULL
- `checkout_operator_id` INT UNSIGNED NULL
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
- `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

### 8. `accommodation_extensions` (Authorized Extensions)
Maintains complete history of accommodation extensions.
- `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `accommodation_id` INT UNSIGNED NOT NULL
- `previous_expires_at` DATETIME NOT NULL
- `new_expires_at` DATETIME NOT NULL
- `extended_hours` INT UNSIGNED NOT NULL
- `reason` TEXT NOT NULL
- `authorized_by_name` VARCHAR(120) NOT NULL
- `authorized_by_svs` VARCHAR(40) NOT NULL DEFAULT ''
- `authorized_by_rank` VARCHAR(60) NOT NULL DEFAULT ''
- `operator_id` INT UNSIGNED NULL
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP

### 9. `audit_logs` (System Audit Trail)
Append-only log for all critical user actions and operations.
- `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY
- `user_id` INT UNSIGNED NULL
- `username` VARCHAR(60) NOT NULL DEFAULT ''
- `camp_code` VARCHAR(60) NOT NULL DEFAULT ''
- `action_type` VARCHAR(60) NOT NULL
- `entity_type` VARCHAR(60) NOT NULL
- `entity_id` VARCHAR(60) NOT NULL DEFAULT ''
- `reference_no` VARCHAR(60) NOT NULL DEFAULT ''
- `details` JSON NULL
- `ip_address` VARCHAR(45) NOT NULL DEFAULT ''
- `user_agent` VARCHAR(255) NOT NULL DEFAULT ''
- `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP

### 10. `system_settings` (Operational Configuration)
Stores configurable system parameters (e.g. `DEFAULT_ACCOMMODATION_HOURS = 24`, `ACCOMMODATION_WARNING_HOURS = 4`).
- `setting_key` VARCHAR(60) UNIQUE PRIMARY KEY
- `setting_value` TEXT NOT NULL
- `description` VARCHAR(255) NOT NULL DEFAULT ''
- `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
