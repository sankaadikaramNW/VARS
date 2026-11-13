-- ============================================================
--  VARS - Visiting Airmen Record System
--  Migration 001: Inter-Camp Personnel Movement & Accommodation
--  Non-destructive schema enhancement
-- ============================================================

-- 1. Table: personnel (Airmen master directory for fast lookup at gates)
CREATE TABLE IF NOT EXISTS personnel (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    svs_no VARCHAR(40) NOT NULL UNIQUE,
    `rank` VARCHAR(60) NOT NULL DEFAULT '',
    name VARCHAR(120) NOT NULL DEFAULT '',
    nic_no VARCHAR(30) NOT NULL DEFAULT '',
    parent_camp VARCHAR(60) NOT NULL DEFAULT 'SJP',
    contact_no VARCHAR(40) NOT NULL DEFAULT '',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_personnel_svs (svs_no),
    INDEX idx_personnel_parent_camp (parent_camp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Table: inter_camp_movements (Core movement transactions)
CREATE TABLE IF NOT EXISTS inter_camp_movements (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    movement_ref VARCHAR(40) NOT NULL UNIQUE,
    svs_no VARCHAR(40) NOT NULL,
    `rank` VARCHAR(60) NOT NULL DEFAULT '',
    name VARCHAR(120) NOT NULL DEFAULT '',
    nic_no VARCHAR(30) NOT NULL DEFAULT '',
    origin_camp VARCHAR(60) NOT NULL,
    destination_camp VARCHAR(60) NOT NULL,
    purpose_of_visit TEXT NOT NULL,
    authority_name VARCHAR(120) NOT NULL DEFAULT '',
    authority_svs VARCHAR(40) NOT NULL DEFAULT '',
    authority_rank VARCHAR(60) NOT NULL DEFAULT '',
    authority_designation VARCHAR(120) NOT NULL DEFAULT '',
    authority_ref VARCHAR(120) NOT NULL DEFAULT '',
    approval_status ENUM('NOT_VERIFIED','VERIFIED','WAIVED') NOT NULL DEFAULT 'NOT_VERIFIED',
    movement_status ENUM(
        'PENDING_OUT',
        'DEPARTED_ORIGIN',
        'ARRIVED_DESTINATION',
        'DEPARTED_DESTINATION',
        'RETURNED_ORIGIN',
        'COMPLETED',
        'OVERDUE',
        'CANCELLED'
    ) NOT NULL DEFAULT 'DEPARTED_ORIGIN',
    expected_arrival DATETIME NULL DEFAULT NULL,
    expected_return DATETIME NULL DEFAULT NULL,
    actual_out_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actual_in_at DATETIME NULL DEFAULT NULL,
    actual_dest_out_at DATETIME NULL DEFAULT NULL,
    actual_return_in_at DATETIME NULL DEFAULT NULL,
    created_by INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_movements_ref (movement_ref),
    INDEX idx_movements_svs (svs_no),
    INDEX idx_movements_origin (origin_camp),
    INDEX idx_movements_dest (destination_camp),
    INDEX idx_movements_status (movement_status),
    INDEX idx_movements_actual_out (actual_out_at),
    INDEX idx_movements_actual_in (actual_in_at),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Table: movement_events (Append-only immutable event history)
CREATE TABLE IF NOT EXISTS movement_events (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    movement_id INT UNSIGNED NOT NULL,
    movement_ref VARCHAR(40) NOT NULL,
    event_type ENUM(
        'ORIGIN_OUT',
        'DESTINATION_IN',
        'DESTINATION_OUT',
        'ORIGIN_RETURN_IN',
        'EXTENSION_GRANTED',
        'CANCELLED',
        'REMARKS_ADDED'
    ) NOT NULL,
    camp_code VARCHAR(60) NOT NULL,
    operator_id INT UNSIGNED NULL,
    event_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remarks TEXT NULL,
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_mevents_movement (movement_id),
    INDEX idx_mevents_ref (movement_ref),
    INDEX idx_mevents_camp (camp_code),
    INDEX idx_mevents_time (event_time),
    FOREIGN KEY (movement_id) REFERENCES inter_camp_movements(id) ON DELETE CASCADE,
    FOREIGN KEY (operator_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Table: temporary_accommodations (24h default accommodation tracking)
CREATE TABLE IF NOT EXISTS temporary_accommodations (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    movement_id INT UNSIGNED NOT NULL UNIQUE,
    movement_ref VARCHAR(40) NOT NULL,
    camp_code VARCHAR(60) NOT NULL,
    svs_no VARCHAR(40) NOT NULL,
    `rank` VARCHAR(60) NOT NULL DEFAULT '',
    name VARCHAR(120) NOT NULL DEFAULT '',
    checkin_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    original_expires_at DATETIME NOT NULL,
    current_expires_at DATETIME NOT NULL,
    accommodation_status ENUM(
        'NOT_STARTED',
        'ACTIVE',
        'EXPIRING_SOON',
        'EXPIRED',
        'EXTENDED',
        'CLOSED'
    ) NOT NULL DEFAULT 'ACTIVE',
    billet_location VARCHAR(120) NOT NULL DEFAULT '',
    checkout_at DATETIME NULL DEFAULT NULL,
    checkin_operator_id INT UNSIGNED NULL,
    checkout_operator_id INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_accom_movement (movement_id),
    INDEX idx_accom_ref (movement_ref),
    INDEX idx_accom_camp (camp_code),
    INDEX idx_accom_status (accommodation_status),
    INDEX idx_accom_expires (current_expires_at),
    FOREIGN KEY (movement_id) REFERENCES inter_camp_movements(id) ON DELETE CASCADE,
    FOREIGN KEY (checkin_operator_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (checkout_operator_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Table: accommodation_extensions (Extension audit log)
CREATE TABLE IF NOT EXISTS accommodation_extensions (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    accommodation_id INT UNSIGNED NOT NULL,
    previous_expires_at DATETIME NOT NULL,
    new_expires_at DATETIME NOT NULL,
    extended_hours INT UNSIGNED NOT NULL,
    reason TEXT NOT NULL,
    authorized_by_name VARCHAR(120) NOT NULL,
    authorized_by_svs VARCHAR(40) NOT NULL DEFAULT '',
    authorized_by_rank VARCHAR(60) NOT NULL DEFAULT '',
    operator_id INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_ext_accom (accommodation_id),
    INDEX idx_ext_created (created_at),
    FOREIGN KEY (accommodation_id) REFERENCES temporary_accommodations(id) ON DELETE CASCADE,
    FOREIGN KEY (operator_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Table: audit_logs (System-wide append-only compliance audit trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT UNSIGNED NULL,
    username VARCHAR(60) NOT NULL DEFAULT '',
    camp_code VARCHAR(60) NOT NULL DEFAULT '',
    action_type VARCHAR(60) NOT NULL,
    entity_type VARCHAR(60) NOT NULL,
    entity_id VARCHAR(60) NOT NULL DEFAULT '',
    reference_no VARCHAR(60) NOT NULL DEFAULT '',
    details JSON NULL,
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    user_agent VARCHAR(255) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_camp (camp_code),
    INDEX idx_audit_action (action_type),
    INDEX idx_audit_entity (entity_type, entity_id),
    INDEX idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. Table: system_settings (Operational parameters)
CREATE TABLE IF NOT EXISTS system_settings (
    setting_key VARCHAR(60) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO system_settings (setting_key, setting_value, description) VALUES
    ('DEFAULT_ACCOMMODATION_HOURS', '24', 'Default duration in hours for temporary accommodation upon destination IN'),
    ('ACCOMMODATION_WARNING_HOURS', '4', 'Threshold in hours before accommodation expiry to flag as EXPIRING_SOON'),
    ('OVERDUE_MOVEMENT_HOURS', '12', 'Threshold in hours past expected arrival/return before flagging movement as OVERDUE');

-- 8. Expand role enum on users table safely
ALTER TABLE users MODIFY COLUMN role ENUM('admin', 'camp_admin', 'user', 'oc_provost', 'stakeholder') NOT NULL DEFAULT 'user';
