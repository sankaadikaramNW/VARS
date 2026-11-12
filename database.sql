-- ============================================================
--  VARS - Visiting Airmen Record System
--  Database Setup Script
--  Run this file once to initialise the database.
-- ============================================================

CREATE DATABASE IF NOT EXISTS vars
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE vars;

-- -------------------------------------------------------
--  Table: locations  (camp / base locations)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS locations (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    code        VARCHAR(60)     NOT NULL UNIQUE,
    name        VARCHAR(120)    NOT NULL DEFAULT '',
    is_active   TINYINT(1)      NOT NULL DEFAULT 1,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO locations (code, name, is_active) VALUES
    ('SJP', 'Sri Jayewardenepura', 1),
    ('KAT', 'Katunayake', 1),
    ('RMA', 'Ratmalana', 1),
    ('CMB', 'Colombo', 1),
    ('CBY', 'China Bay', 1),
    ('VAV', 'Vavuniya', 1),
    ('HIN', 'Hingurakgoda', 1),
    ('AMP', 'Ampara', 1),
    ('BTT', 'Batticaloa', 1),
    ('SIG', 'Sigiriya', 1);

-- -------------------------------------------------------
--  Table: users  (security police login accounts)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    username    VARCHAR(60)     NOT NULL UNIQUE,
    password    VARCHAR(255)    NOT NULL,   -- bcrypt hash
    svs_no      VARCHAR(40)     NOT NULL DEFAULT '',
    `rank`      VARCHAR(60)     NOT NULL DEFAULT '',
    name        VARCHAR(120)    NOT NULL DEFAULT '',
    role        ENUM('admin','user') NOT NULL DEFAULT 'user',
    location    VARCHAR(60)     NOT NULL DEFAULT 'SJP',
    is_active   TINYINT(1)      NOT NULL DEFAULT 1,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------
--  Default admin account
--  DO NOT hardcode a password here.
--  Run seed.php after importing this schema to create the
--  admin account using the credentials in your .env file.
-- -------------------------------------------------------

-- -------------------------------------------------------
--  Table: visitors
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS visitors (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    svs_no      VARCHAR(40)     NOT NULL,
    `rank`      VARCHAR(60)     NOT NULL,
    name        VARCHAR(120)    NOT NULL,
    nic_no      VARCHAR(30)     NOT NULL,
    parent_camp VARCHAR(120)    NOT NULL,
    location    VARCHAR(60)     NOT NULL DEFAULT 'SJP',
    remarks     TEXT,
    authority_by VARCHAR(120)   NOT NULL DEFAULT '',
    in_datetime DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    out_datetime DATETIME       NULL DEFAULT NULL,
    created_by  INT UNSIGNED    NULL,
    PRIMARY KEY (id),
    INDEX idx_visitors_location (location),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

