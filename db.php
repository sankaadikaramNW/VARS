<?php
// ============================================================
//  db.php — PDO Database Connection
//  Credentials are loaded from the .env file in the project
//  root. Copy .env.example → .env and set your values.
// ============================================================

/**
 * Parse a .env file and load values into the environment.
 * Supports: KEY=value, KEY="value", KEY='value', # comments.
 */
function loadEnv(string $path): void
{
    if (!is_file($path)) {
        die('<h2 style="font-family:sans-serif;color:#c0392b;">'
          . '.env file not found. Copy .env.example to .env and configure it.</h2>');
    }

    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);

        // Skip comments and lines without '='
        if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
            continue;
        }

        [$key, $value] = explode('=', $line, 2);
        $key   = trim($key);
        $value = trim($value);

        // Strip surrounding quotes
        if (strlen($value) >= 2
            && (($value[0] === '"'  && $value[-1] === '"')
             || ($value[0] === "'"  && $value[-1] === "'"))
        ) {
            $value = substr($value, 1, -1);
        }

        // Don't overwrite values already set in the real environment
        if (!array_key_exists($key, $_ENV) && !array_key_exists($key, $_SERVER)) {
            putenv("$key=$value");
            $_ENV[$key]    = $value;
            $_SERVER[$key] = $value;
        }
    }
}

// Load once per request
loadEnv(__DIR__ . '/.env');

function getPDO(): PDO
{
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            getenv('DB_HOST') ?: '127.0.0.1',
            getenv('DB_PORT') ?: '3306',
            getenv('DB_NAME') ?: 'vars_db'
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        try {
            $pdo = new PDO(
                $dsn,
                getenv('DB_USER') ?: 'root',
                getenv('DB_PASS') ?: '',
                $options
            );
            ensureSchema($pdo);
        } catch (PDOException $e) {
            http_response_code(500);
            die('<h2 style="font-family:sans-serif;color:#c0392b;">'
              . 'Database connection failed. Check your .env configuration.<br>'
              . '<small>' . htmlspecialchars($e->getMessage()) . '</small>'
              . '</h2>');
        }
    }

    return $pdo;
}

/**
 * Ensure required tables and columns exist for locations, user access, and camp-scoped visitors.
 */
function ensureSchema(PDO $pdo): void
{
    static $checked = false;
    if ($checked) {
        return;
    }
    $checked = true;

    // 1. Locations table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS locations (
            id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
            code       VARCHAR(60)  NOT NULL UNIQUE,
            name       VARCHAR(120) NOT NULL DEFAULT '',
            is_active  TINYINT(1)   NOT NULL DEFAULT 1,
            created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ");

    $locCount = (int)$pdo->query('SELECT COUNT(*) FROM locations')->fetchColumn();
    if ($locCount === 0) {
        $pdo->exec("
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
                ('SIG', 'Sigiriya', 1)
        ");
    }

    // 2. Users table columns (migrate full_name -> svs_no, rank, name)
    $userCols = $pdo->query('SHOW COLUMNS FROM users')->fetchAll(PDO::FETCH_COLUMN);
    $justMigratedUsers = false;

    if (in_array('full_name', $userCols, true) && !in_array('name', $userCols, true)) {
        $pdo->exec("ALTER TABLE users CHANGE COLUMN full_name name VARCHAR(120) NOT NULL DEFAULT ''");
        $userCols = $pdo->query('SHOW COLUMNS FROM users')->fetchAll(PDO::FETCH_COLUMN);
    }
    if (!in_array('svs_no', $userCols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN svs_no VARCHAR(40) NOT NULL DEFAULT '' AFTER password");
    }
    if (!in_array('rank', $userCols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN `rank` VARCHAR(60) NOT NULL DEFAULT '' AFTER svs_no");
    }
    if (!in_array('name', $userCols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN name VARCHAR(120) NOT NULL DEFAULT '' AFTER `rank`");
    }
    if (!in_array('role', $userCols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN role ENUM('admin','user') NOT NULL DEFAULT 'user' AFTER name");
        $justMigratedUsers = true;
    }
    if (!in_array('location', $userCols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN location VARCHAR(60) NOT NULL DEFAULT 'SJP' AFTER role");
        $justMigratedUsers = true;
    }
    if (!in_array('is_active', $userCols, true)) {
        $pdo->exec("ALTER TABLE users ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER location");
        $justMigratedUsers = true;
    }

    if ($justMigratedUsers) {
        $adminUser = getenv('ADMIN_USERNAME') ?: 'admin';
        $adminLoc  = getenv('ADMIN_LOCATION') ?: 'SJP';
        $stmt = $pdo->prepare("UPDATE users SET role = 'admin', location = ?, is_active = 1 WHERE username = ?");
        $stmt->execute([$adminLoc, $adminUser]);
    }

    // 3. Visitors table location & authority_by columns
    $visitorCols = $pdo->query('SHOW COLUMNS FROM visitors')->fetchAll(PDO::FETCH_COLUMN);
    if (!in_array('location', $visitorCols, true)) {
        $pdo->exec("ALTER TABLE visitors ADD COLUMN location VARCHAR(60) NOT NULL DEFAULT 'SJP' AFTER parent_camp");
        $pdo->exec("ALTER TABLE visitors ADD INDEX idx_visitors_location (location)");
    }
    if (!in_array('authority_by', $visitorCols, true)) {
        $pdo->exec("ALTER TABLE visitors ADD COLUMN authority_by VARCHAR(120) NOT NULL DEFAULT '' AFTER remarks");
    }
}

/**
 * Fetch available camp locations ordered with SJP first.
 */
function getLocations(PDO $pdo, bool $activeOnly = true): array
{
    $sql = 'SELECT id, code, name, is_active FROM locations'
         . ($activeOnly ? ' WHERE is_active = 1' : '')
         . " ORDER BY (code = 'SJP') DESC, code ASC";
    return $pdo->query($sql)->fetchAll();
}
