<?php
// ============================================================
//  seed.php — One-time database seeder
//  Run from CLI:  php seed.php
//  Creates the admin user defined in .env.
//  Safe to re-run — skips if the username already exists.
// ============================================================

require_once __DIR__ . '/db.php';   // also loads .env

$username  = getenv('ADMIN_USERNAME') ?: 'admin';
$password  = getenv('ADMIN_PASSWORD');
$name      = getenv('ADMIN_FULL_NAME') ?: 'Administrator';
$location  = getenv('ADMIN_LOCATION') ?: 'SJP';

if (!$password || $password === 'Change_Me_Now!') {
    fwrite(STDERR,
        "[ERROR] Set a real ADMIN_PASSWORD in your .env before seeding.\n"
      . "        The placeholder 'Change_Me_Now!' is not allowed.\n"
    );
    exit(1);
}

$pdo = getPDO();

// Check if user already exists
$stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? LIMIT 1');
$stmt->execute([$username]);

if ($stmt->fetch()) {
    echo "[SKIP]  User '{$username}' already exists — nothing changed.\n";
    exit(0);
}

$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

$stmt = $pdo->prepare(
    'INSERT INTO users (username, password, svs_no, `rank`, name, role, location, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)'
);
$stmt->execute([$username, $hash, '', '', $name, 'admin', $location]);

echo "[OK]    Admin user '{$username}' created successfully.\n";
echo "        Remember to delete or restrict seed.php in production.\n";

