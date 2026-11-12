<?php
// ============================================================
//  security.php — Centralised Security Layer
//  VARS · Visiting Airmen Record System
//
//  Include this file at the very top of every PHP page,
//  BEFORE session_start().
// ============================================================

// ── 1. Secure session configuration ─────────────────────────
ini_set('session.cookie_httponly',  '1');   // block JS access to cookie
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode',  '1');   // reject unrecognised session IDs
ini_set('session.gc_maxlifetime',   '3600'); // 1-hour idle timeout

// Use Secure flag only when served over HTTPS
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

session_start();

// ── 2. Security HTTP headers ─────────────────────────────────
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; "
     . "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
     . "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
     . "font-src 'self'; "
     . "img-src 'self' data:; "
     . "connect-src 'self';");

// ── 3. Session idle timeout enforcement ──────────────────────
define('SESSION_IDLE_SECONDS', 3600);       // 1 hour

if (isset($_SESSION['_last_activity'])) {
    if (time() - $_SESSION['_last_activity'] > SESSION_IDLE_SECONDS) {
        session_unset();
        session_destroy();
        header('Location: index.php?reason=timeout');
        exit;
    }
}
$_SESSION['_last_activity'] = time();

// ── 4. CSRF helpers ──────────────────────────────────────────
define('CSRF_TOKEN_LENGTH', 32);
define('CSRF_SESSION_KEY', '_csrf_token');

/**
 * Return (and lazily create) the session CSRF token.
 */
function csrf_token(): string
{
    if (empty($_SESSION[CSRF_SESSION_KEY])) {
        $_SESSION[CSRF_SESSION_KEY] = bin2hex(random_bytes(CSRF_TOKEN_LENGTH));
    }
    return $_SESSION[CSRF_SESSION_KEY];
}

/**
 * Emit a hidden CSRF input — call inside every <form>.
 */
function csrf_field(): void
{
    echo '<input type="hidden" name="_csrf" value="' . htmlspecialchars(csrf_token()) . '">';
}

/**
 * Verify that the submitted token matches the session token.
 * On failure, responds with 403 JSON or plain text and exits.
 *
 * @param bool $json  true → JSON response (for AJAX); false → plain text
 */
function csrf_verify(bool $json = false): void
{
    $submitted = trim($_POST['_csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''));
    $expected  = csrf_token();

    if (!hash_equals($expected, $submitted)) {
        http_response_code(403);
        if ($json) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'message' => 'Invalid security token. Please reload the page.']);
        } else {
            echo 'Invalid security token. <a href="index.php">Go back</a>';
        }
        exit;
    }
}

// ── 5. Brute-force / rate-limit helpers ──────────────────────
define('LOGIN_MAX_ATTEMPTS',   5);     // max failures before lockout
define('LOGIN_LOCKOUT_SECONDS', 300);  // 5-minute lockout window

/**
 * Record a failed login for the given username.
 */
function login_record_failure(string $username): void
{
    $key = '_login_fail_' . md5($username);
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 0, 'first' => time()];
    }
    // Reset window if the lockout period has passed
    if (time() - $_SESSION[$key]['first'] > LOGIN_LOCKOUT_SECONDS) {
        $_SESSION[$key] = ['count' => 0, 'first' => time()];
    }
    $_SESSION[$key]['count']++;
}

/**
 * Returns true if the username is currently locked out.
 */
function login_is_locked(string $username): bool
{
    $key = '_login_fail_' . md5($username);
    if (!isset($_SESSION[$key])) {
        return false;
    }
    // Expire the window
    if (time() - $_SESSION[$key]['first'] > LOGIN_LOCKOUT_SECONDS) {
        unset($_SESSION[$key]);
        return false;
    }
    return $_SESSION[$key]['count'] >= LOGIN_MAX_ATTEMPTS;
}

/**
 * How many seconds remain in a lockout (0 if not locked).
 */
function login_lockout_remaining(string $username): int
{
    $key = '_login_fail_' . md5($username);
    if (!isset($_SESSION[$key]) || $_SESSION[$key]['count'] < LOGIN_MAX_ATTEMPTS) {
        return 0;
    }
    $elapsed = time() - $_SESSION[$key]['first'];
    return max(0, LOGIN_LOCKOUT_SECONDS - $elapsed);
}

/**
 * Clear failure counters on successful login.
 */
function login_clear_failures(string $username): void
{
    unset($_SESSION['_login_fail_' . md5($username)]);
}

// ── 6. Auth guard helpers ────────────────────────────────────
/**
 * Redirect to login if no authenticated session exists.
 */
function require_auth(): void
{
    if (empty($_SESSION['user_id'])) {
        header('Location: index.php');
        exit;
    }
}

/**
 * Enforce admin role for privileged actions.
 */
function require_admin(bool $json = true): void
{
    if (($_SESSION['role'] ?? 'user') !== 'admin') {
        http_response_code(403);
        if ($json) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'message' => 'Administrator access required.']);
        } else {
            echo 'Administrator access required.';
        }
        exit;
    }
}

// ── 7. Allowed POST actions whitelist ────────────────────────
define('ALLOWED_ACTIONS', [
    'add_visitor',
    'mark_out',
    'delete_visitor',
    'create_user',
    'update_user',
    'delete_user',
    'create_location',
    'edit_location',
    'toggle_location',
    'delete_location',
]);

/**
 * Validate the POSTed action field against the whitelist.
 * Returns the action string or exits with 400.
 */
function validated_action(): string
{
    $action = trim($_POST['action'] ?? '');
    if (!in_array($action, ALLOWED_ACTIONS, true)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Unknown action.']);
        exit;
    }
    return $action;
}

// ── 8. Input helpers ─────────────────────────────────────────
/**
 * Sanitise a plain-text POST value: trim + strip tags.
 */
function post_str(string $key, int $maxLen = 255): string
{
    return mb_substr(strip_tags(trim($_POST[$key] ?? '')), 0, $maxLen);
}

/**
 * Sanitise a positive integer POST value.
 */
function post_int(string $key): int
{
    return max(0, (int)($_POST[$key] ?? 0));
}

