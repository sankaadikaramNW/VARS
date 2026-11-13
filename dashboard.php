<?php
// ============================================================
//  dashboard.php — Main Dashboard
//  VARS · Visiting Airmen Record System
// ============================================================
require_once __DIR__ . '/security.php';

// Auth guard
require_auth();

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/movement_service.php';
$pdo = getPDO();

// 4. Logout (handle early)
if (($_GET['action'] ?? '') === 'logout') {
    session_destroy();
    header('Location: index.php');
    exit;
}

// ── Verify active user session & sync role/location ──────────
$meStmt = $pdo->prepare('SELECT id, username, svs_no, `rank`, name, role, location, is_active FROM users WHERE id = ? LIMIT 1');
$meStmt->execute([$_SESSION['user_id']]);
$me = $meStmt->fetch();

if (!$me || !(int)$me['is_active']) {
    session_unset();
    session_destroy();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Your account access has been disabled.']);
    } else {
        header('Location: index.php?reason=disabled');
    }
    exit;
}

$_SESSION['role']      = $me['role'];
$_SESSION['location']  = strtoupper($me['location']);
$_SESSION['full_name'] = trim(($me['rank'] ? $me['rank'] . ' ' : '') . ($me['name'] ?: $me['username']));

$userRole        = $me['role'];
$isAdmin         = ($userRole === 'admin');
$isProvost       = ($userRole === 'oc_provost' || $isAdmin);
$isCampAdmin     = ($userRole === 'camp_admin' || $isAdmin);
$currentLocation = $_SESSION['location'];

// ── POST handlers (AJAX-friendly JSON responses) ─────────────

// 1. Add new visitor (tagged with active camp location, or selected camp for admin)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add_visitor') {
    csrf_verify(true);
    header('Content-Type: application/json');

    $fields = ['svs_no','rank','name','nic_no','parent_camp','remarks','authority_by'];
    $data   = [];
    foreach ($fields as $f) {
        $data[$f] = post_str($f, $f === 'remarks' ? 1000 : 120);
    }

    if ($data['svs_no'] === '' || $data['name'] === '') {
        echo json_encode(['success' => false, 'message' => 'SVS No and Name are required.']);
        exit;
    }

    $targetLocation = $currentLocation;
    if ($isAdmin && !empty($_POST['location'])) {
        $requestedLoc = strtoupper(post_str('location', 60));
        $locCheck = $pdo->prepare('SELECT code FROM locations WHERE code = ? LIMIT 1');
        $locCheck->execute([$requestedLoc]);
        if (!$locCheck->fetch()) {
            echo json_encode(['success' => false, 'message' => 'Selected camp location does not exist.']);
            exit;
        }
        $targetLocation = $requestedLoc;
    }

    $sql = 'INSERT INTO visitors (svs_no, `rank`, name, nic_no, parent_camp, location, remarks, authority_by, created_by)
            VALUES (:svs_no, :rank, :name, :nic_no, :parent_camp, :location, :remarks, :authority_by, :uid)';
    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':svs_no'       => $data['svs_no'],
        ':rank'         => $data['rank'],
        ':name'         => $data['name'],
        ':nic_no'       => $data['nic_no'],
        ':parent_camp'  => $data['parent_camp'],
        ':location'     => $targetLocation,
        ':remarks'      => $data['remarks'],
        ':authority_by' => $data['authority_by'],
        ':uid'          => $_SESSION['user_id'],
    ]);

    echo json_encode(['success' => true, 'message' => "Visitor added to {$targetLocation}."]);
    exit;
}

// 2. Mark visitor out (admin can mark out any camp; user scoped to active camp)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'mark_out') {
    csrf_verify(true);
    header('Content-Type: application/json');
    $id = post_int('id');

    if ($id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid record ID.']);
        exit;
    }

    // Use provided datetime or fall back to NOW()
    $rawDatetime = trim($_POST['out_datetime'] ?? '');
    if ($rawDatetime !== '') {
        $dt = DateTime::createFromFormat('Y-m-d\TH:i', $rawDatetime);
        $outDatetime = $dt ? $dt->format('Y-m-d H:i:s') : null;
    } else {
        $outDatetime = null;
    }

    if ($isAdmin) {
        if ($outDatetime) {
            $stmt = $pdo->prepare('UPDATE visitors SET out_datetime = ? WHERE id = ? AND out_datetime IS NULL');
            $stmt->execute([$outDatetime, $id]);
        } else {
            $stmt = $pdo->prepare('UPDATE visitors SET out_datetime = NOW() WHERE id = ? AND out_datetime IS NULL');
            $stmt->execute([$id]);
        }
    } else {
        if ($outDatetime) {
            $stmt = $pdo->prepare('UPDATE visitors SET out_datetime = ? WHERE id = ? AND location = ? AND out_datetime IS NULL');
            $stmt->execute([$outDatetime, $id, $currentLocation]);
        } else {
            $stmt = $pdo->prepare('UPDATE visitors SET out_datetime = NOW() WHERE id = ? AND location = ? AND out_datetime IS NULL');
            $stmt->execute([$id, $currentLocation]);
        }
    }

    if ($stmt->rowCount() > 0) {
        echo json_encode(['success' => true, 'message' => 'Visitor marked as out.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Record not found or already marked out.']);
    }
    exit;
}

// 3. Delete visitor (admin any camp; user scoped to active camp)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_visitor') {
    csrf_verify(true);
    header('Content-Type: application/json');
    $id = post_int('id');

    if ($id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid record ID.']);
        exit;
    }

    if ($isAdmin) {
        $stmt = $pdo->prepare('DELETE FROM visitors WHERE id = ?');
        $stmt->execute([$id]);
    } else {
        $stmt = $pdo->prepare('DELETE FROM visitors WHERE id = ? AND location = ?');
        $stmt->execute([$id, $currentLocation]);
    }
    echo json_encode(['success' => true, 'message' => 'Record deleted.']);
    exit;
}

// ── Admin-only POST handlers ─────────────────────────────────

// 5. Create user account
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_user') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $username  = post_str('username', 60);
    $svsNo     = post_str('svs_no', 40);
    $rank      = post_str('rank', 60);
    $name      = post_str('name', 120);
    $password  = trim($_POST['password'] ?? '');
    $role      = ($_POST['role'] ?? 'user') === 'admin' ? 'admin' : 'user';
    $location  = strtoupper(post_str('location', 60));
    $isActive  = (int)($_POST['is_active'] ?? 1) ? 1 : 0;

    if ($svsNo === '' || $name === '') {
        echo json_encode(['success' => false, 'message' => 'SVS No and Name are required.']);
        exit;
    }
    if (!preg_match('/^[a-zA-Z0-9._-]{3,60}$/', $username)) {
        echo json_encode(['success' => false, 'message' => 'Username must be 3–60 characters (letters, numbers, ., _, -).']);
        exit;
    }
    if (strlen($password) < 6) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters.']);
        exit;
    }
    if ($location === '') {
        echo json_encode(['success' => false, 'message' => 'Please select a location.']);
        exit;
    }

    $locCheck = $pdo->prepare('SELECT code FROM locations WHERE code = ? LIMIT 1');
    $locCheck->execute([$location]);
    if (!$locCheck->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Selected location does not exist.']);
        exit;
    }

    $dup = $pdo->prepare('SELECT id FROM users WHERE username = ? LIMIT 1');
    $dup->execute([$username]);
    if ($dup->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Username already exists.']);
        exit;
    }

    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $pdo->prepare('INSERT INTO users (username, password, svs_no, `rank`, name, role, location, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$username, $hash, $svsNo, $rank, $name, $role, $location, $isActive]);
    $newId = (int)$pdo->lastInsertId();

    echo json_encode([
        'success' => true,
        'message' => "Account '{$username}' created for {$location}.",
        'user'    => [
            'id'        => $newId,
            'username'  => $username,
            'svs_no'    => $svsNo,
            'rank'      => $rank,
            'name'      => $name,
            'role'      => $role,
            'location'  => $location,
            'is_active' => $isActive,
        ],
    ]);
    exit;
}

// 6. Update user location, role, access, or password
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_user') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $id = post_int('id');
    if ($id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid user ID.']);
        exit;
    }

    $targetStmt = $pdo->prepare('SELECT id, username, role, location, is_active FROM users WHERE id = ? LIMIT 1');
    $targetStmt->execute([$id]);
    $target = $targetStmt->fetch();
    if (!$target) {
        echo json_encode(['success' => false, 'message' => 'User not found.']);
        exit;
    }

    $isSelf   = ($id === (int)$_SESSION['user_id']);
    $location = isset($_POST['location']) ? strtoupper(post_str('location', 60)) : $target['location'];
    $role     = isset($_POST['role']) ? (($_POST['role'] === 'admin') ? 'admin' : 'user') : $target['role'];
    $isActive = isset($_POST['is_active']) ? ((int)$_POST['is_active'] ? 1 : 0) : (int)$target['is_active'];
    $newPass  = trim($_POST['password'] ?? '');

    if ($isSelf && ($isActive === 0 || $role !== 'admin')) {
        echo json_encode(['success' => false, 'message' => 'You cannot disable or demote your own admin account.']);
        exit;
    }

    $locCheck = $pdo->prepare('SELECT code FROM locations WHERE code = ? LIMIT 1');
    $locCheck->execute([$location]);
    if (!$locCheck->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Invalid location selected.']);
        exit;
    }

    if ($newPass !== '') {
        if (strlen($newPass) < 6) {
            echo json_encode(['success' => false, 'message' => 'New password must be at least 6 characters.']);
            exit;
        }
        $hash = password_hash($newPass, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $pdo->prepare('UPDATE users SET location = ?, role = ?, is_active = ?, password = ? WHERE id = ?');
        $stmt->execute([$location, $role, $isActive, $hash, $id]);
    } else {
        $stmt = $pdo->prepare('UPDATE users SET location = ?, role = ?, is_active = ? WHERE id = ?');
        $stmt->execute([$location, $role, $isActive, $id]);
    }

    if ($isSelf) {
        $_SESSION['location'] = $location;
    }

    echo json_encode([
        'success'     => true,
        'message'     => "Updated {$target['username']} ({$location}).",
        'reload'      => $isSelf && ($location !== $currentLocation),
    ]);
    exit;
}

// 7. Delete user
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_user') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $id = post_int('id');
    if ($id <= 0 || $id === (int)$_SESSION['user_id']) {
        echo json_encode(['success' => false, 'message' => 'Cannot delete this account.']);
        exit;
    }

    $stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
    $stmt->execute([$id]);
    echo json_encode(['success' => true, 'message' => 'User account deleted.']);
    exit;
}

// 8. Create camp location
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_location') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $code = strtoupper(post_str('code', 20));
    $name = post_str('name', 120);

    if (!preg_match('/^[A-Z0-9_-]{2,20}$/', $code)) {
        echo json_encode(['success' => false, 'message' => 'Location code must be 2–20 uppercase letters/numbers.']);
        exit;
    }

    $dup = $pdo->prepare('SELECT id FROM locations WHERE code = ? LIMIT 1');
    $dup->execute([$code]);
    if ($dup->fetch()) {
        echo json_encode(['success' => false, 'message' => "Location '{$code}' already exists."]);
        exit;
    }

    $stmt = $pdo->prepare('INSERT INTO locations (code, name, is_active) VALUES (?, ?, 1)');
    $stmt->execute([$code, $name]);

    echo json_encode([
        'success'  => true,
        'message'  => "Location '{$code}' added.",
        'location' => ['id' => (int)$pdo->lastInsertId(), 'code' => $code, 'name' => $name, 'is_active' => 1],
    ]);
    exit;
}

// 8b. Edit camp location
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'edit_location') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $id   = post_int('id');
    $code = strtoupper(post_str('code', 20));
    $name = post_str('name', 120);

    if ($id <= 0) {
        echo json_encode(['success' => false, 'message' => 'Invalid location ID.']);
        exit;
    }
    if (!preg_match('/^[A-Z0-9_-]{2,20}$/', $code)) {
        echo json_encode(['success' => false, 'message' => 'Location code must be 2–20 uppercase letters/numbers.']);
        exit;
    }

    $oldStmt = $pdo->prepare('SELECT id, code, name, is_active FROM locations WHERE id = ? LIMIT 1');
    $oldStmt->execute([$id]);
    $oldLoc = $oldStmt->fetch();

    if (!$oldLoc) {
        echo json_encode(['success' => false, 'message' => 'Location not found.']);
        exit;
    }

    $oldCode = strtoupper($oldLoc['code']);
    if ($code !== $oldCode) {
        $dup = $pdo->prepare('SELECT id FROM locations WHERE code = ? AND id != ? LIMIT 1');
        $dup->execute([$code, $id]);
        if ($dup->fetch()) {
            echo json_encode(['success' => false, 'message' => "Location '{$code}' already exists."]);
            exit;
        }
    }

    $pdo->beginTransaction();
    try {
        $upd = $pdo->prepare('UPDATE locations SET code = ?, name = ? WHERE id = ?');
        $upd->execute([$code, $name, $id]);

        if ($code !== $oldCode) {
            $pdo->prepare('UPDATE users SET location = ? WHERE location = ?')->execute([$code, $oldCode]);
            $pdo->prepare('UPDATE visitors SET location = ? WHERE location = ?')->execute([$code, $oldCode]);
            if ($oldCode === $currentLocation) {
                $_SESSION['location'] = $code;
                $currentLocation      = $code;
            }
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        echo json_encode(['success' => false, 'message' => 'Failed to update location.']);
        exit;
    }

    echo json_encode([
        'success'  => true,
        'message'  => "Location '{$code}' updated.",
        'old_code' => $oldCode,
        'location' => [
            'id'        => $id,
            'code'      => $code,
            'name'      => $name,
            'is_active' => (int)$oldLoc['is_active'],
        ],
    ]);
    exit;
}

// 9. Toggle location active status
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'toggle_location') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $id       = post_int('id');
    $isActive = (int)($_POST['is_active'] ?? 1) ? 1 : 0;

    $locStmt = $pdo->prepare('SELECT code FROM locations WHERE id = ? LIMIT 1');
    $locStmt->execute([$id]);
    $loc = $locStmt->fetch();

    if (!$loc) {
        echo json_encode(['success' => false, 'message' => 'Location not found.']);
        exit;
    }
    if ($isActive === 0 && strtoupper($loc['code']) === $currentLocation) {
        echo json_encode(['success' => false, 'message' => 'Cannot disable your currently active location.']);
        exit;
    }

    $stmt = $pdo->prepare('UPDATE locations SET is_active = ? WHERE id = ?');
    $stmt->execute([$isActive, $id]);
    echo json_encode(['success' => true, 'message' => "Location '{$loc['code']}' updated."]);
    exit;
}

// 10. Delete location
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_location') {
    csrf_verify(true);
    require_admin(true);
    header('Content-Type: application/json');

    $id = post_int('id');
    $locStmt = $pdo->prepare('SELECT code FROM locations WHERE id = ? LIMIT 1');
    $locStmt->execute([$id]);
    $loc = $locStmt->fetch();

    if (!$loc) {
        echo json_encode(['success' => false, 'message' => 'Location not found.']);
        exit;
    }
    if (strtoupper($loc['code']) === 'SJP' || strtoupper($loc['code']) === $currentLocation) {
        echo json_encode(['success' => false, 'message' => 'Cannot delete default or active location.']);
        exit;
    }

    $inUse = $pdo->prepare('SELECT COUNT(*) FROM users WHERE location = ?');
    $inUse->execute([$loc['code']]);
    if ((int)$inUse->fetchColumn() > 0) {
        echo json_encode(['success' => false, 'message' => 'Reassign users from this location before deleting.']);
        exit;
    }

    $stmt = $pdo->prepare('DELETE FROM locations WHERE id = ?');
    $stmt->execute([$id]);
    echo json_encode(['success' => true, 'message' => "Location '{$loc['code']}' deleted."]);
    exit;
}

// ── Inter-Camp Movement & Accommodation POST Handlers ─────────

// 11. Lookup personnel by SVS number
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'lookup_personnel') {
    csrf_verify(true);
    header('Content-Type: application/json');
    $svsNo = post_str('svs_no', 40);
    $person = lookupPersonnel($pdo, $svsNo);
    echo json_encode(['success' => true, 'personnel' => $person]);
    exit;
}

// 12. Register Origin OUT (Stage A)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register_origin_out') {
    csrf_verify(true);
    header('Content-Type: application/json');
    try {
        $result = registerOriginOut($pdo, $_POST, (int)$_SESSION['user_id'], $currentLocation, $isAdmin);
        echo json_encode(['success' => true, 'message' => "Movement {$result['movement_ref']} registered. Serviceman dispatched.", 'data' => $result]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit;
}

// 13. Confirm Destination IN (Stage B)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'confirm_destination_in') {
    csrf_verify(true);
    header('Content-Type: application/json');
    try {
        $movementId = post_int('movement_id');
        $remarks    = post_str('remarks', 500);
        $billet     = post_str('billet', 120);
        $result = confirmDestinationIn($pdo, $movementId, (int)$_SESSION['user_id'], $currentLocation, $isAdmin, $remarks, $billet);
        echo json_encode(['success' => true, 'message' => "Serviceman checked IN at destination. 24h temporary accommodation activated.", 'data' => $result]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit;
}

// 14. Register Destination OUT (Stage D)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register_destination_out') {
    csrf_verify(true);
    header('Content-Type: application/json');
    try {
        $movementId = post_int('movement_id');
        $remarks    = post_str('remarks', 500);
        $result = registerDestinationOut($pdo, $movementId, (int)$_SESSION['user_id'], $currentLocation, $isAdmin, $remarks);
        echo json_encode(['success' => true, 'message' => "Serviceman checked OUT from destination camp. Returning to home base.", 'data' => $result]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit;
}

// 15. Confirm Origin Return IN (Stage E)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'confirm_origin_return_in') {
    csrf_verify(true);
    header('Content-Type: application/json');
    try {
        $movementId = post_int('movement_id');
        $remarks    = post_str('remarks', 500);
        $result = confirmOriginReturnIn($pdo, $movementId, (int)$_SESSION['user_id'], $currentLocation, $isAdmin, $remarks);
        echo json_encode(['success' => true, 'message' => "Serviceman returned to parent base. Movement lifecycle COMPLETED.", 'data' => $result]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit;
}

// 16. Extend Temporary Accommodation Validity
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'extend_accommodation') {
    csrf_verify(true);
    header('Content-Type: application/json');
    try {
        $accomId   = post_int('accommodation_id');
        $hours     = post_int('additional_hours');
        $reason    = post_str('reason', 500);
        $authName  = post_str('authorized_by_name', 120);
        $authSvs   = post_str('authorized_by_svs', 40);
        $authRank  = post_str('authorized_by_rank', 60);

        $result = extendAccommodation($pdo, $accomId, (int)$_SESSION['user_id'], $currentLocation, $isAdmin, $hours, $reason, $authName, $authSvs, $authRank);
        echo json_encode(['success' => true, 'message' => "Accommodation extended until {$result['new_expiry']}.", 'data' => $result]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit;
}

// 17. Fetch Movement Chronological Event History
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'get_movement_history') {
    csrf_verify(true);
    header('Content-Type: application/json');
    $movId = post_int('movement_id');
    $history = fetchMovementHistory($pdo, $movId);
    echo json_encode(['success' => true, 'history' => $history]);
    exit;
}

// ── Fetch visitors (Admin: all camps or selected camp; User: active camp ONLY) ──
$search    = trim($_GET['q'] ?? '');
$status    = $_GET['status'] ?? 'all';   // all | in | out
if (!in_array($status, ['all', 'in', 'out'], true)) {
    $status = 'all';
}
$locFilter = $isAdmin ? strtoupper(trim($_GET['loc'] ?? 'ALL')) : $currentLocation;
if ($locFilter === '') {
    $locFilter = $isAdmin ? 'ALL' : $currentLocation;
}

$baseSQL = 'SELECT v.*, u.name AS recorded_by
            FROM visitors v
            LEFT JOIN users u ON u.id = v.created_by';
$where   = [];
$params  = [];

if (!$isAdmin || $locFilter !== 'ALL') {
    $targetLoc          = $isAdmin ? $locFilter : $currentLocation;
    $where[]            = 'v.location = :location';
    $params[':location'] = $targetLoc;
}

if ($search !== '') {
    $where[]       = '(v.svs_no LIKE :q1 OR v.name LIKE :q2 OR v.nic_no LIKE :q3 OR v.parent_camp LIKE :q4 OR v.location LIKE :q5 OR v.authority_by LIKE :q6)';
    $params[':q1'] = '%' . $search . '%';
    $params[':q2'] = '%' . $search . '%';
    $params[':q3'] = '%' . $search . '%';
    $params[':q4'] = '%' . $search . '%';
    $params[':q5'] = '%' . $search . '%';
    $params[':q6'] = '%' . $search . '%';
}
if ($status === 'in') {
    $where[] = 'v.out_datetime IS NULL';
} elseif ($status === 'out') {
    $where[] = 'v.out_datetime IS NOT NULL';
}

$sql  = $baseSQL . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY v.id DESC';
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$visitors = $stmt->fetchAll();

foreach ($visitors as &$vRow) {
    $vRow['in_date_fmt']  = date('d M Y', strtotime($vRow['in_datetime']));
    $vRow['in_time_fmt']  = date('H:i:s', strtotime($vRow['in_datetime']));
    $vRow['out_date_fmt'] = !empty($vRow['out_datetime']) ? date('d M Y', strtotime($vRow['out_datetime'])) : '';
    $vRow['out_time_fmt'] = !empty($vRow['out_datetime']) ? date('H:i:s', strtotime($vRow['out_datetime'])) : '';
}
unset($vRow);

// Summary counts (Admin: all camps or selected camp; User: active camp ONLY)
if (!$isAdmin || $locFilter !== 'ALL') {
    $countStmt = $pdo->prepare('SELECT
        COUNT(*) AS total,
        COALESCE(SUM(out_datetime IS NULL), 0) AS still_in,
        COALESCE(SUM(out_datetime IS NOT NULL), 0) AS checked_out
        FROM visitors
        WHERE location = ?');
    $countStmt->execute([$isAdmin ? $locFilter : $currentLocation]);
} else {
    $countStmt = $pdo->query('SELECT
        COUNT(*) AS total,
        COALESCE(SUM(out_datetime IS NULL), 0) AS still_in,
        COALESCE(SUM(out_datetime IS NOT NULL), 0) AS checked_out
        FROM visitors');
}
$counts = $countStmt->fetch();

// Live JSON sync endpoint for auto-updating in/out camp records
if (($_GET['ajax'] ?? '') === 'visitors') {
    header('Content-Type: application/json');
    echo json_encode([
        'success'      => true,
        'visitors'     => $visitors,
        'counts'       => [
            'total'       => (int)$counts['total'],
            'still_in'    => (int)$counts['still_in'],
            'checked_out' => (int)$counts['checked_out'],
        ],
        'loc_filter'   => $locFilter,
        'refreshed_at' => date('d M Y, H:i:s'),
    ], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    exit;
}

// Live JSON sync endpoint for movements
if (($_GET['ajax'] ?? '') === 'movements') {
    header('Content-Type: application/json');
    refreshAccommodationStatuses($pdo);
    $movList = fetchMovementsList($pdo, $isAdmin, $currentLocation, $_GET);
    $pending = fetchPendingArrivalsList($pdo, $isAdmin, $currentLocation);
    $mCounts = fetchMovementCounts($pdo, $isAdmin, $currentLocation);
    echo json_encode([
        'success'          => true,
        'movements'        => $movList,
        'pending_arrivals' => $pending,
        'counts'           => $mCounts,
        'refreshed_at'     => date('d M Y, H:i:s'),
    ], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    exit;
}

// Live JSON sync endpoint for accommodations
if (($_GET['ajax'] ?? '') === 'accommodations') {
    header('Content-Type: application/json');
    refreshAccommodationStatuses($pdo);
    $accomList = fetchAccommodationsList($pdo, $isAdmin, $currentLocation, $_GET);
    $mCounts   = fetchMovementCounts($pdo, $isAdmin, $currentLocation);
    echo json_encode([
        'success'        => true,
        'accommodations' => $accomList,
        'counts'         => $mCounts,
        'refreshed_at'   => date('d M Y, H:i:s'),
    ], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    exit;
}

// JSON endpoint for audit logs
if (($_GET['ajax'] ?? '') === 'audit_logs') {
    header('Content-Type: application/json');
    $auditLogs = fetchAuditLogsList($pdo, $isAdmin, $currentLocation, $_GET);
    echo json_encode([
        'success'    => true,
        'audit_logs' => $auditLogs,
    ], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    exit;
}

/**
 * Format duration between check-in and check-out timestamps.
 */
function formatVisitDuration(?string $inDt, ?string $outDt): string
{
    if (empty($inDt) || empty($outDt)) {
        return 'Still Inside';
    }
    $diff = max(0, strtotime($outDt) - strtotime($inDt));
    $days = intdiv($diff, 86400);
    $hrs  = intdiv($diff % 86400, 3600);
    $mins = intdiv($diff % 3600, 60);
    $parts = [];
    if ($days > 0) $parts[] = $days . 'd';
    if ($hrs > 0)  $parts[] = $hrs . 'h';
    $parts[] = $mins . 'm';
    return implode(' ', $parts);
}

/**
 * Build full summary report rows, totals, and per-camp breakdown.
 * Non-admin users are always scoped strictly to $currentLocation.
 */
function buildVisitorReport(PDO $pdo, bool $isAdmin, string $currentLocation, array $input): array
{
    $loc = $isAdmin ? strtoupper(trim((string)($input['loc'] ?? 'ALL'))) : $currentLocation;
    if ($loc === '') {
        $loc = $isAdmin ? 'ALL' : $currentLocation;
    }

    $status    = $input['status'] ?? 'all';
    if (!in_array($status, ['all', 'in', 'out'], true)) {
        $status = 'all';
    }
    $dateField = $input['date_field'] ?? 'any';
    if (!in_array($dateField, ['any', 'in', 'out'], true)) {
        $dateField = 'any';
    }
    $q         = trim((string)($input['q'] ?? ''));
    $fromDate  = trim((string)($input['from_date'] ?? ''));
    $fromTime  = trim((string)($input['from_time'] ?? ''));
    $toDate    = trim((string)($input['to_date'] ?? ''));
    $toTime    = trim((string)($input['to_time'] ?? ''));

    $fromDt = null;
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $fromDate)) {
        $t = preg_match('/^\d{2}:\d{2}$/', $fromTime) ? $fromTime . ':00' : '00:00:00';
        $fromDt = $fromDate . ' ' . $t;
    }
    $toDt = null;
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $toDate)) {
        $t = preg_match('/^\d{2}:\d{2}$/', $toTime) ? $toTime . ':59' : '23:59:59';
        $toDt = $toDate . ' ' . $t;
    }

    $where  = [];
    $params = [];

    if (!$isAdmin || $loc !== 'ALL') {
        $where[]             = 'v.location = :r_loc';
        $params[':r_loc']    = $isAdmin ? $loc : $currentLocation;
    }

    if ($status === 'in') {
        $where[] = 'v.out_datetime IS NULL';
    } elseif ($status === 'out') {
        $where[] = 'v.out_datetime IS NOT NULL';
    }

    if ($q !== '') {
        $where[]         = '(v.svs_no LIKE :rq1 OR v.name LIKE :rq2 OR v.nic_no LIKE :rq3 OR v.parent_camp LIKE :rq4 OR v.location LIKE :rq5 OR v.authority_by LIKE :rq6 OR v.remarks LIKE :rq7)';
        $params[':rq1']  = '%' . $q . '%';
        $params[':rq2']  = '%' . $q . '%';
        $params[':rq3']  = '%' . $q . '%';
        $params[':rq4']  = '%' . $q . '%';
        $params[':rq5']  = '%' . $q . '%';
        $params[':rq6']  = '%' . $q . '%';
        $params[':rq7']  = '%' . $q . '%';
    }

    if ($fromDt !== null || $toDt !== null) {
        $rangeCond = function (string $col, string $prefix) use ($fromDt, $toDt, &$params): string {
            $sub = [];
            if ($fromDt !== null) {
                $sub[] = "{$col} >= :{$prefix}_from";
                $params[":{$prefix}_from"] = $fromDt;
            }
            if ($toDt !== null) {
                $sub[] = "{$col} <= :{$prefix}_to";
                $params[":{$prefix}_to"] = $toDt;
            }
            return '(' . implode(' AND ', $sub) . ')';
        };

        if ($dateField === 'in') {
            $where[] = $rangeCond('v.in_datetime', 'in');
        } elseif ($dateField === 'out') {
            $where[] = '(v.out_datetime IS NOT NULL AND ' . $rangeCond('v.out_datetime', 'out') . ')';
        } else {
            $inExpr  = $rangeCond('v.in_datetime', 'any_in');
            $outExpr = '(v.out_datetime IS NOT NULL AND ' . $rangeCond('v.out_datetime', 'any_out') . ')';
            $where[] = "({$inExpr} OR {$outExpr})";
        }
    }

    $whereSql = $where ? (' WHERE ' . implode(' AND ', $where)) : '';

    $rowSql = 'SELECT v.*, u.name AS recorded_by
               FROM visitors v
               LEFT JOIN users u ON u.id = v.created_by'
            . $whereSql
            . ' ORDER BY v.id DESC';
    $rowStmt = $pdo->prepare($rowSql);
    $rowStmt->execute($params);
    $rows = $rowStmt->fetchAll();

    $total      = count($rows);
    $stillIn    = 0;
    $checkedOut = 0;
    $campMap    = [];

    foreach ($rows as &$r) {
        $isOut = !empty($r['out_datetime']);
        if ($isOut) {
            $checkedOut++;
        } else {
            $stillIn++;
        }

        $camp = strtoupper($r['location'] ?: 'SJP');
        if (!isset($campMap[$camp])) {
            $campMap[$camp] = ['location' => $camp, 'total' => 0, 'still_in' => 0, 'checked_out' => 0];
        }
        $campMap[$camp]['total']++;
        if ($isOut) {
            $campMap[$camp]['checked_out']++;
        } else {
            $campMap[$camp]['still_in']++;
        }

        $r['in_date_fmt']  = date('d M Y', strtotime($r['in_datetime']));
        $r['in_time_fmt']  = date('H:i:s', strtotime($r['in_datetime']));
        $r['out_date_fmt'] = $isOut ? date('d M Y', strtotime($r['out_datetime'])) : '';
        $r['out_time_fmt'] = $isOut ? date('H:i:s', strtotime($r['out_datetime'])) : '';
        $r['duration_fmt'] = formatVisitDuration($r['in_datetime'], $r['out_datetime'] ?? null);
    }
    unset($r);

    ksort($campMap);

    return [
        'rows'           => $rows,
        'summary'        => [
            'total'       => $total,
            'still_in'    => $stillIn,
            'checked_out' => $checkedOut,
        ],
        'camp_breakdown' => array_values($campMap),
        'loc_filter'     => $loc,
        'generated_at'   => date('d M Y, H:i:s'),
    ];
}

// Report Summary JSON endpoint
if (($_GET['ajax'] ?? '') === 'report') {
    header('Content-Type: application/json');
    $report = buildVisitorReport($pdo, $isAdmin, $currentLocation, $_GET);
    echo json_encode(['success' => true] + $report, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    exit;
}

$initialReport = buildVisitorReport($pdo, $isAdmin, $currentLocation, []);

// Locations & Users for admin sidebar/management
$allLocations    = getLocations($pdo, false);
$activeLocations = array_values(array_filter($allLocations, fn($l) => (int)$l['is_active'] === 1));
$allUsers        = [];
if ($isAdmin) {
    $allUsers = $pdo->query("SELECT id, username, svs_no, `rank`, name, role, location, is_active, created_at FROM users ORDER BY (role = 'admin') DESC, username ASC")->fetchAll();
}

// Initial movement & accommodation SSR states
refreshAccommodationStatuses($pdo);
$initialMovements       = fetchMovementsList($pdo, $isAdmin, $currentLocation, []);
$initialPendingArrivals = fetchPendingArrivalsList($pdo, $isAdmin, $currentLocation);
$initialAccommodations  = fetchAccommodationsList($pdo, $isAdmin, $currentLocation, []);
$initialMovementCounts  = fetchMovementCounts($pdo, $isAdmin, $currentLocation);
$initialAuditLogs       = ($isAdmin || $isProvost) ? fetchAuditLogsList($pdo, $isAdmin, $currentLocation, []) : [];
?>
<!DOCTYPE html>
<html lang="en" class="h-full"
      x-data="varsApp()"
      :class="darkMode ? 'dark' : ''"
      x-init="init()">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="csrf-token" content="<?= htmlspecialchars(csrf_token()) ?>" />
  <title>VARS · Dashboard</title>

  <!-- Tailwind CSS CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50:  '#eff6ff', 100: '#dbeafe',
              400: '#60a5fa', 500: '#3b82f6',
              600: '#2563eb', 700: '#1d4ed8',
              800: '#1e40af', 900: '#1e3a8a',
            }
          },
          animation: {
            'fade-in':    'fadeIn .25s ease both',
            'slide-up':   'slideUp .3s cubic-bezier(.16,1,.3,1) both',
          },
          keyframes: {
            fadeIn:  { from: {opacity:0}, to: {opacity:1} },
            slideUp: { from: {opacity:0, transform:'translateY(20px)'}, to:{opacity:1,transform:'translateY(0)'} }
          }
        }
      }
    }
  </script>

  <!-- Alpine.js CDN -->
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>

  <style>
    [x-cloak] { display: none !important; }

    /* Scrollbar */
    ::-webkit-scrollbar { width:6px; height:6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background:#2563eb; border-radius:9999px; }

    /* Table row hover */
    .tbl-row { transition: background .15s; }

    /* Modal backdrop */
    .modal-backdrop {
      background: rgba(0,0,0,.55);
      backdrop-filter: blur(4px);
    }

    /* Gradient text */
    .grad-text {
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    /* Status pill pulse */
    .pulse-dot {
      animation: pulseDot 2s cubic-bezier(.4,0,.6,1) infinite;
    }
    @keyframes pulseDot {
      0%,100% { opacity:1; }
      50%      { opacity:.4; }
    }

    /* Card glow on hover */
    .stat-card {
      transition: transform .2s, box-shadow .2s;
    }
    .stat-card:hover {
      transform: translateY(-3px);
    }

    /* Clean print layout for Report Summary (Landscape + compact text) */
    .print-only { display: none; }
    @page {
      size: landscape;
      margin: 8mm;
    }
    @media print {
      nav, aside, .no-print { display: none !important; }
      .print-only { display: block !important; }
      html, body {
        background: #ffffff !important;
        color: #000000 !important;
        font-size: 10px !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      main {
        max-width: 100% !important;
        width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
      }
      .report-print-wrap,
      .report-print-wrap > div,
      .report-print-scroll {
        overflow: visible !important;
        box-shadow: none !important;
        border-radius: 4px !important;
        background: #ffffff !important;
      }
      .report-summary-cards {
        display: grid !important;
        grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
        gap: 8px !important;
        margin-bottom: 8px !important;
      }
      .report-summary-cards > div {
        padding: 6px 10px !important;
        box-shadow: none !important;
        background: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
      }
      .report-summary-cards p { color: #000000 !important; }
      .report-summary-cards p.text-3xl { font-size: 16px !important; margin-top: 2px !important; }
      .report-camp-cards {
        margin-bottom: 8px !important;
      }
      .report-camp-cards > div {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: 6px !important;
      }
      .report-camp-cards > div > div {
        padding: 4px 8px !important;
        box-shadow: none !important;
        background: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        font-size: 9px !important;
      }
      .report-print-table {
        width: 100% !important;
        border-collapse: collapse !important;
        font-size: 8.5px !important;
        line-height: 1.25 !important;
      }
      .report-print-table thead { display: table-header-group; }
      .report-print-table tr { page-break-inside: avoid; break-inside: avoid; }
      .report-print-table th,
      .report-print-table td {
        padding: 3px 4px !important;
        white-space: normal !important;
        word-break: break-word !important;
        color: #000000 !important;
        background: transparent !important;
        border: 1px solid #cbd5e1 !important;
        vertical-align: top !important;
      }
      .report-print-table thead th {
        background: #f1f5f9 !important;
        font-size: 8px !important;
        font-weight: 700 !important;
      }
      .report-print-table td span {
        font-size: 8px !important;
        padding: 1px 4px !important;
        background: #f8fafc !important;
        color: #000000 !important;
        border-color: #cbd5e1 !important;
      }
    }
  </style>
</head>

<body class="min-h-screen bg-slate-100 dark:bg-[#06111f] text-slate-800 dark:text-slate-100
             transition-colors duration-300" x-cloak>

<!-- ═══════════════════════════════════════════════════════════
     TOP NAVIGATION BAR
══════════════════════════════════════════════════════════════ -->
<nav class="sticky top-0 z-50 bg-white/95 dark:bg-[#071525]/95
            backdrop-blur border-b border-slate-200 dark:border-blue-900/40
            shadow-sm">
  <div class="w-full px-4 sm:px-6 lg:px-8">
    <div class="flex items-center justify-between h-16">

      <!-- Left: Mobile Sidebar Toggle + Logo + Active Location Badge -->
      <div class="flex items-center gap-3">
        <button @click="sidebarOpen = !sidebarOpen"
                class="lg:hidden p-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-blue-900/40
                       dark:hover:bg-blue-800/60 text-slate-600 dark:text-blue-200 transition-colors"
                title="Toggle sidebar">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h16"/>
          </svg>
        </button>

        <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-500 to-blue-800
                    flex items-center justify-center shadow-md shadow-blue-900/30">
          <svg class="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.25 3.75 10.15 9 11.25C17.25 21.15 21 16.25 21 11V5l-9-4z"/>
          </svg>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <span class="font-black text-lg tracking-tight grad-text">VARS</span>
            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold
                         bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300
                         border border-blue-200 dark:border-blue-700/50">
              <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round"
                      d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
              </svg>
              <?= htmlspecialchars($currentLocation) ?>
            </span>
          </div>
          <p class="text-[10px] text-slate-500 dark:text-blue-300/70 -mt-0.5 hidden sm:block">
            Visiting Airmen Record System
          </p>
        </div>
      </div>

      <!-- Right side controls -->
      <div class="flex items-center gap-3">

        <!-- Add Visitor button -->
        <button @click="openModal('add')"
                class="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold
                       bg-gradient-to-r from-blue-600 to-blue-800 text-white
                       hover:from-blue-700 hover:to-blue-900
                       active:scale-95 transition-all shadow-md shadow-blue-900/30">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>
          </svg>
          <span class="hidden sm:inline">Add Visitor</span>
          <span class="sm:hidden">Add</span>
        </button>

        <!-- Dark mode toggle -->
        <button @click="toggleDark()"
                class="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-blue-900/40
                       dark:hover:bg-blue-800/60 transition-colors" title="Toggle dark mode">
          <svg x-show="!darkMode" class="w-5 h-5 text-slate-600" fill="none"
               stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003
                     9.003 0 008.354-5.646z"/>
          </svg>
          <svg x-show="darkMode" x-cloak class="w-5 h-5 text-yellow-400" fill="none"
               stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343
                     17.657l-.707.707M17.657 17.657l-.707-.707M6.343 6.343l-.707-.707
                     M12 8a4 4 0 100 8 4 4 0 000-8z"/>
          </svg>
        </button>

        <!-- User menu -->
        <div class="relative" x-data="{ open: false }">
          <button @click="open = !open"
                  class="flex items-center gap-2 px-3 py-2 rounded-xl
                         bg-slate-100 hover:bg-slate-200 dark:bg-blue-900/30
                         dark:hover:bg-blue-800/50 transition-colors text-sm font-medium">
            <div class="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-blue-700
                        flex items-center justify-center text-white text-xs font-bold">
              <?= strtoupper(substr($_SESSION['full_name'], 0, 1)) ?>
            </div>
            <span class="hidden md:inline text-slate-700 dark:text-blue-100 max-w-[120px] truncate">
              <?= htmlspecialchars($_SESSION['full_name']) ?>
            </span>
            <svg class="w-4 h-4 text-slate-500 dark:text-blue-300" fill="none"
                 stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/>
            </svg>
          </button>

          <div x-show="open" @click.outside="open=false" x-cloak
               x-transition:enter="transition ease-out duration-150"
               x-transition:enter-start="opacity-0 scale-95"
               x-transition:enter-end="opacity-100 scale-100"
               class="absolute right-0 mt-2 w-52 bg-white dark:bg-[#071525]
                      rounded-xl shadow-xl border border-slate-200 dark:border-blue-900/40
                      overflow-hidden z-50">
            <div class="px-4 py-3 border-b border-slate-100 dark:border-blue-900/30">
              <p class="text-xs text-slate-500 dark:text-blue-300/70">Signed in as</p>
              <p class="text-sm font-semibold text-slate-700 dark:text-blue-100 truncate">
                <?= htmlspecialchars($_SESSION['username']) ?>
              </p>
              <p class="text-[11px] font-semibold text-blue-600 dark:text-blue-400 mt-0.5">
                Camp: <?= htmlspecialchars($currentLocation) ?> · <?= $isAdmin ? 'Administrator' : 'Operator' ?>
              </p>
            </div>
            <button type="button"
                    @click="open = false; openModal('logout')"
                    class="flex items-center gap-2 px-4 py-3 text-sm text-red-600 dark:text-red-400
                           hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors w-full text-left">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round"
                      d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0
                         013-3h4a3 3 0 013 3v1"/>
              </svg>
              Sign Out
            </button>
          </div>
        </div>

      </div>
    </div>
  </div>
</nav>

<!-- Mobile sidebar backdrop -->
<div x-show="sidebarOpen" x-cloak @click="sidebarOpen = false"
     class="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm lg:hidden"></div>

<!-- ═══════════════════════════════════════════════════════════
     WORKSPACE LAYOUT (LEFT SIDEBAR + MAIN CONTENT)
══════════════════════════════════════════════════════════════ -->
<div class="flex min-h-[calc(100vh-4rem)]">

  <!-- ── LEFT SIDEBAR ── -->
  <aside :class="[
           sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
           sidebarCollapsed ? 'w-64 lg:w-20' : 'w-64'
         ]"
         class="fixed top-16 bottom-0 left-0 z-40 lg:sticky lg:top-16 lg:h-[calc(100vh-4rem)] lg:z-30 shrink-0
                bg-white dark:bg-[#071525] border-r border-slate-200 dark:border-blue-900/40
                flex flex-col transition-all duration-200 ease-in-out overflow-y-auto overflow-x-hidden">

    <!-- Top Collapse / Expand Arrow Bar -->
    <div class="px-3 pt-3 pb-1 flex items-center"
         :class="sidebarCollapsed ? 'lg:justify-center justify-between' : 'justify-between'">
      <span class="px-1 text-[10px] font-bold uppercase tracking-wider text-slate-600 dark:text-blue-300/60"
            :class="sidebarCollapsed ? 'lg:hidden' : ''">
        Menu
      </span>
      <!-- Desktop Collapse / Expand Arrow -->
      <button type="button"
              @click="toggleSidebarCollapse()"
              class="hidden lg:inline-flex items-center justify-center w-8 h-8 rounded-lg
                     bg-slate-100 hover:bg-slate-200 dark:bg-blue-900/40 dark:hover:bg-blue-800/60
                     text-black dark:text-blue-200 border border-slate-200 dark:border-blue-800/50 transition-colors"
              :title="sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'">
        <svg x-show="!sidebarCollapsed" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15 19l-7-7 7-7"/>
        </svg>
        <svg x-show="sidebarCollapsed" x-cloak class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
        </svg>
      </button>
      <!-- Mobile Close Arrow -->
      <button type="button"
              @click="sidebarOpen = false"
              class="lg:hidden inline-flex items-center justify-center w-8 h-8 rounded-lg
                     bg-slate-100 hover:bg-slate-200 dark:bg-blue-900/40 dark:hover:bg-blue-800/60
                     text-black dark:text-blue-200 transition-colors"
              title="Close sidebar">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15 19l-7-7 7-7"/>
        </svg>
      </button>
    </div>

    <!-- Current Camp Banner -->
    <div class="p-3 border-b border-slate-100 dark:border-blue-900/30">
      <div class="rounded-xl bg-gradient-to-br from-blue-600 to-blue-800 text-white shadow-md shadow-blue-900/20"
           :class="sidebarCollapsed ? 'p-3.5 lg:p-2.5 lg:text-center' : 'p-3.5'">
        <div class="flex items-center justify-between" :class="sidebarCollapsed ? 'lg:hidden' : ''">
          <span class="text-[10px] font-bold uppercase tracking-widest text-blue-100/80">
            <?= $isAdmin ? 'Admin Scope' : 'Active Camp' ?>
          </span>
          <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-white/20 uppercase">
            <?= $isAdmin ? 'Admin' : 'User' ?>
          </span>
        </div>
        <div class="flex items-center gap-2" :class="sidebarCollapsed ? 'mt-1.5 lg:mt-0 lg:justify-center' : 'mt-1.5'">
          <svg class="w-5 h-5 text-blue-200 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
          <span class="text-xl font-black tracking-wide"
                :class="sidebarCollapsed ? 'lg:text-xs lg:tracking-normal' : ''"
                x-text="isAdmin ? (locFilter === 'ALL' ? 'ALL' : locFilter) : currentLocation"></span>
        </div>
        <p class="text-[11px] text-blue-100/85 mt-1" :class="sidebarCollapsed ? 'lg:hidden' : ''">
          <?php if ($isAdmin): ?>
            <span x-text="locFilter === 'ALL' ? 'Viewing all camps (In & Out)' : ('Viewing camp ' + locFilter)"></span>
          <?php else: ?>
            Showing visitors entered at <?= htmlspecialchars($currentLocation) ?>
          <?php endif; ?>
        </p>
      </div>
    </div>

    <!-- Navigation Links -->
    <nav class="p-3 space-y-1.5">
      <p class="px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-600 dark:text-blue-300/50"
         :class="sidebarCollapsed ? 'lg:hidden' : ''">
        Navigation
      </p>

      <button @click="activeTab = 'visitors'; sidebarOpen = false"
              title="Visitor Records"
              :class="[
                activeTab === 'visitors'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Visitor Records</span>
        </span>
        <span :class="sidebarCollapsed ? 'lg:hidden' : ''"
              class="px-2 py-0.5 rounded-full text-xs bg-slate-200/80 dark:bg-blue-950 text-black dark:text-blue-300 font-bold"
              x-text="counts.total"></span>
      </button>

      <!-- Inter-Camp Movements -->
      <button @click="activeTab = 'movements'; sidebarOpen = false; fetchMovements(true)"
              title="Inter-Camp Movements"
              :class="[
                activeTab === 'movements'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Inter-Camp Movements</span>
        </span>
        <span :class="sidebarCollapsed ? 'lg:hidden' : ''"
              class="px-2 py-0.5 rounded-full text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 font-bold"
              x-text="movementCounts.total_active || 0"></span>
      </button>

      <!-- Temporary Accommodation -->
      <button @click="activeTab = 'accommodation'; sidebarOpen = false; fetchAccommodations(true)"
              title="Temporary Accommodation"
              :class="[
                activeTab === 'accommodation'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Accommodation</span>
        </span>
        <span :class="sidebarCollapsed ? 'lg:hidden' : ''"
              class="px-2 py-0.5 rounded-full text-xs"
              :class="(movementCounts.expired > 0 || movementCounts.expiring_soon > 0) ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200 font-bold animate-pulse' : 'bg-slate-200/80 dark:bg-blue-950 text-black dark:text-blue-300 font-bold'"
              x-text="movementCounts.accommodated || 0"></span>
      </button>

      <!-- Personnel & Movement Inquiry -->
      <button @click="activeTab = 'inquiry'; sidebarOpen = false"
              title="Personnel Inquiry"
              :class="[
                activeTab === 'inquiry'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Personnel Inquiry</span>
        </span>
      </button>

      <button @click="activeTab = 'reports'; sidebarOpen = false; fetchReport(true)"
              title="Report Summary"
              :class="[
                activeTab === 'reports'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Report Summary</span>
        </span>
        <span :class="sidebarCollapsed ? 'lg:hidden' : ''"
              class="px-2 py-0.5 rounded-full text-xs bg-slate-200/80 dark:bg-blue-950 text-black dark:text-blue-300 font-bold"
              x-text="reportSummary.total"></span>
      </button>

      <?php if ($isAdmin): ?>
      <button @click="activeTab = 'users'; sidebarOpen = false"
              title="Users & Access"
              :class="[
                activeTab === 'users'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Users &amp; Access</span>
        </span>
        <span :class="sidebarCollapsed ? 'lg:hidden' : ''"
              class="px-2 py-0.5 rounded-full text-xs bg-slate-200/80 dark:bg-blue-950 text-black dark:text-blue-300 font-bold"
              x-text="users.length"></span>
      </button>

      <button @click="activeTab = 'locations'; sidebarOpen = false"
              title="Camp Locations"
              :class="[
                activeTab === 'locations'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Camp Locations</span>
        </span>
        <span :class="sidebarCollapsed ? 'lg:hidden' : ''"
              class="px-2 py-0.5 rounded-full text-xs bg-slate-200/80 dark:bg-blue-950 text-black dark:text-blue-300 font-bold"
              x-text="locations.length"></span>
      </button>

      <button @click="activeTab = 'audit'; sidebarOpen = false; fetchAuditLogs(true)"
              title="Audit Logs"
              :class="[
                activeTab === 'audit'
                  ? 'bg-blue-50 dark:bg-blue-900/40 text-blue-700 dark:text-blue-200 border-blue-200 dark:border-blue-700/50'
                  : 'text-black dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/20 border-transparent',
                sidebarCollapsed ? 'lg:justify-center lg:px-2' : 'justify-between px-3'
              ]"
              class="w-full flex items-center py-2.5 rounded-xl text-sm font-semibold border transition-colors">
        <span class="flex items-center gap-2.5">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <span :class="sidebarCollapsed ? 'lg:hidden' : ''">Audit Trail</span>
        </span>
      </button>
      <?php endif; ?>
    </nav>

  </aside>

<!-- ═══════════════════════════════════════════════════════════
     MAIN CONTENT
══════════════════════════════════════════════════════════════ -->
<main class="flex-1 min-w-0 max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

  <!-- ── TAB 1: VISITOR RECORDS ── -->
  <div x-show="activeTab === 'visitors'">

  <!-- Page title -->
  <div class="mb-8 flex flex-wrap items-center justify-between gap-4">
    <div>
      <h2 class="text-2xl font-black text-black dark:text-slate-100">
        Visitor Records
        <span class="ml-2 text-sm font-bold px-2.5 py-1 rounded-lg bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 align-middle"
              x-text="isAdmin ? (locFilter === 'ALL' ? 'ALL CAMPS' : locFilter) : currentLocation">
          <?= htmlspecialchars($isAdmin ? ($locFilter === 'ALL' ? 'ALL CAMPS' : $locFilter) : $currentLocation) ?>
        </span>
      </h2>
      <p class="text-slate-800 dark:text-slate-400 text-sm mt-0.5">
        <?php if ($isAdmin): ?>
          <span x-text="locFilter === 'ALL'
                        ? 'Viewing all camp visitor records (automatically saved on check-in and check-out).'
                        : ('Showing visiting airmen recorded at camp location ' + locFilter + '.')"></span>
        <?php else: ?>
          Showing visiting airmen recorded at camp location <strong><?= htmlspecialchars($currentLocation) ?></strong>.
        <?php endif; ?>
      </p>
    </div>
  </div>

  <!-- ── Stat Cards ── -->
  <div class="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">

    <!-- Total -->
    <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm
                border border-slate-200 dark:border-blue-900/40">
      <div class="flex items-start justify-between">
        <div>
          <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">
            Total Visitors
          </p>
          <p class="text-4xl font-black text-black dark:text-white mt-1" x-text="counts.total">
            <?= (int)$counts['total'] ?>
          </p>
        </div>
        <div class="p-3 bg-blue-50 dark:bg-blue-900/40 rounded-xl">
          <svg class="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor"
               stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857
                     M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002
                     5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
        </div>
      </div>
    </div>

    <!-- Still In -->
    <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm
                border border-slate-200 dark:border-blue-900/40">
      <div class="flex items-start justify-between">
        <div>
          <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">
            Currently Inside
          </p>
          <p class="text-4xl font-black text-emerald-700 dark:text-emerald-400 mt-1" x-text="counts.still_in">
            <?= (int)$counts['still_in'] ?>
          </p>
        </div>
        <div class="p-3 bg-emerald-50 dark:bg-emerald-900/30 rounded-xl">
          <svg class="w-6 h-6 text-emerald-600 dark:text-emerald-400" fill="none" stroke="currentColor"
               stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
        </div>
      </div>
    </div>

    <!-- Checked Out -->
    <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm
                border border-slate-200 dark:border-blue-900/40">
      <div class="flex items-start justify-between">
        <div>
          <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">
            Checked Out
          </p>
          <p class="text-4xl font-black text-black dark:text-blue-300/60 mt-1" x-text="counts.checked_out">
            <?= (int)$counts['checked_out'] ?>
          </p>
        </div>
        <div class="p-3 bg-slate-100 dark:bg-blue-900/20 rounded-xl">
          <svg class="w-6 h-6 text-slate-700 dark:text-blue-400/60" fill="none" stroke="currentColor"
               stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0
                     013-3h4a3 3 0 013 3v1"/>
          </svg>
        </div>
      </div>
    </div>

  </div>

  <!-- ── Search & Filter Bar ── -->
  <div class="bg-white dark:bg-[#071d35] rounded-2xl shadow-sm
              border border-slate-200 dark:border-blue-900/40 p-4 mb-5">
    <form @submit.prevent="fetchVisitors()" class="flex flex-col lg:flex-row gap-3">
      <div class="relative flex-1">
        <span class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <svg class="w-4 h-4 text-slate-600 dark:text-blue-300/50" fill="none" stroke="currentColor"
               stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
        </span>
        <input type="search" x-model="searchQuery"
               @input.debounce.300ms="fetchVisitors()"
               placeholder="Search by name, SVS No, NIC, camp…"
               class="w-full pl-9 pr-4 py-2.5 text-sm rounded-xl
                      bg-slate-50 dark:bg-blue-950/60
                      border border-slate-300 dark:border-blue-800/50
                      text-black dark:text-blue-100
                      placeholder-slate-500 dark:placeholder-blue-400/50
                      focus:outline-none focus:ring-2 focus:ring-blue-500
                      transition" />
      </div>

      <?php if ($isAdmin): ?>
      <!-- Admin Camp Location Filter -->
      <div class="sm:w-52">
        <select x-model="locFilter"
                @change="fetchVisitors()"
                class="w-full px-3.5 py-2.5 text-sm font-semibold rounded-xl
                       bg-slate-50 dark:bg-blue-950/60
                       border border-slate-300 dark:border-blue-800/50
                       text-black dark:text-blue-100
                       focus:outline-none focus:ring-2 focus:ring-blue-500 transition">
          <option value="ALL">All Camps (In &amp; Out)</option>
          <template x-for="loc in locations" :key="loc.code">
            <option :value="loc.code" x-text="loc.name ? loc.code + ' — ' + loc.name : loc.code"></option>
          </template>
        </select>
      </div>
      <?php endif; ?>

      <!-- Status filter pills -->
      <div class="flex flex-wrap gap-2">
        <button type="button" @click="setStatusFilter('all')"
                :class="statusFilter === 'all'
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'bg-slate-100 dark:bg-blue-950/50 text-black dark:text-blue-300 hover:bg-slate-200 dark:hover:bg-blue-900/50'"
                class="px-4 py-2.5 rounded-xl text-sm font-semibold transition-all">
          All
        </button>
        <button type="button" @click="setStatusFilter('in')"
                :class="statusFilter === 'in'
                        ? 'bg-emerald-600 text-white shadow-sm'
                        : 'bg-slate-100 dark:bg-blue-950/50 text-black dark:text-blue-300 hover:bg-slate-200 dark:hover:bg-blue-900/50'"
                class="px-4 py-2.5 rounded-xl text-sm font-semibold transition-all">
          Inside
        </button>
        <button type="button" @click="setStatusFilter('out')"
                :class="statusFilter === 'out'
                        ? 'bg-slate-700 dark:bg-blue-900/80 text-white shadow-sm'
                        : 'bg-slate-100 dark:bg-blue-950/50 text-black dark:text-blue-300 hover:bg-slate-200 dark:hover:bg-blue-900/50'"
                class="px-4 py-2.5 rounded-xl text-sm font-semibold transition-all">
          Checked Out
        </button>

        <button type="button"
                x-show="searchQuery !== '' || (isAdmin && locFilter !== 'ALL') || statusFilter !== 'all'"
                x-cloak
                @click="resetFilters()"
                class="px-3 py-2.5 rounded-xl bg-red-50 dark:bg-red-900/20
                       text-red-600 dark:text-red-400 text-sm font-semibold hover:bg-red-100 transition">
          Clear
        </button>
      </div>
    </form>
  </div>

  <!-- ── Toast Notification ── -->
  <div x-show="toast.show" x-cloak
       x-transition:enter="transition ease-out duration-300"
       x-transition:enter-start="opacity-0 translate-y-4"
       x-transition:enter-end="opacity-100 translate-y-0"
       x-transition:leave="transition ease-in duration-200"
       x-transition:leave-start="opacity-100"
       x-transition:leave-end="opacity-0"
       class="fixed bottom-6 right-6 z-50 flex items-center gap-3
              bg-white dark:bg-slate-800 shadow-xl rounded-2xl px-5 py-3.5
              border border-slate-200 dark:border-slate-700 max-w-xs">
    <div :class="toast.success
                 ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-400'
                 : 'bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400'"
         class="p-2 rounded-xl flex-shrink-0">
      <svg x-show="toast.success" class="w-5 h-5" fill="none" stroke="currentColor"
           stroke-width="2.5" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
      </svg>
      <svg x-show="!toast.success" x-cloak class="w-5 h-5" fill="none" stroke="currentColor"
           stroke-width="2.5" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
      </svg>
    </div>
    <p class="text-sm font-medium text-slate-700 dark:text-slate-200" x-text="toast.message"></p>
  </div>

  <!-- ── Records Table ── -->
  <div class="bg-white dark:bg-[#071d35] rounded-2xl shadow-sm
              border border-slate-200 dark:border-blue-900/40 overflow-hidden">

    <div x-show="visitors.length === 0" x-cloak class="text-center py-24">
      <svg class="w-16 h-16 text-slate-300 dark:text-slate-700 mx-auto mb-4" fill="none"
           stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round"
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414
                 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>
      <p class="text-slate-700 dark:text-slate-400 font-semibold">No visitor records found.</p>
      <p class="text-slate-600 dark:text-slate-500 text-sm mt-1"
         x-text="searchQuery ? 'Try a different search term.' : 'Click &quot;Add Visitor&quot; to register the first entry.'"></p>
    </div>

    <div x-show="visitors.length > 0">
      <div class="overflow-x-auto">
        <table class="w-full text-sm text-left">
          <thead>
            <tr class="bg-slate-100 dark:bg-[#051528]
                       border-b border-slate-200 dark:border-blue-900/30">
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">#</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">SVS No</th>
              <?php if ($isAdmin): ?>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Camp</th>
              <?php endif; ?>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Rank</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Name</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">NIC No</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Parent Camp</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">In Date &amp; Time</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Out Date &amp; Time</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Remarks</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Authority By</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Status</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-blue-900/20">
            <template x-for="(v, idx) in visitors" :key="v.id">
              <tr class="tbl-row hover:bg-slate-50/80 dark:hover:bg-blue-900/20"
                  :class="v.out_datetime ? 'dark:opacity-65' : ''"
                  :id="'row-' + v.id">

                <td class="px-4 py-3 text-slate-700 dark:text-slate-400 font-mono text-xs font-semibold"
                    x-text="idx + 1"></td>

                <td class="px-4 py-3 font-mono font-bold text-blue-700 dark:text-blue-400 whitespace-nowrap"
                    x-text="v.svs_no"></td>

                <?php if ($isAdmin): ?>
                <td class="px-4 py-3 whitespace-nowrap">
                  <span class="px-2 py-0.5 rounded-md bg-blue-50 dark:bg-blue-950/70
                               text-blue-800 dark:text-blue-300 text-xs font-bold border border-blue-200 dark:border-blue-800/50"
                        x-text="v.location"></span>
                </td>
                <?php endif; ?>

                <td class="px-4 py-3 whitespace-nowrap">
                  <span class="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-blue-950/60
                               text-black dark:text-blue-200 text-xs font-bold border border-slate-300 dark:border-blue-900/40"
                        x-text="v.rank || '—'"></span>
                </td>

                <td class="px-4 py-3 font-bold whitespace-nowrap text-black dark:text-slate-100"
                    x-text="v.name"></td>

                <td class="px-4 py-3 font-mono font-medium text-black dark:text-slate-300 whitespace-nowrap"
                    x-text="v.nic_no || '—'"></td>

                <td class="px-4 py-3 whitespace-nowrap font-medium text-black dark:text-slate-300"
                    x-text="v.parent_camp || '—'"></td>

                <td class="px-4 py-3 whitespace-nowrap text-xs text-black dark:text-slate-300">
                  <div class="font-bold text-black dark:text-slate-200" x-text="v.in_date_fmt"></div>
                  <div class="text-slate-700 dark:text-slate-400 font-medium" x-text="v.in_time_fmt"></div>
                </td>

                <td class="px-4 py-3 whitespace-nowrap text-xs">
                  <template x-if="v.out_datetime">
                    <div>
                      <div class="font-bold text-black dark:text-slate-200" x-text="v.out_date_fmt"></div>
                      <div class="text-slate-700 dark:text-slate-400 font-medium" x-text="v.out_time_fmt"></div>
                    </div>
                  </template>
                  <template x-if="!v.out_datetime">
                    <span class="text-slate-600 dark:text-slate-500 italic">—</span>
                  </template>
                </td>

                <td class="px-4 py-3 max-w-[160px] text-black dark:text-slate-300 font-medium truncate"
                    :title="v.remarks || ''"
                    x-text="v.remarks ? (v.remarks.length > 40 ? v.remarks.slice(0, 40) + '…' : v.remarks) : '—'"></td>

                <td class="px-4 py-3 whitespace-nowrap text-black dark:text-slate-300 font-medium"
                    x-text="v.authority_by || '—'"></td>

                <td class="px-4 py-3 whitespace-nowrap">
                  <template x-if="v.out_datetime">
                    <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full
                                 bg-slate-200/80 dark:bg-blue-950/60 text-black dark:text-slate-400
                                 text-xs font-bold border border-slate-300 dark:border-blue-900/40">
                      <span class="w-1.5 h-1.5 rounded-full bg-slate-700 dark:bg-slate-400"></span>
                      Out
                    </span>
                  </template>
                  <template x-if="!v.out_datetime">
                    <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full
                                 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-400
                                 text-xs font-bold border border-emerald-300 dark:border-emerald-800/40">
                      <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 pulse-dot"></span>
                      Inside
                    </span>
                  </template>
                </td>

                <td class="px-4 py-3 whitespace-nowrap">
                  <div class="flex items-center gap-2">
                    <template x-if="!v.out_datetime">
                      <button @click="confirmMarkOut(v.id, v.name)"
                              class="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg
                                     bg-amber-100 dark:bg-amber-900/30 text-amber-900 dark:text-amber-300
                                     text-xs font-bold hover:bg-amber-200 dark:hover:bg-amber-900/60
                                     transition-colors active:scale-95">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor"
                             stroke-width="2.5" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round"
                                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0
                                   01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                        </svg>
                        Mark Out
                      </button>
                    </template>
                    <template x-if="v.out_datetime">
                      <span class="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-500 italic">
                        Departed
                      </span>
                    </template>

                    <button @click="confirmDelete(v.id, v.name)"
                            class="p-1.5 rounded-lg text-red-500 dark:text-red-400
                                   hover:bg-red-50 dark:hover:bg-red-900/20
                                   transition-colors active:scale-95" title="Delete record">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor"
                           stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round"
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858
                                 L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>

      <div class="px-5 py-3 border-t border-slate-100 dark:border-blue-900/30
                  flex flex-wrap items-center justify-between gap-2 text-xs text-slate-800 dark:text-slate-400">
        <span>Showing <strong x-text="visitors.length"></strong> record(s)</span>
        <div class="flex items-center gap-3">
          <span class="inline-flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400 font-semibold">
            <span class="w-2 h-2 rounded-full bg-emerald-500 pulse-dot"></span>
            Auto-sync on
          </span>
          <span>Last refreshed: <span x-text="lastRefreshed"></span></span>
        </div>
      </div>
    </div>
  </div>
  </div><!-- /activeTab === 'visitors' -->

  <!-- ── TAB: INTER-CAMP MOVEMENTS ── -->
  <div x-show="activeTab === 'movements'" x-cloak>
    <!-- Page title -->
    <div class="mb-8 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-2xl font-black text-black dark:text-slate-100">
          Inter-Camp Personnel Movements
          <span class="ml-2 text-sm font-bold px-2.5 py-1 rounded-lg bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 align-middle"
                x-text="isAdmin ? (locFilter === 'ALL' ? 'ALL BASES' : locFilter) : currentLocation">
            <?= htmlspecialchars($currentLocation) ?>
          </span>
        </h2>
        <p class="text-slate-800 dark:text-slate-400 text-sm mt-0.5">
          Two-sided journey tracking for servicemen moving between SLAF bases (Origin OUT &rarr; Dest IN &rarr; Dest OUT &rarr; Origin Return IN).
        </p>
      </div>
      <div>
        <button type="button"
                @click="openAddMovementModal()"
                class="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm text-white
                       bg-gradient-to-r from-blue-600 to-blue-800 hover:from-blue-700 hover:to-blue-900
                       shadow-md shadow-blue-700/25 active:scale-95 transition-all">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>
          </svg>
          New Movement (Origin OUT)
        </button>
      </div>
    </div>

    <!-- Movement Stat Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
      <!-- Total Active In-Transit -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Active Movements</p>
            <p class="text-3xl font-black text-black dark:text-white mt-1" x-text="movementCounts.total_active || 0"></p>
          </div>
          <div class="p-3 bg-blue-50 dark:bg-blue-900/40 rounded-xl text-blue-600 dark:text-blue-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/>
            </svg>
          </div>
        </div>
      </div>

      <!-- Pending Arrivals -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40"
           :class="movementCounts.pending_arrivals > 0 ? 'ring-2 ring-blue-500/50' : ''">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Pending Arrivals</p>
            <p class="text-3xl font-black text-amber-600 dark:text-amber-400 mt-1" x-text="movementCounts.pending_arrivals || 0"></p>
          </div>
          <div class="p-3 bg-amber-50 dark:bg-amber-900/30 rounded-xl text-amber-600 dark:text-amber-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
        </div>
      </div>

      <!-- Inside Host Base -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Inside Host Base</p>
            <p class="text-3xl font-black text-emerald-700 dark:text-emerald-400 mt-1" x-text="movementCounts.inside_camp || 0"></p>
          </div>
          <div class="p-3 bg-emerald-50 dark:bg-emerald-900/30 rounded-xl text-emerald-600 dark:text-emerald-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>
            </svg>
          </div>
        </div>
      </div>

      <!-- Returning to Base -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Returning Home</p>
            <p class="text-3xl font-black text-blue-600 dark:text-blue-400 mt-1" x-text="movementCounts.returning || 0"></p>
          </div>
          <div class="p-3 bg-sky-50 dark:bg-sky-900/30 rounded-xl text-sky-600 dark:text-sky-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"/>
            </svg>
          </div>
        </div>
      </div>
    </div>

    <!-- Movement Filter Bar -->
    <div class="bg-white dark:bg-[#071525] rounded-2xl p-4 shadow-sm border border-slate-200 dark:border-blue-900/40 mb-6">
      <div class="flex flex-col md:flex-row gap-3 items-center justify-between">
        <div class="flex flex-wrap items-center gap-3 w-full md:w-auto">
          <!-- Sub-view switcher -->
          <div class="inline-flex rounded-xl p-1 bg-slate-100 dark:bg-blue-950/60 border border-slate-200 dark:border-blue-900/50">
            <button type="button"
                    @click="movementSubTab = 'all'; fetchMovements()"
                    :class="movementSubTab === 'all' ? 'bg-white dark:bg-blue-900/60 text-blue-700 dark:text-white shadow-sm' : 'text-slate-600 dark:text-slate-400'"
                    class="px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all">
              All Movements
            </button>
            <button type="button"
                    @click="movementSubTab = 'pending'; fetchMovements()"
                    :class="movementSubTab === 'pending' ? 'bg-white dark:bg-blue-900/60 text-blue-700 dark:text-white shadow-sm' : 'text-slate-600 dark:text-slate-400'"
                    class="px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5">
              Pending Arrivals
              <span class="px-1.5 py-0.2 rounded-full text-[10px] bg-amber-500 text-white font-black"
                    x-text="pendingArrivals.length"></span>
            </button>
          </div>

          <!-- Status Filter -->
          <select x-model="movementStatusFilter"
                  @change="fetchMovements()"
                  class="input-field text-xs font-semibold px-3 py-2 rounded-xl text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-[#071d35] border border-slate-200 dark:border-blue-900/50">
            <option value="all">All Movement Statuses</option>
            <option value="DEPARTED_ORIGIN">En Route to Destination (Stage A)</option>
            <option value="ARRIVED_DESTINATION">Inside Destination Base (Stage B)</option>
            <option value="DEPARTED_DESTINATION">Returning to Origin (Stage D)</option>
            <option value="COMPLETED">Completed Journey (Stage E)</option>
          </select>
        </div>

        <div class="flex items-center gap-3 w-full md:w-auto justify-end">
          <div class="relative w-full md:w-64">
            <input type="text"
                   x-model="movementSearch"
                   @input.debounce.300ms="fetchMovements()"
                   placeholder="Search SVS, Name, Ref..."
                   class="input-field w-full pl-9 pr-3 py-2 rounded-xl text-xs font-medium text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-[#071d35] border border-slate-200 dark:border-blue-900/50" />
            <svg class="w-4 h-4 text-slate-400 absolute left-3 top-2.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
          </div>

          <button type="button"
                  @click="fetchMovements()"
                  title="Refresh records"
                  class="p-2 rounded-xl border border-slate-200 dark:border-blue-900/50 bg-slate-50 dark:bg-[#071d35] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-blue-900/30">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
          </button>
        </div>
      </div>
    </div>

    <!-- Movements Table -->
    <div class="bg-white dark:bg-[#071525] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm border-collapse">
          <thead>
            <tr class="bg-slate-50 dark:bg-[#071d35]/70 border-b border-slate-200 dark:border-blue-900/40 text-xs font-bold text-slate-600 dark:text-blue-300/80 uppercase tracking-wider">
              <th class="py-3.5 px-4">Movement Ref</th>
              <th class="py-3.5 px-4">Serviceman</th>
              <th class="py-3.5 px-4">Journey Route</th>
              <th class="py-3.5 px-4">Purpose &amp; Authority</th>
              <th class="py-3.5 px-4">Status</th>
              <th class="py-3.5 px-4">Out / In Timestamps</th>
              <th class="py-3.5 px-4 text-right">Gate Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-blue-900/30">
            <template x-for="m in displayedMovements" :key="m.id">
              <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/10 transition-colors">
                <!-- Ref -->
                <td class="py-3.5 px-4 font-mono font-bold text-xs text-blue-700 dark:text-blue-400">
                  <span x-text="m.movement_ref"></span>
                </td>

                <!-- Serviceman -->
                <td class="py-3.5 px-4">
                  <div class="font-bold text-slate-900 dark:text-white" x-text="(m.rank ? m.rank + ' ' : '') + m.name"></div>
                  <div class="text-xs text-slate-500 font-mono" x-text="'SVS: ' + m.svs_no + (m.nic_no ? ' · NIC: ' + m.nic_no : '')"></div>
                </td>

                <!-- Route -->
                <td class="py-3.5 px-4">
                  <div class="inline-flex items-center gap-1.5 font-bold text-xs">
                    <span class="px-2 py-0.5 rounded bg-slate-100 dark:bg-blue-950 text-slate-800 dark:text-blue-200 border border-slate-200 dark:border-blue-900/50"
                          x-text="m.origin_camp"></span>
                    <span class="text-slate-400">&rarr;</span>
                    <span class="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-200 border border-blue-200 dark:border-blue-800/50"
                          x-text="m.destination_camp"></span>
                  </div>
                </td>

                <!-- Purpose & Authority -->
                <td class="py-3.5 px-4 max-w-xs">
                  <div class="text-xs text-slate-800 dark:text-slate-200 font-medium truncate" x-text="m.purpose_of_visit" :title="m.purpose_of_visit"></div>
                  <div class="text-[11px] text-slate-500 truncate" x-text="'Auth: ' + (m.authority_name || '—') + (m.authority_ref ? ' (' + m.authority_ref + ')' : '')"></div>
                </td>

                <!-- Status Badge -->
                <td class="py-3.5 px-4">
                  <span x-show="m.movement_status === 'DEPARTED_ORIGIN'"
                        class="px-2.5 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200">
                    En Route to Host
                  </span>
                  <span x-show="m.movement_status === 'ARRIVED_DESTINATION'"
                        class="px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200">
                    Inside Host Base
                  </span>
                  <span x-show="m.movement_status === 'DEPARTED_DESTINATION'"
                        class="px-2.5 py-1 rounded-full text-xs font-bold bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-200">
                    Returning Home
                  </span>
                  <span x-show="m.movement_status === 'COMPLETED'"
                        class="px-2.5 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    Completed
                  </span>
                </td>

                <!-- Timestamps -->
                <td class="py-3.5 px-4 text-xs text-slate-600 dark:text-slate-400">
                  <div x-text="'OUT: ' + m.out_fmt"></div>
                  <div x-show="m.actual_in_at" x-text="'IN: ' + m.in_fmt"></div>
                  <div x-show="m.actual_return_in_at" x-text="'RTN: ' + m.return_in_fmt"></div>
                </td>

                <!-- Actions -->
                <td class="py-3.5 px-4 text-right">
                  <div class="inline-flex items-center gap-1.5 justify-end">
                    <!-- Confirm Destination IN (Stage B) -->
                    <button type="button"
                            x-show="m.movement_status === 'DEPARTED_ORIGIN' && (isAdmin || m.destination_camp === currentLocation)"
                            @click="openDestInModal(m)"
                            class="px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-700 text-white shadow-sm transition-all">
                      Confirm IN
                    </button>

                    <!-- Destination OUT (Stage D) -->
                    <button type="button"
                            x-show="m.movement_status === 'ARRIVED_DESTINATION' && (isAdmin || m.destination_camp === currentLocation)"
                            @click="openDestOutModal(m)"
                            class="px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-600 hover:bg-amber-700 text-white shadow-sm transition-all">
                      Check OUT
                    </button>

                    <!-- Origin Return IN (Stage E) -->
                    <button type="button"
                            x-show="m.movement_status === 'DEPARTED_DESTINATION' && (isAdmin || m.origin_camp === currentLocation)"
                            @click="openReturnInModal(m)"
                            class="px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-700 text-white shadow-sm transition-all">
                      Confirm Return
                    </button>

                    <!-- View Journey Timeline -->
                    <button type="button"
                            @click="openMovementTimeline(m)"
                            title="View chronological movement audit events"
                            class="p-1.5 rounded-lg border border-slate-200 dark:border-blue-900/50 bg-slate-50 dark:bg-blue-950/40 text-slate-600 dark:text-blue-300 hover:bg-slate-100">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </template>
            <tr x-show="displayedMovements.length === 0">
              <td colspan="7" class="py-12 text-center text-slate-400 text-sm">
                No matching inter-camp personnel movements found.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div><!-- /activeTab === 'movements' -->

  <!-- ── TAB: TEMPORARY ACCOMMODATION ── -->
  <div x-show="activeTab === 'accommodation'" x-cloak>
    <!-- Page title -->
    <div class="mb-8 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-2xl font-black text-black dark:text-slate-100">
          Temporary Accommodation
          <span class="ml-2 text-sm font-bold px-2.5 py-1 rounded-lg bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 align-middle"
                x-text="isAdmin ? (locFilter === 'ALL' ? 'ALL HOST BASES' : locFilter) : currentLocation">
            <?= htmlspecialchars($currentLocation) ?>
          </span>
        </h2>
        <p class="text-slate-800 dark:text-slate-400 text-sm mt-0.5">
          24-hour default temporary accommodation validity monitoring, approaching-expiry alerts, and authorized extension tracking.
        </p>
      </div>
      <div>
        <button type="button"
                @click="fetchAccommodations()"
                class="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border border-slate-200 dark:border-blue-900/50 bg-white dark:bg-[#071525] text-slate-700 dark:text-blue-200 hover:bg-slate-50">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          Refresh Accommodations
        </button>
      </div>
    </div>

    <!-- Stat Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">
      <!-- Currently Accommodated -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Currently Accommodated</p>
            <p class="text-3xl font-black text-black dark:text-white mt-1" x-text="movementCounts.accommodated || 0"></p>
          </div>
          <div class="p-3 bg-blue-50 dark:bg-blue-900/40 rounded-xl text-blue-600 dark:text-blue-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
            </svg>
          </div>
        </div>
      </div>

      <!-- Expiring Soon (< 4h) -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40"
           :class="movementCounts.expiring_soon > 0 ? 'ring-2 ring-amber-500' : ''">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Expiring Soon (&lt; 4h)</p>
            <p class="text-3xl font-black text-amber-600 dark:text-amber-400 mt-1" x-text="movementCounts.expiring_soon || 0"></p>
          </div>
          <div class="p-3 bg-amber-50 dark:bg-amber-900/30 rounded-xl text-amber-600 dark:text-amber-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          </div>
        </div>
      </div>

      <!-- Expired Inside Base -->
      <div class="stat-card bg-white dark:bg-[#071d35] rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-blue-900/40"
           :class="movementCounts.expired > 0 ? 'ring-2 ring-red-500 animate-pulse' : ''">
        <div class="flex items-start justify-between">
          <div>
            <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Expired (Inside Base)</p>
            <p class="text-3xl font-black text-red-600 dark:text-red-400 mt-1" x-text="movementCounts.expired || 0"></p>
          </div>
          <div class="p-3 bg-red-50 dark:bg-red-900/30 rounded-xl text-red-600 dark:text-red-400">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
        </div>
      </div>
    </div>

    <!-- Accommodations Table -->
    <div class="bg-white dark:bg-[#071525] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm border-collapse">
          <thead>
            <tr class="bg-slate-50 dark:bg-[#071d35]/70 border-b border-slate-200 dark:border-blue-900/40 text-xs font-bold text-slate-600 dark:text-blue-300/80 uppercase tracking-wider">
              <th class="py-3.5 px-4">Airman</th>
              <th class="py-3.5 px-4">Home Base &rarr; Host Base</th>
              <th class="py-3.5 px-4">Check-In Time</th>
              <th class="py-3.5 px-4">Validity Expiry</th>
              <th class="py-3.5 px-4">Time Remaining</th>
              <th class="py-3.5 px-4">Status &amp; Billet</th>
              <th class="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-blue-900/30">
            <template x-for="a in accommodations" :key="a.id">
              <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/10 transition-colors">
                <!-- Airman -->
                <td class="py-3.5 px-4">
                  <div class="font-bold text-slate-900 dark:text-white" x-text="(a.rank ? a.rank + ' ' : '') + a.name"></div>
                  <div class="text-xs text-slate-500 font-mono" x-text="'SVS: ' + a.svs_no"></div>
                </td>

                <!-- Route -->
                <td class="py-3.5 px-4 text-xs font-bold">
                  <span class="text-slate-600 dark:text-slate-300" x-text="a.origin_camp"></span>
                  <span class="text-slate-400 mx-1">&rarr;</span>
                  <span class="text-blue-700 dark:text-blue-400" x-text="a.camp_code"></span>
                </td>

                <!-- Checkin -->
                <td class="py-3.5 px-4 text-xs text-slate-600 dark:text-slate-400" x-text="a.checkin_fmt"></td>

                <!-- Expiry -->
                <td class="py-3.5 px-4 text-xs font-mono font-semibold"
                    :class="a.accommodation_status === 'EXPIRED' ? 'text-red-600 dark:text-red-400' : 'text-slate-700 dark:text-slate-300'"
                    x-text="a.expires_fmt"></td>

                <!-- Time Remaining -->
                <td class="py-3.5 px-4">
                  <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold"
                        :class="a.time_left_class"
                        x-text="a.time_left_str"></span>
                </td>

                <!-- Status & Billet -->
                <td class="py-3.5 px-4 text-xs">
                  <span x-show="a.accommodation_status === 'ACTIVE'" class="px-2 py-0.5 rounded font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200">ACTIVE</span>
                  <span x-show="a.accommodation_status === 'EXPIRING_SOON'" class="px-2 py-0.5 rounded font-bold bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200 animate-pulse">EXPIRING SOON</span>
                  <span x-show="a.accommodation_status === 'EXPIRED'" class="px-2 py-0.5 rounded font-bold bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200">EXPIRED</span>
                  <span x-show="a.accommodation_status === 'EXTENDED'" class="px-2 py-0.5 rounded font-bold bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-200">EXTENDED</span>
                  <span x-show="a.accommodation_status === 'CLOSED'" class="px-2 py-0.5 rounded font-bold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">CLOSED</span>
                  <div x-show="a.billet_location" class="text-[11px] text-slate-500 mt-0.5" x-text="'Billet: ' + a.billet_location"></div>
                </td>

                <!-- Action: Extend -->
                <td class="py-3.5 px-4 text-right">
                  <button type="button"
                          x-show="a.accommodation_status !== 'CLOSED' && (isAdmin || a.camp_code === currentLocation)"
                          @click="openExtendAccomModal(a)"
                          class="px-3 py-1.5 rounded-lg text-xs font-bold bg-gradient-to-r from-blue-600 to-blue-800 hover:from-blue-700 hover:to-blue-900 text-white shadow-sm transition-all">
                    + Extend
                  </button>
                </td>
              </tr>
            </template>
            <tr x-show="accommodations.length === 0">
              <td colspan="7" class="py-12 text-center text-slate-400 text-sm">
                No active temporary accommodation records found.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div><!-- /activeTab === 'accommodation' -->

  <!-- ── TAB: PERSONNEL & MOVEMENT INQUIRY ── -->
  <div x-show="activeTab === 'inquiry'" x-cloak>
    <!-- Page title -->
    <div class="mb-8 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-2xl font-black text-black dark:text-slate-100">
          Personnel &amp; Movement Inquiry
        </h2>
        <p class="text-slate-800 dark:text-slate-400 text-sm mt-0.5">
          Multi-parameter inquiry across servicemen master records, origin/destination journeys, and audit history.
        </p>
      </div>
    </div>

    <!-- Inquiry Filter Card -->
    <div class="bg-white dark:bg-[#071525] rounded-2xl p-6 shadow-sm border border-slate-200 dark:border-blue-900/40 mb-8">
      <form @submit.prevent="executeInquiry()" class="space-y-4">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <!-- Service Number -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1 uppercase">Service Number</label>
            <input type="text" x-model="inquiryFilters.svs_no" placeholder="e.g. S/12345"
                   class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-[#071d35] border border-slate-200 dark:border-blue-900/50" />
          </div>

          <!-- Name -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1 uppercase">Personnel Name</label>
            <input type="text" x-model="inquiryFilters.name" placeholder="Search by name"
                   class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-[#071d35] border border-slate-200 dark:border-blue-900/50" />
          </div>

          <!-- Movement Reference -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1 uppercase">Movement Ref No</label>
            <input type="text" x-model="inquiryFilters.movement_ref" placeholder="e.g. MOV-20261113-..."
                   class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-[#071d35] border border-slate-200 dark:border-blue-900/50" />
          </div>

          <!-- Status -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1 uppercase">Movement Status</label>
            <select x-model="inquiryFilters.status"
                    class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-[#071d35] border border-slate-200 dark:border-blue-900/50">
              <option value="">Any Status</option>
              <option value="DEPARTED_ORIGIN">En Route to Destination</option>
              <option value="ARRIVED_DESTINATION">Inside Destination Base</option>
              <option value="DEPARTED_DESTINATION">Returning to Origin</option>
              <option value="COMPLETED">Completed</option>
            </select>
          </div>
        </div>

        <div class="flex items-center justify-end gap-3 pt-2">
          <button type="button" @click="resetInquiry()"
                  class="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-blue-900/30">
            Reset Filters
          </button>
          <button type="submit"
                  class="px-5 py-2 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 shadow-sm transition-all">
            Execute Inquiry
          </button>
        </div>
      </form>
    </div>

    <!-- Inquiry Results -->
    <div class="bg-white dark:bg-[#071525] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div class="px-5 py-4 border-b border-slate-100 dark:border-blue-900/40 flex items-center justify-between">
        <h3 class="font-bold text-sm text-slate-900 dark:text-white">Inquiry Records (<span x-text="inquiryResults.length"></span>)</h3>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm border-collapse">
          <thead>
            <tr class="bg-slate-50 dark:bg-[#071d35]/70 border-b border-slate-200 dark:border-blue-900/40 text-xs font-bold text-slate-600 dark:text-blue-300/80 uppercase tracking-wider">
              <th class="py-3 px-4">Ref</th>
              <th class="py-3 px-4">Airman</th>
              <th class="py-3 px-4">Route</th>
              <th class="py-3 px-4">Purpose</th>
              <th class="py-3 px-4">Status</th>
              <th class="py-3 px-4">Dispatch Date</th>
              <th class="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-blue-900/30">
            <template x-for="r in inquiryResults" :key="r.id">
              <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/10 transition-colors">
                <td class="py-3 px-4 font-mono font-bold text-xs text-blue-700 dark:text-blue-400" x-text="r.movement_ref"></td>
                <td class="py-3 px-4">
                  <div class="font-bold text-slate-900 dark:text-white" x-text="(r.rank ? r.rank + ' ' : '') + r.name"></div>
                  <div class="text-xs text-slate-500 font-mono" x-text="'SVS: ' + r.svs_no"></div>
                </td>
                <td class="py-3 px-4 text-xs font-bold">
                  <span x-text="r.origin_camp"></span> &rarr; <span x-text="r.destination_camp"></span>
                </td>
                <td class="py-3 px-4 text-xs max-w-xs truncate" x-text="r.purpose_of_visit"></td>
                <td class="py-3 px-4">
                  <span class="px-2 py-0.5 rounded-full text-xs font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
                        x-text="r.movement_status"></span>
                </td>
                <td class="py-3 px-4 text-xs text-slate-500" x-text="r.out_fmt"></td>
                <td class="py-3 px-4 text-right">
                  <button type="button" @click="openMovementTimeline(r)"
                          class="px-2.5 py-1 rounded-lg text-xs font-bold bg-slate-100 hover:bg-slate-200 dark:bg-blue-950 dark:hover:bg-blue-900 text-slate-700 dark:text-blue-200">
                    View Journey
                  </button>
                </td>
              </tr>
            </template>
            <tr x-show="inquiryResults.length === 0">
              <td colspan="7" class="py-12 text-center text-slate-400 text-sm">
                Enter search parameters above to perform an inquiry.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div><!-- /activeTab === 'inquiry' -->

  <!-- ── TAB: SYSTEM AUDIT LOGS ── -->
  <div x-show="activeTab === 'audit'" x-cloak>
    <!-- Page title -->
    <div class="mb-8 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-2xl font-black text-black dark:text-slate-100">
          Security &amp; Operations Audit Trail
        </h2>
        <p class="text-slate-800 dark:text-slate-400 text-sm mt-0.5">
          Append-only chronological audit log of all gate operations, temporary accommodation events, and administrative changes.
        </p>
      </div>
      <div>
        <button type="button"
                @click="fetchAuditLogs()"
                class="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border border-slate-200 dark:border-blue-900/50 bg-white dark:bg-[#071525] text-slate-700 dark:text-blue-200 hover:bg-slate-50">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          Refresh Audit Trail
        </button>
      </div>
    </div>

    <!-- Audit Table -->
    <div class="bg-white dark:bg-[#071525] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm border-collapse">
          <thead>
            <tr class="bg-slate-50 dark:bg-[#071d35]/70 border-b border-slate-200 dark:border-blue-900/40 text-xs font-bold text-slate-600 dark:text-blue-300/80 uppercase tracking-wider">
              <th class="py-3 px-4">Timestamp</th>
              <th class="py-3 px-4">Operator / User</th>
              <th class="py-3 px-4">Base</th>
              <th class="py-3 px-4">Action Type</th>
              <th class="py-3 px-4">Reference / Entity</th>
              <th class="py-3 px-4">Details Summary</th>
              <th class="py-3 px-4">IP Address</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-blue-900/30">
            <template x-for="log in auditLogs" :key="log.id">
              <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/10 transition-colors">
                <td class="py-3 px-4 text-xs font-mono text-slate-500 whitespace-nowrap" x-text="log.created_fmt"></td>
                <td class="py-3 px-4 font-bold text-slate-800 dark:text-slate-200" x-text="log.username"></td>
                <td class="py-3 px-4 text-xs font-bold text-blue-700 dark:text-blue-400" x-text="log.camp_code"></td>
                <td class="py-3 px-4">
                  <span class="px-2 py-0.5 rounded text-xs font-bold"
                        :class="log.action_type.includes('IN') ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300' : (log.action_type.includes('OUT') ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300' : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300')"
                        x-text="log.action_type"></span>
                </td>
                <td class="py-3 px-4 text-xs font-mono font-semibold" x-text="log.reference_no || ('#' + log.entity_id)"></td>
                <td class="py-3 px-4 text-xs text-slate-600 dark:text-slate-400 max-w-sm truncate" x-text="JSON.stringify(log.details_obj)"></td>
                <td class="py-3 px-4 text-xs font-mono text-slate-400" x-text="log.ip_address"></td>
              </tr>
            </template>
            <tr x-show="auditLogs.length === 0">
              <td colspan="7" class="py-12 text-center text-slate-400 text-sm">
                No audit trail records found.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div><!-- /activeTab === 'audit' -->

  <?php if ($isAdmin): ?>
  <!-- ── TAB 2: USER ACCOUNTS & ACCESS ── -->
  <div x-show="activeTab === 'users'" x-cloak>
    <div class="mb-6 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-2xl font-black text-black dark:text-slate-100">Users &amp; Access Control</h2>
        <p class="text-slate-700 dark:text-slate-400 text-sm mt-0.5">
          Create accounts, assign camp locations, and manage login permissions.
        </p>
      </div>
      <button @click="openModal('createUser')"
              class="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold
                     bg-gradient-to-r from-blue-600 to-blue-800 text-white
                     hover:from-blue-700 hover:to-blue-900 active:scale-95 transition-all shadow-md shadow-blue-900/30">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/>
        </svg>
        Create Account
      </button>
    </div>

    <div class="bg-white dark:bg-[#071d35] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-sm text-left">
          <thead>
            <tr class="bg-slate-100 dark:bg-[#051528] border-b border-slate-200 dark:border-blue-900/30">
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">SVS No</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Rank</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Name / User</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Role</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Assigned Location</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Login Access</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-blue-900/20">
            <template x-for="u in users" :key="u.id">
              <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/20 transition-colors">
                <td class="px-4 py-3 font-mono font-bold text-blue-700 dark:text-blue-400 whitespace-nowrap"
                    x-text="u.svs_no || '—'"></td>
                <td class="px-4 py-3 whitespace-nowrap">
                  <span class="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-blue-950/60 text-black dark:text-blue-200 text-xs font-bold border border-slate-300 dark:border-blue-900/40"
                        x-text="u.rank || '—'"></span>
                </td>
                <td class="px-4 py-3">
                  <div class="font-bold text-black dark:text-slate-100" x-text="u.name || u.username"></div>
                  <div class="text-xs font-mono font-semibold text-blue-700 dark:text-blue-400" x-text="'@' + u.username"></div>
                </td>
                <td class="px-4 py-3">
                  <select x-model="u.role"
                          :disabled="u.id == currentUserId"
                          @change="updateUserField(u)"
                          class="px-2.5 py-1.5 rounded-lg text-xs font-semibold
                                 bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50
                                 text-black dark:text-slate-100 disabled:opacity-60">
                    <option value="user">Operator (user)</option>
                    <option value="admin">Administrator (admin)</option>
                  </select>
                </td>
                <td class="px-4 py-3">
                  <select x-model="u.location"
                          @change="updateUserLocation(u)"
                          class="px-2.5 py-1.5 rounded-lg text-xs font-semibold
                                 bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50
                                 text-black dark:text-slate-100">
                    <template x-for="loc in activeLocations()" :key="loc.code">
                      <option :value="loc.code" x-text="loc.name ? loc.code + ' — ' + loc.name : loc.code"></option>
                    </template>
                  </select>
                </td>
                <td class="px-4 py-3">
                  <button type="button"
                          :disabled="u.id == currentUserId"
                          @click="toggleUserAccess(u)"
                          :class="Number(u.is_active) === 1
                                  ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/40'
                                  : 'bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800/40'"
                          class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border disabled:opacity-60 disabled:cursor-not-allowed transition-colors">
                    <span class="w-1.5 h-1.5 rounded-full"
                          :class="Number(u.is_active) === 1 ? 'bg-emerald-500' : 'bg-red-500'"></span>
                    <span x-text="Number(u.is_active) === 1 ? 'Allowed' : 'Blocked'"></span>
                  </button>
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-2">
                    <button type="button"
                            @click="openResetPass(u)"
                            class="px-2.5 py-1 rounded-lg text-xs font-semibold bg-blue-50 dark:bg-blue-900/30
                                   text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors">
                      Reset Password
                    </button>
                    <button type="button"
                            x-show="u.id != currentUserId"
                            @click="deleteUser(u)"
                            class="p-1.5 rounded-lg text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                            title="Delete user">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round"
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── TAB 3: CAMP LOCATIONS ── -->
  <div x-show="activeTab === 'locations'" x-cloak>
    <div class="mb-6">
      <h2 class="text-2xl font-black text-black dark:text-slate-100">Camp Locations</h2>
      <p class="text-slate-700 dark:text-slate-400 text-sm mt-0.5">
        Manage the camp locations shown in the login and assignment dropdowns.
      </p>
    </div>

    <!-- Add Location Form -->
    <form @submit.prevent="submitCreateLocation()"
          class="bg-white dark:bg-[#071d35] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 p-4 mb-6 flex flex-col sm:flex-row gap-3">
      <input x-model="locForm.code" type="text" placeholder="Camp Code (e.g. PAL)" required maxlength="20"
             class="sm:w-44 px-3.5 py-2.5 rounded-xl text-sm uppercase bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 placeholder-slate-500 dark:placeholder-blue-300/40 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      <input x-model="locForm.name" type="text" placeholder="Camp Name (e.g. Palaly)" maxlength="120"
             class="flex-1 px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 placeholder-slate-500 dark:placeholder-blue-300/40 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      <button type="submit"
              class="px-5 py-2.5 rounded-xl text-sm font-bold bg-gradient-to-r from-blue-600 to-blue-800 text-white hover:from-blue-700 hover:to-blue-900 active:scale-95 transition-all">
        Add Location
      </button>
    </form>

    <div class="bg-white dark:bg-[#071d35] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-sm text-left">
          <thead>
            <tr class="bg-slate-100 dark:bg-[#051528] border-b border-slate-200 dark:border-blue-900/30">
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Code</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Camp Name</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Status</th>
              <th class="px-4 py-3.5 text-xs font-bold text-black dark:text-blue-300/60 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-blue-900/20">
            <template x-for="loc in locations" :key="loc.id">
              <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/20 transition-colors">
                <td class="px-4 py-3 font-mono font-bold text-blue-700 dark:text-blue-400" x-text="loc.code"></td>
                <td class="px-4 py-3 text-black font-medium dark:text-slate-200" x-text="loc.name || '—'"></td>
                <td class="px-4 py-3">
                  <button type="button"
                          :disabled="loc.code === currentLocation"
                          @click="toggleLocation(loc)"
                          :class="Number(loc.is_active) === 1
                                  ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/40'
                                  : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700'"
                          class="px-3 py-1 rounded-full text-xs font-bold border disabled:opacity-60 disabled:cursor-not-allowed transition-colors">
                    <span x-text="Number(loc.is_active) === 1 ? 'Active' : 'Inactive'"></span>
                  </button>
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-1.5">
                    <button type="button"
                            @click="openEditLocation(loc)"
                            class="p-1.5 rounded-lg text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 transition-colors"
                            title="Edit location">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round"
                              d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                      </svg>
                    </button>
                    <button type="button"
                            x-show="loc.code !== 'SJP' && loc.code !== currentLocation"
                            @click="deleteLocation(loc)"
                            class="p-1.5 rounded-lg text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                            title="Delete location">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round"
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- ── TAB 4: REPORT SUMMARY (USER OWN CAMP & ADMIN ALL CAMPS) ── -->
  <div x-show="activeTab === 'reports'" x-cloak>
    <div class="mb-6 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-2xl font-black text-black dark:text-slate-100">
          Report Summary
          <span class="ml-2 text-sm font-bold px-2.5 py-1 rounded-lg bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 align-middle"
                x-text="isAdmin ? (reportFilters.loc === 'ALL' ? 'ALL CAMPS' : reportFilters.loc) : currentLocation"></span>
        </h2>
        <p class="text-slate-800 dark:text-slate-400 text-sm mt-0.5">
          <?php if ($isAdmin): ?>
            Full In / Out summary report across all camps or selected camp with date &amp; time filters.
          <?php else: ?>
            Full In / Out summary report for your camp (<strong class="text-black dark:text-blue-200"><?= htmlspecialchars($currentLocation) ?></strong>).
          <?php endif; ?>
        </p>
      </div>

      <div class="no-print flex flex-wrap items-center gap-2.5">
        <button type="button" @click="exportReportCsv()"
                class="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold
                       bg-emerald-600 hover:bg-emerald-700 text-white active:scale-95 transition-all shadow-sm">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
          </svg>
          Export CSV
        </button>
        <button type="button" @click="printReport()"
                class="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold
                       bg-gradient-to-r from-blue-600 to-blue-800 hover:from-blue-700 hover:to-blue-900
                       text-white active:scale-95 transition-all shadow-md shadow-blue-900/30">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/>
          </svg>
          Print Report
        </button>
      </div>
    </div>

    <!-- Summary Totals Cards -->
    <div class="report-summary-cards grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
      <div class="bg-white dark:bg-[#071d35] rounded-2xl p-4 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Report Total Records</p>
        <p class="text-3xl font-black text-black dark:text-white mt-1" x-text="reportSummary.total"></p>
      </div>
      <div class="bg-white dark:bg-[#071d35] rounded-2xl p-4 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">In Camp (Inside)</p>
        <p class="text-3xl font-black text-emerald-700 dark:text-emerald-400 mt-1" x-text="reportSummary.still_in"></p>
      </div>
      <div class="bg-white dark:bg-[#071d35] rounded-2xl p-4 shadow-sm border border-slate-200 dark:border-blue-900/40">
        <p class="text-xs font-bold text-slate-700 dark:text-blue-300/70 uppercase tracking-wider">Out Camp (Checked Out)</p>
        <p class="text-3xl font-black text-black dark:text-blue-300/80 mt-1" x-text="reportSummary.checked_out"></p>
      </div>
    </div>

    <!-- Per-Camp Summary Breakdown -->
    <div x-show="reportCamps.length > 0" class="report-camp-cards mb-5">
      <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <template x-for="c in reportCamps" :key="c.location">
          <div class="bg-white dark:bg-[#071d35] rounded-xl p-3 border border-slate-200 dark:border-blue-900/40 shadow-sm">
            <div class="flex items-center justify-between mb-1">
              <span class="text-xs font-black text-blue-700 dark:text-blue-300" x-text="c.location"></span>
              <span class="text-xs font-bold text-black dark:text-white" x-text="c.total + ' total'"></span>
            </div>
            <div class="flex items-center justify-between text-[11px] font-semibold">
              <span class="text-emerald-700 dark:text-emerald-400" x-text="'In: ' + c.still_in"></span>
              <span class="text-slate-700 dark:text-slate-300" x-text="'Out: ' + c.checked_out"></span>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- Date, Time, Camp & Status Filters -->
    <div class="no-print bg-white dark:bg-[#071d35] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 p-4 mb-5 space-y-3">
      <!-- Quick Presets -->
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-xs font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mr-1">Quick Range:</span>
          <button type="button" @click="applyReportPreset('all')"
                  :class="reportPreset === 'all' ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-100 hover:bg-slate-200 dark:bg-blue-950/60 dark:hover:bg-blue-900/60 text-black dark:text-blue-200'"
                  class="px-3 py-1.5 rounded-lg text-xs font-bold transition-colors">
            All Time
          </button>
          <button type="button" @click="applyReportPreset('today')"
                  :class="reportPreset === 'today' ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-100 hover:bg-slate-200 dark:bg-blue-950/60 dark:hover:bg-blue-900/60 text-black dark:text-blue-200'"
                  class="px-3 py-1.5 rounded-lg text-xs font-bold transition-colors">
            Today
          </button>
          <button type="button" @click="applyReportPreset('week')"
                  :class="reportPreset === 'week' ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-100 hover:bg-slate-200 dark:bg-blue-950/60 dark:hover:bg-blue-900/60 text-black dark:text-blue-200'"
                  class="px-3 py-1.5 rounded-lg text-xs font-bold transition-colors">
            Last 7 Days
          </button>
          <button type="button" @click="applyReportPreset('month')"
                  :class="reportPreset === 'month' ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-100 hover:bg-slate-200 dark:bg-blue-950/60 dark:hover:bg-blue-900/60 text-black dark:text-blue-200'"
                  class="px-3 py-1.5 rounded-lg text-xs font-bold transition-colors">
            This Month
          </button>
        </div>

        <button type="button" @click="resetReportFilters()"
                class="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-50 hover:bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400 transition-colors">
          Reset Filters
        </button>
      </div>

      <!-- Filter Inputs -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">From Date</label>
          <input type="date" x-model="reportFilters.from_date" @change="onReportDateInput()"
                 class="w-full px-3 py-2 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">From Time</label>
          <input type="time" x-model="reportFilters.from_time" @change="onReportDateInput()"
                 class="w-full px-3 py-2 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">To Date</label>
          <input type="date" x-model="reportFilters.to_date" @change="onReportDateInput()"
                 class="w-full px-3 py-2 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">To Time</label>
          <input type="time" x-model="reportFilters.to_time" @change="onReportDateInput()"
                 class="w-full px-3 py-2 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">Date/Time Scope</label>
          <select x-model="reportFilters.date_field" @change="fetchReport()"
                  class="w-full px-3 py-2 rounded-xl text-sm font-semibold bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="any">In or Out Date &amp; Time</option>
            <option value="in">In Date &amp; Time Only</option>
            <option value="out">Out Date &amp; Time Only</option>
          </select>
        </div>

        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">In / Out Status</label>
          <select x-model="reportFilters.status" @change="fetchReport()"
                  class="w-full px-3 py-2 rounded-xl text-sm font-semibold bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="all">All (In &amp; Out)</option>
            <option value="in">Inside (In Camp)</option>
            <option value="out">Checked Out (Out Camp)</option>
          </select>
        </div>

        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">Camp Location</label>
          <?php if ($isAdmin): ?>
          <select x-model="reportFilters.loc" @change="fetchReport()"
                  class="w-full px-3 py-2 rounded-xl text-sm font-semibold bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="ALL">All Camps</option>
            <template x-for="loc in locations" :key="loc.code">
              <option :value="loc.code" x-text="loc.name ? loc.code + ' — ' + loc.name : loc.code"></option>
            </template>
          </select>
          <?php else: ?>
          <div class="w-full px-3 py-2 rounded-xl text-sm font-bold bg-slate-100 dark:bg-blue-950/40 border border-slate-300 dark:border-blue-800/50 text-black dark:text-blue-200">
            <?= htmlspecialchars($currentLocation) ?> (Own Camp)
          </div>
          <?php endif; ?>
        </div>

        <div>
          <label class="block text-[11px] font-bold text-black dark:text-blue-300/70 uppercase tracking-wider mb-1">Search Details</label>
          <input type="search" x-model="reportFilters.q" @input.debounce.300ms="fetchReport()"
                 placeholder="SVS No, Name, NIC, Authority…"
                 class="w-full px-3 py-2 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
      </div>
    </div>

    <!-- Full Details Summary Report Table -->
    <div class="report-print-wrap bg-white dark:bg-[#071d35] rounded-2xl shadow-sm border border-slate-200 dark:border-blue-900/40 overflow-hidden">
      <div x-show="reportRows.length === 0" x-cloak class="text-center py-20">
        <p class="text-black dark:text-slate-300 font-semibold">No records match the selected report criteria.</p>
        <p class="text-slate-600 dark:text-slate-500 text-xs mt-1">Adjust date, time, status, or camp filters.</p>
      </div>

      <div x-show="reportRows.length > 0">
        <div class="report-print-scroll overflow-x-auto">
          <table class="report-print-table w-full text-xs text-left">
            <thead>
              <tr class="bg-slate-100 dark:bg-[#051528] border-b border-slate-200 dark:border-blue-900/30">
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">#</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">SVS No</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Camp</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Rank</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Name</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">NIC No</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Parent Camp</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">In Date &amp; Time</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Out Date &amp; Time</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Duration</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Remarks</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Authority By</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Recorded By</th>
                <th class="px-3 py-3 font-bold text-black dark:text-blue-300/60 uppercase tracking-wider whitespace-nowrap">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-blue-900/20">
              <template x-for="(r, idx) in reportRows" :key="r.id">
                <tr class="hover:bg-slate-50/80 dark:hover:bg-blue-900/20 transition-colors">
                  <td class="px-3 py-2.5 font-mono font-semibold text-slate-700 dark:text-slate-400" x-text="idx + 1"></td>
                  <td class="px-3 py-2.5 font-mono font-bold text-blue-700 dark:text-blue-400 whitespace-nowrap" x-text="r.svs_no"></td>
                  <td class="px-3 py-2.5 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded-md bg-blue-50 dark:bg-blue-950/70 text-blue-800 dark:text-blue-300 font-bold border border-blue-200 dark:border-blue-800/50"
                          x-text="r.location"></span>
                  </td>
                  <td class="px-3 py-2.5 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded bg-slate-100 dark:bg-blue-950/60 text-black dark:text-blue-200 font-bold border border-slate-300 dark:border-blue-900/40"
                          x-text="r.rank || '—'"></span>
                  </td>
                  <td class="px-3 py-2.5 font-bold text-black dark:text-slate-100 whitespace-nowrap" x-text="r.name"></td>
                  <td class="px-3 py-2.5 font-mono font-medium text-black dark:text-slate-300 whitespace-nowrap" x-text="r.nic_no || '—'"></td>
                  <td class="px-3 py-2.5 font-medium text-black dark:text-slate-300 whitespace-nowrap" x-text="r.parent_camp || '—'"></td>
                  <td class="px-3 py-2.5 whitespace-nowrap">
                    <div class="font-bold text-black dark:text-slate-200" x-text="r.in_date_fmt"></div>
                    <div class="text-slate-700 dark:text-slate-400 font-medium" x-text="r.in_time_fmt"></div>
                  </td>
                  <td class="px-3 py-2.5 whitespace-nowrap">
                    <template x-if="r.out_datetime">
                      <div>
                        <div class="font-bold text-black dark:text-slate-200" x-text="r.out_date_fmt"></div>
                        <div class="text-slate-700 dark:text-slate-400 font-medium" x-text="r.out_time_fmt"></div>
                      </div>
                    </template>
                    <template x-if="!r.out_datetime">
                      <span class="text-slate-600 dark:text-slate-500 italic">—</span>
                    </template>
                  </td>
                  <td class="px-3 py-2.5 whitespace-nowrap font-semibold text-black dark:text-slate-200" x-text="r.duration_fmt"></td>
                  <td class="px-3 py-2.5 max-w-[180px] text-black dark:text-slate-300 font-medium" x-text="r.remarks || '—'"></td>
                  <td class="px-3 py-2.5 whitespace-nowrap font-medium text-black dark:text-slate-300" x-text="r.authority_by || '—'"></td>
                  <td class="px-3 py-2.5 whitespace-nowrap font-medium text-slate-700 dark:text-slate-300" x-text="r.recorded_by || '—'"></td>
                  <td class="px-3 py-2.5 whitespace-nowrap">
                    <span x-show="!r.out_datetime"
                          class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-400 font-bold border border-emerald-300 dark:border-emerald-800/40">
                      Inside
                    </span>
                    <span x-show="r.out_datetime"
                          class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-200/80 dark:bg-blue-950/60 text-black dark:text-slate-300 font-bold border border-slate-300 dark:border-blue-900/40">
                      Out
                    </span>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <div class="px-5 py-3 border-t border-slate-100 dark:border-blue-900/30 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-800 dark:text-slate-400">
          <span>Showing <strong x-text="reportRows.length"></strong> full record(s)</span>
          <span>Report generated: <span x-text="reportGeneratedAt"></span></span>
        </div>
      </div>
    </div>
  </div><!-- /activeTab === 'reports' -->

</main>
</div><!-- /workspace layout -->

<!-- ═══════════════════════════════════════════════════════════
     ADD VISITOR MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'add'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()"
     x-transition:enter="transition ease-out duration-200"
     x-transition:enter-start="opacity-0"
     x-transition:enter-end="opacity-100">

  <div @click.self="closeModal()"
       class="absolute inset-0"></div>

  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-2xl
              max-h-[90vh] overflow-y-auto animate-slide-up border border-slate-200 dark:border-blue-900/40"
       x-transition:enter="transition ease-out duration-250"
       x-transition:enter-start="opacity-0 scale-95 translate-y-4"
       x-transition:enter-end="opacity-100 scale-100 translate-y-0">

    <!-- Modal Header -->
    <div class="sticky top-0 bg-white dark:bg-[#071d35] px-6 pt-6 pb-4
                border-b border-slate-100 dark:border-blue-900/40 z-10 rounded-t-2xl">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="p-2.5 bg-blue-100 dark:bg-blue-900/40 rounded-xl">
            <svg class="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none"
                 stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3
                       20a6 6 0 0112 0v1H3v-1z"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-bold text-slate-800 dark:text-slate-100">Add New Visitor</h3>
            <p class="text-xs text-slate-500 dark:text-slate-400">
              In Date &amp; Time will be recorded automatically.
            </p>
          </div>
        </div>
        <button @click="closeModal()"
                class="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800
                       text-slate-500 dark:text-slate-400 transition-colors">
          <svg class="w-5 h-5" fill="none" stroke="currentColor"
               stroke-width="2.5" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- Modal Body (Form) -->
    <form @submit.prevent="submitAddVisitor()" class="px-6 py-5">
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">

        <!-- SVS No -->
        <div>
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            SVS No <span class="text-red-500">*</span>
          </label>
          <input x-model="form.svs_no" type="text" placeholder="e.g. SVS-2024-001"
                 required maxlength="40"
                 class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                        bg-slate-50 dark:bg-blue-950/60
                        border border-slate-200 dark:border-blue-800/50
                        text-slate-800 dark:text-slate-100
                        placeholder-slate-400 dark:placeholder-slate-500
                        focus:outline-none focus:ring-2 focus:ring-blue-500 transition" />
        </div>

        <!-- Rank -->
        <div>
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            Rank
          </label>
          <select x-model="form.rank"
                  class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                         bg-slate-50 dark:bg-blue-950/60
                         border border-slate-200 dark:border-blue-800/50
                         text-slate-800 dark:text-slate-100
                         focus:outline-none focus:ring-2 focus:ring-blue-500 transition">
            <option value="">— Select Rank —</option>
            <?php
            $ranks = ['AC','LAC','CPL','SGT','FSGT','WO','MWO'];
            foreach ($ranks as $r) echo "<option value='$r'>$r</option>";
            ?>
          </select>
        </div>

        <!-- Name -->
        <div class="sm:col-span-2">
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            Full Name <span class="text-red-500">*</span>
          </label>
          <input x-model="form.name" type="text" placeholder="Full name of visitor"
                 required maxlength="120"
                 class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                        bg-slate-50 dark:bg-blue-950/60
                        border border-slate-200 dark:border-blue-800/50
                        text-slate-800 dark:text-slate-100
                        placeholder-slate-400 dark:placeholder-slate-500
                        focus:outline-none focus:ring-2 focus:ring-blue-500 transition" />
        </div>

        <!-- NIC No -->
        <div>
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            NIC No
          </label>
          <input x-model="form.nic_no" type="text" placeholder="National ID Card No."
                 maxlength="30"
                 class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                        bg-slate-50 dark:bg-blue-950/60
                        border border-slate-200 dark:border-blue-800/50
                        text-slate-800 dark:text-slate-100
                        placeholder-slate-400 dark:placeholder-slate-500
                        focus:outline-none focus:ring-2 focus:ring-blue-500 transition" />
        </div>

        <!-- Parent Camp -->
        <div>
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            Parent Camp
          </label>
          <input x-model="form.parent_camp" type="text" placeholder="Home unit / camp"
                 maxlength="120"
                 class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                        bg-slate-50 dark:bg-blue-950/60
                        border border-slate-200 dark:border-blue-800/50
                        text-slate-800 dark:text-slate-100
                        placeholder-slate-400 dark:placeholder-slate-500
                        focus:outline-none focus:ring-2 focus:ring-blue-500 transition" />
        </div>

        <?php if ($isAdmin): ?>
        <!-- Visited Camp Location (Admin) -->
        <div class="sm:col-span-2">
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            Camp Location (Entry Point)
          </label>
          <select x-model="form.location"
                  class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                         bg-slate-50 dark:bg-blue-950/60
                         border border-slate-200 dark:border-blue-800/50
                         text-slate-800 dark:text-slate-100
                         focus:outline-none focus:ring-2 focus:ring-blue-500 transition">
            <template x-for="loc in activeLocations()" :key="loc.code">
              <option :value="loc.code" x-text="loc.name ? loc.code + ' — ' + loc.name : loc.code"></option>
            </template>
          </select>
        </div>
        <?php endif; ?>

        <!-- Remarks -->
        <div class="sm:col-span-2">
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            Remarks
          </label>
          <textarea x-model="form.remarks" rows="3"
                    placeholder="Purpose of visit, vehicle reg., escort details…"
                    class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                           bg-slate-50 dark:bg-blue-950/60
                           border border-slate-200 dark:border-blue-800/50
                           text-slate-800 dark:text-slate-100
                           placeholder-slate-400 dark:placeholder-slate-500
                           focus:outline-none focus:ring-2 focus:ring-blue-500
                           transition resize-none"></textarea>
        </div>

        <!-- Authority By -->
        <div class="sm:col-span-2">
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1.5">
            Authority By
          </label>
          <input x-model="form.authority_by" type="text" placeholder="Authorizing officer / authority"
                 maxlength="120"
                 class="form-input w-full px-3.5 py-2.5 rounded-xl text-sm
                        bg-slate-50 dark:bg-blue-950/60
                        border border-slate-200 dark:border-blue-800/50
                        text-slate-800 dark:text-slate-100
                        placeholder-slate-400 dark:placeholder-slate-500
                        focus:outline-none focus:ring-2 focus:ring-blue-500 transition" />
        </div>

        <!-- Auto-timestamp info -->
        <div class="sm:col-span-2">
          <div class="flex items-center gap-2.5 bg-blue-50 dark:bg-blue-900/20
                      border border-blue-200 dark:border-blue-800/50
                      rounded-xl px-4 py-3">
            <svg class="w-4 h-4 text-blue-600 dark:text-blue-400 flex-shrink-0" fill="none" stroke="currentColor"
                 stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round"
                    d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <p class="text-xs text-blue-800 dark:text-blue-200">
              <strong>In Date &amp; Time</strong> is automatically set by the database
              at the moment this record is saved. No manual entry required.
            </p>
          </div>
        </div>

      </div>

      <!-- Error in modal -->
      <div x-show="formError" x-cloak
           class="mt-4 flex items-center gap-2 bg-red-50 dark:bg-red-900/20
                  border border-red-200 dark:border-red-800 rounded-xl px-4 py-3
                  text-sm text-red-700 dark:text-red-400">
        <svg class="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0
            11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
        </svg>
        <span x-text="formError"></span>
      </div>

      <!-- Modal Footer -->
      <div class="flex justify-end gap-3 mt-6 pt-5
                  border-t border-slate-100 dark:border-blue-900/30">
        <button type="button" @click="closeModal()"
                class="px-5 py-2.5 rounded-xl text-sm font-semibold
                       bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300
                       hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
          Cancel
        </button>
        <button type="submit" :disabled="submitting"
                class="flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-bold
                       bg-gradient-to-r from-blue-600 to-blue-800 text-white
                       hover:from-blue-700 hover:to-blue-900
                       disabled:opacity-50 disabled:cursor-not-allowed
                       active:scale-95 transition-all shadow-md shadow-blue-900/30">
          <svg x-show="submitting" class="w-4 h-4 animate-spin" fill="none"
               viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10"
                    stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          <span x-text="submitting ? 'Saving…' : 'Save Visitor'"></span>
        </button>
      </div>
    </form>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     CONFIRM MARK OUT MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'markout'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div class="bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-sm p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center gap-4 mb-5">
      <div class="p-3 bg-amber-100 dark:bg-amber-900/30 rounded-xl">
        <svg class="w-6 h-6 text-amber-600 dark:text-amber-400" fill="none"
             stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round"
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667
                   1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34
                   16c-.77 1.333.192 3 1.732 3z"/>
        </svg>
      </div>
      <div>
        <h4 class="font-bold text-slate-800 dark:text-slate-100">Confirm Mark Out</h4>
        <p class="text-sm text-slate-500 dark:text-slate-300 mt-0.5">
          Record the departure of <strong x-text="confirm.name" class="text-slate-700 dark:text-blue-200"></strong>
        </p>
      </div>
    </div>

    <!-- Date & Time picker -->
    <div class="mb-5 space-y-3">
      <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider">
        Out Date &amp; Time
      </label>
      <input type="date" x-model="confirm.out_date"
             class="w-full px-3.5 py-2.5 rounded-xl text-sm
                    bg-slate-50 dark:bg-blue-950/60
                    border border-slate-200 dark:border-blue-800/50
                    text-slate-800 dark:text-slate-100
                    focus:outline-none focus:ring-2 focus:ring-amber-400 transition" />
      <input type="time" x-model="confirm.out_time"
             class="w-full px-3.5 py-2.5 rounded-xl text-sm
                    bg-slate-50 dark:bg-blue-950/60
                    border border-slate-200 dark:border-blue-800/50
                    text-slate-800 dark:text-slate-100
                    focus:outline-none focus:ring-2 focus:ring-amber-400 transition" />
      <p class="text-xs text-slate-400 dark:text-slate-400">
        Pre-filled with the current date &amp; time. Adjust if needed.
      </p>
    </div>

    <div class="flex gap-3">
      <button @click="closeModal()"
              class="flex-1 py-2.5 rounded-xl text-sm font-semibold
                     bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300
                     hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
        Cancel
      </button>
      <button @click="doMarkOut()"
              class="flex-1 py-2.5 rounded-xl text-sm font-bold
                     bg-gradient-to-r from-amber-500 to-orange-500 text-white
                     hover:from-amber-600 hover:to-orange-600
                     active:scale-95 transition-all">
        Yes, Mark Out
      </button>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     UNIFIED CONFIRM DELETE POPUP MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'delete'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-sm p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center gap-4 mb-5">
      <div class="p-3 bg-red-100 dark:bg-red-900/30 rounded-xl shrink-0">
        <svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none"
             stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round"
                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5
                   4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
        </svg>
      </div>
      <div>
        <h4 class="font-bold text-black dark:text-slate-100" x-text="deleteDialog.title"></h4>
        <p class="text-sm text-slate-700 dark:text-slate-300 mt-0.5">
          Permanently delete
          <strong x-text="deleteDialog.label" class="text-black dark:text-blue-200"></strong>?
        </p>
      </div>
    </div>
    <p class="text-xs text-red-600 dark:text-red-400 mb-5 font-medium">
      ⚠ This action is irreversible and cannot be undone.
    </p>
    <div class="flex gap-3">
      <button type="button" @click="closeModal()"
              class="flex-1 py-2.5 rounded-xl text-sm font-semibold
                     bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300
                     hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
        Cancel
      </button>
      <button type="button" @click="executeDelete()" :disabled="submitting"
              class="flex-1 py-2.5 rounded-xl text-sm font-bold
                     bg-gradient-to-r from-red-500 to-rose-600 text-white
                     hover:from-red-600 hover:to-rose-700
                     disabled:opacity-50 active:scale-95 transition-all">
        Delete
      </button>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     CONFIRM SIGN OUT POPUP MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'logout'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-sm p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center gap-4 mb-5">
      <div class="p-3 bg-blue-100 dark:bg-blue-900/40 rounded-xl shrink-0">
        <svg class="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round"
                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
        </svg>
      </div>
      <div>
        <h4 class="font-bold text-black dark:text-slate-100">Sign Out</h4>
        <p class="text-sm text-slate-700 dark:text-slate-300 mt-0.5">
          Are you sure you want to sign out of VARS?
        </p>
      </div>
    </div>
    <div class="flex gap-3">
      <button type="button" @click="closeModal()"
              class="flex-1 py-2.5 rounded-xl text-sm font-semibold
                     bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300
                     hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
        Cancel
      </button>
      <a href="?action=logout"
         class="flex-1 py-2.5 rounded-xl text-sm font-bold text-center
                bg-gradient-to-r from-red-500 to-rose-600 text-white
                hover:from-red-600 hover:to-rose-700 transition-all">
        Sign Out
      </a>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     ERROR ALERT POPUP DIALOG BOX
══════════════════════════════════════════════════════════════ -->
<div x-show="errorDialog.show" x-cloak
     class="fixed inset-0 z-[70] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="errorDialog.show = false">
  <div @click.self="errorDialog.show = false" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-sm p-6
              animate-slide-up border border-red-200 dark:border-red-800/60">
    <div class="flex items-start gap-4 mb-5">
      <div class="p-3 bg-red-100 dark:bg-red-900/40 rounded-xl shrink-0">
        <svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round"
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
        </svg>
      </div>
      <div class="min-w-0">
        <h4 class="font-bold text-black dark:text-slate-100" x-text="errorDialog.title"></h4>
        <p class="text-sm text-slate-800 dark:text-slate-300 mt-1 break-words" x-text="errorDialog.message"></p>
      </div>
    </div>
    <div class="flex justify-end">
      <button type="button" @click="errorDialog.show = false"
              class="w-full py-2.5 rounded-xl text-sm font-bold
                     bg-gradient-to-r from-red-600 to-rose-600 text-white
                     hover:from-red-700 hover:to-rose-700 active:scale-95 transition-all">
        OK
      </button>
    </div>
  </div>
</div>

<?php if ($isAdmin): ?>
<!-- ═══════════════════════════════════════════════════════════
     CREATE USER ACCOUNT MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'createUser'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-md p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center justify-between mb-5">
      <div>
        <h4 class="text-lg font-bold text-slate-800 dark:text-slate-100">Create User Account</h4>
        <p class="text-xs text-slate-500 dark:text-slate-400">Assign camp location and login access.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>
    </div>

    <form @submit.prevent="submitCreateUser()" class="space-y-4">
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-xs font-bold text-black dark:text-slate-300 uppercase tracking-wider mb-1">SVS No <span class="text-red-500">*</span></label>
          <input x-model="userForm.svs_no" type="text" required maxlength="40" placeholder="e.g. 51638"
                 class="w-full px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label class="block text-xs font-bold text-black dark:text-slate-300 uppercase tracking-wider mb-1">Rank</label>
          <select x-model="userForm.rank"
                  class="w-full px-3 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="">— Select Rank —</option>
            <?php
            foreach (['AC','LAC','CPL','SGT','FSGT','WO','MWO'] as $r) echo "<option value='$r'>$r</option>";
            ?>
          </select>
        </div>
      </div>
      <div>
        <label class="block text-xs font-bold text-black dark:text-slate-300 uppercase tracking-wider mb-1">Name <span class="text-red-500">*</span></label>
        <input x-model="userForm.name" type="text" required maxlength="120" placeholder="e.g. Silva"
               class="w-full px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div>
        <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1">Username</label>
        <input x-model="userForm.username" type="text" required maxlength="60" placeholder="e.g. sjp_guard"
               class="w-full px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-200 dark:border-blue-800/50 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div>
        <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1">Password</label>
        <input x-model="userForm.password" type="password" required minlength="6" placeholder="Minimum 6 characters"
               class="w-full px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-200 dark:border-blue-800/50 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1">Location</label>
          <select x-model="userForm.location" required
                  class="w-full px-3 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-200 dark:border-blue-800/50 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <template x-for="loc in activeLocations()" :key="loc.code">
              <option :value="loc.code" x-text="loc.name ? loc.code + ' — ' + loc.name : loc.code"></option>
            </template>
          </select>
        </div>
        <div>
          <label class="block text-xs font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider mb-1">Role</label>
          <select x-model="userForm.role"
                  class="w-full px-3 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-200 dark:border-blue-800/50 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="user">Operator (user)</option>
            <option value="admin">Administrator</option>
          </select>
        </div>
      </div>

      <label class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200 cursor-pointer">
        <input type="checkbox" x-model="userForm.is_active" class="rounded text-blue-600 focus:ring-blue-500" />
        <span>Allow login access immediately</span>
      </label>

      <div x-show="userFormError" x-cloak class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl px-3.5 py-2.5 text-xs text-red-700 dark:text-red-400" x-text="userFormError"></div>

      <div class="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-blue-900/30">
        <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-sm font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">Cancel</button>
        <button type="submit" :disabled="submitting" class="px-5 py-2 rounded-xl text-sm font-bold bg-gradient-to-r from-blue-600 to-blue-800 text-white disabled:opacity-50">Create Account</button>
      </div>
    </form>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     RESET USER PASSWORD MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'resetPass'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-sm p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <h4 class="text-lg font-bold text-slate-800 dark:text-slate-100 mb-1">Reset Password</h4>
    <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">
      Set a new password for <strong x-text="resetTarget.username"></strong>.
    </p>
    <form @submit.prevent="submitResetPass()" class="space-y-4">
      <input x-model="resetTarget.password" type="password" required minlength="6" placeholder="New password (min 6 chars)"
             class="w-full px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-200 dark:border-blue-800/50 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      <div class="flex gap-3">
        <button type="button" @click="closeModal()" class="flex-1 py-2 rounded-xl text-sm font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">Cancel</button>
        <button type="submit" class="flex-1 py-2 rounded-xl text-sm font-bold bg-gradient-to-r from-blue-600 to-blue-800 text-white">Update Password</button>
      </div>
    </form>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     EDIT CAMP LOCATION MODAL
══════════════════════════════════════════════════════════════ -->
<div x-show="modal === 'editLocation'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-md p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h4 class="text-lg font-bold text-black dark:text-slate-100">Edit Camp Location</h4>
        <p class="text-xs text-slate-600 dark:text-slate-400">Update camp code or display name.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>
    </div>

    <form @submit.prevent="submitEditLocation()" class="space-y-4">
      <div>
        <label class="block text-xs font-bold text-black dark:text-slate-300 uppercase tracking-wider mb-1">Camp Code</label>
        <input x-model="editLocForm.code" type="text" required maxlength="20" placeholder="e.g. SJP"
               class="w-full px-3.5 py-2.5 rounded-xl text-sm uppercase bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>
      <div>
        <label class="block text-xs font-bold text-black dark:text-slate-300 uppercase tracking-wider mb-1">Camp Name</label>
        <input x-model="editLocForm.name" type="text" maxlength="120" placeholder="e.g. Sri Jayewardenepura"
               class="w-full px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 dark:bg-blue-950/60 border border-slate-300 dark:border-blue-800/50 text-black dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500" />
      </div>

      <div x-show="editLocError" x-cloak class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl px-3.5 py-2.5 text-xs text-red-700 dark:text-red-400" x-text="editLocError"></div>

      <div class="flex justify-end gap-3 pt-2 border-t border-slate-100 dark:border-blue-900/30">
        <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-sm font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">Cancel</button>
        <button type="submit" :disabled="submitting" class="px-5 py-2 rounded-xl text-sm font-bold bg-gradient-to-r from-blue-600 to-blue-800 text-white disabled:opacity-50">Save Changes</button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<!-- ═══════════════════════════════════════════════════════════
     INTER-CAMP MOVEMENT MODALS
══════════════════════════════════════════════════════════════ -->

<!-- 1. Origin OUT Modal -->
<div x-show="modal === 'addMovement'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-2xl p-6 sm:p-7
              animate-slide-up border border-slate-200 dark:border-blue-900/40 max-h-[90vh] overflow-y-auto">
    <div class="flex items-center justify-between mb-5">
      <div>
        <h4 class="text-xl font-black text-black dark:text-slate-100">Register Movement (Origin OUT)</h4>
        <p class="text-xs text-slate-600 dark:text-slate-400">Dispatch airman on official visit to another SLAF base.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>
    </div>

    <form @submit.prevent="submitAddMovement()" class="space-y-4">
      <!-- Airman Lookup / Info -->
      <div class="p-4 rounded-xl bg-slate-50 dark:bg-blue-950/40 border border-slate-200 dark:border-blue-900/50 space-y-3">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <!-- SVS No -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">
              Service Number *
            </label>
            <input type="text" x-model="movementForm.svs_no"
                   @input.debounce.300ms="checkPersonnelLookup()"
                   required placeholder="e.g. S/12345"
                   class="input-field w-full px-3 py-2 rounded-xl text-xs font-bold text-slate-900 dark:text-white bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60 uppercase" />
          </div>

          <!-- Rank -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Rank *</label>
            <select x-model="movementForm.rank" required
                    class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-900 dark:text-white bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60">
              <option value="">— Select Rank —</option>
              <?php
              $ranks = ['AC','LAC','CPL','SGT','FSGT','WO','MWO','Plt Off','Fg Off','Flt Lt','Sqn Ldr','Wg Cdr','Gp Capt','Air Cdre','AVM'];
              foreach ($ranks as $r) echo "<option value='$r'>$r</option>";
              ?>
            </select>
          </div>

          <!-- NIC No -->
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">NIC No</label>
            <input type="text" x-model="movementForm.nic_no" placeholder="e.g. 199012345678"
                   class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-900 dark:text-white bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
          </div>
        </div>

        <!-- Name -->
        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Full Name *</label>
          <input type="text" x-model="movementForm.name" required placeholder="Enter airman's full name"
                 class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-900 dark:text-white bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>
      </div>

      <!-- Route: Origin & Destination -->
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Origin (Parent Base) *</label>
          <select x-model="movementForm.origin_camp" required :disabled="!isAdmin"
                  class="input-field w-full px-3 py-2 rounded-xl text-xs font-bold text-slate-900 dark:text-white bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60">
            <template x-for="loc in activeLocations" :key="loc.code">
              <option :value="loc.code" x-text="loc.code + ' — ' + (loc.name || loc.code)"></option>
            </template>
          </select>
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Destination Base *</label>
          <select x-model="movementForm.destination_camp" required
                  class="input-field w-full px-3 py-2 rounded-xl text-xs font-bold text-blue-700 dark:text-blue-400 bg-white dark:bg-[#071d35] border border-blue-400 dark:border-blue-700">
            <option value="">— Select Destination Base —</option>
            <template x-for="loc in activeLocations" :key="loc.code">
              <option :value="loc.code" x-text="loc.code + ' — ' + (loc.name || loc.code)" :disabled="loc.code === movementForm.origin_camp"></option>
            </template>
          </select>
        </div>
      </div>

      <!-- Purpose of Visit -->
      <div>
        <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Purpose of Visit *</label>
        <textarea x-model="movementForm.purpose_of_visit" required rows="2" placeholder="Official duty, court martial witness, transit, sports, etc."
                  class="input-field w-full px-3 py-2 rounded-xl text-xs font-medium text-slate-900 dark:text-white bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60"></textarea>
      </div>

      <!-- Authority Details -->
      <div class="p-3.5 rounded-xl bg-slate-50 dark:bg-blue-950/30 border border-slate-200 dark:border-blue-900/50 space-y-2.5">
        <p class="text-[11px] font-bold text-slate-600 dark:text-blue-300/80 uppercase tracking-wider">Authorizing Officer Details</p>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          <input type="text" x-model="movementForm.authority_name" placeholder="Officer Name"
                 class="input-field w-full px-3 py-1.5 rounded-lg text-xs bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
          <input type="text" x-model="movementForm.authority_rank" placeholder="Officer Rank"
                 class="input-field w-full px-3 py-1.5 rounded-lg text-xs bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
          <input type="text" x-model="movementForm.authority_ref" placeholder="Signal / Authority Ref No"
                 class="input-field w-full px-3 py-1.5 rounded-lg text-xs bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>
      </div>

      <!-- Expected Arrival / Return -->
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Expected Arrival at Destination</label>
          <input type="datetime-local" x-model="movementForm.expected_arrival"
                 class="input-field w-full px-3 py-2 rounded-xl text-xs bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>
        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Expected Return to Base</label>
          <input type="datetime-local" x-model="movementForm.expected_return"
                 class="input-field w-full px-3 py-2 rounded-xl text-xs bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>
      </div>

      <!-- Remarks -->
      <div>
        <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Remarks</label>
        <input type="text" x-model="movementForm.remarks" placeholder="Optional gate remarks"
               class="input-field w-full px-3 py-2 rounded-xl text-xs bg-white dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
      </div>

      <div x-show="movementError" x-cloak class="p-3 rounded-xl bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 text-xs font-medium" x-text="movementError"></div>

      <div class="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-blue-900/40">
        <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-100">Cancel</button>
        <button type="submit" :disabled="submitting"
                class="px-6 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-blue-800 hover:from-blue-700 hover:to-blue-900 shadow-md disabled:opacity-50">
          Confirm Dispatch (Origin OUT)
        </button>
      </div>
    </form>
  </div>
</div>

<!-- 2. Destination IN Confirmation Modal -->
<div x-show="modal === 'destIn'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-lg p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h4 class="text-lg font-bold text-black dark:text-slate-100">Confirm Host Base Arrival (IN)</h4>
        <p class="text-xs text-slate-600 dark:text-slate-400">Verify serviceman arrival at destination base.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>

    <template x-if="activeTargetMovement">
      <div class="space-y-4">
        <div class="p-4 rounded-xl bg-slate-50 dark:bg-blue-950/40 border border-slate-200 dark:border-blue-900/50">
          <div class="flex items-center justify-between text-xs font-mono font-bold text-blue-700 dark:text-blue-400 mb-2">
            <span x-text="activeTargetMovement.movement_ref"></span>
            <span class="px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200"
                  x-text="activeTargetMovement.origin_camp + ' &rarr; ' + activeTargetMovement.destination_camp"></span>
          </div>
          <div class="text-base font-black text-slate-900 dark:text-white"
               x-text="(activeTargetMovement.rank ? activeTargetMovement.rank + ' ' : '') + activeTargetMovement.name"></div>
          <div class="text-xs text-slate-500 font-mono mt-0.5" x-text="'Service No: ' + activeTargetMovement.svs_no"></div>
          <div class="text-xs text-slate-700 dark:text-slate-300 mt-2 font-medium" x-text="'Purpose: ' + activeTargetMovement.purpose_of_visit"></div>
        </div>

        <div class="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/50 text-xs text-emerald-800 dark:text-emerald-300 font-medium">
          &check; A 24-hour temporary accommodation validity period will automatically activate starting from confirmation.
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Billet / Room Location (Optional)</label>
          <input type="text" x-model="actionForm.billet" placeholder="e.g. Transit Billet Room 4"
                 class="input-field w-full px-3.5 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Gate Remarks</label>
          <input type="text" x-model="actionForm.remarks" placeholder="Optional arrival remarks"
                 class="input-field w-full px-3.5 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>

        <div class="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-blue-900/40">
          <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-300">Cancel</button>
          <button type="button" @click="submitDestIn()" :disabled="submitting"
                  class="px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-700 hover:to-emerald-800 shadow-md">
            Confirm Arrival &amp; Activate Accommodation
          </button>
        </div>
      </div>
    </template>
  </div>
</div>

<!-- 3. Destination OUT Modal -->
<div x-show="modal === 'destOut'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-lg p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h4 class="text-lg font-bold text-black dark:text-slate-100">Confirm Host Base Departure (OUT)</h4>
        <p class="text-xs text-slate-600 dark:text-slate-400">Record serviceman departure from host base. Closes temporary accommodation.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>

    <template x-if="activeTargetMovement">
      <div class="space-y-4">
        <div class="p-4 rounded-xl bg-slate-50 dark:bg-blue-950/40 border border-slate-200 dark:border-blue-900/50">
          <div class="font-bold text-slate-900 dark:text-white"
               x-text="(activeTargetMovement.rank ? activeTargetMovement.rank + ' ' : '') + activeTargetMovement.name + ' (' + activeTargetMovement.svs_no + ')'"></div>
          <div class="text-xs text-slate-500 mt-1" x-text="'Departing from ' + activeTargetMovement.destination_camp + ' &rarr; Returning to ' + activeTargetMovement.origin_camp"></div>
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Departure Remarks</label>
          <input type="text" x-model="actionForm.remarks" placeholder="Optional checkout remarks"
                 class="input-field w-full px-3.5 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>

        <div class="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-blue-900/40">
          <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-300">Cancel</button>
          <button type="button" @click="submitDestOut()" :disabled="submitting"
                  class="px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-amber-600 to-amber-700 hover:from-amber-700 hover:to-amber-800 shadow-md">
            Confirm Departure from Base
          </button>
        </div>
      </div>
    </template>
  </div>
</div>

<!-- 4. Origin Return IN Modal -->
<div x-show="modal === 'returnIn'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-lg p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h4 class="text-lg font-bold text-black dark:text-slate-100">Confirm Return to Parent Base (Final IN)</h4>
        <p class="text-xs text-slate-600 dark:text-slate-400">Serviceman has returned to home base. Finalizes the movement journey as COMPLETED.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>

    <template x-if="activeTargetMovement">
      <div class="space-y-4">
        <div class="p-4 rounded-xl bg-slate-50 dark:bg-blue-950/40 border border-slate-200 dark:border-blue-900/50">
          <div class="font-bold text-slate-900 dark:text-white"
               x-text="(activeTargetMovement.rank ? activeTargetMovement.rank + ' ' : '') + activeTargetMovement.name + ' (' + activeTargetMovement.svs_no + ')'"></div>
          <div class="text-xs text-slate-500 mt-1" x-text="'Returned safely from ' + activeTargetMovement.destination_camp + ' to ' + activeTargetMovement.origin_camp"></div>
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Return Remarks</label>
          <input type="text" x-model="actionForm.remarks" placeholder="Optional return remarks"
                 class="input-field w-full px-3.5 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>

        <div class="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-blue-900/40">
          <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-300">Cancel</button>
          <button type="button" @click="submitReturnIn()" :disabled="submitting"
                  class="px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-blue-800 hover:from-blue-700 hover:to-blue-900 shadow-md">
            Confirm Return &amp; Complete Journey
          </button>
        </div>
      </div>
    </template>
  </div>
</div>

<!-- 5. Extend Accommodation Modal -->
<div x-show="modal === 'extendAccom'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-lg p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h4 class="text-lg font-bold text-black dark:text-slate-100">Extend Temporary Accommodation</h4>
        <p class="text-xs text-slate-600 dark:text-slate-400">Grant an authorized validity extension for accommodated airman.</p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>

    <template x-if="activeTargetAccom">
      <form @submit.prevent="submitExtendAccom()" class="space-y-4">
        <div class="p-3.5 rounded-xl bg-slate-50 dark:bg-blue-950/40 border border-slate-200 dark:border-blue-900/50">
          <div class="font-bold text-sm text-slate-900 dark:text-white"
               x-text="(activeTargetAccom.rank ? activeTargetAccom.rank + ' ' : '') + activeTargetAccom.name + ' (' + activeTargetAccom.svs_no + ')'"></div>
          <div class="text-xs text-slate-500 mt-0.5" x-text="'Current Expiry: ' + activeTargetAccom.expires_fmt"></div>
        </div>

        <!-- Extension Hours -->
        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Additional Duration (Hours) *</label>
          <div class="grid grid-cols-4 gap-2 mb-2">
            <button type="button" @click="extendForm.hours = 12"
                    :class="extendForm.hours === 12 ? 'bg-blue-600 text-white font-bold' : 'bg-slate-100 dark:bg-blue-950 text-slate-700 dark:text-slate-300'"
                    class="py-1.5 rounded-lg text-xs transition-colors">+12 Hours</button>
            <button type="button" @click="extendForm.hours = 24"
                    :class="extendForm.hours === 24 ? 'bg-blue-600 text-white font-bold' : 'bg-slate-100 dark:bg-blue-950 text-slate-700 dark:text-slate-300'"
                    class="py-1.5 rounded-lg text-xs transition-colors">+24 Hours</button>
            <button type="button" @click="extendForm.hours = 48"
                    :class="extendForm.hours === 48 ? 'bg-blue-600 text-white font-bold' : 'bg-slate-100 dark:bg-blue-950 text-slate-700 dark:text-slate-300'"
                    class="py-1.5 rounded-lg text-xs transition-colors">+48 Hours</button>
            <button type="button" @click="extendForm.hours = 72"
                    :class="extendForm.hours === 72 ? 'bg-blue-600 text-white font-bold' : 'bg-slate-100 dark:bg-blue-950 text-slate-700 dark:text-slate-300'"
                    class="py-1.5 rounded-lg text-xs transition-colors">+72 Hours</button>
          </div>
          <input type="number" x-model.number="extendForm.hours" min="1" max="168" required
                 placeholder="Custom hours"
                 class="input-field w-full px-3.5 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
        </div>

        <!-- Authorizing Officer -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Authorizing Officer Name *</label>
            <input type="text" x-model="extendForm.authorized_by_name" required placeholder="Officer Name"
                   class="input-field w-full px-3 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Officer Rank</label>
            <input type="text" x-model="extendForm.authorized_by_rank" placeholder="e.g. Wg Cdr"
                   class="input-field w-full px-3 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60" />
          </div>
        </div>

        <!-- Reason -->
        <div>
          <label class="block text-xs font-bold text-slate-700 dark:text-slate-300 uppercase mb-1">Reason for Extension *</label>
          <textarea x-model="extendForm.reason" required rows="2" placeholder="Official duty extended, vehicle breakdown, flight reschedule, etc."
                    class="input-field w-full px-3 py-2 rounded-xl text-xs bg-slate-50 dark:bg-[#071d35] border border-slate-300 dark:border-blue-800/60"></textarea>
        </div>

        <div class="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-blue-900/40">
          <button type="button" @click="closeModal()" class="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-300">Cancel</button>
          <button type="submit" :disabled="submitting"
                  class="px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-blue-800 hover:from-blue-700 hover:to-blue-900 shadow-md">
            Grant Extension
          </button>
        </div>
      </form>
    </template>
  </div>
</div>

<!-- 6. Movement Journey Timeline Modal -->
<div x-show="modal === 'movementTimeline'" x-cloak
     class="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop"
     @keydown.escape.window="closeModal()">
  <div @click.self="closeModal()" class="absolute inset-0"></div>
  <div class="relative bg-white dark:bg-[#071d35] rounded-2xl shadow-2xl w-full max-w-xl p-6
              animate-slide-up border border-slate-200 dark:border-blue-900/40 max-h-[85vh] overflow-y-auto">
    <div class="flex items-center justify-between mb-4 pb-3 border-b border-slate-100 dark:border-blue-900/40">
      <div>
        <h4 class="text-lg font-bold text-black dark:text-slate-100">Movement Journey Timeline</h4>
        <p class="text-xs font-mono text-blue-600 dark:text-blue-400" x-text="timelineTarget?.movement_ref"></p>
      </div>
      <button @click="closeModal()" class="p-2 rounded-xl hover:bg-slate-100 text-slate-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>

    <!-- Timeline List -->
    <div class="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200 dark:before:bg-blue-900/60">
      <template x-for="(evt, idx) in timelineEvents" :key="evt.id">
        <div class="relative group">
          <div class="absolute -left-6 top-1 w-5 h-5 rounded-full border-2 border-white dark:border-[#071d35] flex items-center justify-center text-white"
               :class="evt.event_type.includes('IN') ? 'bg-emerald-500' : (evt.event_type.includes('OUT') ? 'bg-amber-500' : 'bg-blue-500')">
            <div class="w-1.5 h-1.5 rounded-full bg-white"></div>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold text-slate-900 dark:text-white" x-text="evt.event_type.replace('_', ' ')"></span>
              <span class="px-2 py-0.2 rounded text-[10px] font-bold bg-slate-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300"
                    x-text="'Base: ' + evt.camp_code"></span>
            </div>
            <p class="text-xs text-slate-600 dark:text-slate-400 mt-1" x-text="evt.remarks"></p>
            <div class="flex items-center gap-2 text-[11px] text-slate-400 mt-1">
              <span x-text="evt.event_time"></span>
              <span>&bull;</span>
              <span x-text="'Operator: ' + (evt.operator_name || evt.operator_username || 'System')"></span>
            </div>
          </div>
        </div>
      </template>
      <div x-show="timelineEvents.length === 0" class="text-xs text-slate-400 py-4">
        No event history logged yet.
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     ALPINE.JS APPLICATION LOGIC
══════════════════════════════════════════════════════════════ -->
<script>
function varsApp() {
  return {
    // Dark mode & Sidebar
    darkMode: false,
    sidebarOpen: false,
    sidebarCollapsed: false,
    activeTab: 'visitors',

    // Auth / Location state
    isAdmin: <?= $isAdmin ? 'true' : 'false' ?>,
    currentUserId: <?= (int)$_SESSION['user_id'] ?>,
    currentLocation: <?= json_encode($currentLocation, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    locFilter: <?= json_encode($locFilter, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    searchQuery: <?= json_encode($search, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    statusFilter: <?= json_encode($status, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    visitors: <?= json_encode($visitors, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    counts: <?= json_encode(['total' => (int)$counts['total'], 'still_in' => (int)$counts['still_in'], 'checked_out' => (int)$counts['checked_out']]) ?>,
    lastRefreshed: <?= json_encode(date('d M Y, H:i:s')) ?>,
    users: <?= json_encode($allUsers, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    locations: <?= json_encode($allLocations, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,

    // Inter-Camp Movements State
    movements: <?= json_encode($initialMovements, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    pendingArrivals: <?= json_encode($initialPendingArrivals, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    accommodations: <?= json_encode($initialAccommodations, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    movementCounts: <?= json_encode($initialMovementCounts, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    auditLogs: <?= json_encode($initialAuditLogs, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    activeLocationsList: <?= json_encode($activeLocations, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,

    movementSubTab: 'all',
    movementStatusFilter: 'all',
    movementSearch: '',
    movementForm: {
      svs_no: '',
      rank: '',
      name: '',
      nic_no: '',
      origin_camp: '',
      destination_camp: '',
      purpose_of_visit: '',
      authority_name: '',
      authority_svs: '',
      authority_rank: '',
      authority_designation: '',
      authority_ref: '',
      expected_arrival: '',
      expected_return: '',
      remarks: ''
    },
    movementError: '',
    activeTargetMovement: null,
    activeTargetAccom: null,
    actionForm: { remarks: '', billet: '' },
    extendForm: { hours: 24, reason: '', authorized_by_name: '', authorized_by_svs: '', authorized_by_rank: '' },
    timelineTarget: null,
    timelineEvents: [],
    inquiryFilters: { svs_no: '', name: '', movement_ref: '', status: '' },
    inquiryResults: [],

    get displayedMovements() {
      if (this.movementSubTab === 'pending') {
        return this.pendingArrivals || [];
      }
      return this.movements || [];
    },

    // Modal state: null | 'add' | 'markout' | 'delete' | 'createUser' | 'resetPass' | 'editLocation'
    modal: null,

    // Add-visitor form data
    form: { svs_no:'', rank:'', name:'', nic_no:'', parent_camp:'', location:'', remarks:'', authority_by:'' },
    formError: '',
    submitting: false,

    // Admin forms
    userForm: { svs_no:'', rank:'', name:'', username:'', password:'', location:'SJP', role:'user', is_active: true },
    userFormError: '',
    resetTarget: { id: null, username: '', password: '' },
    locForm: { code: '', name: '' },
    editLocForm: { id: null, code: '', name: '' },
    editLocError: '',

    // Confirm & error dialog context
    confirm: { id: null, name: '' },
    deleteDialog: { type: '', id: null, title: '', label: '' },
    errorDialog: { show: false, title: 'Error', message: '' },

    // Report Summary state
    reportRows: <?= json_encode($initialReport['rows'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    reportSummary: <?= json_encode($initialReport['summary'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    reportCamps: <?= json_encode($initialReport['camp_breakdown'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    reportGeneratedAt: <?= json_encode($initialReport['generated_at'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    reportPreset: 'all',
    reportFilters: {
      from_date: '',
      from_time: '',
      to_date: '',
      to_time: '',
      date_field: 'any',
      status: 'all',
      loc: <?= json_encode($isAdmin ? 'ALL' : $currentLocation, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
      q: ''
    },

    // Toast
    toast: { show: false, message: '', success: true, timer: null },

    // ── Lifecycle ──────────────────────────────────────────
    init() {
      this.darkMode = localStorage.getItem('vars_dark') === 'true';
      this.sidebarCollapsed = localStorage.getItem('vars_sidebar_collapsed') === 'true';
      setInterval(() => {
        if (this.activeTab === 'visitors' && !this.modal) {
          this.fetchVisitors(true);
        } else if (this.activeTab === 'movements' && !this.modal) {
          this.fetchMovements(true);
        } else if (this.activeTab === 'accommodation' && !this.modal) {
          this.fetchAccommodations(true);
        } else if (this.activeTab === 'reports' && !this.modal) {
          this.fetchReport(true);
        }
      }, 8000);
    },

    toggleSidebarCollapse() {
      this.sidebarCollapsed = !this.sidebarCollapsed;
      localStorage.setItem('vars_sidebar_collapsed', this.sidebarCollapsed);
    },

    async fetchVisitors(silent = false) {
      const params = new URLSearchParams();
      params.set('ajax', 'visitors');
      params.set('status', this.statusFilter || 'all');
      if (this.searchQuery) params.set('q', this.searchQuery);
      if (this.isAdmin) params.set('loc', this.locFilter || 'ALL');

      try {
        const res  = await fetch('dashboard.php?' + params.toString());
        if (!res.ok) return;
        const data = await res.json();
        if (data.success) {
          this.visitors      = data.visitors;
          this.counts        = data.counts;
          this.lastRefreshed = data.refreshed_at;
        }
      } catch (e) {
        if (!silent) this.showToast('Failed to refresh records.', false);
      }
    },

    setStatusFilter(val) {
      this.statusFilter = val;
      this.fetchVisitors();
    },

    resetFilters() {
      this.searchQuery  = '';
      this.statusFilter = 'all';
      if (this.isAdmin) this.locFilter = 'ALL';
      this.fetchVisitors();
    },

    async fetchReport(silent = false) {
      const params = new URLSearchParams();
      params.set('ajax', 'report');
      params.set('date_field', this.reportFilters.date_field || 'any');
      params.set('status', this.reportFilters.status || 'all');
      if (this.reportFilters.from_date) params.set('from_date', this.reportFilters.from_date);
      if (this.reportFilters.from_time) params.set('from_time', this.reportFilters.from_time);
      if (this.reportFilters.to_date)   params.set('to_date',   this.reportFilters.to_date);
      if (this.reportFilters.to_time)   params.set('to_time',   this.reportFilters.to_time);
      if (this.reportFilters.q)         params.set('q',         this.reportFilters.q);
      if (this.isAdmin)                 params.set('loc',       this.reportFilters.loc || 'ALL');

      try {
        const res  = await fetch('dashboard.php?' + params.toString());
        if (!res.ok) return;
        const data = await res.json();
        if (data.success) {
          this.reportRows        = data.rows;
          this.reportSummary     = data.summary;
          this.reportCamps       = data.camp_breakdown;
          this.reportGeneratedAt = data.generated_at;
        } else if (!silent) {
          this.showError(data.error || 'Failed to load report summary.');
        }
      } catch (e) {
        if (!silent) this.showError('Failed to load report summary.');
      }
    },

    onReportDateInput() {
      const f = this.reportFilters;
      this.reportPreset = (!f.from_date && !f.from_time && !f.to_date && !f.to_time) ? 'all' : '';
      this.fetchReport();
    },

    applyReportPreset(preset) {
      const pad = (n) => String(n).padStart(2, '0');
      const fmtDate = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
      const now = new Date();
      this.reportPreset = preset;
      if (preset === 'all') {
        this.reportFilters.from_date = '';
        this.reportFilters.from_time = '';
        this.reportFilters.to_date   = '';
        this.reportFilters.to_time   = '';
      } else if (preset === 'today') {
        const today = fmtDate(now);
        this.reportFilters.from_date = today;
        this.reportFilters.from_time = '00:00';
        this.reportFilters.to_date   = today;
        this.reportFilters.to_time   = '23:59';
      } else if (preset === 'week') {
        const start = new Date(now);
        start.setDate(now.getDate() - 6);
        this.reportFilters.from_date = fmtDate(start);
        this.reportFilters.from_time = '00:00';
        this.reportFilters.to_date   = fmtDate(now);
        this.reportFilters.to_time   = '23:59';
      } else if (preset === 'month') {
        const start = new Date(now.getFullYear(), now.getMonth(), 1);
        this.reportFilters.from_date = fmtDate(start);
        this.reportFilters.from_time = '00:00';
        this.reportFilters.to_date   = fmtDate(now);
        this.reportFilters.to_time   = '23:59';
      }
      this.fetchReport();
    },

    resetReportFilters() {
      this.reportPreset = 'all';
      this.reportFilters = {
        from_date: '',
        from_time: '',
        to_date: '',
        to_time: '',
        date_field: 'any',
        status: 'all',
        loc: this.isAdmin ? 'ALL' : this.currentLocation,
        q: ''
      };
      this.fetchReport();
    },

    printReport() {
      window.print();
    },

    exportReportCsv() {
      if (!this.reportRows || this.reportRows.length === 0) {
        this.showError('No report records available to export for the selected filters.', 'Nothing to Export');
        return;
      }
      const headers = [
        '#', 'SVS No', 'Camp', 'Rank', 'Name', 'NIC No', 'Parent Camp',
        'In Date', 'In Time', 'Out Date', 'Out Time', 'Duration',
        'Remarks', 'Authority By', 'Recorded By', 'Status'
      ];
      const esc = (val) => {
        const str = val === null || val === undefined ? '' : String(val);
        return '"' + str.replace(/"/g, '""') + '"';
      };
      const lines = [headers.map(esc).join(',')];
      this.reportRows.forEach((r, idx) => {
        const row = [
          idx + 1,
          r.svs_no || '',
          r.location || '',
          r.rank || '',
          r.name || '',
          r.nic_no || '',
          r.parent_camp || '',
          r.in_date_fmt || '',
          r.in_time_fmt || '',
          r.out_date_fmt || '',
          r.out_time_fmt || '',
          r.duration_fmt || '',
          r.remarks || '',
          r.authority_by || '',
          r.recorded_by || '',
          r.out_datetime ? 'Out Camp' : 'In Camp'
        ];
        lines.push(row.map(esc).join(','));
      });
      const csvContent = '\uFEFF' + lines.join('\r\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const scope = (this.isAdmin ? (this.reportFilters.loc || 'ALL') : this.currentLocation).toLowerCase();
      const stamp = new Date().toISOString().slice(0, 10);
      a.href = url;
      a.download = `vars-report-${scope}-${stamp}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    activeLocations() {
      return this.locations.filter(l => Number(l.is_active) === 1);
    },

    csrf() {
      return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    },

    // ── Dark mode ─────────────────────────────────────────
    toggleDark() {
      this.darkMode = !this.darkMode;
      localStorage.setItem('vars_dark', this.darkMode);
    },

    // ── Modal helpers ──────────────────────────────────────
    openModal(type) {
      this.modal = type;
      if (type === 'add') {
        const defLoc    = (this.isAdmin && this.locFilter !== 'ALL') ? this.locFilter : this.currentLocation;
        this.form       = { svs_no:'', rank:'', name:'', nic_no:'', parent_camp:'', location: defLoc, remarks:'', authority_by:'' };
        this.formError  = '';
        this.submitting = false;
      } else if (type === 'createUser') {
        const defLoc = this.activeLocations()[0]?.code || 'SJP';
        this.userForm      = { svs_no:'', rank:'', name:'', username:'', password:'', location: defLoc, role:'user', is_active: true };
        this.userFormError = '';
        this.submitting    = false;
      } else if (type === 'editLocation') {
        this.editLocError = '';
        this.submitting   = false;
      }
      document.body.classList.add('overflow-hidden');
    },

    closeModal() {
      this.modal = null;
      document.body.classList.remove('overflow-hidden');
    },

    // ── Show toast / Error popup dialog ────────────────────
    showError(message, title = 'Error') {
      this.errorDialog = { show: true, title, message: message || 'An unexpected error occurred.' };
    },

    showToast(message, success = true) {
      if (!success) {
        this.showError(message);
        return;
      }
      clearTimeout(this.toast.timer);
      this.toast = { show: true, message, success: true };
      this.toast.timer = setTimeout(() => { this.toast.show = false; }, 3800);
    },

    // ── Add Visitor (AJAX) ─────────────────────────────────
    async submitAddVisitor() {
      this.formError  = '';
      this.submitting = true;

      const payload = new FormData();
      payload.append('action', 'add_visitor');
      payload.append('_csrf', this.csrf());
      for (const [k, v] of Object.entries(this.form)) payload.append(k, v);

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();

        if (data.success) {
          this.closeModal();
          this.showToast(data.message, true);
          await this.fetchVisitors(true);
        } else {
          this.formError  = data.message;
          this.submitting = false;
          this.showError(data.message, 'Unable to Add Visitor');
        }
      } catch (e) {
        this.formError  = 'Network error. Please try again.';
        this.submitting = false;
        this.showError('Network error. Please try again.');
      }
    },

    // ── Mark Out ───────────────────────────────────────────
    confirmMarkOut(id, name) {
      const now  = new Date();
      const pad  = n => String(n).padStart(2, '0');
      const date = `${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())}`;
      const time = `${pad(now.getHours())}:${pad(now.getMinutes())}`;
      this.confirm = { id, name, out_date: date, out_time: time };
      this.openModal('markout');
    },

    async doMarkOut() {
      const payload = new FormData();
      payload.append('action', 'mark_out');
      payload.append('_csrf', this.csrf());
      payload.append('id', this.confirm.id);
      payload.append('out_datetime', this.confirm.out_date + 'T' + this.confirm.out_time);

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        this.closeModal();

        if (data.success) {
          this.showToast(data.message, true);
          await this.fetchVisitors(true);
        } else {
          this.showToast(data.message, false);
        }
      } catch (e) {
        this.showToast('Network error. Please try again.', false);
      }
    },

    // ── Delete Confirm Popup (Visitor / User / Location) ────
    confirmDelete(id, name) {
      this.deleteDialog = {
        type: 'visitor',
        id,
        title: 'Delete Visitor Record',
        label: name + "'s record",
      };
      this.submitting = false;
      this.openModal('delete');
    },

    deleteUser(u) {
      this.deleteDialog = {
        type: 'user',
        id: u.id,
        title: 'Delete User Account',
        label: '@' + u.username,
      };
      this.submitting = false;
      this.openModal('delete');
    },

    deleteLocation(loc) {
      this.deleteDialog = {
        type: 'location',
        id: loc.id,
        title: 'Delete Camp Location',
        label: loc.name ? `${loc.code} — ${loc.name}` : loc.code,
      };
      this.submitting = false;
      this.openModal('delete');
    },

    async executeDelete() {
      const { type, id } = this.deleteDialog;
      if (!type || !id) return;

      const actionMap = {
        visitor:  'delete_visitor',
        user:     'delete_user',
        location: 'delete_location',
      };
      const action = actionMap[type];
      if (!action) return;

      this.submitting = true;
      const payload = new FormData();
      payload.append('action', action);
      payload.append('_csrf', this.csrf());
      payload.append('id', id);

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        this.submitting = false;
        this.closeModal();

        if (data.success) {
          if (type === 'visitor') {
            await this.fetchVisitors(true);
          } else if (type === 'user') {
            this.users = this.users.filter(x => Number(x.id) !== Number(id));
          } else if (type === 'location') {
            this.locations = this.locations.filter(x => Number(x.id) !== Number(id));
          }
          this.showToast(data.message, true);
        } else {
          this.showError(data.message, 'Delete Failed');
        }
      } catch (e) {
        this.submitting = false;
        this.closeModal();
        this.showError('Network error. Please try again.');
      }
    },

    // ── Admin: Create User ─────────────────────────────────
    async submitCreateUser() {
      this.userFormError = '';
      this.submitting    = true;

      const payload = new FormData();
      payload.append('action', 'create_user');
      payload.append('_csrf', this.csrf());
      payload.append('svs_no', this.userForm.svs_no);
      payload.append('rank', this.userForm.rank);
      payload.append('name', this.userForm.name);
      payload.append('username', this.userForm.username);
      payload.append('password', this.userForm.password);
      payload.append('location', this.userForm.location);
      payload.append('role', this.userForm.role);
      payload.append('is_active', this.userForm.is_active ? '1' : '0');

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        this.submitting = false;

        if (data.success) {
          this.users.push(data.user);
          this.closeModal();
          this.showToast(data.message, true);
        } else {
          this.userFormError = data.message;
          this.showError(data.message, 'Account Error');
        }
      } catch (e) {
        this.userFormError = 'Network error. Please try again.';
        this.submitting    = false;
        this.showError('Network error. Please try again.');
      }
    },

    // ── Admin: Assign Location / Update Role ───────────────
    async updateUserLocation(u) {
      await this.updateUserField(u);
    },

    async updateUserField(u) {
      const payload = new FormData();
      payload.append('action', 'update_user');
      payload.append('_csrf', this.csrf());
      payload.append('id', u.id);
      payload.append('location', u.location);
      payload.append('role', u.role);
      payload.append('is_active', Number(u.is_active) === 1 ? '1' : '0');

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        if (!data.success) {
          this.showError(data.message, 'Update Failed');
          return false;
        }
        this.showToast(data.message, true);
        if (data.reload) {
          setTimeout(() => location.reload(), 600);
        }
        return true;
      } catch (e) {
        this.showError('Failed to update user.');
        return false;
      }
    },

    async toggleUserAccess(u) {
      const prev = Number(u.is_active) === 1 ? 1 : 0;
      u.is_active = prev === 1 ? 0 : 1;
      const ok = await this.updateUserField(u);
      if (!ok) u.is_active = prev;
    },

    openResetPass(u) {
      this.resetTarget = { id: u.id, username: u.username, password: '' };
      this.openModal('resetPass');
    },

    async submitResetPass() {
      const payload = new FormData();
      payload.append('action', 'update_user');
      payload.append('_csrf', this.csrf());
      payload.append('id', this.resetTarget.id);
      payload.append('password', this.resetTarget.password);

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        this.closeModal();
        this.showToast(data.message, !!data.success);
      } catch (e) {
        this.closeModal();
        this.showError('Failed to reset password.');
      }
    },

    // ── Admin: Locations ───────────────────────────────────
    async submitCreateLocation() {
      const payload = new FormData();
      payload.append('action', 'create_location');
      payload.append('_csrf', this.csrf());
      payload.append('code', this.locForm.code);
      payload.append('name', this.locForm.name);

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        if (data.success) {
          this.locations.push(data.location);
          this.locForm = { code: '', name: '' };
        }
        this.showToast(data.message, !!data.success);
      } catch (e) {
        this.showToast('Failed to add location.', false);
      }
    },

    openEditLocation(loc) {
      this.editLocForm = { id: loc.id, code: loc.code, name: loc.name || '' };
      this.openModal('editLocation');
    },

    async submitEditLocation() {
      this.editLocError = '';
      this.submitting   = true;

      const payload = new FormData();
      payload.append('action', 'edit_location');
      payload.append('_csrf', this.csrf());
      payload.append('id', this.editLocForm.id);
      payload.append('code', this.editLocForm.code);
      payload.append('name', this.editLocForm.name);

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        this.submitting = false;

        if (data.success) {
          const updated = data.location;
          this.locations = this.locations.map(x => Number(x.id) === Number(updated.id) ? updated : x);
          if (data.old_code && data.old_code !== updated.code) {
            this.users = this.users.map(u => u.location === data.old_code ? { ...u, location: updated.code } : u);
            if (this.locFilter === data.old_code) this.locFilter = updated.code;
            if (this.currentLocation === data.old_code) {
              this.currentLocation = updated.code;
              setTimeout(() => location.reload(), 500);
            }
          }
          await this.fetchVisitors(true);
          this.closeModal();
          this.showToast(data.message, true);
        } else {
          this.editLocError = data.message;
          this.showError(data.message, 'Location Error');
        }
      } catch (e) {
        this.editLocError = 'Network error. Please try again.';
        this.submitting   = false;
        this.showError('Network error. Please try again.');
      }
    },

    async toggleLocation(loc) {
      const next = Number(loc.is_active) === 1 ? 0 : 1;
      const payload = new FormData();
      payload.append('action', 'toggle_location');
      payload.append('_csrf', this.csrf());
      payload.append('id', loc.id);
      payload.append('is_active', String(next));

      try {
        const res  = await fetch('dashboard.php', { method:'POST', body: payload });
        const data = await res.json();
        if (data.success) loc.is_active = next;
        this.showToast(data.message, !!data.success);
      } catch (e) {
        this.showError('Failed to update location.');
      }
    },

    // ── Inter-Camp Movement & Accommodation Methods ────────
    async fetchMovements(silent = false) {
      const params = new URLSearchParams();
      params.set('ajax', 'movements');
      if (this.movementStatusFilter && this.movementStatusFilter !== 'all') {
        params.set('status', this.movementStatusFilter);
      }
      if (this.movementSearch) {
        params.set('q', this.movementSearch);
      }
      if (this.isAdmin) {
        params.set('loc', this.locFilter || 'ALL');
      }

      try {
        const res = await fetch('dashboard.php?' + params.toString());
        if (!res.ok) return;
        const data = await res.json();
        if (data.success) {
          this.movements       = data.movements || [];
          this.pendingArrivals = data.pending_arrivals || [];
          this.movementCounts  = data.counts || this.movementCounts;
        }
      } catch (e) {
        if (!silent) this.showToast('Failed to refresh movements.', false);
      }
    },

    async fetchAccommodations(silent = false) {
      const params = new URLSearchParams();
      params.set('ajax', 'accommodations');
      if (this.isAdmin) {
        params.set('loc', this.locFilter || 'ALL');
      }

      try {
        const res = await fetch('dashboard.php?' + params.toString());
        if (!res.ok) return;
        const data = await res.json();
        if (data.success) {
          this.accommodations = data.accommodations || [];
          this.movementCounts = data.counts || this.movementCounts;
        }
      } catch (e) {
        if (!silent) this.showToast('Failed to refresh accommodations.', false);
      }
    },

    async fetchAuditLogs(silent = false) {
      const params = new URLSearchParams();
      params.set('ajax', 'audit_logs');
      if (this.isAdmin) {
        params.set('loc', this.locFilter || 'ALL');
      }

      try {
        const res = await fetch('dashboard.php?' + params.toString());
        if (!res.ok) return;
        const data = await res.json();
        if (data.success) {
          this.auditLogs = data.audit_logs || [];
        }
      } catch (e) {
        if (!silent) this.showToast('Failed to refresh audit trail.', false);
      }
    },

    async checkPersonnelLookup() {
      const svs = (this.movementForm.svs_no || '').trim();
      if (svs.length < 3) return;
      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'lookup_personnel');
      payload.append('svs_no', svs);

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        if (data.success && data.personnel) {
          const p = data.personnel;
          if (p.rank && !this.movementForm.rank) this.movementForm.rank = p.rank;
          if (p.name && !this.movementForm.name) this.movementForm.name = p.name;
          if (p.nic_no && !this.movementForm.nic_no) this.movementForm.nic_no = p.nic_no;
          if (p.parent_camp && !this.isAdmin) this.movementForm.origin_camp = p.parent_camp;
        }
      } catch (e) {}
    },

    openAddMovementModal() {
      const defLoc = (this.isAdmin && this.locFilter !== 'ALL') ? this.locFilter : this.currentLocation;
      this.movementForm = {
        svs_no: '',
        rank: '',
        name: '',
        nic_no: '',
        origin_camp: defLoc,
        destination_camp: '',
        purpose_of_visit: '',
        authority_name: '',
        authority_svs: '',
        authority_rank: '',
        authority_designation: '',
        authority_ref: '',
        expected_arrival: '',
        expected_return: '',
        remarks: ''
      };
      this.movementError = '';
      this.submitting = false;
      this.openModal('addMovement');
    },

    async submitAddMovement() {
      this.movementError = '';
      this.submitting = true;
      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'register_origin_out');
      for (const [k, v] of Object.entries(this.movementForm)) {
        payload.append(k, v || '');
      }

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        this.submitting = false;
        if (data.success) {
          this.closeModal();
          this.showToast(data.message, true);
          await this.fetchMovements(true);
        } else {
          this.movementError = data.message || 'Failed to dispatch serviceman.';
        }
      } catch (e) {
        this.submitting = false;
        this.movementError = 'Server error processing movement.';
      }
    },

    openDestInModal(m) {
      this.activeTargetMovement = m;
      this.actionForm = { remarks: '', billet: '' };
      this.submitting = false;
      this.openModal('destIn');
    },

    async submitDestIn() {
      if (!this.activeTargetMovement) return;
      this.submitting = true;
      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'confirm_destination_in');
      payload.append('movement_id', this.activeTargetMovement.id);
      payload.append('remarks', this.actionForm.remarks || '');
      payload.append('billet', this.actionForm.billet || '');

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        this.submitting = false;
        if (data.success) {
          this.closeModal();
          this.showToast(data.message, true);
          await this.fetchMovements(true);
          await this.fetchAccommodations(true);
        } else {
          this.showError(data.message || 'Failed to confirm arrival.');
        }
      } catch (e) {
        this.submitting = false;
        this.showError('Server error confirming destination arrival.');
      }
    },

    openDestOutModal(m) {
      this.activeTargetMovement = m;
      this.actionForm = { remarks: '', billet: '' };
      this.submitting = false;
      this.openModal('destOut');
    },

    async submitDestOut() {
      if (!this.activeTargetMovement) return;
      this.submitting = true;
      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'register_destination_out');
      payload.append('movement_id', this.activeTargetMovement.id);
      payload.append('remarks', this.actionForm.remarks || '');

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        this.submitting = false;
        if (data.success) {
          this.closeModal();
          this.showToast(data.message, true);
          await this.fetchMovements(true);
          await this.fetchAccommodations(true);
        } else {
          this.showError(data.message || 'Failed to register destination departure.');
        }
      } catch (e) {
        this.submitting = false;
        this.showError('Server error registering departure.');
      }
    },

    openReturnInModal(m) {
      this.activeTargetMovement = m;
      this.actionForm = { remarks: '', billet: '' };
      this.submitting = false;
      this.openModal('returnIn');
    },

    async submitReturnIn() {
      if (!this.activeTargetMovement) return;
      this.submitting = true;
      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'confirm_origin_return_in');
      payload.append('movement_id', this.activeTargetMovement.id);
      payload.append('remarks', this.actionForm.remarks || '');

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        this.submitting = false;
        if (data.success) {
          this.closeModal();
          this.showToast(data.message, true);
          await this.fetchMovements(true);
        } else {
          this.showError(data.message || 'Failed to confirm return to base.');
        }
      } catch (e) {
        this.submitting = false;
        this.showError('Server error confirming return to base.');
      }
    },

    openExtendAccomModal(a) {
      this.activeTargetAccom = a;
      this.extendForm = {
        hours: 24,
        reason: '',
        authorized_by_name: '',
        authorized_by_svs: '',
        authorized_by_rank: ''
      };
      this.submitting = false;
      this.openModal('extendAccom');
    },

    async submitExtendAccom() {
      if (!this.activeTargetAccom) return;
      this.submitting = true;
      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'extend_accommodation');
      payload.append('accommodation_id', this.activeTargetAccom.id);
      payload.append('additional_hours', this.extendForm.hours);
      payload.append('reason', this.extendForm.reason);
      payload.append('authorized_by_name', this.extendForm.authorized_by_name);
      payload.append('authorized_by_svs', this.extendForm.authorized_by_svs || '');
      payload.append('authorized_by_rank', this.extendForm.authorized_by_rank || '');

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        this.submitting = false;
        if (data.success) {
          this.closeModal();
          this.showToast(data.message, true);
          await this.fetchAccommodations(true);
        } else {
          this.showError(data.message || 'Failed to extend accommodation.');
        }
      } catch (e) {
        this.submitting = false;
        this.showError('Server error extending accommodation.');
      }
    },

    async openMovementTimeline(m) {
      this.timelineTarget = m;
      this.timelineEvents = [];
      this.openModal('movementTimeline');

      const payload = new FormData();
      payload.append('_csrf', this.csrf());
      payload.append('action', 'get_movement_history');
      payload.append('movement_id', m.id);

      try {
        const res = await fetch('dashboard.php', { method: 'POST', body: payload });
        const data = await res.json();
        if (data.success) {
          this.timelineEvents = data.history || [];
        }
      } catch (e) {}
    },

    async executeInquiry() {
      const params = new URLSearchParams();
      params.set('ajax', 'movements');
      if (this.inquiryFilters.svs_no) params.set('q', this.inquiryFilters.svs_no);
      else if (this.inquiryFilters.name) params.set('q', this.inquiryFilters.name);
      else if (this.inquiryFilters.movement_ref) params.set('q', this.inquiryFilters.movement_ref);
      if (this.inquiryFilters.status) params.set('status', this.inquiryFilters.status);
      params.set('loc', 'ALL');

      try {
        const res = await fetch('dashboard.php?' + params.toString());
        const data = await res.json();
        if (data.success) {
          this.inquiryResults = data.movements || [];
        }
      } catch (e) {
        this.showToast('Inquiry search failed.', false);
      }
    },

    resetInquiry() {
      this.inquiryFilters = { svs_no: '', name: '', movement_ref: '', status: '' };
      this.inquiryResults = [];
    },
  };
}
</script>

</body>
</html>

