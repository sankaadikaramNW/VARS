<?php
// ============================================================
//  movement_service.php — Inter-Camp Personnel Movement & Accommodation Logic
//  VARS · Visiting Airmen Record System
// ============================================================

class SecurityException extends RuntimeException {}

/**
 * Record an entry into the immutable system audit log.
 */
function auditLog(
    PDO $pdo,
    string $actionType,
    string $entityType,
    string $entityId,
    string $refNo,
    array $details = []
): void {
    $userId    = $_SESSION['user_id'] ?? null;
    $username  = $_SESSION['username'] ?? 'system';
    $campCode  = $_SESSION['location'] ?? 'ALL';
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $userAgent = mb_substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

    $stmt = $pdo->prepare('
        INSERT INTO audit_logs 
            (user_id, username, camp_code, action_type, entity_type, entity_id, reference_no, details, ip_address, user_agent, created_at)
        VALUES 
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ');
    $stmt->execute([
        $userId,
        $username,
        $campCode,
        $actionType,
        $entityType,
        $entityId,
        $refNo,
        json_encode($details, JSON_UNESCAPED_UNICODE),
        $ipAddress,
        $userAgent
    ]);
}

/**
 * Retrieve a system setting from the database with a default fallback.
 */
function getSystemSetting(PDO $pdo, string $key, string $default = ''): string
{
    $stmt = $pdo->prepare('SELECT setting_value FROM system_settings WHERE setting_key = ? LIMIT 1');
    $stmt->execute([$key]);
    $val = $stmt->fetchColumn();
    return $val !== false ? (string)$val : $default;
}

/**
 * Generate a unique movement reference, e.g. MOV-20261113-A7F9K.
 */
function generateMovementRef(PDO $pdo): string
{
    $prefix = 'MOV-' . date('Ymd') . '-';
    for ($i = 0; $i < 10; $i++) {
        $candidate = $prefix . strtoupper(substr(bin2hex(random_bytes(3)), 0, 5));
        $check = $pdo->prepare('SELECT id FROM inter_camp_movements WHERE movement_ref = ? LIMIT 1');
        $check->execute([$candidate]);
        if (!$check->fetch()) {
            return $candidate;
        }
    }
    return $prefix . strtoupper(bin2hex(random_bytes(4)));
}

/**
 * Quick lookup of registered airman in the personnel master directory.
 */
function lookupPersonnel(PDO $pdo, string $svsNo): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM personnel WHERE svs_no = ? LIMIT 1');
    $stmt->execute([$svsNo]);
    $res = $stmt->fetch();
    return $res ?: null;
}

/**
 * Ensure personnel record is saved or updated in personnel master directory.
 */
function savePersonnel(PDO $pdo, array $data): void
{
    $svsNo      = trim($data['svs_no'] ?? '');
    $rank       = trim($data['rank'] ?? '');
    $name       = trim($data['name'] ?? '');
    $nicNo      = trim($data['nic_no'] ?? '');
    $parentCamp = trim($data['parent_camp'] ?? 'SJP');
    $contactNo  = trim($data['contact_no'] ?? '');

    if ($svsNo === '') {
        return;
    }

    $existing = lookupPersonnel($pdo, $svsNo);
    if ($existing) {
        $stmt = $pdo->prepare('
            UPDATE personnel 
            SET `rank` = ?, name = ?, nic_no = ?, parent_camp = ?, contact_no = ?, updated_at = NOW() 
            WHERE id = ?
        ');
        $stmt->execute([
            $rank ?: $existing['rank'],
            $name ?: $existing['name'],
            $nicNo ?: $existing['nic_no'],
            $parentCamp ?: $existing['parent_camp'],
            $contactNo ?: $existing['contact_no'],
            $existing['id']
        ]);
    } else {
        $stmt = $pdo->prepare('
            INSERT INTO personnel (svs_no, `rank`, name, nic_no, parent_camp, contact_no, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, NOW())
        ');
        $stmt->execute([$svsNo, $rank, $name, $nicNo, $parentCamp, $contactNo]);
    }
}

/**
 * Refresh accommodation statuses dynamically based on the current timestamp.
 */
function refreshAccommodationStatuses(PDO $pdo): void
{
    $warningHours = (int)getSystemSetting($pdo, 'ACCOMMODATION_WARNING_HOURS', '4');

    // 1. Mark EXPIRED if not checked out and past expiry time
    $pdo->exec("
        UPDATE temporary_accommodations 
        SET accommodation_status = 'EXPIRED'
        WHERE checkout_at IS NULL 
          AND accommodation_status != 'EXPIRED'
          AND current_expires_at < NOW()
    ");

    // 2. Mark EXPIRING_SOON if not checked out, not expired, and within warning threshold
    $stmt = $pdo->prepare("
        UPDATE temporary_accommodations 
        SET accommodation_status = 'EXPIRING_SOON'
        WHERE checkout_at IS NULL 
          AND accommodation_status IN ('ACTIVE', 'EXTENDED')
          AND current_expires_at >= NOW()
          AND current_expires_at <= DATE_ADD(NOW(), INTERVAL ? HOUR)
    ");
    $stmt->execute([$warningHours]);

    // 3. Mark ACTIVE/EXTENDED if expiry was extended into the future beyond warning threshold
    $pdo->exec("
        UPDATE temporary_accommodations 
        SET accommodation_status = 'ACTIVE'
        WHERE checkout_at IS NULL 
          AND accommodation_status = 'EXPIRING_SOON'
          AND current_expires_at > DATE_ADD(NOW(), INTERVAL {$warningHours} HOUR)
    ");
}

/**
 * Stage A: Register Origin OUT (Departed from Origin Camp).
 */
function registerOriginOut(
    PDO $pdo,
    array $data,
    int $userId,
    string $operatorCamp,
    bool $isAdmin
): array {
    $svsNo        = trim($data['svs_no'] ?? '');
    $rank         = trim($data['rank'] ?? '');
    $name         = trim($data['name'] ?? '');
    $nicNo        = trim($data['nic_no'] ?? '');
    $originCamp   = strtoupper(trim($data['origin_camp'] ?? ''));
    $destCamp     = strtoupper(trim($data['destination_camp'] ?? ''));
    $purpose      = trim($data['purpose_of_visit'] ?? '');
    $authName     = trim($data['authority_name'] ?? '');
    $authSvs      = trim($data['authority_svs'] ?? '');
    $authRank     = trim($data['authority_rank'] ?? '');
    $authDesig    = trim($data['authority_designation'] ?? '');
    $authRef      = trim($data['authority_ref'] ?? '');
    $expArrival   = !empty($data['expected_arrival']) ? date('Y-m-d H:i:s', strtotime($data['expected_arrival'])) : null;
    $expReturn    = !empty($data['expected_return']) ? date('Y-m-d H:i:s', strtotime($data['expected_return'])) : null;
    $remarks      = trim($data['remarks'] ?? '');

    if ($svsNo === '' || $name === '' || $originCamp === '' || $destCamp === '' || $purpose === '') {
        throw new InvalidArgumentException('Please complete all required fields (Service No, Name, Origin Camp, Destination Camp, and Purpose).');
    }

    if ($originCamp === $destCamp) {
        throw new InvalidArgumentException('Destination Camp must be different from Origin Camp.');
    }

    if (!$isAdmin && $originCamp !== strtoupper($operatorCamp)) {
        throw new SecurityException('You can only dispatch servicemen whose journey departs from your assigned camp (' . $operatorCamp . ').');
    }

    // Check for an active open movement for this serviceman
    $activeCheck = $pdo->prepare("
        SELECT movement_ref, movement_status, origin_camp, destination_camp 
        FROM inter_camp_movements 
        WHERE svs_no = ? AND movement_status NOT IN ('COMPLETED', 'CANCELLED')
        LIMIT 1
    ");
    $activeCheck->execute([$svsNo]);
    $openMov = $activeCheck->fetch();
    if ($openMov) {
        throw new RuntimeException("Airman {$svsNo} already has an active incomplete journey ({$openMov['movement_ref']} - {$openMov['movement_status']}). Must be returned or closed before starting a new movement.");
    }

    $pdo->beginTransaction();
    try {
        // Auto-save airman to personnel directory
        savePersonnel($pdo, [
            'svs_no'      => $svsNo,
            'rank'        => $rank,
            'name'        => $name,
            'nic_no'      => $nicNo,
            'parent_camp' => $originCamp
        ]);

        $movementRef = generateMovementRef($pdo);

        $stmt = $pdo->prepare('
            INSERT INTO inter_camp_movements (
                movement_ref, svs_no, `rank`, name, nic_no, origin_camp, destination_camp,
                purpose_of_visit, authority_name, authority_svs, authority_rank, authority_designation, authority_ref,
                movement_status, expected_arrival, expected_return, actual_out_at, created_by, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                "DEPARTED_ORIGIN", ?, ?, NOW(), ?, NOW()
            )
        ');
        $stmt->execute([
            $movementRef, $svsNo, $rank, $name, $nicNo, $originCamp, $destCamp,
            $purpose, $authName, $authSvs, $authRank, $authDesig, $authRef,
            $expArrival, $expReturn, $userId
        ]);
        $movementId = (int)$pdo->lastInsertId();

        // Record Stage A event in immutable log
        $evt = $pdo->prepare('
            INSERT INTO movement_events (movement_id, movement_ref, event_type, camp_code, operator_id, event_time, remarks, ip_address)
            VALUES (?, ?, "ORIGIN_OUT", ?, ?, NOW(), ?, ?)
        ');
        $evt->execute([
            $movementId,
            $movementRef,
            $originCamp,
            $userId,
            $remarks ?: 'Serviceman checked OUT from Origin base.',
            $_SERVER['REMOTE_ADDR'] ?? ''
        ]);

        auditLog($pdo, 'ORIGIN_OUT', 'inter_camp_movements', (string)$movementId, $movementRef, [
            'svs_no'           => $svsNo,
            'origin_camp'      => $originCamp,
            'destination_camp' => $destCamp,
            'purpose'          => $purpose
        ]);

        $pdo->commit();

        return [
            'movement_id'  => $movementId,
            'movement_ref' => $movementRef,
            'status'       => 'DEPARTED_ORIGIN'
        ];
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * Stage B: Confirm Destination IN (Arrival at Host Camp & Activate 24h Accommodation).
 */
function confirmDestinationIn(
    PDO $pdo,
    int $movementId,
    int $userId,
    string $operatorCamp,
    bool $isAdmin,
    string $remarks = '',
    string $billet = ''
): array {
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT * FROM inter_camp_movements WHERE id = ? FOR UPDATE');
        $stmt->execute([$movementId]);
        $mov = $stmt->fetch();

        if (!$mov) {
            throw new RuntimeException('Movement record not found.');
        }

        if ($mov['movement_status'] !== 'DEPARTED_ORIGIN') {
            throw new RuntimeException("Cannot check IN: Movement status is {$mov['movement_status']} (expected DEPARTED_ORIGIN).");
        }

        if (!$isAdmin && strtoupper($mov['destination_camp']) !== strtoupper($operatorCamp)) {
            throw new SecurityException("Access denied: You are stationed at {$operatorCamp}, but this serviceman's destination is {$mov['destination_camp']}.");
        }

        // Update movement
        $upd = $pdo->prepare('
            UPDATE inter_camp_movements 
            SET movement_status = "ARRIVED_DESTINATION", actual_in_at = NOW(), updated_at = NOW() 
            WHERE id = ?
        ');
        $upd->execute([$movementId]);

        // Event log
        $evt = $pdo->prepare('
            INSERT INTO movement_events (movement_id, movement_ref, event_type, camp_code, operator_id, event_time, remarks, ip_address)
            VALUES (?, ?, "DESTINATION_IN", ?, ?, NOW(), ?, ?)
        ');
        $evt->execute([
            $movementId,
            $mov['movement_ref'],
            $mov['destination_camp'],
            $userId,
            $remarks ?: 'Serviceman checked IN at Destination base.',
            $_SERVER['REMOTE_ADDR'] ?? ''
        ]);

        // 24-hour default temporary accommodation
        $defaultHours = (int)getSystemSetting($pdo, 'DEFAULT_ACCOMMODATION_HOURS', '24');
        $accomStmt = $pdo->prepare('
            INSERT INTO temporary_accommodations (
                movement_id, movement_ref, camp_code, svs_no, `rank`, name,
                checkin_at, original_expires_at, current_expires_at, accommodation_status,
                billet_location, checkin_operator_id, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?,
                NOW(), DATE_ADD(NOW(), INTERVAL ? HOUR), DATE_ADD(NOW(), INTERVAL ? HOUR), "ACTIVE",
                ?, ?, NOW()
            )
        ');
        $accomStmt->execute([
            $movementId,
            $mov['movement_ref'],
            $mov['destination_camp'],
            $mov['svs_no'],
            $mov['rank'],
            $mov['name'],
            $defaultHours,
            $defaultHours,
            $billet,
            $userId
        ]);

        auditLog($pdo, 'DESTINATION_IN', 'inter_camp_movements', (string)$movementId, $mov['movement_ref'], [
            'destination_camp' => $mov['destination_camp'],
            'accom_hours'      => $defaultHours,
            'billet'           => $billet
        ]);

        $pdo->commit();

        return [
            'movement_id'   => $movementId,
            'movement_ref'  => $mov['movement_ref'],
            'status'        => 'ARRIVED_DESTINATION',
            'accom_hours'   => $defaultHours
        ];
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * Stage D: Register Destination OUT (Departed from Destination Camp, Closes Accommodation).
 */
function registerDestinationOut(
    PDO $pdo,
    int $movementId,
    int $userId,
    string $operatorCamp,
    bool $isAdmin,
    string $remarks = ''
): array {
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT * FROM inter_camp_movements WHERE id = ? FOR UPDATE');
        $stmt->execute([$movementId]);
        $mov = $stmt->fetch();

        if (!$mov) {
            throw new RuntimeException('Movement record not found.');
        }

        if ($mov['movement_status'] !== 'ARRIVED_DESTINATION') {
            throw new RuntimeException("Cannot check OUT from destination: Airman is not currently recorded as inside ({$mov['movement_status']}).");
        }

        if (!$isAdmin && strtoupper($mov['destination_camp']) !== strtoupper($operatorCamp)) {
            throw new SecurityException("Access denied: You are stationed at {$operatorCamp}, but this serviceman is stationed at {$mov['destination_camp']}.");
        }

        // Update movement
        $upd = $pdo->prepare('
            UPDATE inter_camp_movements 
            SET movement_status = "DEPARTED_DESTINATION", actual_dest_out_at = NOW(), updated_at = NOW() 
            WHERE id = ?
        ');
        $upd->execute([$movementId]);

        // Close accommodation
        $accomUpd = $pdo->prepare('
            UPDATE temporary_accommodations 
            SET accommodation_status = "CLOSED", checkout_at = NOW(), checkout_operator_id = ?, updated_at = NOW() 
            WHERE movement_id = ? AND checkout_at IS NULL
        ');
        $accomUpd->execute([$userId, $movementId]);

        // Event log
        $evt = $pdo->prepare('
            INSERT INTO movement_events (movement_id, movement_ref, event_type, camp_code, operator_id, event_time, remarks, ip_address)
            VALUES (?, ?, "DESTINATION_OUT", ?, ?, NOW(), ?, ?)
        ');
        $evt->execute([
            $movementId,
            $mov['movement_ref'],
            $mov['destination_camp'],
            $userId,
            $remarks ?: 'Serviceman checked OUT from Destination base. Returning to parent camp.',
            $_SERVER['REMOTE_ADDR'] ?? ''
        ]);

        auditLog($pdo, 'DESTINATION_OUT', 'inter_camp_movements', (string)$movementId, $mov['movement_ref'], [
            'destination_camp' => $mov['destination_camp']
        ]);

        $pdo->commit();

        return [
            'movement_id'  => $movementId,
            'movement_ref' => $mov['movement_ref'],
            'status'       => 'DEPARTED_DESTINATION'
        ];
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * Stage E: Confirm Final IN (Returned to Origin Camp & Movement Completed).
 */
function confirmOriginReturnIn(
    PDO $pdo,
    int $movementId,
    int $userId,
    string $operatorCamp,
    bool $isAdmin,
    string $remarks = ''
): array {
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT * FROM inter_camp_movements WHERE id = ? FOR UPDATE');
        $stmt->execute([$movementId]);
        $mov = $stmt->fetch();

        if (!$mov) {
            throw new RuntimeException('Movement record not found.');
        }

        if ($mov['movement_status'] !== 'DEPARTED_DESTINATION') {
            throw new RuntimeException("Cannot confirm return: Serviceman has not yet departed the destination camp (status: {$mov['movement_status']}).");
        }

        if (!$isAdmin && strtoupper($mov['origin_camp']) !== strtoupper($operatorCamp)) {
            throw new SecurityException("Access denied: You are stationed at {$operatorCamp}, but this serviceman's parent camp is {$mov['origin_camp']}.");
        }

        // Finalize movement
        $upd = $pdo->prepare('
            UPDATE inter_camp_movements 
            SET movement_status = "COMPLETED", actual_return_in_at = NOW(), updated_at = NOW() 
            WHERE id = ?
        ');
        $upd->execute([$movementId]);

        // Event log
        $evt = $pdo->prepare('
            INSERT INTO movement_events (movement_id, movement_ref, event_type, camp_code, operator_id, event_time, remarks, ip_address)
            VALUES (?, ?, "ORIGIN_RETURN_IN", ?, ?, NOW(), ?, ?)
        ');
        $evt->execute([
            $movementId,
            $mov['movement_ref'],
            $mov['origin_camp'],
            $userId,
            $remarks ?: 'Serviceman returned to parent base. Movement lifecycle finalized.',
            $_SERVER['REMOTE_ADDR'] ?? ''
        ]);

        auditLog($pdo, 'ORIGIN_RETURN_IN', 'inter_camp_movements', (string)$movementId, $mov['movement_ref'], [
            'origin_camp' => $mov['origin_camp']
        ]);

        $pdo->commit();

        return [
            'movement_id'  => $movementId,
            'movement_ref' => $mov['movement_ref'],
            'status'       => 'COMPLETED'
        ];
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * Authorized Extension of Temporary Accommodation Validity.
 */
function extendAccommodation(
    PDO $pdo,
    int $accommodationId,
    int $userId,
    string $operatorCamp,
    bool $isAdmin,
    int $additionalHours,
    string $reason,
    string $authName,
    string $authSvs = '',
    string $authRank = ''
): array {
    if ($additionalHours <= 0 || $additionalHours > 168) {
        throw new InvalidArgumentException('Extension duration must be between 1 and 168 hours (7 days).');
    }
    if ($reason === '' || $authName === '') {
        throw new InvalidArgumentException('Please provide a reason and authorizing officer details.');
    }

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT * FROM temporary_accommodations WHERE id = ? FOR UPDATE');
        $stmt->execute([$accommodationId]);
        $accom = $stmt->fetch();

        if (!$accom) {
            throw new RuntimeException('Accommodation record not found.');
        }

        if ($accom['accommodation_status'] === 'CLOSED') {
            throw new RuntimeException('Cannot extend: Accommodation has already been closed/checked out.');
        }

        if (!$isAdmin && strtoupper($accom['camp_code']) !== strtoupper($operatorCamp)) {
            throw new SecurityException("Access denied: You are stationed at {$operatorCamp}, but this accommodation is at {$accom['camp_code']}.");
        }

        $prevExpiry = $accom['current_expires_at'];
        // If already expired, extend starting from current timestamp; otherwise extend from existing expiry
        $baseTime   = strtotime($prevExpiry) < time() ? time() : strtotime($prevExpiry);
        $newExpiry  = date('Y-m-d H:i:s', $baseTime + ($additionalHours * 3600));

        // Insert extension audit record
        $ext = $pdo->prepare('
            INSERT INTO accommodation_extensions (
                accommodation_id, previous_expires_at, new_expires_at, extended_hours,
                reason, authorized_by_name, authorized_by_svs, authorized_by_rank, operator_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ');
        $ext->execute([
            $accommodationId,
            $prevExpiry,
            $newExpiry,
            $additionalHours,
            $reason,
            $authName,
            $authSvs,
            $authRank,
            $userId
        ]);

        // Update accommodation record
        $upd = $pdo->prepare('
            UPDATE temporary_accommodations 
            SET current_expires_at = ?, accommodation_status = "EXTENDED", updated_at = NOW() 
            WHERE id = ?
        ');
        $upd->execute([$newExpiry, $accommodationId]);

        // Add event to movement event stream
        $evt = $pdo->prepare('
            INSERT INTO movement_events (movement_id, movement_ref, event_type, camp_code, operator_id, event_time, remarks, ip_address)
            VALUES (?, ?, "EXTENSION_GRANTED", ?, ?, NOW(), ?, ?)
        ');
        $evt->execute([
            $accom['movement_id'],
            $accom['movement_ref'],
            $accom['camp_code'],
            $userId,
            "Accommodation extended by {$additionalHours}h until {$newExpiry}. Authorized by {$authRank} {$authName}. Reason: {$reason}",
            $_SERVER['REMOTE_ADDR'] ?? ''
        ]);

        auditLog($pdo, 'EXTEND_ACCOMMODATION', 'temporary_accommodations', (string)$accommodationId, $accom['movement_ref'], [
            'previous_expiry'  => $prevExpiry,
            'new_expiry'       => $newExpiry,
            'additional_hours' => $additionalHours,
            'authorized_by'    => "{$authRank} {$authName}",
            'reason'           => $reason
        ]);

        $pdo->commit();

        return [
            'accommodation_id' => $accommodationId,
            'new_expiry'       => $newExpiry,
            'status'           => 'EXTENDED'
        ];
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * Fetch chronological event history for a movement.
 */
function fetchMovementHistory(PDO $pdo, int $movementId): array
{
    $stmt = $pdo->prepare('
        SELECT me.*, u.name AS operator_name, u.username AS operator_username, u.rank AS operator_rank
        FROM movement_events me
        LEFT JOIN users u ON u.id = me.operator_id
        WHERE me.movement_id = ?
        ORDER BY me.event_time ASC, me.id ASC
    ');
    $stmt->execute([$movementId]);
    return $stmt->fetchAll();
}

/**
 * Fetch movements list with camp and status scoping.
 */
function fetchMovementsList(PDO $pdo, bool $isAdmin, string $currentLocation, array $filters = []): array
{
    $q         = trim($filters['q'] ?? '');
    $status    = trim($filters['status'] ?? 'all');
    $locFilter = $isAdmin ? strtoupper(trim($filters['loc'] ?? 'ALL')) : $currentLocation;

    $sql = '
        SELECT m.*, u.name AS created_by_name, u.rank AS created_by_rank,
               ta.id AS accommodation_id, ta.accommodation_status, ta.current_expires_at, ta.billet_location
        FROM inter_camp_movements m
        LEFT JOIN users u ON u.id = m.created_by
        LEFT JOIN temporary_accommodations ta ON ta.movement_id = m.id
    ';
    $where  = [];
    $params = [];

    if (!$isAdmin || $locFilter !== 'ALL') {
        $target = $isAdmin ? $locFilter : $currentLocation;
        $where[] = '(m.origin_camp = :loc1 OR m.destination_camp = :loc2)';
        $params[':loc1'] = $target;
        $params[':loc2'] = $target;
    }

    if ($status !== 'all' && $status !== '') {
        $where[] = 'm.movement_status = :status';
        $params[':status'] = $status;
    }

    if ($q !== '') {
        $where[] = '(m.movement_ref LIKE :q1 OR m.svs_no LIKE :q2 OR m.name LIKE :q3 OR m.nic_no LIKE :q4 OR m.origin_camp LIKE :q5 OR m.destination_camp LIKE :q6 OR m.authority_name LIKE :q7)';
        $searchTerm = '%' . $q . '%';
        for ($i = 1; $i <= 7; $i++) {
            $params[":q{$i}"] = $searchTerm;
        }
    }

    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY m.id DESC LIMIT 300';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$r) {
        $r['out_fmt']        = date('d M Y, H:i', strtotime($r['actual_out_at']));
        $r['in_fmt']         = !empty($r['actual_in_at']) ? date('d M Y, H:i', strtotime($r['actual_in_at'])) : '—';
        $r['dest_out_fmt']   = !empty($r['actual_dest_out_at']) ? date('d M Y, H:i', strtotime($r['actual_dest_out_at'])) : '—';
        $r['return_in_fmt']  = !empty($r['actual_return_in_at']) ? date('d M Y, H:i', strtotime($r['actual_return_in_at'])) : '—';
    }
    unset($r);

    return $rows;
}

/**
 * Fetch pending incoming arrivals for a camp.
 */
function fetchPendingArrivalsList(PDO $pdo, bool $isAdmin, string $currentLocation): array
{
    $sql = '
        SELECT m.*, u.name AS operator_name, u.rank AS operator_rank
        FROM inter_camp_movements m
        LEFT JOIN users u ON u.id = m.created_by
        WHERE m.movement_status = "DEPARTED_ORIGIN"
    ';
    $params = [];
    if (!$isAdmin) {
        $sql .= ' AND m.destination_camp = ?';
        $params[] = $currentLocation;
    }
    $sql .= ' ORDER BY m.actual_out_at ASC';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$r) {
        $r['out_fmt'] = date('d M Y, H:i', strtotime($r['actual_out_at']));
    }
    unset($r);

    return $rows;
}

/**
 * Fetch temporary accommodations with remaining time calculations.
 */
function fetchAccommodationsList(PDO $pdo, bool $isAdmin, string $currentLocation, array $filters = []): array
{
    $status    = trim($filters['status'] ?? 'all');
    $locFilter = $isAdmin ? strtoupper(trim($filters['loc'] ?? 'ALL')) : $currentLocation;

    $sql = '
        SELECT ta.*, m.origin_camp, m.purpose_of_visit, m.authority_name, m.movement_status,
               u1.name AS checkin_op_name, u2.name AS checkout_op_name
        FROM temporary_accommodations ta
        JOIN inter_camp_movements m ON m.id = ta.movement_id
        LEFT JOIN users u1 ON u1.id = ta.checkin_operator_id
        LEFT JOIN users u2 ON u2.id = ta.checkout_operator_id
    ';
    $where  = [];
    $params = [];

    if (!$isAdmin || $locFilter !== 'ALL') {
        $target = $isAdmin ? $locFilter : $currentLocation;
        $where[] = 'ta.camp_code = :camp';
        $params[':camp'] = $target;
    }

    if ($status === 'active') {
        $where[] = 'ta.checkout_at IS NULL AND ta.accommodation_status IN ("ACTIVE", "EXPIRING_SOON", "EXTENDED")';
    } elseif ($status === 'expired') {
        $where[] = 'ta.checkout_at IS NULL AND ta.accommodation_status = "EXPIRED"';
    } elseif ($status === 'closed') {
        $where[] = 'ta.checkout_at IS NOT NULL';
    } elseif ($status !== 'all' && $status !== '') {
        $where[] = 'ta.accommodation_status = :status';
        $params[':status'] = $status;
    }

    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY (ta.checkout_at IS NULL) DESC, ta.current_expires_at ASC';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $now = time();
    foreach ($rows as &$r) {
        $r['checkin_fmt'] = date('d M Y, H:i', strtotime($r['checkin_at']));
        $r['expires_fmt'] = date('d M Y, H:i', strtotime($r['current_expires_at']));
        $r['checkout_fmt'] = !empty($r['checkout_at']) ? date('d M Y, H:i', strtotime($r['checkout_at'])) : '—';

        $expTime = strtotime($r['current_expires_at']);
        $diffSec = $expTime - $now;

        if ($r['checkout_at'] !== null) {
            $r['time_left_str'] = 'Checked Out';
            $r['time_left_class'] = 'text-slate-500';
        } elseif ($diffSec <= 0) {
            $overdueMins = abs(round($diffSec / 60));
            $r['time_left_str'] = 'Overdue by ' . ($overdueMins < 60 ? "{$overdueMins}m" : floor($overdueMins/60) . 'h ' . ($overdueMins%60) . 'm');
            $r['time_left_class'] = 'text-red-600 font-bold';
        } else {
            $leftMins = round($diffSec / 60);
            $hours = floor($leftMins / 60);
            $mins  = $leftMins % 60;
            $r['time_left_str'] = "{$hours}h {$mins}m left";
            $r['time_left_class'] = $hours < 4 ? 'text-amber-600 font-bold' : 'text-emerald-600 font-medium';
        }
    }
    unset($r);

    return $rows;
}

/**
 * Fetch movement & accommodation counts for the active operator scope.
 */
function fetchMovementCounts(PDO $pdo, bool $isAdmin, string $currentLocation): array
{
    $camp = $isAdmin ? 'ALL' : $currentLocation;

    if ($camp !== 'ALL') {
        // Pending arrivals to this camp
        $stmtPending = $pdo->prepare('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status = "DEPARTED_ORIGIN" AND destination_camp = ?');
        $stmtPending->execute([$camp]);
        $pendingArrivals = (int)$stmtPending->fetchColumn();

        // Currently inside destination camp
        $stmtInside = $pdo->prepare('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status = "ARRIVED_DESTINATION" AND destination_camp = ?');
        $stmtInside->execute([$camp]);
        $insideCamp = (int)$stmtInside->fetchColumn();

        // Departed and returning to this camp
        $stmtReturning = $pdo->prepare('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status = "DEPARTED_DESTINATION" AND origin_camp = ?');
        $stmtReturning->execute([$camp]);
        $returning = (int)$stmtReturning->fetchColumn();

        // Total active movements involving this camp
        $stmtActive = $pdo->prepare('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status NOT IN ("COMPLETED", "CANCELLED") AND (origin_camp = ? OR destination_camp = ?)');
        $stmtActive->execute([$camp, $camp]);
        $totalActive = (int)$stmtActive->fetchColumn();

        // Accommodations at this camp
        $stmtAccom = $pdo->prepare('SELECT
            COUNT(*) AS total_accom,
            COALESCE(SUM(accommodation_status IN ("ACTIVE", "EXTENDED")), 0) AS active_accom,
            COALESCE(SUM(accommodation_status = "EXPIRING_SOON"), 0) AS expiring_soon,
            COALESCE(SUM(accommodation_status = "EXPIRED" AND checkout_at IS NULL), 0) AS expired
            FROM temporary_accommodations
            WHERE camp_code = ? AND checkout_at IS NULL
        ');
        $stmtAccom->execute([$camp]);
        $accom = $stmtAccom->fetch();

    } else {
        $pendingArrivals = (int)$pdo->query('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status = "DEPARTED_ORIGIN"')->fetchColumn();
        $insideCamp      = (int)$pdo->query('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status = "ARRIVED_DESTINATION"')->fetchColumn();
        $returning       = (int)$pdo->query('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status = "DEPARTED_DESTINATION"')->fetchColumn();
        $totalActive     = (int)$pdo->query('SELECT COUNT(*) FROM inter_camp_movements WHERE movement_status NOT IN ("COMPLETED", "CANCELLED")')->fetchColumn();

        $stmtAccom = $pdo->query('SELECT
            COUNT(*) AS total_accom,
            COALESCE(SUM(accommodation_status IN ("ACTIVE", "EXTENDED")), 0) AS active_accom,
            COALESCE(SUM(accommodation_status = "EXPIRING_SOON"), 0) AS expiring_soon,
            COALESCE(SUM(accommodation_status = "EXPIRED" AND checkout_at IS NULL), 0) AS expired
            FROM temporary_accommodations
            WHERE checkout_at IS NULL
        ');
        $accom = $stmtAccom->fetch();
    }

    return [
        'total_active'     => $totalActive,
        'pending_arrivals' => $pendingArrivals,
        'inside_camp'      => $insideCamp,
        'returning'        => $returning,
        'accommodated'     => (int)($accom['total_accom'] ?? 0),
        'expiring_soon'    => (int)($accom['expiring_soon'] ?? 0),
        'expired'          => (int)($accom['expired'] ?? 0),
    ];
}

/**
 * Fetch system audit logs.
 */
function fetchAuditLogsList(PDO $pdo, bool $isAdmin, string $currentLocation, array $filters = []): array
{
    $locFilter = $isAdmin ? strtoupper(trim($filters['loc'] ?? 'ALL')) : $currentLocation;
    $action    = trim($filters['action'] ?? '');
    $q         = trim($filters['q'] ?? '');

    $sql = 'SELECT * FROM audit_logs';
    $where = [];
    $params = [];

    if (!$isAdmin || $locFilter !== 'ALL') {
        $where[] = 'camp_code = :camp';
        $params[':camp'] = $isAdmin ? $locFilter : $currentLocation;
    }
    if ($action !== '' && $action !== 'all') {
        $where[] = 'action_type = :action';
        $params[':action'] = $action;
    }
    if ($q !== '') {
        $where[] = '(username LIKE :q1 OR reference_no LIKE :q2 OR entity_id LIKE :q3)';
        $params[':q1'] = "%{$q}%";
        $params[':q2'] = "%{$q}%";
        $params[':q3'] = "%{$q}%";
    }

    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY id DESC LIMIT 200';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$r) {
        $r['created_fmt'] = date('d M Y, H:i:s', strtotime($r['created_at']));
        $r['details_obj'] = json_decode($r['details'] ?? '{}', true) ?: [];
    }
    unset($r);

    return $rows;
}
