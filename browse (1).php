<?php
// Only enable display_errors on local development or when explicitly requested
$devHosts = ['127.0.0.1', '::1', 'localhost'];
$isLocal = in_array($_SERVER['REMOTE_ADDR'] ?? '', $devHosts, true) || (isset($_SERVER['HTTP_HOST']) && strpos($_SERVER['HTTP_HOST'], 'localhost') !== false);
$enableDebug = $isLocal || (isset($_GET['dev_debug']) && $_GET['dev_debug'] === '1');
if ($enableDebug) {
  ini_set('display_errors', 1);
  ini_set('display_startup_errors', 1);
  error_reporting(E_ALL);
} else {
  // In production, keep errors off to avoid breaking JSON/JS in-browser
  ini_set('display_errors', 0);
  ini_set('display_startup_errors', 0);
  error_reporting(0);
}


// --- Record thesis view in student_reads (AJAX handler) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['tc_id'])) {
    session_start();
    // Debug: Log session and POST data
    error_log('DEBUG student_reads POST: SESSION=' . print_r($_SESSION, true) . ' POST=' . print_r($_POST, true));
    if (isset($_SESSION['student_id'])) {
        include 'database.php';
        $tc_id = intval($_POST['tc_id']);
        $student_id = intval($_SESSION['student_id']);
        // Only insert if not already present
        $stmt = $conn->prepare("SELECT 1 FROM student_reads WHERE student_id = ? AND tc_id = ?");
        if ($stmt) {
            $stmt->bind_param('ii', $student_id, $tc_id);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows === 0) {
                $stmt->close();
                $stmt = $conn->prepare("INSERT INTO student_reads (student_id, tc_id, read_timestamp) VALUES (?, ?, NOW())");
                if ($stmt) {
                    $stmt->bind_param('ii', $student_id, $tc_id);
                    $stmt->execute();
                }
            } else {
                $stmt->close();
            }
        }
    } else {
        // Debug: Log missing session
        error_log('DEBUG student_reads POST: No student_id in session');
    }
    exit;
}
// --- Handle "request archive" (owner only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'archive_request') {
    header('Content-Type: application/json');
    session_start();
    if (!isset($_SESSION['student_id']) || !isset($_POST['tc_id'])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Not allowed']);
        exit;
    }
    include 'database.php';
    $student_id = (int)$_SESSION['student_id'];
    $tc_id = (int)$_POST['tc_id'];
    $reason = trim($_POST['reason'] ?? '');

    // Verify ownership via thesis_submission
    $own = 0;
    $stmt = $conn->prepare("SELECT COUNT(*) FROM thesis_submission WHERE student_id = ? AND tc_id = ?");
    $stmt->bind_param('ii', $student_id, $tc_id);
    $stmt->execute();
    $stmt->bind_result($own);
    $stmt->fetch();
    $stmt->close();
    if ($own == 0) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'You can request archiving only for your own submission.']);
        exit;
    }

    // Prevent duplicate pending requests
    $dup = 0;
    $stmt = $conn->prepare("SELECT COUNT(*) FROM archive_requests WHERE tc_id = ? AND student_id = ? AND status = 'pending'");
    $stmt->bind_param('ii', $tc_id, $student_id);
    $stmt->execute();
    $stmt->bind_result($dup);
    $stmt->fetch();
    $stmt->close();
    if ($dup > 0) {
        echo json_encode(['ok' => true, 'message' => 'You already have a pending archive request for this file.']);
        exit;
    }

    $stmt = $conn->prepare("INSERT INTO archive_requests (tc_id, student_id, reason, status, created_at) VALUES (?, ?, ?, 'pending', NOW())");
    $stmt->bind_param('iis', $tc_id, $student_id, $reason);
    $stmt->execute();
    $stmt->close();

    echo json_encode(['ok' => true, 'message' => 'Archive request submitted.']);
    exit;
}

// --- Handle "report thesis" (non-owners)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'report_thesis') {
    header('Content-Type: application/json');
    session_start();
    if (!isset($_SESSION['student_id']) || !isset($_POST['tc_id'])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Not allowed']);
        exit;
    }
    include 'database.php';
    $student_id = (int)$_SESSION['student_id'];
    $tc_id = (int)$_POST['tc_id'];
    $reason = trim($_POST['reason'] ?? '');
    $severity = in_array(($_POST['severity'] ?? 'Medium'), ['Low','Medium','High']) ? $_POST['severity'] : 'Medium';

    // If user owns this, we encourage archive_request instead of report
    $own = 0;
    $stmt = $conn->prepare("SELECT COUNT(*) FROM thesis_submission WHERE student_id = ? AND tc_id = ?");
    $stmt->bind_param('ii', $student_id, $tc_id);
    $stmt->execute();
    $stmt->bind_result($own);
    $stmt->fetch();
    $stmt->close();
    if ($own > 0) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'Owners should use Request Archive instead of Report.']);
        exit;
    }

    $stmt = $conn->prepare("INSERT INTO thesis_reports (tc_id, student_id, reason, severity, status, created_at) VALUES (?, ?, ?, ?, 'pending', NOW())");
    $stmt->bind_param('iiss', $tc_id, $student_id, $reason, $severity);
    $stmt->execute();
    $stmt->close();

    echo json_encode(['ok' => true, 'message' => 'Report submitted. Thank you.']);
    exit;
}


session_start();
if (!isset($_SESSION['student_id']) && !isset($_SESSION['admin_id'])) {
    header('Location: index.php'); // or your login page
    exit();
}
include 'database.php';
if (!function_exists('ru_parseAcademicYearStart')) {
    function ru_parseAcademicYearStart($value) {
        $value = trim((string)$value);
        if ($value === '') return null;
        if (preg_match('/(\d{4})/', $value, $matches)) {
            return (int)$matches[1];
        }
        return null;
    }
}
if (!function_exists('ru_autoArchiveLegacyTheses')) {
    function ru_autoArchiveLegacyTheses($conn, $actor = 'Auto Scheduler') {
        static $ruAutoRan = false;
        if ($ruAutoRan) return null;
        $ruAutoRan = true;

        $conn->query("ALTER TABLE thesis_capstone ADD COLUMN IF NOT EXISTS archive_reason VARCHAR(255) NULL");
        $conn->query("ALTER TABLE thesis_capstone ADD COLUMN IF NOT EXISTS archived_at DATETIME NULL");

        $cutoffTs = strtotime('-5 years');
        $records = [];
        $res = $conn->query("
            SELECT tc.tc_id, tc.title, tc.academic_year,
                   MIN(ts.submission_date) AS submitted_at
            FROM thesis_capstone tc
            LEFT JOIN thesis_submission ts ON ts.tc_id = tc.tc_id
            WHERE COALESCE(tc.is_archived,0) = 0
            GROUP BY tc.tc_id, tc.title, tc.academic_year
        ");
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $shouldArchive = false;
                if (!empty($row['submitted_at'])) {
                    $shouldArchive = strtotime($row['submitted_at']) <= $cutoffTs;
                } else {
                    $ay = ru_parseAcademicYearStart($row['academic_year'] ?? '');
                    if ($ay !== null) {
                        $shouldArchive = $ay <= (int)date('Y', $cutoffTs);
                    }
                }
                if ($shouldArchive) {
                    $records[] = [
                        'tc_id' => (int)$row['tc_id'],
                        'title' => $row['title'] ?? 'Untitled',
                    ];
                }
            }
            $res->free();
        }
        if (!$records) return null;

        $updated = 0;
        $stmt = $conn->prepare("UPDATE thesis_capstone SET is_archived=1, archive_reason='Auto-archived (5-year policy)', archived_at=NOW() WHERE tc_id=?");
        $audit = $conn->prepare("INSERT INTO audit_logs (action_type, actor, target, details) VALUES ('Auto Archive', ?, ?, ?)");
        $stmtId = 0;
        $stmt->bind_param('i', $stmtId);
        $auditActor = $actor;
        $auditTarget = '';
        $auditDetails = '';
        $audit->bind_param('sss', $auditActor, $auditTarget, $auditDetails);

        foreach ($records as $rec) {
            $stmtId = $rec['tc_id'];
            if ($stmt->execute()) {
                $updated++;
                $auditTarget = 'TC#'.$stmtId;
                $auditDetails = "Auto-archived (5-year policy) -> ".$rec['title'];
                $audit->execute();
            }
        }
        $stmt->close();
        $audit->close();
        return $updated;
    }
}

if (!function_exists('browse_prepare_pagination')) {
    function browse_prepare_pagination(array $rows, &$resultCount, &$perPage, &$totalPages, &$page, &$offset, &$slice) {
        $resultCount = count($rows);
        $perPage = isset($_GET['per_page']) ? max(6, min(36, (int)$_GET['per_page'])) : 6;
        $totalPages = max(1, (int)ceil(max(1, $resultCount) / $perPage));
        $page = isset($_GET['page']) ? max(1, min((int)$_GET['page'], $totalPages)) : 1;
        $offset = ($page - 1) * $perPage;
        $slice = array_slice($rows, $offset, $perPage);
    }
}

if (!function_exists('buildBrowseQueryUrl')) {
    function buildBrowseQueryUrl(array $overrides = []) {
        $params = array_merge($_GET, $overrides);
        foreach ($params as $key => $value) {
            if ($value === null || $value === '') {
                unset($params[$key]);
            }
        }
        $base = strtok($_SERVER['REQUEST_URI'] ?? 'browse.php', '?');
        if ($base === false || $base === '') {
            $base = 'browse.php';
        }
        return $base . (empty($params) ? '' : ('?' . http_build_query($params)));
    }
}
ru_autoArchiveLegacyTheses($conn, 'Browse Auto Scheduler');

// Unified filtering/search logic
$searchTerm = isset($_GET['q']) ? trim($_GET['q']) : '';
$searchField = isset($_GET['f']) ? strtolower($_GET['f']) : 'keyword';

$project_type = isset($_GET['project_type']) ? $_GET['project_type'] : 'all';
$college_id = isset($_GET['college_id']) ? $_GET['college_id'] : '';
$program_id = isset($_GET['program_id']) ? $_GET['program_id'] : '';
$college = isset($_GET['college']) ? $_GET['college'] : '';
$program = isset($_GET['program']) ? $_GET['program'] : '';
$year_min = isset($_GET['year_min']) ? intval($_GET['year_min']) : 0;
$year_max = isset($_GET['year_max']) ? intval($_GET['year_max']) : 9999;

if ($searchTerm !== '') {
    $_SESSION['browse_last_search'] = $searchTerm;
}
$lastSearchTerm = $_SESSION['browse_last_search'] ?? '';


$resultRows = [];
// If search term is present, use ML search
if (!empty($searchTerm)) {
    $searchType = $searchField;
    $mlResults = null;
    $mlJson = '';
    // Some shared hosting (e.g. Hostinger) disables shell_exec()/proc functions.
    // Guard against calling shell_exec when it's unavailable to avoid fatal errors.
    if (function_exists('shell_exec') && is_callable('shell_exec')) {
      $escapedTerm = escapeshellarg($searchTerm);
      $escapedType = escapeshellarg($searchType);
      // Try both venv and system python for robustness
      $venvPython = __DIR__ . DIRECTORY_SEPARATOR . '.venv' . DIRECTORY_SEPARATOR . 'Scripts' . DIRECTORY_SEPARATOR . 'python.exe';
      $systemPython = 'python';
      $scriptPath = __DIR__ . DIRECTORY_SEPARATOR . 'ml_search.py';

      // Try venv python first (Windows-style venv path kept for local dev)
      $cmd = escapeshellarg($venvPython) . ' ' . escapeshellarg($scriptPath) . ' ' . $escapedTerm . ' ' . $escapedType . ' 2>&1';
      $mlJson = @shell_exec($cmd);

      // If venv invocation produced nothing or an OS-level "not found", try system python
      if (trim((string)$mlJson) === '' || strpos((string)$mlJson, 'not found') !== false || strpos((string)$mlJson, 'No such file') !== false) {
        $cmd = escapeshellarg($systemPython) . ' ' . escapeshellarg($scriptPath) . ' ' . $escapedTerm . ' ' . $escapedType . ' 2>&1';
        $mlJson = @shell_exec($cmd);
      }

      $mlResults = json_decode($mlJson, true);
      if ($mlResults === null && !empty($mlJson)) {
        error_log('ML search produced invalid JSON: ' . substr($mlJson, 0, 200));
      }
    } else {
      // Log and gracefully skip ML step on hosts that disable shell_exec()
      error_log('ML search skipped: shell_exec not available. Falling back to SQL LIKE search.');
      $mlResults = [];
    }
  // If ML returned nothing or failed, fall back to a simple SQL LIKE search so title/author queries still work
  if (!is_array($mlResults) || count($mlResults) === 0) {
    $mlResults = [];
    $like = '%' . strtolower($searchTerm) . '%';
    // Build SQL depending on search type
    if ($searchType === 'title') {
      $sql = "SELECT tc.tc_id, tc.title, tc.authorone, tc.authortwo, tc.authorthree, tc.authorfour, tc.authorfive, tc.colleges_id, tc.program_id, tc.academic_year, tc.project_type, tc.views, ts.status FROM thesis_capstone tc INNER JOIN thesis_submission ts ON tc.tc_id = ts.tc_id WHERE LOWER(tc.title) LIKE ? AND LOWER(ts.status) = 'approved' AND COALESCE(tc.is_archived,0)=0 LIMIT 200";
      $stmt2 = $conn->prepare($sql);
      if ($stmt2) {
        $stmt2->bind_param('s', $like);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        while ($r = $res2->fetch_assoc()) $mlResults[] = $r;
        $stmt2->close();
      }
    } elseif ($searchType === 'author') {
      $sql = "SELECT DISTINCT tc.tc_id, tc.title, tc.authorone, tc.authortwo, tc.authorthree, tc.authorfour, tc.authorfive, tc.colleges_id, tc.program_id, tc.academic_year, tc.project_type, tc.views, ts.status FROM thesis_capstone tc INNER JOIN thesis_submission ts ON tc.tc_id = ts.tc_id WHERE (LOWER(tc.authorone) LIKE ? OR LOWER(tc.authortwo) LIKE ? OR LOWER(tc.authorthree) LIKE ? OR LOWER(tc.authorfour) LIKE ? OR LOWER(tc.authorfive) LIKE ?) AND LOWER(ts.status) = 'approved' AND COALESCE(tc.is_archived,0)=0 LIMIT 200";
      $stmt2 = $conn->prepare($sql);
      if ($stmt2) {
        $stmt2->bind_param('sssss', $like, $like, $like, $like, $like);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        while ($r = $res2->fetch_assoc()) $mlResults[] = $r;
        $stmt2->close();
      }
    } else {
      // keyword: search title, authors, and fulltext
      $sql = "SELECT DISTINCT tc.tc_id, tc.title, tc.authorone, tc.authortwo, tc.authorthree, tc.authorfour, tc.authorfive, tc.colleges_id, tc.program_id, tc.academic_year, tc.project_type, tc.views, ts.status FROM thesis_capstone tc INNER JOIN thesis_submission ts ON tc.tc_id = ts.tc_id WHERE (LOWER(tc.title) LIKE ? OR LOWER(tc.authorone) LIKE ? OR LOWER(tc.authortwo) LIKE ? OR LOWER(tc.authorthree) LIKE ? OR LOWER(tc.authorfour) LIKE ? OR LOWER(tc.authorfive) LIKE ? OR LOWER(tc.`fulltext`) LIKE ?) AND LOWER(ts.status) = 'approved' AND COALESCE(tc.is_archived,0)=0 LIMIT 200";
      $stmt2 = $conn->prepare($sql);
      if ($stmt2) {
        $stmt2->bind_param('sssssss', $like, $like, $like, $like, $like, $like, $like);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        while ($r = $res2->fetch_assoc()) $mlResults[] = $r;
        $stmt2->close();
      }
    }
  }
$uniqueRows = [];
if (is_array($mlResults)) {
    foreach ($mlResults as $row) {
        // Ensure tc_id exists and is unique
        if (empty($row['tc_id'])) continue;

        // Only include Approved (case-insensitive)
        if (isset($row['status']) && strtolower(trim($row['status'])) !== 'approved') {
            continue;
        }

        $tc_id = (string)$row['tc_id'];
        if (isset($uniqueRows[$tc_id])) continue;

        $row_college_id = isset($row['colleges_id']) ? (string)$row['colleges_id'] : '';
        $row_program_id = isset($row['program_id']) ? (string)$row['program_id'] : '';
        $row_project_type = $row['project_type'] ?? '';
        $row_year = isset($row['academic_year']) ? (int)$row['academic_year'] : (isset($row['year']) ? (int)$row['year'] : 0);

        $college_filter = ($college_id !== '' && $college_id !== null);
        $program_filter = ($program_id !== '' && $program_id !== null);
        $project_type_filter = ($project_type !== 'all' && $project_type !== '' && $project_type !== null);
        $year_min_filter = ($year_min > 0);
        $year_max_filter = ($year_max < 9999);

        $college_match = (!$college_filter || $row_college_id === (string)$college_id);
        $program_match = (!$program_filter || $row_program_id === (string)$program_id);
        $project_type_match = (!$project_type_filter || $row_project_type == $project_type);
        $year_min_match = (!$year_min_filter || $row_year >= $year_min);
        $year_max_match = (!$year_max_filter || $row_year <= $year_max);

        if (!($college_match && $program_match && $project_type_match && $year_min_match && $year_max_match)) {
            continue;
        }

        // Lookup college/program display names
        $collegeName = '';
        $programName = '';
        $year = $row['year'] ?? ($row['academic_year'] ?? '');

        if ($row_college_id !== '') {
            $stmt = $conn->prepare('SELECT colleges FROM colleges WHERE colleges_id = ?');
            $cid = (int)$row_college_id;
            $stmt->bind_param('i', $cid);
            $stmt->execute();
            $stmt->bind_result($collegeName);
            $stmt->fetch();
            $stmt->close();
        }
        if ($row_program_id !== '') {
            $stmt = $conn->prepare('SELECT program FROM program WHERE program_id = ?');
            $pid = (int)$row_program_id;
            $stmt->bind_param('i', $pid);
            $stmt->execute();
            $stmt->bind_result($programName);
            $stmt->fetch();
            $stmt->close();
        }

        $row['college'] = $collegeName ?: $row_college_id;
        $row['program'] = $programName ?: $row_program_id;
        $row['academic_year'] = $year;

        // Compact authors
        $authorsArr = [];
        foreach (['authorone','authortwo','authorthree','authorfour','authorfive'] as $a) {
            if (!empty($row[$a]) && trim($row[$a]) !== '') $authorsArr[] = $row[$a];
        }
        $row['authors'] = $authorsArr ? implode(', ', $authorsArr) : 'N/A';

        $uniqueRows[$tc_id] = $row;
    }
    $resultRows = array_values($uniqueRows);
}

    // DEBUG: Output the filtered results
} else {
    // No search term: use normal SQL filtering
    $sql = "SELECT tc.tc_id, tc.title, tc.authorone, tc.authortwo, tc.authorthree, tc.authorfour, tc.authorfive, tc.colleges_id, tc.program_id, tc.academic_year, tc.type, tc.project_type, tc.file, tc.views, p.program, c.colleges AS college FROM thesis_capstone tc LEFT JOIN program p ON tc.program_id = p.program_id LEFT JOIN colleges c ON tc.colleges_id = c.colleges_id INNER JOIN thesis_submission ts ON tc.tc_id = ts.tc_id WHERE ts.status = 'Approved' AND COALESCE(tc.is_archived,0)=0";
    $params = [];
    $types = '';
    if ($project_type !== 'all') {
        $sql .= " AND tc.project_type = ?";
        $params[] = $project_type;
        $types .= 's';
    }
    if (!empty($college_id)) {
        $sql .= " AND tc.colleges_id = ?";
        $params[] = $college_id;
        $types .= 'i';
    }
    if (!empty($program_id)) {
        $sql .= " AND tc.program_id = ?";
        $params[] = $program_id;
        $types .= 'i';
    }
    // Only filter by college/program name if ID is not set
    if (empty($college_id) && !empty($college)) {
        $sql .= " AND c.colleges = ?";
        $params[] = $college;
        $types .= 's';
    }
    if (empty($program_id) && !empty($program)) {
        $sql .= " AND p.program = ?";
        $params[] = $program;
        $types .= 's';
    }
    if ($year_min > 0) {
        $sql .= " AND tc.academic_year >= ?";
        $params[] = $year_min;
        $types .= 'i';
    }
    if ($year_max < 9999) {
        $sql .= " AND tc.academic_year <= ?";
        $params[] = $year_max;
        $types .= 'i';
    }
    $sql .= " ORDER BY tc.tc_id DESC";
    if (!empty($params)) {
        // Debug output for SQL troubleshooting
        error_log("DEBUG SQL: $sql");
        error_log("DEBUG PARAMS: " . print_r($params, true));
        error_log("DEBUG TYPES: $types");
        $stmt = $conn->prepare($sql);
        if ($stmt) {
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $authorsArr = [];
                foreach (['authorone','authortwo','authorthree','authorfour','authorfive'] as $a) {
                    if (isset($row[$a]) && $row[$a] !== null && trim($row[$a]) !== '') {
                        $authorsArr[] = $row[$a];
                    }
                }
                $row['authors'] = count($authorsArr) > 0 ? implode(', ', $authorsArr) : 'N/A';
                $resultRows[] = $row;
            }
            $stmt->close();
        }
    } else {
        $res = $conn->query($sql);
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $authorsArr = [];
                foreach (['authorone','authortwo','authorthree','authorfour','authorfive'] as $a) {
                    if (isset($row[$a]) && $row[$a] !== null && trim($row[$a]) !== '') {
                        $authorsArr[] = $row[$a];
                    }
                }
                $row['authors'] = count($authorsArr) > 0 ? implode(', ', $authorsArr) : 'N/A';
                $resultRows[] = $row;
            }
        }
    }
}

// --- Collaborative Filtering Recommendations via external Python API ---\
$cfJson = ""; // Prevent undefined variable warning

$recommendedRows = [];
$recommendationSource = 'trending';

// Only try CF if there is a logged-in student
if (isset($_SESSION['student_id'])) {
    $student_id = (int)$_SESSION['student_id'];

    // 🔴 TODO: REPLACE WITH YOUR REAL RENDER URL
    // Example: https://plp-recommend-api.onrender.com
    $apiBase = 'https://research-cf-api.onrender.com';

    // We pass the REAL numeric student_id here (this fixes the "student_id" string error)
    $apiUrl = $apiBase . '/recommend?student_id=' . urlencode($student_id);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $apiUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
    ]);

    $response = curl_exec($ch);
    $curlErr  = curl_error($ch);
    $status   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response !== false && $status >= 200 && $status < 300) {
        $decoded = json_decode($response, true);
        if (is_array($decoded)) {
            $recommendedRows = $decoded;
        } else {
            error_log('CF API: invalid JSON: ' . substr($response, 0, 500));
        }
    } else {
        error_log("CF API error: HTTP $status, cURL error: $curlErr, body: " . substr((string)$response, 0, 500));
    }

    if (!empty($recommendedRows)) {
        $recommendationSource = 'cf';
    }
}

// DB fallback: if CF returned nothing (or not run), return top-viewed approved theses
if (empty($recommendedRows)) {
    $recommendationSource = 'trending';
    try {
        $recommendedRows = [];
        $sql = "SELECT tc.tc_id, tc.title, tc.authorone, tc.authortwo, tc.authorthree, 
                       tc.authorfour, tc.authorfive, tc.file, tc.views, 
                       p.program, c.colleges AS college, ts.status
                FROM thesis_capstone tc
                LEFT JOIN program p ON tc.program_id = p.program_id
                LEFT JOIN colleges c ON tc.colleges_id = c.colleges_id
                INNER JOIN thesis_submission ts ON tc.tc_id = ts.tc_id
                WHERE LOWER(ts.status) = 'approved'
                  AND COALESCE(tc.is_archived,0)=0
                ORDER BY tc.views DESC
                LIMIT 12";
        $res = $conn->query($sql);
        if ($res) {
            while ($r = $res->fetch_assoc()) {
                $authorsArr = [];
                foreach (['authorone','authortwo','authorthree','authorfour','authorfive'] as $a) {
                    if (!empty($r[$a])) $authorsArr[] = $r[$a];
                }
                $r['authors'] = $authorsArr ? implode(', ', $authorsArr) : '';
                $recommendedRows[] = $r;
            }
        }
    } catch (Exception $e) {
        error_log('Recommended fallback error: ' . $e->getMessage());
    }
}


$recommendationLead = '';
$recommendationBadgeLabel = '';
$recommendationCardLabel = '';
if (!empty($recommendedRows)) {
    if ($recommendationSource === 'cf' && isset($_SESSION['student_id'])) {
        $recommendationLead = 'Powered by our collaborative-filtering engine (recommend_cf.py), these picks adapt to your reading and viewing history.';
        $recommendationBadgeLabel = 'Personalized';
        $recommendationCardLabel = 'Because you read similar works';
    } elseif ($searchTerm !== '') {
        $recommendationLead = "While you explore \"{$searchTerm}\", here are adjacent titles other students loved.";
        $recommendationBadgeLabel = 'Related Picks';
        $recommendationCardLabel = "Inspired by \"{$searchTerm}\"";
    } else {
        $recommendationLead = 'These titles are trending right now across Research Unlocked.';
        $recommendationBadgeLabel = 'Trending';
        $recommendationCardLabel = 'Popular this week';
    }
}

$recommendationSummary = [];
$recommendationCount = count($recommendedRows);
$recommendationSummary[] = [
    'eyebrow' => 'Feed mode',
    'value' => $recommendationSource === 'cf' ? 'Personalized feed' : 'Trending feed',
    'hint' => $recommendationSource === 'cf'
        ? 'Learns from your browsing and opens'
        : 'Surfacing what the community is reading',
];
$recommendationSummary[] = [
    'eyebrow' => 'Ready to read',
    'value' => number_format($recommendationCount),
    'hint' => $recommendationCount === 1 ? 'title in this batch' : 'titles in this batch',
];
if ($recommendationCount > 0) {
    $viewsSum = 0;
    $programCounts = [];
    foreach ($recommendedRows as $recommendedRow) {
        $viewsSum += max(0, (int)($recommendedRow['views'] ?? 0));
        $programName = trim((string)($recommendedRow['program'] ?? $recommendedRow['program_name'] ?? $recommendedRow['program_label'] ?? ''));
        if ($programName === '') {
            $programName = 'Various programs';
        }
        $programCounts[$programName] = ($programCounts[$programName] ?? 0) + 1;
    }
    $avgViewsLabel = $viewsSum > 0
        ? '~' . number_format((int)round($viewsSum / max(1, $recommendationCount)))
        : 'Fresh picks';
    $recommendationSummary[] = [
        'eyebrow' => 'Reader energy',
        'value' => $avgViewsLabel,
        'hint' => $viewsSum > 0 ? 'avg. views per paper' : 'Recently added titles',
    ];
    arsort($programCounts);
    $topProgram = !empty($programCounts) ? array_keys($programCounts)[0] : 'Various programs';
    $recommendationSummary[] = [
        'eyebrow' => 'Popular program',
        'value' => $topProgram,
        'hint' => 'Most frequent inside this set',
    ];
} else {
    $recommendationSummary[] = [
        'eyebrow' => 'Reader energy',
        'value' => 'Lean feed',
        'hint' => 'Open a thesis to unlock personalization',
    ];
    $recommendationSummary[] = [
        'eyebrow' => 'Popular program',
        'value' => 'Awaiting activity',
        'hint' => 'Adjust filters to jump-start',
    ];
}

// Remove duplicate thesis entries by tc_id
$uniqueRows = [];
foreach ($resultRows as $row) {
    $uniqueRows[$row['tc_id']] = $row;
}
$resultRows = array_values($uniqueRows);
browse_prepare_pagination($resultRows, $resultCount, $perPage, $totalPages, $page, $offset, $pagedResults);
$resultCountLabel = $resultCount === 1 ? '1 result' : number_format($resultCount) . ' results';
$resultCountLabelUi = $totalPages > 1
    ? sprintf('%s - Page %d of %d', $resultCountLabel, $page, $totalPages)
    : $resultCountLabel;
$searchInsightItems = [
    [
        'label' => 'Results',
        'value' => $resultCountLabel,
        'hint'  => 'Matching entries found',
    ],
    [
        'label' => 'Page',
        'value' => sprintf('%d / %d', $page, $totalPages),
        'hint'  => 'Current pagination slot',
    ],
    [
        'label' => 'Recommended',
        'value' => number_format(count($recommendedRows)),
        'hint'  => 'Feed titles ready',
    ],
];
if ($lastSearchTerm !== '') {
    $searchInsightItems[] = [
        'label' => 'Last Search',
        'value' => $lastSearchTerm,
        'hint'  => 'Previous keyword',
    ];
}
$discoverLeadCopy = $searchTerm !== ''
    ? sprintf('Fine-tune results around "%s" or explore something new.', $searchTerm)
    : 'Dial in your next read with keywords, filters, and program pickers.';
if ($searchTerm !== '') {
    $resultsHeading = sprintf('Results for "%s"', $searchTerm);
    $resultsLead = $resultCount > 0
        ? "Showing {$resultCountLabelUi} that match your request."
        : "We couldn't find matches for \"{$searchTerm}\". Try adjusting your filters or keywords.";
} else {
    $resultsHeading = 'Library Catalog';
    $resultsLead = "Browse the newest approved theses and capstone projects from across PLP. {$resultCountLabelUi}.";
}

// PDF download logic must be before any HTML output
if (isset($_GET['pdf_id'])) {
    $id = intval($_GET['pdf_id']);
    $stmt = $conn->prepare("SELECT file FROM thesis_capstone WHERE tc_id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($file);
    if ($stmt->fetch()) {
        $filepath = __DIR__ . '/' . $file;
        if (file_exists($filepath)) {
            header("Content-Type: application/pdf");
            header('Content-Disposition: inline; filename="' . basename($filepath) . '"');
            header('Content-Length: ' . filesize($filepath));
            readfile($filepath);
            exit;
        } else {
            http_response_code(404);
            echo "PDF not found.";
            exit;
        }
    } else {
        http_response_code(404);
        echo "PDF not found.";
        exit;
    }
}



$student_number = $_SESSION['student_number'] ?? '';
$hasUnread = false;

if ($student_number) {
  $stmt = $conn->prepare("SELECT COUNT(*) as unread_count FROM notifications WHERE student_number = ? AND is_read = 0");
  $stmt->bind_param("s", $student_number);
  $stmt->execute();
  $result = $stmt->get_result()->fetch_assoc();
  $hasUnread = ($result['unread_count'] ?? 0) > 0;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <title> Browse | Research Unlocked </title>
  <link rel="icon" href="pictures/researchgatelogo1.png" type="image/png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">  
  <link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap" rel="stylesheet">

  <style>
    html{
        scroll-behavior: smooth;

    }
      html::-webkit-scrollbar {
        display: none;
      }

  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Poppins';
    }

    body.fade-out {
  opacity: 0;
  transition: opacity 0.4s ease;
}

  html, body {
    height: 100%;
    margin: 0;
    padding: 0;
  }

  body {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
    background: #ffffff;
    color: #333;
    overflow-x: hidden;
    opacity: 1;
    transition: opacity 0.4s ease;
  }

.navbar {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 80px;
  padding: 0 40px;
  background: rgba(255, 255, 255, 0.05);
  backdrop-filter: blur(10px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: background 0.3s ease, color 0.3s ease;
}

.navbar.scrolled {
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
}

.navbar.scrolled .nav-center a,
.navbar.scrolled .nav-login a,
.navbar.scrolled .user-info,
.navbar.scrolled .logo-texts .title,
.navbar.scrolled .logo-texts .subtitle {
  color: #256633;
}
  .logo {
    display: flex;
    align-items: center;
    gap: 8px;
  }

.logo img {
  width: 50px;
  height: 50px;
}

.logo-texts {
  display: flex;
  flex-direction: column;
  line-height: 1;
}

.logo-texts .title,
.logo-texts .subtitle {
  color: white;
}

.logo-texts .title {
  font-size: 14px;
  font-weight: 600;
}

.logo-texts .subtitle {
  font-size: 12px;
  font-weight: 300;
}

.nav-center {
  display: flex;
  gap: 30px;
  transform: translateX(-50%);
  position: absolute;
  left: 50%;
}

.nav-center a  {
  color: white;
  text-decoration: none;
  font-weight: 500;
  transition: color 0.3s ease, font-weight 0.3s ease, transform 0.3s ease;

  font-size: 14px;
}


.nav-login a {
  color: white;
  font-weight: 500;
  text-decoration: none;
  transition: color 0.3s ease, font-weight 0.3s ease, transform 0.3s ease;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.nav-login a:hover,.nav-center a:hover {
  color:rgb(171, 255, 93);
  font-weight: 700;
  transform: scale(1.05);
    text-decoration: none;

}

.user-info {
  display: flex;
  align-items: center;
  gap: 8px;
  color: white;
  text-decoration: none;
  font-weight: 500;
}

.user-info:hover {
  color: #76ff78;
  text-decoration: underline;
}

.user-info i {
  font-size: 20px;
}



  .hero {
  position: relative;
  min-height: 30vh;
  background: #77BD8A;
  background: linear-gradient(0deg, rgba(119, 189, 138, 1) 0%, rgba(59, 129, 76, 1) 45%, rgba(50, 120, 67, 1) 67%, rgba(22, 91, 37, 1) 100%);  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 80px 20px 40px;
  overflow: hidden;
  flex-shrink: 0;
}

.hero .circle {
  position: absolute;
  border-radius: 50%;
  filter: blur(2px);
  opacity: 0.5;
  animation: float 8s ease-in-out infinite;

  z-index: 0;
}

.hero .circle1 {
  width: 500px;
  height: 500px;
  background: #3F8549;
  background: linear-gradient(263deg, rgba(43, 104, 53, 0.942) 18%, rgb(156, 179, 78) 65%, rgba(217, 203, 109, 1) 100%);
    top: -36%;
  left: -2%;
  position: absolute; 
  animation-delay: 0s;
  border-radius: 50%; 
  filter: blur(7px);

}

.hero .circle2 {
  width: 250px;
  height: 250px;
  background: #358047;
  background: linear-gradient(60deg, rgba(53, 128, 71, 1) 32%, rgba(92, 146, 80, 1) 51%, rgba(217, 203, 109, 1) 100%);
    position: absolute; 
  bottom: -12%;
  right: 92%;
  animation-delay: 2s;
  filter: blur(2.8px);
  box-shadow: 6px 12px 17px 0px rgb(45 78 36 / 35%);

}

.hero .circle3 {
  width: 400px;
  height: 400px;
  background: #358047;
  background: linear-gradient(220deg, rgba(53, 128, 71, 1) 33%, rgba(217, 203, 109, 1) 100%);
  top: 20%;
  left: 84%;
  animation-delay: 4s;
  opacity: 1;
  box-shadow: 1px 3px 13px 0px rgb(31 52 25 / 10%);
  filter: blur(4.8px);

  z-index: 2;

}

.hero .circle4 {
  width: 1000px;
  height: 1000px;
  background: #C2D559;
  background: linear-gradient(170deg, rgba(194, 213, 89, 1) 0%, rgba(165, 209, 104, 1) 16%, rgba(149, 194, 100, 1) 27%, rgba(149, 203, 130, 1) 34%, rgba(129, 198, 148, 1) 82%);
  position: absolute; 
  top: 60%;

  left: 13%;
  animation-delay: 1s;
  opacity: 1;
  box-shadow: -8px -9px 40.3px 4px rgb(244 255 108 / 34%);
  z-index: 1;

}
.hero .circle5 {
  width: 550px;
  height: 550px;
  background: #C2D559;
  background: linear-gradient(170deg, rgb(171, 255, 159) 0%, rgb(141, 166, 106) 16%, rgb(129, 173, 82) 27%, rgb(192, 255, 169) 34%, rgba(129, 198, 148, 1) 82%);
  position: absolute; 
  top: 30%;
  right: -1%;
  opacity: 0.1;
  box-shadow: -8px -9px 40.3px 4px rgb(244 255 108 / 34%);
  z-index: 1;

}

.hero .circle6 {
  width: 500px;
  height: 500px;
  background: #66a3298d;
  position: absolute; 
  top: 10%;
  right: 40%;
  opacity: 0.3;
  filter: blur(60px);


}
@keyframes float {
  0% {
    transform: translateY(0px);
  }
  25% {
    transform: translateY(40px);
  }
  50% {
    transform: translateY(-60px);
  }
  900% {
    transform: translateY(-10px);
  }
  100% {
    transform: translateY(0);
  }
}

.hero .content {
  position: relative;
  z-index: 1;
}


    .hero h1 {
      font-size: 3.5rem;
      margin-bottom: -1rem;
      margin-top: 2rem;

      letter-spacing: -1px;
      font-weight: 900;

    }
    .white-text {
  color: white;
  text-shadow: 4px 2px 7px rgb(17 17 17 / 32%);

}

/* Nested Accordion */
.nested-accordion details {
  margin-left: 10px;
  margin-top: 10px;
}

.nested-accordion summary {
  font-size: 13px;
  color: #2c3e50;
  padding: 5px 0;
}

.selectable-list li {
  padding: 6px 8px;
  border-radius: 6px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.selectable-list li:hover,
.selectable-list li.active {
  background-color: #e0f3ea;
  color: #2c7a4d;
  font-weight: bold;
}

.venue-buttons button {
  background-color:rgb(255, 255, 255);
  transition: all 0.2s ease;
}

.venue-buttons button.active {
  background-color: #2c7a4d;
  color: white;
  font-weight: bold;
}

.apply-filter {
  width: 100%;
  padding: 12px;
  background-color: #2c7a4d;
  color: #fff;
  border: none;
  border-radius: 8px;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

.apply-filter:hover {
  background-color: #256d41;
}

.page-container {
  flex: 1;
  display: flex;
  padding: 50px 70px;
  gap: 10px;
  align-items: flex-start;
}

/* Sidebar Styles */
.sidebar {
  width: 270px;
  background-color: #ffffff;
  padding: 20px;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  border: 1px solid #ccc;
  flex-shrink: 0;
}

.filter-section h3 {
  font-size: 18px;
  margin-bottom: 30px;
  display: flex;
  align-items: center;
  gap: 10px;
  color: #2c3e50;
}

.filter-group {
  margin-bottom: 25px;
}

.filter-group h4 {
  font-size: 13px;
  text-transform: uppercase;
  margin-bottom: 10px;
  color: #6c757d;
}

.filter-group ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.filter-group ul li {
  font-size: 14px;
  margin-bottom: 8px;
  margin-top: 8px;
  color: #333;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
}

.filter-group ul li.active {
  font-weight: bold;
  color: #2c7a4d;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}

.purple { background-color: #a55eea; }
.red { background-color: #e74c3c; }
.yellow { background-color: #f1c40f; }
.green { background-color: #2ecc71; }
.blue { background-color: #3498db; }
.orange { background-color: #e67e22; }
.pink { background-color: #fd79a8; }
.teal { background-color: #1abc9c; }

.venue-buttons button {
  width: 100%;
  border: none;
  padding: 8px 10px;
  border-radius: 8px;
  margin-bottom: 2px;
  margin-left: 2px;

  font-size: 13px;
  cursor: pointer;
  text-align: left;
  font-weight:600;
  color:#2c3e50;
}

.venue-buttons button.active {
  background-color: #2c7a4d;
  color: white;
}

.apply-filter {
  width: 100%;
  padding: 10px;
  background-color: #2c7a4d;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
  margin-top: 10px;
}
.filter-group summary {
  font-size: 14px;
  font-weight: 600;
  color: #2c3e50;
  cursor: pointer;
  padding: 10px 0;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
  list-style: none;
  position: relative;
}

.filter-group summary::after {
  content: '\25BC';
  font-size: 12px;
  transition: transform 0.3s ease;
  margin-left: auto;
  color: #888;
}

details[open] summary::after {
  transform: rotate(180deg);
}

details ul, .venue-buttons {
  margin-top: 10px;
  padding-left: 0;
  transition: all 0.3s ease;
}

details ul li {
  padding-left: 5px;
}
/* Organizer summary (Level 1) */
.organizer-item summary {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  padding: 6px 0;
  font-weight: 600;
  color: #2c3e50;
  border-bottom: 1px solid #eee;
}

.organizer-item summary::after {
  content: '\25BC';
  font-size: 12px;
  color: #888;
  margin-left: auto;
  transition: transform 0.3s ease;
}

.organizer-item[open] summary::after {
  transform: rotate(180deg);
}

/* Program list inside organizer */
.program-list {
  list-style: none;
  padding-left: 18px;
  margin-top: 6px;
}

.program-list li {
  font-size: 14px;
  margin-bottom: 6px;
  color: #333;
  cursor: pointer;
  transition: color 0.2s ease;
}

.program-list li:hover {
  color: #2c7a4d;
}

.program-list li.active {
  font-weight: bold;
  color: #2c7a4d;
}
.program-list li {
  font-size: 14px;
  margin-bottom: 6px;
  color: #333;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 6px;
  border-radius: 6px;
  transition: background-color 0.2s, color 0.2s;
}

.program-list li:hover {
  background-color: #f1f8f5;
}

.program-list li.active {
  background-color: #2c7a4d;
  color: white;
  font-weight: 500;
}


.sub-orgs {
  margin-left: 20px;
  margin-top: 8px;
}

.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  width: 100%;
  min-width: 0;
}
.discover-section {
  margin: 0 24px 24px;
}
.discover-shell {
  border-radius: 32px;
  padding: 32px;
  background: linear-gradient(135deg, #f8fdfa 0%, #f4f6ff 100%);
  border: 1px solid #e1ece5;
  box-shadow: 0 30px 50px rgba(5, 35, 22, 0.1);
}
.discover-top {
  display: flex;
  justify-content: space-between;
  gap: 24px;
  flex-wrap: wrap;
}
.discover-title {
  margin: 4px 0;
  font-size: 2rem;
  color: #0f3d29;
}
.discover-lead {
  margin: 0;
  color: #50635a;
  font-size: 1rem;
}
.discover-badge {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 6px;
  min-width: 160px;
}
.discover-hint {
  font-size: 0.9rem;
  color: #4a5a52;
  background: #ffffff;
  border-radius: 999px;
  padding: 6px 16px;
  border: 1px solid #dfe9e3;
}
.discover-search {
  margin-top: 20px;
}
.search-container {
  width: 100%;
  padding: 0;
}
.insight-grid {
  margin-top: 24px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px;
}
.insight-card {
  background: #ffffff;
  border-radius: 24px;
  padding: 16px 18px;
  border: 1px solid #dfe8e2;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.6);
}
.results-section {
  margin: 0 24px 24px;
}
.results-shell {
  background: #ffffff;
  border-radius: 32px;
  padding: 32px;
  box-shadow: 0 24px 48px rgba(11, 40, 25, 0.08);
  border: 1px solid #e3ebe5;
}
.results-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
}
.results-header h2 {
  margin: 4px 0;
  font-size: 1.9rem;
  color: #0f3d29;
}
.results-header p {
  margin: 6px 0 0;
  color: #5b6f66;
  font-size: 1rem;
}
.per-page-control {
  display: flex;
  align-items: center;
  gap: 8px;
  background: #f6faf8;
  border: 1px solid #dbe3dd;
  border-radius: 14px;
  padding: 8px 14px;
}
.per-page-control label {
  font-size: 0.85rem;
  font-weight: 600;
  color: #1d3d2f;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.per-page-control select {
  border: none;
  background: transparent;
  font-weight: 600;
  font-size: 0.95rem;
  color: #1d5b40;
  cursor: pointer;
  padding: 4px 2px;
}
.result-eyebrow {
  font-size: 0.75rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: #6c7a73;
  margin: 0;
}
.results-listing-header {
  margin-top: 28px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.results-listing-title {
  margin: 6px 0 0;
  font-size: 1.4rem;
  color: #123d2a;
}
.results-count-chip {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 8px 16px;
  background: #f4f8f5;
  border: 1px solid #dfe8e2;
  font-weight: 600;
  color: #1c4d34;
}
.results-grid {
  margin-top: 24px;
}

.search-bar-wrapper {
  position: relative;
  width: 100%;
  max-width: 1000px;
}

.search-bar {
  display: flex;
  align-items: center;
  background: #fff;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  border: 1px solid #ccc;
  padding: 5px;
  gap: 10px;
  width: 100%;
}

.search-input {
  flex: 1;
  border: none;
  padding: 14px 18px;
  font-size: 15px;
  border-radius: 8px;
  background-color: rgb(255, 255, 255);
  outline: none;
}

.search-filter {
  border: none;
  padding: 14px 12px;
  border-radius: 8px;
  background-color: rgb(239, 248, 238);
  color: #333;
  font-size: 14px;
  cursor: pointer;
  border: 1px solid #dbe5f1;
  outline: none;
}

.search-button {
  background-color: #2c7a4d;
  color: white;
  padding: 14px 22px;
  font-size: 15px;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: background-color 0.3s ease;
  white-space: nowrap;
  font-weight: 700;
}

.search-button:hover {
  background-color: rgb(38, 111, 41);
}

# Suggestions dropdown (styled to match requested design)
# Dark background, icon on left, primary and secondary text, first item highlighted
# Hidden by default; becomes visible when JS populates it
# The container
# Positioned by .search-bar-wrapper
# max-height limits vertical size
# z-index high so it sits above other elements
# Border uses subtle light stroke to stand out on dark backgrounds
# Rounded bottom corners
.search-button:hover {
  background-color: rgb(38, 111, 41);
}

#suggestionsList {
  display: none;
  list-style: none;
  padding: 6px;
  margin: 4px 0 0 0;
  position: absolute;
  width: 100%;
  background-color: #1b0f16;
  border: 1px solid rgba(255,255,255,0.06);
  border-top: none;
  max-height: 260px;
  overflow-y: auto;
  z-index: 1000;
  border-radius: 0 0 8px 8px;
}

/* Suggestion row */
.suggestion-item {
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 10px 12px;
  cursor: pointer;
  color: #dbeef8;
  border-radius: 6px;
}

.suggestion-item .suggestion-icon {
  width: 36px;
  height: 36px;
  border-radius: 6px;
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #222;
  flex-shrink: 0;
}

.suggestion-item .suggestion-texts {
  display: flex;
  flex-direction: column;
}

.suggestion-item .primary {
  font-size: 15px;
  font-weight: 700;
  color: #ffdce6;
}

.suggestion-item .secondary {
  font-size: 13px;
  color: #7fb3c6;
  margin-top: 2px;
}

.suggestion-item.hovered,
.suggestion-item.active-first {
  background: #4b0f1c;
}

.suggestion-item:hover { background: rgba(255,255,255,0.02); }


#searchInput {
  width: 100%;
  padding: 10px;
  font-size: 16px;
  border-radius: 5px;
}
#suggestionsList {
  display: none; /* ✅ Hides it by default */
  list-style: none;
  padding: 0;
  margin: 4px 0 0 0;
  position: absolute;
  width: 100%;
  background-color: white;
  border: 1px solid #ccc;
  border-top: none;
  max-height: 200px;
  overflow-y: auto;
  z-index: 1000;
  border-radius: 0 0 8px 8px;
}


#suggestionsList li {
  padding: 10px;
  cursor: pointer;
}

#suggestionsList li:hover {
  background-color: #f0f0f0;
}



.event-card {
  position: relative;
  background: #ffffff;
  border-radius: 16px;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.06);
  overflow: hidden;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  cursor: pointer;
  height: fit-content;
  max-width: 100%;
}

.event-card:hover {
  transform: translateY(-6px);
  box-shadow: 0 12px 24px rgba(0, 0, 0, 0.12);
}

.event-image-container img {
  width: 100%;
  height: 200px;
  object-fit: cover;
  border-bottom: 1px solid #eee;
}

.event-info {
  padding: 24px;
  text-align: center;
}

.event-title {
  font-size: 1.2rem;
  font-weight: 600;
  color: #064209;
  margin-bottom: 8px;
  word-wrap: break-word;
}

.event-location,
.event-time {
  font-size: 0.95rem;
  color: #555;
  margin: 4px 0;
}

.date-badge {
  
  position: absolute;
  top: 16px;
  right: 16px;
  background-color:rgb(53, 110, 56);
  color: #fff;
  padding: 8px 12px;
  border-radius: 8px;
  text-align: center;
  font-weight: 600;
  font-size: 0.85rem;
  line-height: 1.2;
  z-index: 1;
}


.date-day {
  font-size: 1.2rem;
  font-weight: 700;
}

.date-month {
  font-size: 0.75rem;
  text-transform: uppercase;
}
#fade-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: white;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.5s ease;
  z-index: 9999;
}

/* Responsive adjustments */
@media (max-width: 1200px) {
  .events-grid {
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 25px;
  }
  
  .page-container {
    padding: 30px 40px;
  }
}

@media (max-width: 768px) {
  .events-grid {
    grid-template-columns: 1fr;
    gap: 20px;
  }
  .discover-section,
  .results-section {
    margin: 0 12px 18px;
  }
  .discover-shell,
  .results-shell {
    padding: 24px;
    border-radius: 24px;
  }
  .discover-badge {
    align-items: flex-start;
  }
  .insight-grid {
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  }
  
  .page-container {
    flex-direction: column;
    padding: 20px;
  }
  
  .sidebar {
    width: 100%;
    margin-bottom: 20px;
  }
  
  .search-wrapper input {
    width: 100%;
  }
}

.modal {
  display: none;
  position: fixed;
  z-index: 9999;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  overflow-y: auto;
  background-color: rgba(0, 0, 0, 0.4);
  padding: 40px 20px;

  /* This ensures centering works when shown */
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

/* Modal Content Wrapper */
.modal-content {
  background-color: #fff;
  border-radius: 12px;
  max-width: 1000px;
  width: 95%;
  overflow: hidden;
  position: relative;
  box-shadow: 0 8px 20px rgba(33, 122, 44, 0.2);
}

/* Close Button */
.close-btn {
  position: absolute;
  top: 12px;
  right: 16px;
  font-size: 28px;
  font-weight: bold;
  color: #1b5e20;
  cursor: pointer;
}

/* Body: Split Layout */
.modal-body {
  display: flex;
  flex-direction: row;
  height: 600px;
}

/* LEFT SIDE: Details */
.modal-details {
  width: 40%;
  padding: 24px;
  background-color: #f1f8f4;
  border-right: 1px solid #e0e0e0;
  overflow-y: auto;
}

.modal-title {
  color: #1b5e20;
  font-size: 22px;
  font-weight: 700;
  margin-bottom: 10px;
}

.views-line {
  display: flex;
  align-items: center;
  color: #2e7d32;
  font-weight: 600;
  margin-bottom: 20px;
}
.views-line img {
  width: 20px;
  margin-right: 8px;
}

.detail-group p {
  margin: 8px 0;
  font-size: 15px;
  color: #333;
}

/* Action Buttons */
.action-buttons {
  margin-top: 24px;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}
.btn {
  border: none;
  border-radius: 8px;
  padding: 8px 16px;
  font-size: 14px;
  cursor: pointer;
  transition: 0.2s;
}
.btn.green {
  background-color: #4caf50;
  color: white;
}
.btn.green:hover {
  background-color: #388e3c;
}
.btn.light {
  background-color: #e8f5e9;
  color: #2e7d32;
}
.btn.light:hover {
  background-color: #d0f0dd;
}

/* RIGHT SIDE: PDF Preview */
.modal-pdf {
  width: 60%;
  background: #fafafa;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.modal-pdf embed {
  height: 100%;
  width: 100%;
  border: none;
}
.close-btn {
  position: absolute;
  top: 15px;
  right: 20px;
  font-size: 24px;
  font-weight: bold;
  cursor: pointer;
  color: #333;
}

.close-btn:hover {
  color: #e00;
}
.organizer-label{

  font-size: 13px;
}
.program-list ul li{
  font-size: 10px;

}
.filter-group .program-list li {
  font-size: 13px !important;
  margin-bottom: 5px !important;
  margin-top: 0 !important;
  padding: 5px 6px;
  gap: 6px;
  line-height: 1.4;
}
.filter-group .program-list li.active {
  font-size: 13px !important;
  margin-bottom: 5px !important;
  margin-top: 0 !important;
  padding: 5px 6px;
  gap: 6px;
  line-height: 1.4;
  background-color: rgb(34, 83, 62);
  color: rgb(239, 239, 239);
  font-weight: 500;
  border-radius: 6px;
  transition: background-color 0.2s ease;
}





::selection {
  color: #fff;
  background: #17a2b8;
}
.wrapper {
  width: 400px;
  background: #fff;
  border-radius: 10px;
  padding: 20px 25px 40px;
  box-shadow: 0 12px 35px rgba(0, 0, 0, 0.1);
}
header h2 {
  font-size: 24px;
  font-weight: 600;
}
header p {
  margin-top: 5px;
  font-size: 16px;
}
.price-input {
  display: flex;
  align-items: center;
  margin: 20px 0 20px;
  gap: 10px;
}

.price-input .field {
  flex: 1;
  display: flex;
  align-items: center;
}

.field input {
  width: 100%;
  font-size: 12px;
  border-radius: 5px;
  text-align: center;
  border: 1px solid #999;
  -moz-appearance: textfield;
  padding: 2px;
  margin-left: 0; /* Remove this if it's making one input smaller */
}

input[type="number"]::-webkit-outer-spin-button,
input[type="number"]::-webkit-inner-spin-button {
  -webkit-appearance: none;
}

.price-input .separator {
  font-size: 19px;
  padding: 0 10px;
  white-space: nowrap;
}

.slider {
  height: 5px;
  position: relative;
  background: #ddd;
  border-radius: 5px;
}
.slider .progress {
  height: 100%;
  position: absolute;
  border-radius: 5px;
  background:rgb(52, 138, 59);
  width: 100%;
}
.range-input {
  position: relative;
}
.range-input input {
  position: absolute;
  width: 100%;
  height: 5px;
  top: -5px;
  background: none;
  pointer-events: none;
  -webkit-appearance: none;
  -moz-appearance: none;
}
input[type="range"]::-webkit-slider-thumb {
  height: 17px;
  width: 17px;
  border-radius: 50%;
  background:rgb(52, 138, 59);
  pointer-events: auto;
  -webkit-appearance: none;
  box-shadow: 0 0 6px rgba(0, 0, 0, 0.05);
}
input[type="range"]::-moz-range-thumb {
  height: 17px;
  width: 17px;
  border: none;
  border-radius: 50%;
  background: #17a2b8;
  pointer-events: auto;
  -moz-appearance: none;
  box-shadow: 0 0 6px rgba(0, 0, 0, 0.05);
}

 .footer-section {
  background-color: rgba(27, 42, 35, 1);
  padding: 100px 132px 40px;
  font-family: 'Poppins', sans-serif;
  color: #eff3f2;
  animation: fadeInUp 1s ease-in-out;
}

@keyframes fadeInUp {
  0% {
    opacity: 0;
    transform: translateY(40px);
  }
  100% {
    opacity: 1;
    transform: translateY(0);
  }
}

.footer-main {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  max-width: 1200px;
  margin: 0 auto 40px auto;
}

.footer-branding {
  display: flex;
  align-items: center;
  gap: 15px;
  flex: 1;
  min-width: 280px;
}

.footer-logo {
  height: 60px;
  width: auto;
  transition: transform 0.3s ease, filter 0.3s ease;
}
.footer-logo:hover {
  transform: scale(1.05);
  filter: drop-shadow(0 0 8px rgba(74, 209, 103, 0.6));
}

.footer-site-info h2 {
  margin: 0;
  font-size: 28px;
  color: #eff3f2;
  font-weight: 600;
}

.footer-site-info p {
  margin: -6px 0 0 0;
  font-size: 14px;
  color: #eff3f2;
}

.footer-links {
  display: flex;
  flex: 2;
  gap: 60px;
  flex-wrap: wrap;
  justify-content: flex-end;
  min-width: 280px;
}

.footer-column {
  display: flex;
  flex-direction: column;
  gap: 41px;
  min-width: 150px;
}

.footer-column h4 {
  font-size: 16px;
  color: #d7dad8;
  margin-bottom: 5px;
  font-family: 'Inter';
  font-weight: 800;
  position: relative;
}


.footer-column a {
  text-decoration: none;
  font-size: 14px;
  color:rgba(255, 255, 255, 0.87);
  font-family: 'Inter';
  font-weight: 300;
  letter-spacing: -0.2px;
  position: relative;
  transition: all 0.3s ease;
}

.footer-column a::before {
  content: '';
  position: absolute;
  width: 0%;
  height: 2px;
  bottom: -2px;
  left: 0;
  background-color: #4ad167;
  transition: width 0.3s ease;
}

.footer-column a:hover::before {
  width: 50%;
}

.footer-column a:hover {
  color: #c2f7d3;
}

.footer-divider {
  border-top: 1px solid rgb(174, 188, 174);
  max-width: 1200px;
  margin: 90px auto 35px;
}

.footer-bottom {
  text-align: center;
  font-size: 13px;
  color:rgb(174, 188, 174);
}

.footer-branding {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 15px;
}

.footer-branding-row {
  display: flex;
  align-items: center;
  gap: 15px;
}
.footer-description {
  font-size: 13px;
  color: #c5ded7;
  line-height: 1.6;
  max-width: 480px;
  margin: 20px 0 0 74px;
  position: relative;
}

.hover-animate {
  position: relative;
  display: inline-block;
  font-weight: 300;
  color: inherit;
  transition: font-weight 0.3s ease, color 0.3s ease;
}

/* Shine pass */
.hover-animate::before {
  content: "";
  position: absolute;
  top: 0;
  left: -120%;
  width: 120%;
  height: 100%;
  background: linear-gradient(120deg, rgba(255,255,255,0.4), rgba(255,255,255,0));
  opacity: 0;
  pointer-events: none;
}



@keyframes boldFadeIn {
  to {
    font-weight: 600;
    color: #eff3f2;
  }
}

@keyframes shinePass {
  0% {
    left: -120%;
    opacity: 1;
  }
  100% {
    left: 120%;
    opacity: 0;
  }
}

.footer-description:hover .hover-animate:nth-of-type(1)::before {
  animation: shinePass 0.5s forwards 0.1s;
}
.footer-description:hover .hover-animate:nth-of-type(2)::before {
  animation: shinePass 0.5s forwards 0.4s;
}
.footer-description:hover .hover-animate:nth-of-type(3)::before {
  animation: shinePass 0.5s forwards 0.7s;
}
.footer-description:hover .hover-animate:nth-of-type(4)::before {
  animation: shinePass 0.5s forwards 1s;
}

.footer-description:hover .hover-animate:nth-of-type(1) {
  animation: boldFadeIn 0.3s forwards;
  animation-delay: 0.1s;
}
.footer-description:hover .hover-animate:nth-of-type(2) {
  animation: boldFadeIn 0.3s forwards;
  animation-delay: 0.4s;
}
.footer-description:hover .hover-animate:nth-of-type(3) {
  animation: boldFadeIn 0.3s forwards;
  animation-delay: 0.7s;
}
.footer-description:hover .hover-animate:nth-of-type(4) {
  animation: boldFadeIn 0.3s forwards;
  animation-delay: 1s;
}

.icon-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.notif-dot {
  position: absolute;
  top: -2px;
  right: -4px;
  width: 12px;
  height: 12px;
  background-color: #ff3b30;
  border-radius: 50%;
  box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.08);
  pointer-events: none;
}

.events-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 20px;
  margin-top: 30px;
  padding: 0 16px;
}

.no-results {
  grid-column: 1 / -1;
  text-align: center;
  margin-top: 50px;
  color: #555;
  font-weight: 500;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.no-results img {
  width: 140px;
  opacity: 0.7;
}

.no-results p {
  font-size: 18px;
  color: #888;
}

.thesis-card {
  background: #fff;
  border-radius: 12px;
  padding: 20px 24px;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.06);
  border: 1px solid #e2e2e2;
  transition: 0.2s ease;
  cursor: pointer;
  margin-bottom: 16px;
}

.thesis-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 14px rgba(0, 0, 0, 0.08);
}

.thesis-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.thesis-title {
  font-size: 1.1rem;
  font-weight: 700;
  color: #1e4d2b;
  margin: 0 0 10px 0;
  flex: 1;
}

.thesis-card p {
  font-size: 0.95rem;
  color: #444;
  margin: 6px 0;
}

.thesis-card span {
  color: #222;
  font-weight: 500;
}

.views-badge {
  display: flex;
  align-items: center;
  background-color: #e8f8ed;
  color: #1e7a30;
  font-weight: 600;
  border-radius: 14px;
  padding: 3px 8px;
  font-size: 0.85rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}

.views-badge img {
  width: 16px;
  height: 16px;
  margin-right: 5px;
  opacity: 0.8;
}

.tag-bubbles {
  margin-top: 12px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.tag {
  font-size: 0.75rem;
  padding: 4px 10px;
  border-radius: 20px;
  font-weight: 600;
  color: white;
  display: inline-block;
}

.tag.green { background-color: #358047; }
.tag.blue { background-color: #1976d2; }
.tag.gray { background-color: #757575; }

.academic-card {
  background: #fff;
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
  border: 1px solid #e0e0e0;
  margin-bottom: 20px;
  font-family: 'Segoe UI', sans-serif;
  max-width: 800px;
  transition: 0.2s ease;
}

.academic-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.08);
}

.top-meta {
  margin-bottom: 10px;
}

.open-access {
  font-size: 0.8rem;
  background-color: #f1f8e9;
  color: #689f38;
  padding: 4px 10px;
  border-radius: 8px;
  font-weight: 600;
  display: inline-block;
}

.paper-title {
  font-size: 1.35rem;
  font-weight: 700;
  color: #111;
  margin-bottom: 6px;
}

.authors-line {
  font-size: 0.95rem;
  color: #444;
  margin-bottom: 4px;
}

.publisher {
  font-size: 0.9rem;
  color: #666;
  margin-bottom: 14px;
}

.paper-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.btn {
  background-color: #f5f5f5;
  border: none;
  border-radius: 8px;
  padding: 10px 16px;
  font-weight: 600;
  font-size: 0.9rem;
  color: #333;
  cursor: pointer;
  transition: all 0.2s ease-in-out;
}

.btn:hover {
  background-color: #e0e0e0;
}

.btn.green {
  background-color: #268447ff;
  color: #ffffff;
}

.btn.green:hover {
  background-color: #237a33ff;
    color: #ffffff;

}

.section-title {
  margin: 0;
  font-size: 1.6rem;
  color: #0f3d29;
}

.section-block {
  margin: 32px 24px;
  padding: 24px;
  border-radius: 24px;
  background: #ffffff;
  box-shadow: 0 18px 42px rgba(12, 35, 28, 0.08);
}
.section-block.section-muted {
  background: #f6faf8;
  border: 1px solid #e2ece6;
  box-shadow: none;
}
.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.section-lead {
  margin: 6px 0 0;
  color: #5b6f66;
  font-size: 0.95rem;
}
.section-block .events-grid {
  margin-top: 18px;
}


.recommendation-section {
  background: linear-gradient(135deg, #f5fbf8 0%, #f1f4ff 100%);
  padding: 40px 24px 80px;
}
.recommendation-shell {
  max-width: 1200px;
  margin: 0 auto;
  border-radius: 32px;
  padding: 32px;
  background: #ffffff;
  border: 1px solid #e2ece6;
  box-shadow: 0 22px 60px rgba(15, 61, 41, 0.08);
}
.recommendation-label,
.eyebrow-label {
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.75rem;
  color: #6a7a74;
  margin-bottom: 4px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.recommendation-title-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.recommendation-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  flex-wrap: wrap;
}
.recommendation-intro {
  flex: 1 1 320px;
}
.recommendation-summary {
  flex: 1 1 280px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 16px;
  align-items: stretch;   /* para lahat ng cells same height per row */
}

.recommendation-metric {
 background: #f6faf8;
  border: 1px solid #dce8e2;
  border-radius: 20px;
  padding: 16px 18px;

  width: 100%;
  min-height: 160px;  /* or 180px, depende sa feel mo */
  
  display: flex;
  flex-direction: column;
  justify-content: flex-start;  /* wag space-between para di humila pababa */
  box-sizing: border-box;
}

.metric-eyebrow {
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.7rem;
  color: #7f9188;
  display: block;
  margin-bottom: 4px;
}
.metric-value {
  font-size: 1.4rem;
  color: #0f3d29;
  display: block;
  line-height: 1.1;
}
.metric-hint {
  margin: 4px 0 0;
  color: #5b6f66;
  font-size: 0.85rem;
}
.recommendation-scroller {
  margin-top: 28px;
  display: grid;
  grid-auto-flow: column;
  grid-auto-columns: minmax(280px, 1fr);
  gap: 20px;
  overflow-x: auto;
  padding-bottom: 8px;
  scroll-snap-type: x mandatory;
}
.recommendation-scroller::-webkit-scrollbar {
  height: 8px;
}
.recommendation-scroller::-webkit-scrollbar-thumb {
  background: #cfe2d9;
  border-radius: 999px;
}
.recommendation-scroller .academic-card {
  min-width: 280px;
  scroll-snap-align: start;
  box-shadow: 0 14px 34px rgba(12, 35, 28, 0.08);
}
.recommendation-empty {
  margin-top: 28px;
  padding: 28px;
  border-radius: 24px;
  border: 1px dashed #c5d8cf;
  background: #fdfefd;
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  align-items: center;
  justify-content: space-between;
}
.recommendation-empty h3 {
  margin: 0 0 8px;
  font-size: 1.3rem;
  color: #123d29;
}
.recommendation-empty p {
  margin: 0;
  color: #5b6f66;
  max-width: 520px;
}
.recommendation-empty-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}
@media (min-width: 1024px) {
  .recommendation-scroller {
    grid-auto-columns: minmax(320px, 1fr);
  }
}
@media (max-width: 768px) {
  .recommendation-section {
    padding: 32px 16px 60px;
  }
  .recommendation-shell {
    padding: 24px;
  }
  .recommendation-header {
    flex-direction: column;
  }
  .recommendation-summary {
    width: 100%;
  }
  .recommendation-scroller {
    grid-auto-columns: 85%;
  }
}
.chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 999px;
  padding: 6px 14px;
  font-size: 0.85rem;
  font-weight: 600;
  background: #e6f2ed;
  color: #155737;
  border: 1px solid #cfe5d9;
}
.chip-success {
  background: #e0f6ee;
  border-color: #aee6cf;
  color: #056644;
}
.chip-info {
  background: #edf2ff;
  border-color: #cdd9ff;
  color: #314b99;
}
.chip-neutral {
  background: #f2f2f6;
  border-color: #e2e2ea;
  color: #4b4f66;
}
.views-chip {
  background: #edf5f1;
  border-radius: 12px;
  padding: 4px 10px;
  font-size: 0.8rem;
  color: #2d5a44;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.card-context {
  margin-top: 12px;
  font-size: 0.85rem;
  color: #27594a;
  background: #eff8f4;
  border-left: 3px solid #1d7b58;
  padding: 6px 10px;
  border-radius: 10px;
}
.modal-context {
  background: #ecf7f2;
  color: #1f4e3a;
  padding: 10px 12px;
  border-radius: 12px;
  font-size: 0.9rem;
  margin: 8px 0 16px;
}
.modal-meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.modal-meta-grid small {
  display: block;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #5f6e67;
}
.modal-meta-grid strong {
  display: block;
  font-size: 1rem;
  color: #0f3d29;
}

.pagination {
  display: flex;
  gap: 8px;
  justify-content: center;
  align-items: center;
  margin: 24px auto 10px;
  flex-wrap: wrap;
}
.page-btn {
  min-width: 36px;
  padding: 8px 12px;
  border-radius: 10px;
  border: 1px solid #cdd9d0;
  text-align: center;
  font-weight: 600;
  color: #1f3d2f;
  text-decoration: none;
  background: #fff;
  transition: background 0.2s ease, color 0.2s ease;
}
.page-btn:hover:not(.active):not(.disabled) {
  background: #eaf3ed;
}
.page-btn.active {
  background: #0f5a46;
  color: #fff;
  border-color: #0f5a46;
}
.page-btn.disabled {
  pointer-events: none;
  opacity: 0.4;
}
.page-ellipsis {
  color: #6a7b72;
  padding: 0 4px;
}

/* Status badges */
.badge {
  display: inline-block;
  font-size: 0.8rem;
  font-weight: 700;
  padding: 4px 10px;
  border-radius: 8px;
  line-height: 1;
}

.badge-approved {
  background-color: #e9f7ef;  /* light green bg */
  color: #2e7d32;             /* green text */
  border: 1px solid #c8e6c9;
}

.badge-pending {
  background-color: #fff8e1;  /* light amber bg */
  color: #b26a00;             /* amber text */
  border: 1px solid #ffe0b2;
}

.badge-rejected {
  background-color: #ffebee;  /* light red bg */
  color: #c62828;             /* red text */
  border: 1px solid #ffcdd2;
}

.event-image-container {
  width: 100%;
  height: 180px;            /* fixed preview height for uniform cards */
  overflow: hidden;
  background: #f8faf9;
  border-bottom: 1px solid #eee;
    margin-bottom: 10px;
}

.event-image-container img {
  width: 100%;
  height: 100%;
  object-fit: cover;        /* crop nicely */
  display: block;

}
/* Hero-style PDF header with consistent aspect ratio */
.pdf-hero {
  position: relative;
  width: 100%;
  border-radius: 12px 12px 0 0;
  overflow: hidden;
  /* 16:9 aspect ratio via intrinsic sizing */
  aspect-ratio: 16 / 9;              /* modern browsers */
  background: #f6f8f7;
  border-bottom: 1px solid #eaeaea;
}

/* Fallback if aspect-ratio is not available */
@supports not (aspect-ratio: 16 / 9) {
  .pdf-hero {
    height: 0;
    padding-top: 56.25%;
  }
  .pdf-hero img {
    position: absolute;
    inset: 0;
  }
}

/* Gradient gloss overlay for depth */
.pdf-hero::after {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: linear-gradient(
    to bottom,
    rgba(0,0,0,0.10),
    rgba(0,0,0,0.00) 50%,
    rgba(0,0,0,0.08)
  );
}

/* The rendered thumbnail */
.pdf-hero img {
  width: 100%;
  height: 100%;
  object-fit: cover;                  /* clean crop */
  display: block;
  transform: scale(1);
  transition: transform .35s ease, filter .35s ease;
  will-change: transform, filter;
  margin-bottom: 20px;
}

/* Subtle zoom on hover */
.academic-card:hover .pdf-hero img {
  transform: scale(1.03);
  filter: saturate(1.02);
}

/* "PDF" badge */
.file-badge {
  position: absolute;
  top: 10px;
  left: 10px;
  z-index: 2;
  padding: 6px 10px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: .4px;
  color: #ffffff;
  background: linear-gradient(135deg, #e53935, #d81b60);
  box-shadow: 0 4px 10px rgba(0,0,0,.12);
}

/* Shimmer skeleton while rendering */
.skeleton {
  position: relative;
  background: #eef2ef !important;
}

.skeleton::before {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg,
    rgba(255,255,255,0) 0%,
    rgba(255,255,255,.6) 50%,
    rgba(255,255,255,0) 100%);
  transform: translateX(-100%);
  animation: shimmer 1.2s infinite;
}

@keyframes shimmer {
  100% { transform: translateX(100%); }
}

/* When rendering failed */
.thumb-failed {
  background: #fff3f3 !important;
  object-fit: contain !important;
}

.thumb-failed + .file-badge {
  background: linear-gradient(135deg, #999, #777);
}

  </style>
</head>
<body>
<div id="fade-overlay"></div>

    <div class="navbar">
      <div class="logo">
        <img id="navbar-logo" src="pictures/researchgatelogo3.png" alt="Logo" />
        <div class="logo-texts">
          <span class="title">Research</span>
          <span class="subtitle">Unlocked</span>
        </div>
      </div>

      <div class="nav-center">
        <a href="homepage.php">Home</a>
        <a href="browse.php"><b><u>Browse</u></b></a>
        <a href="about.php">About</a>
        <a href="upload.php">Upload</a>
      </div>


      <div class="nav-login">
        <a href="userdashboard.php" class="user-info">
          <span class="student-number"><?= htmlspecialchars($_SESSION['student_number']) ?></span>
          <div class="icon-wrapper">
            <i class="fas fa-user-circle user-icon"></i>
            <?php if ($hasUnread): ?>
              <span class="notif-dot"></span>
            <?php endif; ?>
          </div>
        </a>
      </div>



    </div>


  <!-- Hero Section -->
  <section class="hero">
    <div class="circle circle1"></div>
    <div class="circle circle2"></div>
    <div class="circle circle3"></div>
    <div class="circle circle4"></div>
    <div class="circle circle5"></div>
    <div class="circle circle6"></div>
    <div class="content">
      <h1 class="white-text">Browse</h1>
      <br><br>
    </div>   
  </section>


<div class="page-container">



  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="filter-section">
      <h3><i class="fas fa-sliders-h"></i> Filters</h3>

      <!-- Date Filter -->
<details class="filter-group" open>
     <summary>Date</summary>
     

<div class="price-input">
  <div class="field">
    <input type="number" name="year_min" class="input-min" min="2000" max="2025" value="<?php echo isset($_GET['year_min']) ? intval($_GET['year_min']) : 2001; ?>">
  </div>
  <div class="separator">-</div>
  <div class="field">
    <input type="number" name="year_max" class="input-max" min="2000" max="2025" value="<?php echo isset($_GET['year_max']) ? intval($_GET['year_max']) : 2025; ?>">
  </div>
</div>

<div class="slider">
  <div class="progress"></div>
</div>

<div class="range-input">
  <input type="range" class="range-min" min="2000" max="2025" value="2000" step="1">
  <input type="range" class="range-max" min="2000" max="2025" value="2025" step="1">
</div>
</details>



<div id="citeModal" class="modal" style="display:none;">
  <div class="modal-content" style="max-width:720px;">
    <span class="close-btn" onclick="closeCite()">&times;</span>
    <div style="padding:20px;">
      <h3 style="margin:0 0 12px; color:#1b5e20;">Cite this work</h3>

      <div style="display:flex; gap:10px; flex-wrap:wrap; margin:10px 0 16px;">
        <button class="btn light" data-style="APA"     onclick="setCiteTab(this)">APA</button>
        <button class="btn light" data-style="MLA"     onclick="setCiteTab(this)">MLA</button>
        <button class="btn light" data-style="Chicago" onclick="setCiteTab(this)">Chicago</button>
        <button class="btn light" data-style="IEEE"    onclick="setCiteTab(this)">IEEE</button>
        <button class="btn light" data-style="BibTeX"  onclick="setCiteTab(this)">BibTeX</button>
      </div>

      <div style="position:relative;">
        <textarea id="citeText" rows="6" style="width:100%; padding:12px; border:1px solid #dcdcdc; border-radius:8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;"></textarea>
        <div style="display:flex; gap:8px; margin-top:10px;">
          <button class="btn green" onclick="copyCitation()">Copy</button>
          <button class="btn" onclick="downloadBib()">Download .bib</button>
        </div>
      </div>
    </div>
  </div>
</div>


      <!-- Organizers Filter -->
  <details class="filter-group">
    <summary>Colleges</summary>
    <div class="nested-accordion" id="organizer-group">

      <!-- College of Arts and Science -->

      <!-- Dynamic Program List by College -->
      <?php
      $collegeResult = $conn->query("SELECT colleges_id, colleges FROM colleges ORDER BY colleges");
      while ($collegeRow = $collegeResult->fetch_assoc()) {
        echo '<details class="organizer-item">';
        echo '<summary><span class="organizer-label">' . htmlspecialchars($collegeRow['colleges']) . '</span></summary>';
        echo '<ul class="program-list">';
        $programResult = $conn->prepare("SELECT program_id, program FROM program WHERE colleges_id = ? ORDER BY program");
        $programResult->bind_param('i', $collegeRow['colleges_id']);
        $programResult->execute();
        $programResult->bind_result($pid, $pname);
        while ($programResult->fetch()) {
          echo '<li data-value="' . $pid . '">' . htmlspecialchars($pname) . '</li>';
        }
        $programResult->close();
        echo '</ul>';
        echo '</details>';
      }
      ?>

    </div>
  </details>


      <!-- Venue -->
      <form id="filterForm" method="GET" action="browse.php">
        <details class="filter-group">
          <summary>Project Type</summary>
          <div class="venue-buttons selectable-buttons" data-group="projecttype">
            <button type="button" data-value="Capstone">Capstone</button>
            <button type="button" data-value="Thesis">Thesis</button>
            <button type="button" data-value="Feasibility Study">Feasibility Study</button>
            <button type="button" data-value="Research Paper">Research Paper</button>
            <button type="button" data-value="Personal Research">Personal Research</button>
            <button type="button" data-value="all" class="active">All</button>
          </div>
          <input type="hidden" id="selectedProjectType" name="project_type" value="<?php echo htmlspecialchars($project_type ?? 'all'); ?>">
          <!-- Add hidden input for selected program -->
          <input type="hidden" id="selectedProgramId" name="program_id" value="">
        </details>
        <!-- Apply -->
        <button class="apply-filter" type="submit">Apply Filters</button>
      </form>
<script>
// Project Type filter button logic
document.querySelectorAll('.venue-buttons button').forEach(btn => {
  btn.addEventListener('click', function() {
    // Remove active from all
    document.querySelectorAll('.venue-buttons button').forEach(b => b.classList.remove('active'));
    this.classList.add('active');
    document.getElementById('selectedProjectType').value = this.getAttribute('data-value');
  });
});

// Program filter logic
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.program-list li').forEach(li => {
    li.addEventListener('click', function() {
      // Remove active from all programs
      document.querySelectorAll('.program-list li').forEach(item => item.classList.remove('active'));
      this.classList.add('active');
      // Set hidden input for program_id
      document.getElementById('selectedProgramId').value = this.getAttribute('data-value');
      // Do NOT submit the form automatically; user must click 'Apply Filters'
    });
  });
});
</script>

      <!-- Apply -->
      
    </div>
  </aside>

 <!-- Main Content -->
<main class="main-content">


<section class="discover-section">
  <div class="discover-shell">
    <div class="discover-top">
      <div>
        <p class="eyebrow-label">Library Explorer</p>
        <h2 class="discover-title">Search the collection</h2>
        <p class="discover-lead"><?= htmlspecialchars($discoverLeadCopy) ?></p>
      </div>
      <div class="discover-badge">
        <span class="chip chip-success">Live catalog</span>
        <span class="discover-hint"><?= htmlspecialchars($resultCountLabelUi) ?></span>
      </div>
    </div>
    <div class="discover-search">
      <div class="search-container">
        <div class="search-bar-wrapper">
          <div class="search-bar">
            <input type="text" id="searchInput" placeholder="Search for a keyword, title, author, publisher..." class="search-input" oninput="autocompleteSearch()"/>
            <select class="search-filter">
              <option>Keyword</option>
              <option>Title</option>
              <option>Author</option>
              <option>Publisher</option>
            </select>
            <button class="search-button" id="findNowBtn">Find it now</button>
          </div>
          <ul id="suggestionsList"></ul>
        </div>
      </div>
    </div>
    <?php if (!empty($searchInsightItems)): ?>
      <div class="insight-grid">
        <?php foreach ($searchInsightItems as $insight): ?>
          <div class="insight-card">
            <span class="metric-eyebrow"><?= htmlspecialchars($insight['label']) ?></span>
            <strong class="metric-value"><?= htmlspecialchars($insight['value']) ?></strong>
            <?php if (!empty($insight['hint'])): ?>
              <p class="metric-hint"><?= htmlspecialchars($insight['hint']) ?></p>
            <?php endif; ?>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>
</section>

<?php

// Function to render a thesis event card
function renderThesisCard($row) {
    $tc_id = isset($row['tc_id']) ? (int)$row['tc_id'] : 0;
    if ($tc_id <= 0) return;

    $titlePlain   = trim((string)($row['title'] ?? 'Untitled manuscript'));
    $authorsPlain = trim((string)($row['authors'] ?? 'Unknown authors'));
    $collegePlain = trim((string)($row['college'] ?? ($row['college_name'] ?? 'College unspecified')));
    $yearPlain    = trim((string)($row['academic_year'] ?? 'Unspecified'));
    $programPlain = trim((string)($row['program'] ?? 'Program unspecified'));
    $projectPlain = trim((string)($row['project_type'] ?? 'Research'));
    $contextPlain = trim((string)($row['context_label'] ?? ''));
    $viewsTotal   = isset($row['views']) ? max(0, (int)$row['views']) : 0;
    $viewsLabel   = number_format($viewsTotal) . ' ' . ($viewsTotal === 1 ? 'view' : 'views');

    $title   = htmlspecialchars($titlePlain);
    $authors = htmlspecialchars($authorsPlain !== '' ? $authorsPlain : 'Unknown authors');
    $college = htmlspecialchars($collegePlain !== '' ? $collegePlain : 'College unspecified');
    $year    = htmlspecialchars($yearPlain !== '' ? $yearPlain : 'Unspecified');
    $programLabel = htmlspecialchars($programPlain !== '' ? $programPlain : 'Program unspecified');
    $projectLabel = htmlspecialchars($projectPlain !== '' ? $projectPlain : 'Research');

    $programAttr     = htmlspecialchars($programPlain, ENT_QUOTES);
    $projectTypeAttr = htmlspecialchars($projectPlain, ENT_QUOTES);
    $contextAttr     = htmlspecialchars($contextPlain, ENT_QUOTES);

    $contextMarkup = $contextPlain !== ''
        ? '<div class="card-context">' . htmlspecialchars($contextPlain) . '</div>'
        : '';

    $titleJs   = json_encode($titlePlain, JSON_HEX_APOS | JSON_HEX_QUOT);
    $authorsJs = json_encode($authorsPlain, JSON_HEX_APOS | JSON_HEX_QUOT);
    $collegeJs = json_encode($collegePlain, JSON_HEX_APOS | JSON_HEX_QUOT);
    $yearJs    = json_encode($yearPlain, JSON_HEX_APOS | JSON_HEX_QUOT);

    $pdfInlineUrl = 'serve_pdf.php?tc_id=' . urlencode((string)$tc_id);
    $thumbAlt = htmlspecialchars("PDF preview of {$titlePlain}", ENT_QUOTES);

    $badgeText = 'Public';
    $badgeClass = 'badge badge-approved';
    if (isset($row['status'])) {
        $status = strtolower(trim($row['status']));
        if ($status === 'approved') {
            $badgeText  = 'Approved';
            $badgeClass = 'badge badge-approved';
        } elseif ($status === 'pending') {
            $badgeText  = 'Pending';
            $badgeClass = 'badge badge-pending';
        } elseif ($status === 'rejected') {
            $badgeText  = 'Rejected';
            $badgeClass = 'badge badge-rejected';
        } else {
            $badgeText  = htmlspecialchars(ucfirst($row['status']));
            $badgeClass = 'badge badge-pending';
        }
    }

    $dataAttrs = sprintf(
        'data-program="%s" data-project="%s" data-context="%s"',
        $programAttr,
        $projectTypeAttr,
        $contextAttr
    );

    echo <<<HTML
    <div class="academic-card" {$dataAttrs} onclick='openModal({$titleJs}, {$authorsJs}, {$collegeJs}, {$yearJs}, {$tc_id}, {$viewsTotal}, this)'>
        <div class="pdf-hero">
            <span class="file-badge">PDF</span>
            <img
              class="pdf-thumb skeleton"
              data-pdf="{$pdfInlineUrl}"
              alt="{$thumbAlt}"
              loading="lazy"
              src="pictures/pdf-placeholder.png">
        </div>

        <div class="top-meta">
            <span class="{$badgeClass}">{$badgeText}</span>
            <span class="views-chip card-views-count">{$viewsLabel}</span>
        </div>

        <h2 class="paper-title">{$title}</h2>
        <div class="authors-line">{$authors} - <span class="muted">Published {$year}</span></div>
        <div class="publisher">{$college} - {$programLabel}</div>

        <div class="paper-actions">
            <button type="button" class="btn green" onclick="openPdfViewer(event, {$tc_id});">View PDF</button>
        </div>
        {$contextMarkup}
    </div>
HTML;
}
?>

<?php $perPageChoices = [6, 12, 18, 24, 36]; ?>
<section class="results-section" aria-live="polite">
  <div class="results-shell">
    <div class="results-header">
      <div class="results-copy">
        <p class="result-eyebrow">Result summary</p>
        <h2><?= htmlspecialchars($resultsHeading) ?></h2>
        <p><?= htmlspecialchars($resultsLead) ?></p>
      </div>
      <div class="per-page-control">
        <label for="perPageSelect">Per Page</label>
        <select id="perPageSelect" onchange="if(this.value){ window.location.href = this.value; }">
          <?php foreach ($perPageChoices as $choice): ?>
            <?php
              $url = htmlspecialchars(buildBrowseQueryUrl(['per_page' => $choice, 'page' => 1]));
              $selected = $choice === $perPage ? 'selected' : '';
            ?>
            <option value="<?= $url ?>" <?= $selected ?>><?= $choice ?> items</option>
          <?php endforeach; ?>
        </select>
      </div>
    </div>

    <div class="results-listing-header">
      <div>
        <p class="result-eyebrow">Current set</p>
        <h3 class="results-listing-title">Thesis Papers</h3>
      </div>
      <span class="results-count-chip"><?= htmlspecialchars($resultCountLabelUi) ?></span>
    </div>

    <div class="events-grid results-grid">
        <?php if (!empty($pagedResults)): ?>
            <?php foreach ($pagedResults as $row): ?>
                <?php
                  $card = $row;
                  $card['context_label'] = $searchTerm !== ''
                    ? sprintf('Matches "%s"', $searchTerm)
                    : 'Library pick';
                  renderThesisCard($card);
                ?>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="no-results">
                <img src="images/no-results.png" alt="No results" />
                <p>No matching thesis or capstone found.</p>
            </div>
        <?php endif; ?>
    </div>
    <?php if ($totalPages > 1): ?>
      <nav class="pagination">
        <?php
          $prevUrl = $page === 1 ? '#' : htmlspecialchars(buildBrowseQueryUrl(['page' => $page - 1]));
          $nextUrl = $page === $totalPages ? '#' : htmlspecialchars(buildBrowseQueryUrl(['page' => $page + 1]));
          $window = 2;
          $startPage = max(1, $page - $window);
          $endPage = min($totalPages, $page + $window);
        ?>
        <a class="page-btn <?= $page === 1 ? 'disabled' : '' ?>" href="<?= $prevUrl ?>">&laquo;</a>
        <?php if ($startPage > 1): ?>
          <a class="page-btn" href="<?= htmlspecialchars(buildBrowseQueryUrl(['page' => 1])) ?>">1</a>
          <?php if ($startPage > 2): ?><span class="page-ellipsis">???</span><?php endif; ?>
        <?php endif; ?>
        <?php for ($p = $startPage; $p <= $endPage; $p++): ?>
          <?php if ($p === $page): ?>
            <span class="page-btn active"><?= $p ?></span>
          <?php else: ?>
            <a class="page-btn" href="<?= htmlspecialchars(buildBrowseQueryUrl(['page' => $p])) ?>"><?= $p ?></a>
          <?php endif; ?>
        <?php endfor; ?>
        <?php if ($endPage < $totalPages): ?>
          <?php if ($endPage < $totalPages - 1): ?><span class="page-ellipsis">???</span><?php endif; ?>
          <a class="page-btn" href="<?= htmlspecialchars(buildBrowseQueryUrl(['page' => $totalPages])) ?>"><?= $totalPages ?></a>
        <?php endif; ?>
        <a class="page-btn <?= $page === $totalPages ? 'disabled' : '' ?>" href="<?= $nextUrl ?>">&raquo;</a>
      </nav>
    <?php endif; ?>
  </div>
</section>
</div>
<?php if ($totalPages > 1): ?>
  <nav class="pagination">
    <?php
      $prevUrl = $page === 1 ? '#' : htmlspecialchars(buildBrowseQueryUrl(['page' => $page - 1]));
      $nextUrl = $page === $totalPages ? '#' : htmlspecialchars(buildBrowseQueryUrl(['page' => $page + 1]));
      $window = 2;
      $startPage = max(1, $page - $window);
      $endPage = min($totalPages, $page + $window);
    ?>
    <a class="page-btn <?= $page === 1 ? 'disabled' : '' ?>" href="<?= $prevUrl ?>">&laquo;</a>
    <?php if ($startPage > 1): ?>
      <a class="page-btn" href="<?= htmlspecialchars(buildBrowseQueryUrl(['page' => 1])) ?>">1</a>
      <?php if ($startPage > 2): ?><span class="page-ellipsis">…</span><?php endif; ?>
    <?php endif; ?>
    <?php for ($p = $startPage; $p <= $endPage; $p++): ?>
      <?php if ($p === $page): ?>
        <span class="page-btn active"><?= $p ?></span>
      <?php else: ?>
        <a class="page-btn" href="<?= htmlspecialchars(buildBrowseQueryUrl(['page' => $p])) ?>"><?= $p ?></a>
      <?php endif; ?>
    <?php endfor; ?>
    <?php if ($endPage < $totalPages): ?>
      <?php if ($endPage < $totalPages - 1): ?><span class="page-ellipsis">…</span><?php endif; ?>
      <a class="page-btn" href="<?= htmlspecialchars(buildBrowseQueryUrl(['page' => $totalPages])) ?>"><?= $totalPages ?></a>
    <?php endif; ?>
    <a class="page-btn <?= $page === $totalPages ? 'disabled' : '' ?>" href="<?= $nextUrl ?>">&raquo;</a>
  </nav>
<?php endif; ?>

</main>
</div>

<?php if (!empty($recommendedRows) || $recommendationLead !== ''): ?>
  <section class="recommendation-section" aria-label="Recommendation feed">
    <div class="recommendation-shell">
      <div class="recommendation-header">
        <div class="recommendation-intro">
          <p class="recommendation-label">Recommendation Feed</p>
          <div class="recommendation-title-row">
            <h2 class="section-title">Recommended for You</h2>
            <?php if ($recommendationBadgeLabel !== ''): ?>
              <span class="chip chip-info"><?= htmlspecialchars($recommendationBadgeLabel) ?></span>
            <?php endif; ?>
          </div>
          <?php if ($recommendationLead !== ''): ?>
            <p class="section-lead"><?= htmlspecialchars($recommendationLead) ?></p>
          <?php endif; ?>
        </div>
        <?php if (!empty($recommendationSummary)): ?>
          <div class="recommendation-summary">
            <?php foreach ($recommendationSummary as $summary): ?>
              <div class="recommendation-metric">
                <span class="metric-eyebrow"><?= htmlspecialchars($summary['eyebrow']) ?></span>
                <strong class="metric-value"><?= htmlspecialchars($summary['value']) ?></strong>
                <p class="metric-hint"><?= htmlspecialchars($summary['hint']) ?></p>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </div>
      <?php if (!empty($recommendedRows)): ?>
        <div class="recommendation-scroller" role="list">
          <?php foreach ($recommendedRows as $row): ?>
            <?php
              $card = $row;
              if (!empty($recommendationCardLabel) && empty($card['context_label'])) {
                  $card['context_label'] = $recommendationCardLabel;
              }
              renderThesisCard($card);
            ?>
          <?php endforeach; ?>
        </div>
      <?php else: ?>
        <div class="recommendation-empty">
          <div>
            <h3>Teach the feed what you care about</h3>
            <p>Open any thesis, try another search, or tweak the filters so our engine can return sharper picks next visit.</p>
          </div>
          <div class="recommendation-empty-actions">
            <button type="button" class="btn green" onclick="var input=document.getElementById('searchInput'); if (input) { input.focus(); }">Search library</button>
            <button type="button" class="btn light" onclick="scrollToFilters()">Adjust filters</button>
          </div>
        </div>
      <?php endif; ?>
    </div>
  </section>
<?php endif; ?>



<!-- Modal for Viewing PDF -->
<div id="thesisModal" class="modal">
  <div class="modal-content">
    <div class="modal-body">
      
      <!-- LEFT DETAILS PANE -->
      <div class="modal-details">
        <input type="hidden" id="currentTcId" value="">
        <h2 id="modalTitle" class="modal-title">Title Here</h2>

        <div class="views-line">
          <img src="pictures/eye.png" alt="Views">
          <span id="viewCount">0 views</span>
        </div>

        <div class="modal-context" id="modalContext">Selected from Research Unlocked.</div>

        <div class="modal-meta-grid">
          <div>
            <small>College</small>
            <strong id="modalCollege">&mdash;</strong>
          </div>
          <div>
            <small>Program</small>
            <strong id="modalProgram">&mdash;</strong>
          </div>
          <div>
            <small>Project Type</small>
            <strong id="modalProject">&mdash;</strong>
          </div>
          <div>
            <small>Year</small>
            <strong id="modalYear">&mdash;</strong>
          </div>
        </div>

        <div class="detail-group">
          <p><strong>Authors:</strong> <span id="modalAuthors"></span></p>
        </div>

        <!-- Push buttons to the bottom -->
        <div class="action-buttons">
          <button onclick="viewPDF()" class="btn green">View PDF</button>
          <button onclick="confirmDownloadPDF()" class="btn light">Download</button>
          <button onclick="citePaper()" class="btn light">Cite</button>
        </div>
      </div>

      <!-- RIGHT PDF PREVIEW PANE -->
      <div class="modal-pdf">
        <!-- Moved Close Button Here -->
        <span class="close-btn" onclick="closeModal()">&times;</span>
        <embed id="modalPDF" src="" type="application/pdf" width="100%" height="100%">
      </div>

    </div>
  </div>
</div>



  <!-- Footer Section -->
 
  <footer class="footer-section">
  <div class="footer-main">
    <div class="footer-branding">
      <div class="footer-branding-row">
        <img src="pictures/researchgatelogo2.png" alt="Research Unlocked Logo" class="footer-logo" />
        <div class="footer-site-info">
          <h2>Research Unlocked</h2>
          <p>Capstone & Thesis E-Library of PLP</p>
        </div>
      </div>

    <p class="footer-description">
    This platform serves as a centralized digital <span class="hover-animate">archive</span> for <span class="hover-animate">research outputs</span> from <span class="hover-animate">different colleges</span> in PLP. Browse, access, and learn from past works to guide your <span class="hover-animate">research</span> journey.</p>

    </div>

    <div class="footer-links">
      <div class="footer-column">
        <h4>Explore</h4>
        <a href="homepage.php">HOME</a>
        <a href="research.php">BROWSE</a>
        <a href="about.php">ABOUT</a>
      </div>
      <div class="footer-column">
        <h4>Support</h4>
        <a href="help.php">HELP CENTER</a>
        <a href="faq.php">FAQs</a>
        <a href="about.php">CONTACT</a>
      </div>
      <div class="footer-column">
        <h4>Legal</h4>
        <a href="#terms">TERMS OF SERVICE</a>
        <a href="#privacy">PRIVACY POLICY</a>
      </div>
    </div>
  </div>

  <div class="footer-divider"></div>

  <div class="footer-bottom">
    <p>© 2025 BSIT 3B – Pamantasan ng Lungsod ng Pasig | All rights reserved.</p>
  </div>
</footer>



 
<!-- Only one events-grid, already rendered above. Remove duplicate. -->


  <script>
    window.browseSuggest = <?= json_encode($suggestPayload, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
  </script>

  <script>
    function scrollToFilters() {
      const sidebar = document.querySelector('.sidebar');
      if (sidebar && typeof sidebar.scrollIntoView === 'function') {
        sidebar.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }

    function showDialog(id) {
      document.getElementById(id).showModal();
    }

    function closeDialog(id) {
      document.getElementById(id).close();
    }

    // Open PDF in new tab (full screen effect)
    function viewPDF() {
      const pdfUrl = document.getElementById('modalPDF').src;
      window.open(pdfUrl, '_blank');
    }

       window.addEventListener('scroll', function () {
  const navbar = document.querySelector('.navbar');
  const logo = document.getElementById('navbar-logo');

  if (window.scrollY > 10) {
    navbar.classList.add('scrolled');
    logo.src = "pictures/researchgatelogo1.png"; // logo when scrolled
  } else {
    navbar.classList.remove('scrolled');
    logo.src = "pictures/researchgatelogo3.png"; // logo when at top
  }
});


  const organizerGroup = document.getElementById('organizer-group');

  organizerGroup.addEventListener('click', e => {
    const clickedSummary = e.target.closest('summary');
    const clickedItem = e.target.closest('.organizer-item');

    if (clickedSummary && clickedItem) {
      // Close all others
      document.querySelectorAll('.organizer-item').forEach(item => {
        if (item !== clickedItem) {
          item.removeAttribute('open');
          item.classList.remove('active');
        }
      });

      // Toggle current
      clickedItem.classList.add('active');
    }
  });

  // Reuse logic for single-select lists (e.g. Date)
  document.querySelectorAll('.selectable-list').forEach(group => {
    group.addEventListener('click', e => {
      if (e.target.tagName === 'LI') {
        [...group.children].forEach(li => li.classList.remove('active'));
        e.target.classList.add('active');
      }
    });
  });

  // Reuse logic for Venue buttons
  document.querySelectorAll('.selectable-buttons').forEach(group => {
    group.addEventListener('click', e => {
      if (e.target.tagName === 'BUTTON') {
        [...group.children].forEach(btn => btn.classList.remove('active'));
        e.target.classList.add('active');
      }
    });
  });
 
        document.addEventListener("DOMContentLoaded", () => {
    const links = document.querySelectorAll("a[href]:not([target='_blank']):not([href^='#'])");

    links.forEach(link => {
      link.addEventListener("click", function (e) {
        e.preventDefault();
        const target = this.getAttribute("href");
        
        // Start fade overlay
        const overlay = document.getElementById("fade-overlay");
        overlay.style.opacity = "1";

        // Delay navigation after fade
        setTimeout(() => {
          window.location.href = target;
        }, 500); // Match transition duration
      });
    });
  });


  document.querySelectorAll('.program-list').forEach(list => {
    const items = list.querySelectorAll('li');

    items.forEach(item => {
      item.addEventListener('click', () => {
        // If already active, unselect
        if (item.classList.contains('active')) {
          item.classList.remove('active');
        } else {
          // Remove others, then select
          items.forEach(i => i.classList.remove('active'));
          item.classList.add('active');
        }
      });
    });
  });



    window.addEventListener("load", () => {
    const overlay = document.getElementById("fade-overlay");
    overlay.style.opacity = "0";
  });

      const modal = document.getElementById('policyModal');
  const links = document.querySelectorAll('a[href="#terms"], a[href="#privacy"]');
  const closeBtn = document.querySelector('.close-btn');

  links.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      modal.style.display = 'block';
    });
  });

  closeBtn.addEventListener('click', function() {
    modal.style.display = 'none';
  });

  window.addEventListener('click', function(e) {
    if (e.target === modal) {
      modal.style.display = 'none';
    }
  });


  const rangeInput = document.querySelectorAll(".range-input input"),
  yearInput = document.querySelectorAll(".price-input input"),
  range = document.querySelector(".slider .progress");

let yearGap = 1; // Minimum allowed gap between years

// When numeric year input boxes are manually changed
yearInput.forEach((input) => {
  input.addEventListener("input", (e) => {
    let fromYear = parseInt(yearInput[0].value),
        toYear = parseInt(yearInput[1].value);

    if (toYear - fromYear >= yearGap && toYear <= parseInt(rangeInput[1].max)) {
      if (e.target.classList.contains("input-min")) {
        rangeInput[0].value = fromYear;
      } else {
        rangeInput[1].value = toYear;
      }
      updateSliderTrack();
    }
  });
});

// When range sliders are dragged
rangeInput.forEach((input) => {
  input.addEventListener("input", (e) => {
    let fromVal = parseInt(rangeInput[0].value),
        toVal = parseInt(rangeInput[1].value);

    if (toVal - fromVal < yearGap) {
      if (e.target.classList.contains("range-min")) {
        rangeInput[0].value = toVal - yearGap;
      } else {
        rangeInput[1].value = fromVal + yearGap;
      }
    } else {
      yearInput[0].value = fromVal;
      yearInput[1].value = toVal;
      updateSliderTrack();
    }
  });
});

function updateSliderTrack() {
  const min = parseInt(rangeInput[0].min),
        max = parseInt(rangeInput[0].max),
        fromVal = parseInt(rangeInput[0].value),
        toVal = parseInt(rangeInput[1].value);

  const percentFrom = ((fromVal - min) / (max - min)) * 100;
  const percentTo = ((toVal - min) / (max - min)) * 100;

  range.style.left = percentFrom + "%";
  range.style.width = (percentTo - percentFrom) + "%";
}


const browseSuggestState = window.browseSuggest || { recommended: [], results: [], recent: '' };

function normalizeSuggestion(item, fallbackSubtitle = 'Search', iconHtml = '<i class=\"fa fa-search\"></i>') {
  return {
    title: (item.title || item || 'Untitled').toString(),
    subtitle: (item.subtitle || fallbackSubtitle || '').toString(),
    icon: iconHtml,
  };
}

function localRecommendedSuggestions() {
  return (browseSuggestState.recommended || []).map(row =>
    normalizeSuggestion(
      {
        title: row.title ?? 'Untitled',
        subtitle: row.subtitle ?? 'Recommended for you',
      },
      'Recommended for you',
      '<i class=\"fa fa-star\"></i>'
    )
  );
}

function localFilteredSuggestions(query) {
  const needle = (query || '').toLowerCase();
  if (!needle) return [];
  return (browseSuggestState.results || [])
    .filter(row => {
      const haystack = [row.title, row.subtitle, row.program, row.college]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    })
    .slice(0, 8)
    .map(row =>
      normalizeSuggestion(
        {
          title: row.title ?? 'Untitled',
          subtitle: row.subtitle ?? 'Library catalog',
        },
        'Library catalog'
      )
    );
}

function renderSuggestionEntries(entries) {
  const list = document.getElementById('suggestionsList');
  const input = document.getElementById('searchInput');
  if (!list || !input) return false;
  if (!entries || !entries.length) {
    list.innerHTML = '';
    list.style.display = 'none';
    return false;
  }
  const esc = str => String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  list.innerHTML = '';
  list.style.display = 'block';
  entries.forEach((entry, index) => {
    const li = document.createElement('li');
    li.className = 'suggestion-item' + (index === 0 ? ' active-first' : '');
    li.dataset.value = entry.title;

    const icon = document.createElement('div');
    icon.className = 'suggestion-icon';
    icon.innerHTML = entry.icon || '<i class=\"fa fa-search\"></i>';

    const texts = document.createElement('div');
    texts.className = 'suggestion-texts';
    const p = document.createElement('div');
    p.className = 'primary';
    p.innerHTML = esc(entry.title || 'Untitled');
    const s = document.createElement('div');
    s.className = 'secondary';
    s.innerHTML = esc(entry.subtitle || '');

    texts.appendChild(p);
    texts.appendChild(s);
    li.appendChild(icon);
    li.appendChild(texts);

    li.addEventListener('click', () => {
      input.value = entry.title || '';
      list.innerHTML = '';
      list.style.display = 'none';
      input.focus();
    });

    list.appendChild(li);
  });
  return true;
}

let autocompleteTimer = null;
const AUTOCOMPLETE_DELAY = 220;

async function autocompleteSearch() {
  const input = document.getElementById('searchInput');
  if (!input) return;
  const q = (input.value || '').trim();

  if (autocompleteTimer) clearTimeout(autocompleteTimer);

  if (!q && renderSuggestionEntries(localRecommendedSuggestions())) {
    return;
  }

  autocompleteTimer = setTimeout(async () => {
    const list = document.getElementById('suggestionsList');
    if (!list) return;

    try {
      // Try multiple candidate endpoints in case the app is hosted under a subpath
      const data = await tryAutocomplete(q);
      if (!Array.isArray(data) || data.length === 0) {
        if (renderSuggestionEntries(localFilteredSuggestions(q))) return;
        list.innerHTML = '';
        list.style.display = 'none';
        return;
      }

      const normalized = data.slice(0, 10).map(raw => {
        // Accept both string responses (legacy) and structured objects {title, subtitle, tc_id}
        if (raw && typeof raw === 'object') {
          return normalizeSuggestion({ title: raw.title || raw.label || '', subtitle: raw.subtitle || '', tc_id: raw.tc_id }, 'Search');
        }
        let primary = (raw || '').toString();
        let secondary = 'Search';
        if (primary.indexOf(' — ') !== -1) {
          const parts = primary.split(' — ');
          primary = parts[0];
          secondary = 'Search — ' + parts.slice(1).join(' — ');
        } else if (primary.indexOf(' - ') !== -1) {
          const parts = primary.split(' - ');
          primary = parts[0];
          secondary = 'Search - ' + parts.slice(1).join(' - ');
        }
        return normalizeSuggestion({ title: primary, subtitle: secondary }, 'Search');
      });

      renderSuggestionEntries(normalized);
    } catch (err) {
      if (renderSuggestionEntries(localFilteredSuggestions(q))) return;
      const listEl = document.getElementById('suggestionsList');
      if (listEl) {
        listEl.innerHTML = '';
        listEl.style.display = 'none';
      }
    }
  }, AUTOCOMPLETE_DELAY);
}

// Try several candidate autocomplete endpoints (helps when the app is served from a subpath)
async function tryAutocomplete(q) {
  const encoded = encodeURIComponent(q);
  const origin = window.location.origin.replace(/\/$/, '');
  // Directory portion of the current path (e.g. '' for root or '/subdir')
  let pathDir = (window.location.pathname || '/').replace(/\/[^/]*$/, '');
  pathDir = pathDir.replace(/^\/+|\/+$/g, ''); // trim leading/trailing slashes
  // dirPrefix will be empty for root, or like '/subdir' for subfolders
  const dirPrefix = pathDir === '' ? '' : ('/' + pathDir);

  const candidates = [
    // origin + current directory (handles sites served from a subfolder)
    `${origin}${dirPrefix}/autocomplete.php?q=${encoded}`,
    // origin root
    `${origin}/autocomplete.php?q=${encoded}`,
    // site-relative directory (no doubling of leading slash when root)
    `${dirPrefix}/autocomplete.php?q=${encoded}`,
    // relative to current document
    `autocomplete.php?q=${encoded}`
  ];

  // Deduplicate candidates while preserving order
  const seen = new Set();
  const uniqCandidates = [];
  for (const c of candidates) {
    if (!seen.has(c)) {
      seen.add(c);
      uniqCandidates.push(c);
    }
  }

  for (const url of uniqCandidates) {
    try {
      const resp = await fetch(url, { cache: 'no-cache', credentials: 'same-origin' });
      console.debug('autocomplete: tried', url, 'status', resp.status);
      if (!resp.ok) {
        try { const text = await resp.text(); console.debug('autocomplete: body for ' + url, text.slice(0, 300)); } catch (e) {}
        continue;
      }
      let data;
      try {
        data = await resp.json();
      } catch (e) {
        try { const text = await resp.text(); console.warn('autocomplete: invalid JSON from', url, text.slice(0, 500)); } catch (e2) {}
        continue;
      }
      if (Array.isArray(data)) return data;
      if (data && data.error) {
        console.warn('autocomplete: server error', data.error);
      }
    } catch (e) {
      console.debug('autocomplete: fetch error for', url, e && e.message ? e.message : e);
      continue;
    }
  }
  return [];
}
function openModal(title, authors, college, year, tc_id, currentViews, cardElem) {
  const fallback = (value, placeholder = 'Not specified') => {
    if (typeof value !== 'string') return placeholder;
    const trimmed = value.trim();
    return trimmed !== '' ? trimmed : placeholder;
  };
  const formatViews = (value) => {
    const num = Number(value) || 0;
    const formatted = num.toLocaleString();
    return `${formatted} ${num === 1 ? 'view' : 'views'}`;
  };
  const updateCardViews = (text) => {
    if (!cardElem) return;
    const chip = cardElem.querySelector('.card-views-count');
    if (chip) chip.innerText = text;
  };
  const tcField = document.getElementById("currentTcId");
  if (tcField) tcField.value = tc_id;
  document.getElementById("modalTitle").innerText = fallback(title, 'Untitled manuscript');
  document.getElementById("modalAuthors").innerText = fallback(authors, 'Unknown authors');
  document.getElementById("modalCollege").innerText = fallback(college, 'College unspecified');
  document.getElementById("modalYear").innerText = fallback(year, 'Unspecified');
  const dataset = (cardElem && cardElem.dataset) ? cardElem.dataset : {};
  const programEl = document.getElementById("modalProgram");
  if (programEl) {
    programEl.textContent = fallback(dataset.program || '', 'Program unspecified');
  }
  const projectEl = document.getElementById("modalProject");
  if (projectEl) {
    projectEl.textContent = fallback(dataset.project || '', 'Research');
  }
  const contextEl = document.getElementById("modalContext");
  if (contextEl) {
    contextEl.textContent = fallback(dataset.context || '', 'Selected from Research Unlocked.');
  }
  fetch('serve_pdf.php?tc_id=' + encodeURIComponent(tc_id))
    .then(response => response.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob);
      document.getElementById("modalPDF").src = url;
      const modal = document.getElementById("thesisModal");
      modal.style.display = "flex";
      modal.scrollTop = 0; 
    });

  // Optimistically update view count in modal
  let viewCountElem = document.getElementById("viewCount");
  const optimistic = formatViews(currentViews + 1);
  if (viewCountElem) viewCountElem.innerText = optimistic;
  updateCardViews(optimistic);
  // AJAX call to update views in DB
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'update_views.php', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      try {
        var resp = JSON.parse(xhr.responseText);
        if (resp.success && resp.views !== undefined) {
          const label = formatViews(resp.views);
          if (viewCountElem) viewCountElem.innerText = label;
          updateCardViews(label);
        }
      } catch (e) {}
    }
  };
  xhr.send('tc_id=' + encodeURIComponent(tc_id));
  // --- Record thesis view in student_reads via AJAX ---
  var xhr2 = new XMLHttpRequest();
  xhr2.open('POST', window.location.pathname, true);
  xhr2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr2.send('tc_id=' + encodeURIComponent(tc_id));
}

      function closeModal() {
        const modal = document.getElementById("thesisModal");
        modal.style.display = "none";
        modal.scrollTop = 0;
        document.getElementById("modalPDF").src = "";
      }
    document.querySelector(".search-button").addEventListener("click", function () {
  const input = document.getElementById("searchInput");
  const filter = document.querySelector(".search-filter");
  const value = input.value.trim();
  const type = filter ? filter.value.toLowerCase() : 'keyword';
  let url = "browse.php";
  if (value !== "") {
    url += "?q=" + encodeURIComponent(value) + "&f=" + encodeURIComponent(type);
  }
  window.location.href = url;
});

// Apply Filters button logic
document.querySelector('.apply-filter').addEventListener('click', function () {
  // Get year range
  const yearMin = document.querySelector('.input-min').value;
  const yearMax = document.querySelector('.input-max').value;
  // Get selected college/program (first active li in .program-list)
  let college = '';
  let program = '';
  const activeLi = document.querySelector('.program-list li.active');
  if (activeLi) {
    program = activeLi.textContent.trim();
    // Find the closest organizer label (college)
    const organizer = activeLi.closest('.organizer-item');
    if (organizer) {
      const label = organizer.querySelector('.organizer-label');
      if (label) college = label.textContent.trim();
    }
  }
  // Build URL
  let url = 'browse.php?';
  const params = [];
  if (yearMin) params.push('year_min=' + encodeURIComponent(yearMin));
  if (yearMax) params.push('year_max=' + encodeURIComponent(yearMax));
  if (college) params.push('college=' + encodeURIComponent(college));
  if (program) params.push('program=' + encodeURIComponent(program));
  if (params.length > 0) url += params.join('&');
  else url = 'browse.php';
  window.location.href = url;
});




setInterval(() => {
  fetch('fetch_notifications.php')
    .then(res => res.json())
    .then(data => {
      const wrapper = document.querySelector('.icon-wrapper');
      const existingDot = document.querySelector('.notif-dot');

      if (data.unread > 0) {
        if (!existingDot) {
          const span = document.createElement('span');
          span.classList.add('notif-dot');
          wrapper.appendChild(span);
        }
      } else {
        if (existingDot) existingDot.remove();
      }
    });
}, 10000); // Check every 10 seconds



  <?php
  // Serve the PDF directly if requested
  if (isset($_GET['pdf_id'])) {
    $id = $_GET['pdf_id'];
    $stmt = $conn->prepare("SELECT file FROM thesis_capstone WHERE tc_id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($file);
    if ($stmt->fetch()) {
      $filepath = __DIR__ . '/' . $file;
      if (file_exists($filepath)) {
        header("Content-Type: application/pdf");
        readfile($filepath);
        exit;
      } else {
        http_response_code(404);
        echo "PDF not found.";
        exit;
      }
    }
  }
  ?>
 // Confirmation dialog before downloading PDF
function confirmDownloadPDF() {
  if (confirm('Do you want to download this PDF?')) {
    downloadPDF();
  }
}

// Actually download the currently viewed PDF in the modal
function downloadPDF() {
  var pdfEmbed = document.getElementById('modalPDF');
  var pdfUrl = pdfEmbed ? pdfEmbed.src : null;
  if (pdfUrl) {
    var a = document.createElement('a');
    a.href = pdfUrl;
    a.download = 'download.pdf'; // You can customize the filename if you want
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } else {
    alert('No PDF loaded to download.');
  }
}
 
  </script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script>
  (function () {
    if (!window['pdfjsLib']) return;

    pdfjsLib.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

    const rendered = new WeakSet();

    async function renderThumb(imgEl) {
      if (rendered.has(imgEl)) return;

      const url = imgEl.getAttribute('data-pdf');
      if (!url) return;

      // Find the visible width/height of the hero box
      const hero = imgEl.closest('.pdf-hero') || imgEl.parentElement;
      const heroRect = hero.getBoundingClientRect();
      const cssWidth = Math.max( heroRect.width || hero.clientWidth || 320, 320 );
      const cssHeight = Math.round(cssWidth * 9 / 16);

      // render sharper on HiDPI screens but cap for perf
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const targetWidth = Math.floor(cssWidth * dpr);
      const targetHeight = Math.floor(cssHeight * dpr);

      try {
        const pdf = await pdfjsLib.getDocument({ url }).promise;
        const page = await pdf.getPage(1);

        // base viewport at scale 1
        const base = page.getViewport({ scale: 1 });
        const scale = Math.min(targetWidth / base.width, targetHeight / base.height);

        const viewport = page.getViewport({ scale });

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d', { willReadFrequently: false });

        // white background to avoid transparent edges
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, viewport.width, viewport.height);

        canvas.width = Math.ceil(viewport.width);
        canvas.height = Math.ceil(viewport.height);

        await page.render({ canvasContext: ctx, viewport }).promise;

        // convert to blob url (more memory-friendly than big data URLs)
        canvas.toBlob(function(blob) {
          if (!blob) throw new Error('Canvas toBlob failed');
          const blobUrl = URL.createObjectURL(blob);

          // set final image, drop skeleton shimmer
          imgEl.src = blobUrl;
          imgEl.classList.remove('skeleton');
          rendered.add(imgEl);

          // revoke when image has been applied for a bit
          setTimeout(() => URL.revokeObjectURL(blobUrl), 8000);
        }, 'image/jpeg', 0.85);

      } catch (e) {
        // leave placeholder but style as failed (muted badge)
        imgEl.classList.remove('skeleton');
        imgEl.classList.add('thumb-failed');
        // console.warn('PDF thumb render failed:', e);
      }
    }

    // Lazy render when visible
    const io = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          renderThumb(entry.target);
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '200px 0px', threshold: 0.01 });

    // Observe initial thumbs
    document.querySelectorAll('img.pdf-thumb[data-pdf]').forEach(img => io.observe(img));

    // If you inject more cards later, call this to observe new ones
    window.observePdfThumbs = function () {
      document.querySelectorAll('img.pdf-thumb[data-pdf]').forEach(img => {
        if (!rendered.has(img)) io.observe(img);
      });
    };

    // Re-render on resize for first-load cards (optional; guarded)
    let resizeT;
    window.addEventListener('resize', () => {
      clearTimeout(resizeT);
      resizeT = setTimeout(() => {
        document.querySelectorAll('img.pdf-thumb[data-pdf]').forEach(img => {
          if (!rendered.has(img)) return; // already rendered
          // if layout drastically changed (e.g., grid wrap), we could re-render
          // but to keep it simple, only render those not yet done
        });
      }, 150);
    });
  })();

  // Apply Filters button logic
document.querySelector('.apply-filter').addEventListener('click', function (e) {
  e.preventDefault();

  const yearMin = document.querySelector('.input-min')?.value || '';
  const yearMax = document.querySelector('.input-max')?.value || '';

  // read the hidden fields that other UI already sets
  const projectType = document.getElementById('selectedProjectType')?.value || 'all';
  const programId = document.getElementById('selectedProgramId')?.value || '';

  const params = new URLSearchParams();

  if (yearMin) params.set('year_min', yearMin);
  if (yearMax) params.set('year_max', yearMax);

  // Include project_type even if 'all' (backend expects it)
  params.set('project_type', projectType);

  if (programId) {
    // Prefer strict ID filter when present
    params.set('program_id', programId);
  } else {
    // Optional: fallback to name if you want; otherwise omit.
    const activeLi = document.querySelector('.program-list li.active');
    if (activeLi) {
      // we could set program=activeLi.textContent but sticking to IDs is cleaner
      params.set('program', activeLi.textContent.trim());
    }
  }

  window.location.href = 'browse.php' + (params.toString() ? ('?' + params.toString()) : '');
});

document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.program-list li').forEach(li => {
    li.addEventListener('click', function() {
      document.querySelectorAll('.program-list li').forEach(item => item.classList.remove('active'));
      this.classList.add('active');
      document.getElementById('selectedProgramId').value = this.getAttribute('data-value') || '';
    });
  });
});


document.addEventListener('DOMContentLoaded', function() {
  const qs = new URLSearchParams(window.location.search);
  const minY = parseInt(qs.get('year_min') || document.querySelector('.input-min')?.value || '2000', 10);
  const maxY = parseInt(qs.get('year_max') || document.querySelector('.input-max')?.value || '2025', 10);

  const rMin = document.querySelector('.range-min');
  const rMax = document.querySelector('.range-max');
  const iMin = document.querySelector('.input-min');
  const iMax = document.querySelector('.input-max');

  if (rMin && rMax && iMin && iMax) {
    rMin.value = iMin.value = minY;
    rMax.value = iMax.value = maxY;

    // redraw progress bar
    (function updateSliderTrack() {
      const range = document.querySelector('.slider .progress');
      const min = parseInt(rMin.min, 10);
      const max = parseInt(rMin.max, 10);
      const percentFrom = ((minY - min) / (max - min)) * 100;
      const percentTo = ((maxY - min) / (max - min)) * 100;
      range.style.left = percentFrom + '%';
      range.style.width = (percentTo - percentFrom) + '%';
    })();
  }
});


const LS_KEY = "ru:browse:filters";

function readParams() {
  const qs = new URLSearchParams(window.location.search);
  return {
    q: qs.get("q") || "",
    f: (qs.get("f") || "keyword").toLowerCase(),
    project_type: qs.get("project_type") || "all",
    program_id: qs.get("program_id") || "",
    college: qs.get("college") || "",
    program: qs.get("program") || "",
    year_min: qs.get("year_min") || "",
    year_max: qs.get("year_max") || ""
  };
}

function readLocal() {
  try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; }
  catch { return {}; }
}

function saveLocal(state) {
  localStorage.setItem(LS_KEY, JSON.stringify(state));
}

function currentStateFromUI() {
  return {
    q: document.getElementById("searchInput")?.value?.trim() || "",
    f: (document.querySelector(".search-filter")?.value || "Keyword").toLowerCase(),
    project_type: document.getElementById("selectedProjectType")?.value || "all",
    program_id: document.getElementById("selectedProgramId")?.value || "",
    // college/program names are optional (you mostly use ids now)
    year_min: document.querySelector(".input-min")?.value || "",
    year_max: document.querySelector(".input-max")?.value || ""
  };
}

/* set UI widgets from a state object */
function applyStateToUI(state) {
  // search box + filter dropdown
  const si = document.getElementById("searchInput");
  if (si && state.q !== undefined) si.value = state.q;

  const sf = document.querySelector(".search-filter");
  if (sf && state.f) {
    const label = state.f.charAt(0).toUpperCase() + state.f.slice(1);
    [...sf.options].forEach(o => { if (o.text.toLowerCase() === label.toLowerCase()) sf.value = o.text; });
  }

  // year range + slider track
  const iMin = document.querySelector(".input-min");
  const iMax = document.querySelector(".input-max");
  const rMin = document.querySelector(".range-min");
  const rMax = document.querySelector(".range-max");
  if (iMin && iMax && rMin && rMax) {
    if (state.year_min) { iMin.value = state.year_min; rMin.value = state.year_min; }
    if (state.year_max) { iMax.value = state.year_max; rMax.value = state.year_max; }
    const min = parseInt(rMin.min || "2000", 10);
    const max = parseInt(rMin.max || "2025", 10);
    const from = parseInt(rMin.value, 10);
    const to = parseInt(rMax.value, 10);
    const progress = document.querySelector(".slider .progress");
    if (progress) {
      const pf = ((from - min) / (max - min)) * 100;
      const pt = ((to - min) / (max - min)) * 100;
      progress.style.left = pf + "%";
      progress.style.width = (pt - pf) + "%";
    }
  }

  // project type buttons + hidden input
  const ptHidden = document.getElementById("selectedProjectType");
  if (ptHidden && state.project_type) {
    ptHidden.value = state.project_type;
    document.querySelectorAll('.venue-buttons button').forEach(b => {
      b.classList.toggle("active", (b.getAttribute("data-value") || "") === state.project_type);
    });
  }

  // program id selection + highlight in nested list
  const pidHidden = document.getElementById("selectedProgramId");
  if (pidHidden) {
    pidHidden.value = state.program_id || "";
  }
  if (state.program_id) {
    // mark active li
    const li = document.querySelector(`.program-list li[data-value="${CSS.escape(state.program_id)}"]`);
    if (li) {
      document.querySelectorAll(".program-list li").forEach(x => x.classList.remove("active"));
      li.classList.add("active");
      // open its parent <details>
      const organizer = li.closest(".organizer-item");
      if (organizer) organizer.setAttribute("open", "");
    }
  }
}

/* write to localStorage whenever the user changes something */
function wireSavers() {
  const save = () => saveLocal(currentStateFromUI());

  // search input + dropdown + button
  const si = document.getElementById("searchInput");
  const sf = document.querySelector(".search-filter");
  if (si) si.addEventListener("input", save);
  if (sf) sf.addEventListener("change", save);

  // project type buttons
  document.querySelectorAll(".venue-buttons button").forEach(b => {
    b.addEventListener("click", save);
  });

  // year inputs + sliders
  const iMin = document.querySelector(".input-min");
  const iMax = document.querySelector(".input-max");
  const rMin = document.querySelector(".range-min");
  const rMax = document.querySelector(".range-max");
  [iMin, iMax, rMin, rMax].forEach(el => el && el.addEventListener("input", save));

  // program list (sets hidden program_id in your existing code)
  document.querySelectorAll(".program-list li").forEach(li => {
    li.addEventListener("click", () => {
      const pidHidden = document.getElementById("selectedProgramId");
      if (pidHidden) pidHidden.value = li.getAttribute("data-value") || "";
      save();
    });
  });

  // Apply Filters: also store immediately before navigating
  const applyBtn = document.querySelector(".apply-filter");
  if (applyBtn) applyBtn.addEventListener("click", () => saveLocal(currentStateFromUI()));

  // Find it now (search) — persist before changing URL
  const findNowBtn = document.getElementById("findNowBtn");
  if (findNowBtn) {
    findNowBtn.addEventListener("click", () => {
      const state = currentStateFromUI();
      saveLocal(state);
      // Build query params including q and f so backend runs search
      const params = new URLSearchParams();
      if (state.q) params.set('q', state.q);
      if (state.f) params.set('f', state.f);
      if (state.project_type) params.set('project_type', state.project_type);
      if (state.program_id) params.set('program_id', state.program_id);
      if (state.year_min) params.set('year_min', state.year_min);
      if (state.year_max) params.set('year_max', state.year_max);
      window.location.href = 'browse.php' + (params.toString() ? ('?' + params.toString()) : '');
    });
  }
}

/* INIT: prefer URL params; fallback to localStorage */
document.addEventListener("DOMContentLoaded", () => {
  const fromParams = readParams();
  const hasParams = Object.values(fromParams).some(v => v && String(v).trim() !== "");
  const fromLocal = readLocal();

  const state = hasParams ? { ...fromLocal, ...fromParams } : { ...fromParams, ...fromLocal };
  applyStateToUI(state);

  // keep localStorage in sync with whatever is shown
  saveLocal(state);
  wireSavers();
});

let _CITE_CACHE = {};       // cache per tc_id
let _CITE_STYLE = 'APA';    // default tab

function openCiteFromModal() {
  const tc_id = document.getElementById('currentTcId')?.value || '';
  if (tc_id) openCite(null, tc_id);
}

const CITE_BASE = new URL('cite.php', window.location.href);

function citeUrl(tc_id) {
  const url = new URL(CITE_BASE.toString());
  url.searchParams.set('tc_id', tc_id);
  return url.toString();
}

function citePaper() {
  const tc_id = document.getElementById('currentTcId')?.value || '';
  if (!tc_id) {
    alert('Open a thesis record first to generate citations.');
    return;
  }
  openCite(null, tc_id);
}

function openCite(ev, tc_id) {
  if (ev) ev.stopPropagation();
  const modal = document.getElementById('citeModal');
  modal.style.display = 'flex';
  const textarea = document.getElementById('citeText');
  if (textarea) textarea.value = 'Generating citation...';

  if (_CITE_CACHE[tc_id]) {
    setCiteData(_CITE_CACHE[tc_id]);
    return;
  }

  const url = citeUrl(tc_id);

  fetch(url, {
    method: 'GET',
    cache: 'no-store',
    credentials: 'same-origin', // send PHP session cookie
  })
  .then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`);
    return r.text();
  })
  .then(t => {
    let j;
    try { j = JSON.parse(t); } catch (e) {
      const plain = t.replace(/<[^>]+>/g, '').slice(0, 500);
      throw new Error(plain || 'Non-JSON response');
    }
    if (!j.ok) throw new Error(j.error || 'Citation error');
    _CITE_CACHE[tc_id] = j.formats;
    setCiteData(j.formats);
  })
  .catch(err => {
    const out = document.getElementById('citeText');
    out.value = `Citation unavailable:\n${err.message}`;
    // Extra hints in console
    console.error('[cite] fetch failed', { url, err, online: navigator.onLine });
  });
}


function setCiteData(formats) {
  // Make APA the default if available
  const initial = formats[_CITE_STYLE] ? _CITE_STYLE :
                  (formats['APA'] ? 'APA' : Object.keys(formats)[0]);
  _CITE_STYLE = initial;
  document.querySelectorAll('#citeModal .btn.light[data-style]').forEach(b=>{
    b.classList.toggle('green', b.getAttribute('data-style') === _CITE_STYLE);
  });
  document.getElementById('citeText').value = formats[_CITE_STYLE] || '';
}

function setCiteTab(btn) {
  const style = btn.getAttribute('data-style');
  _CITE_STYLE = style;
  // Toggle selected styling
  document.querySelectorAll('#citeModal .btn.light[data-style]').forEach(b=>{
    b.classList.toggle('green', b === btn);
  });

  const textEl = document.getElementById('citeText');
  const tc_id = document.getElementById('currentTcId')?.value || '';
  const formats = _CITE_CACHE[tc_id] || {};
  textEl.value = formats[style] || '';
}

function closeCite() {
  const modal = document.getElementById('citeModal');
  modal.style.display = 'none';
}

function copyCitation() {
  const t = document.getElementById('citeText');
  t.select();
  t.setSelectionRange(0, 99999);
  document.execCommand('copy');
  // tiny feedback
  const old = t.value;
  t.value = old + '\n\n[Copied to clipboard]';
  setTimeout(()=>{ t.value = old; }, 700);
}

function downloadBib() {
  // Only makes sense for BibTeX; otherwise we can still download as .txt
  const txt = document.getElementById('citeText').value || '';
  const isBib = _CITE_STYLE === 'BibTeX';
  const blob = new Blob([txt], {type: 'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = isBib ? 'citation.bib' : 'citation.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
function promptArchive(tc_id) {
  const reason = prompt('Reason for archiving (optional):', '');
  if (reason === null) return;
  fetch(window.location.pathname, {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: new URLSearchParams({ action: 'archive_request', tc_id, reason })
  }).then(r=>r.json()).then(j=>{
    alert(j.message || (j.ok ? 'Request submitted.' : (j.error || 'Failed')));
  }).catch(()=>alert('Network error'));
}

function promptReport(tc_id) {
  const reason = prompt('Describe the issue (plagiarism, wrong file, offensive, etc.):', '');
  if (reason === null || reason.trim()==='') return;
  const severity = prompt('Severity: Low / Medium / High', 'Medium') || 'Medium';
  fetch(window.location.pathname, {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: new URLSearchParams({ action: 'report_thesis', tc_id, reason, severity })
  }).then(r=>r.json()).then(j=>{
    alert(j.message || (j.ok ? 'Report submitted.' : (j.error || 'Failed')));
  }).catch(()=>alert('Network error'));
}
</script>



</body>
</html>

