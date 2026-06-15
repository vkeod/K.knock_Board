<?php

declare(strict_types=1);

define('APP_NAME', 'Knock Boards');
define('APP_ROOT', dirname(__DIR__));
define('UPLOAD_DIR', getenv('UPLOAD_DIR') ?: '/var/www/uploads');
define('MAX_UPLOAD_BYTES', 5 * 1024 * 1024);
define('MAX_UPLOAD_FILES_PER_REQUEST', 10);
define('MAX_ATTACHMENTS_PER_POST', 10);
define('MAX_ATTACHMENT_BYTES_PER_POST', 20 * 1024 * 1024);
define('MAX_UPLOAD_NAME_CHARS', 180);
define('SESSION_IDLE_SECONDS', 30 * 60);
define('SESSION_ABSOLUTE_SECONDS', 8 * 60 * 60);
define('SESSION_REGENERATE_SECONDS', 10 * 60);
define('MAX_TITLE_CHARS', 200);
define('MAX_BODY_CHARS', 20000);
define('MAX_BODY_BYTES', 60000);
define('MAX_SEARCH_CHARS', 100);
define('MIN_PASSWORD_LENGTH', 10);
define('MAX_PASSWORD_LENGTH', 128);
define('MAX_USERNAME_CHARS', 30);
define('FILE_DOWNLOAD_TOKEN_TTL_SECONDS', 10 * 60);
define('SECURITY_EVENT_RETENTION_DAYS', 7);
define('SECURITY_EVENT_MAX_ROWS', 20000);
define('SECURITY_EVENT_CLEANUP_INTERVAL_SECONDS', 5 * 60);

class HttpException extends RuntimeException
{
    public function __construct(public int $status, string $message = '')
    {
        parent::__construct($message !== '' ? $message : status_text($status));
    }
}

date_default_timezone_set('Asia/Seoul');

if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
session_name('knock_session');

enforce_allowed_host();
$secureCookie = is_https_request();
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $secureCookie,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
enforce_session_lifetime();

header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
if ($secureCookie) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

function db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $name = getenv('DB_NAME') ?: 'board_app';
    $user = getenv('DB_USER') ?: 'board_user';
    $pass = required_env('DB_PASS');
    $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";

    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

function required_env(string $key): string
{
    $value = getenv($key);
    if (!is_string($value) || $value === '') {
        throw new RuntimeException("Missing required environment variable: {$key}");
    }

    return $value;
}

function app_secret(): string
{
    static $secret = null;

    if ($secret !== null) {
        return $secret;
    }

    $secret = (string) getenv('APP_SECRET');
    if (valid_config_secret($secret)) {
        return $secret;
    }

    ensure_app_settings_table();
    $stmt = db()->prepare('SELECT setting_value FROM app_settings WHERE setting_key = ?');
    $stmt->execute(['app_secret']);
    $stored = $stmt->fetchColumn();
    if (is_string($stored) && strlen($stored) >= 64) {
        $secret = $stored;
        return $secret;
    }

    $generated = bin2hex(random_bytes(32));
    try {
        $insert = db()->prepare('INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)');
        $insert->execute(['app_secret', $generated]);
        $secret = $generated;
        return $secret;
    } catch (PDOException $exception) {
        $stmt->execute(['app_secret']);
        $stored = $stmt->fetchColumn();
        if (is_string($stored) && strlen($stored) >= 64) {
            $secret = $stored;
            return $secret;
        }

        throw $exception;
    }
}

function valid_config_secret(string $secret): bool
{
    if (strlen($secret) < 32) {
        return false;
    }

    $lower = strtolower($secret);
    foreach (['change-this', 'replace-with', 'password', 'secret', 'example'] as $weakMarker) {
        if (str_contains($lower, $weakMarker)) {
            return false;
        }
    }

    return true;
}

function ensure_app_settings_table(): void
{
    static $ready = false;

    if ($ready) {
        return;
    }

    db()->query('SELECT 1 FROM app_settings LIMIT 1');
    $ready = true;
}

function allowed_hosts(): array
{
    $hosts = (string) (getenv('APP_ALLOWED_HOSTS') ?: 'localhost:8082,127.0.0.1:8082,[::1]:8082,localhost,127.0.0.1');
    $allowed = [];

    foreach (explode(',', $hosts) as $host) {
        $normalized = normalize_host($host);
        if ($normalized !== '') {
            $allowed[] = $normalized;
        }
    }

    return array_values(array_unique($allowed));
}

function request_host(): string
{
    $host = (string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '');
    return normalize_host($host);
}

function normalize_host(string $host): string
{
    $host = strtolower(trim($host));
    if (
        $host === ''
        || str_contains($host, "\r")
        || str_contains($host, "\n")
        || str_contains($host, "\0")
        || str_contains($host, '/')
        || str_contains($host, '\\')
        || str_contains($host, '@')
        || str_contains($host, ',')
    ) {
        return '';
    }

    return $host;
}

function enforce_allowed_host(): void
{
    $host = request_host();
    $allowed = allowed_hosts();
    if ($host === '' || !in_array($host, $allowed, true)) {
        reject_early_request(400, '허용되지 않는 호스트입니다.');
    }
}

function reject_early_request(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    echo $message;
    exit;
}

function is_https_request(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    if (is_trusted_proxy_request()) {
        return forwarded_proto() === 'https';
    }

    return false;
}

function is_trusted_proxy_request(): bool
{
    if (getenv('TRUST_PROXY_HEADERS') !== '1') {
        return false;
    }

    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    if (filter_var($remote, FILTER_VALIDATE_IP) === false) {
        return false;
    }

    foreach (trusted_proxy_ips() as $trusted) {
        if (ip_matches_trusted_proxy($remote, $trusted)) {
            return true;
        }
    }

    return false;
}

function trusted_proxy_ips(): array
{
    $value = (string) (getenv('TRUSTED_PROXY_IPS') ?: '');
    $trusted = [];

    foreach (explode(',', $value) as $entry) {
        $entry = trim($entry);
        if ($entry !== '') {
            $trusted[] = $entry;
        }
    }

    return $trusted;
}

function forwarded_proto(): string
{
    $header = (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '');
    $first = strtolower(trim(explode(',', $header)[0] ?? ''));

    return in_array($first, ['http', 'https'], true) ? $first : '';
}

function enforce_session_lifetime(): void
{
    $now = time();
    $_SESSION['created_at'] ??= $now;
    $_SESSION['last_activity'] ??= $now;
    $_SESSION['last_regenerated'] ??= $now;
    $_SESSION['fingerprint'] ??= session_fingerprint();

    if (!is_string($_SESSION['fingerprint']) || !hash_equals(session_fingerprint(), $_SESSION['fingerprint'])) {
        reset_session_state($now, '세션 정보를 확인할 수 없습니다. 다시 로그인해 주세요.');
        return;
    }

    $tooOld = $now - (int) $_SESSION['created_at'] > SESSION_ABSOLUTE_SECONDS;
    $tooIdle = current_user() !== null && $now - (int) $_SESSION['last_activity'] > SESSION_IDLE_SECONDS;

    if ($tooOld || $tooIdle) {
        reset_session_state($now, '세션이 만료되었습니다. 다시 로그인해 주세요.');
        return;
    }

    if ($now - (int) $_SESSION['last_regenerated'] > SESSION_REGENERATE_SECONDS) {
        session_regenerate_id(true);
        $_SESSION['last_regenerated'] = $now;
    }

    $_SESSION['last_activity'] = $now;
}

function session_fingerprint(): string
{
    $userAgent = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
    $language = substr((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''), 0, 120);

    return signed_token('session-fingerprint', [$userAgent, $language]);
}

function reset_session_state(int $now, string $message): void
{
    $_SESSION = [];
    session_regenerate_id(true);
    $_SESSION['created_at'] = $now;
    $_SESSION['last_activity'] = $now;
    $_SESSION['last_regenerated'] = $now;
    $_SESSION['fingerprint'] = session_fingerprint();
    $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    $_SESSION['flash'][] = [
        'type' => 'error',
        'message' => $message,
    ];
}

function route_path(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    if (!is_string($path) || $path === '' || $path[0] !== '/') {
        abort_request(400, '요청 경로가 올바르지 않습니다.');
    }

    if (str_contains($path, "\0") || str_contains($path, '\\') || preg_match('/%(?:00|2f|5c)/i', $path)) {
        abort_request(400, '요청 경로가 올바르지 않습니다.');
    }

    $decoded = rawurldecode($path);
    if (
        $decoded === ''
        || $decoded[0] !== '/'
        || str_contains($decoded, "\0")
        || str_contains($decoded, '\\')
        || str_contains($decoded, '//')
        || preg_match('#(?:^|/)\.{1,2}(?:/|$)#', $decoded)
        || preg_match('/%(?:00|2f|5c)/i', $decoded)
    ) {
        abort_request(400, '요청 경로가 올바르지 않습니다.');
    }

    return $decoded;
}

function effective_method(): string
{
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if ($method === 'HEAD') {
        return 'GET';
    }

    if (!in_array($method, ['GET', 'POST'], true)) {
        abort_request(405, '허용되지 않는 메서드입니다.');
    }

    if ($method === 'POST' && isset($_POST['_method'])) {
        if (!is_string($_POST['_method'])) {
            abort_request(400, '요청 메서드가 올바르지 않습니다.');
        }
        $override = strtoupper($_POST['_method']);
        if (in_array($override, ['PUT', 'DELETE'], true)) {
            return $override;
        }
    }

    return $method;
}

function h(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['_csrf'])) {
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['_csrf'];
}

function rotate_csrf_token(): void
{
    $_SESSION['_csrf'] = bin2hex(random_bytes(32));
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . h(csrf_token()) . '">';
}

function verify_csrf(): void
{
    $token = (string) ($_POST['_csrf'] ?? '');
    if ($token === '' || !hash_equals(csrf_token(), $token)) {
        throw new HttpException(400, '요청이 만료되었거나 올바르지 않습니다. 다시 시도해 주세요.');
    }
}

function verify_same_origin(): void
{
    $expected = request_origin();
    $rawOrigin = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));
    $originPresent = $rawOrigin !== '' && strtolower($rawOrigin) !== 'null';

    if ($originPresent) {
        $origin = normalize_origin($rawOrigin);
        if ($origin === '' || !hash_equals($expected, $origin)) {
            abort_request(403, '요청 출처를 확인할 수 없습니다.');
        }
        return;
    }

    $rawReferer = trim((string) ($_SERVER['HTTP_REFERER'] ?? ''));
    if ($rawReferer === '') {
        abort_request(403, '요청 출처를 확인할 수 없습니다.');
    }

    $referer = normalize_origin($rawReferer);
    if ($referer === '' || !hash_equals($expected, $referer)) {
        abort_request(403, '요청 출처를 확인할 수 없습니다.');
    }
}

function request_origin(): string
{
    return (is_https_request() ? 'https' : 'http') . '://' . request_host();
}

function normalize_origin(string $value): string
{
    $value = trim($value);
    if ($value === '' || str_contains($value, "\r") || str_contains($value, "\n") || str_contains($value, "\0")) {
        return '';
    }

    $parts = parse_url($value);
    if (!is_array($parts)) {
        return '';
    }

    if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
        return '';
    }

    if (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/') {
        return '';
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = strtolower((string) ($parts['host'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
        return '';
    }

    if (str_contains($host, ':') && !str_starts_with($host, '[')) {
        $host = '[' . $host . ']';
    }

    $port = '';
    if (isset($parts['port'])) {
        $portValue = (int) $parts['port'];
        if ($portValue < 1 || $portValue > 65535) {
            return '';
        }
        $port = ':' . $portValue;
    }
    $normalizedHost = normalize_host($host . $port);
    if ($normalizedHost === '') {
        return '';
    }

    return $scheme . '://' . $normalizedHost;
}

function current_user(): ?array
{
    if (empty($_SESSION['user']) || !is_array($_SESSION['user'])) {
        return null;
    }

    return $_SESSION['user'];
}

function require_login(): array
{
    $user = current_user();
    if ($user === null) {
        flash('error', '로그인이 필요합니다.');
        redirect('/login');
    }

    return $user;
}

function login_user(array $user): void
{
    session_regenerate_id(true);
    rotate_csrf_token();
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'username' => (string) $user['username'],
    ];
}

function logout_user(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax',
        ]);
    }

    session_destroy();
}

function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = [
        'type' => $type,
        'message' => $message,
    ];
}

function consume_flashes(): array
{
    $flashes = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return is_array($flashes) ? $flashes : [];
}

function redirect(string $path): never
{
    header('Location: ' . safe_redirect_path($path), true, 303);
    exit;
}

function safe_redirect_path(string $path): string
{
    if ($path === '' || str_contains($path, "\r") || str_contains($path, "\n") || str_contains($path, "\0")) {
        return '/';
    }

    if ($path[0] !== '/' || str_starts_with($path, '//') || parse_url($path, PHP_URL_SCHEME) !== null) {
        return '/';
    }

    return $path;
}

function abort_request(int $status, string $message = ''): never
{
    throw new HttpException($status, $message);
}

function status_text(int $status): string
{
    return match ($status) {
        400 => '잘못된 요청',
        401 => '인증 필요',
        403 => '권한 없음',
        404 => '찾을 수 없음',
        405 => '허용되지 않는 메서드',
        419 => '요청 만료',
        429 => '요청 제한 초과',
        default => '서버 오류',
    };
}

function client_ip(): string
{
    if (is_trusted_proxy_request()) {
        $forwarded = forwarded_for_client_ip();
        if ($forwarded !== '') {
            return $forwarded;
        }
    }

    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    return filter_var($remote, FILTER_VALIDATE_IP) !== false ? $remote : '0.0.0.0';
}

function forwarded_for_client_ip(): string
{
    $header = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
    $candidates = array_reverse(explode(',', $header));
    $trustedProxies = trusted_proxy_ips();

    foreach ($candidates as $candidate) {
        $candidate = trim($candidate);
        if ($candidate === '' || filter_var($candidate, FILTER_VALIDATE_IP) === false) {
            continue;
        }

        $isTrustedProxy = false;
        foreach ($trustedProxies as $trusted) {
            if (ip_matches_trusted_proxy($candidate, $trusted)) {
                $isTrustedProxy = true;
                break;
            }
        }

        if (!$isTrustedProxy) {
            return $candidate;
        }
    }

    return '';
}

function ip_matches_trusted_proxy(string $ip, string $trusted): bool
{
    $trusted = trim($trusted);
    if ($trusted === '') {
        return false;
    }

    if (str_contains($trusted, '/')) {
        return ip_matches_cidr($ip, $trusted);
    }

    $packedIp = inet_pton($ip);
    $packedTrusted = inet_pton($trusted);
    return is_string($packedIp)
        && is_string($packedTrusted)
        && strlen($packedIp) === strlen($packedTrusted)
        && hash_equals($packedTrusted, $packedIp);
}

function ip_matches_cidr(string $ip, string $cidr): bool
{
    [$network, $bits] = array_pad(explode('/', $cidr, 2), 2, '');
    if ($network === '' || !ctype_digit($bits)) {
        return false;
    }

    $ipBytes = inet_pton($ip);
    $networkBytes = inet_pton($network);
    if (!is_string($ipBytes) || !is_string($networkBytes) || strlen($ipBytes) !== strlen($networkBytes)) {
        return false;
    }

    $bitCount = (int) $bits;
    $maxBits = strlen($ipBytes) * 8;
    if ($bitCount < 0 || $bitCount > $maxBits) {
        return false;
    }

    $wholeBytes = intdiv($bitCount, 8);
    $remainingBits = $bitCount % 8;
    if ($wholeBytes > 0 && substr($ipBytes, 0, $wholeBytes) !== substr($networkBytes, 0, $wholeBytes)) {
        return false;
    }

    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xff << (8 - $remainingBits)) & 0xff;
    return (ord($ipBytes[$wholeBytes]) & $mask) === (ord($networkBytes[$wholeBytes]) & $mask);
}

function security_identity(array $parts): string
{
    return hash('sha256', implode('|', array_map('strval', $parts)));
}

function ensure_security_events_table(): void
{
    static $ready = false;

    if ($ready) {
        return;
    }

    db()->query('SELECT 1 FROM security_events LIMIT 1');
    $ready = true;
}

function security_event_count(string $eventType, string $identityHash, int $windowSeconds): int
{
    cleanup_security_events_if_needed();
    ensure_security_events_table();
    $windowSeconds = max(1, $windowSeconds);
    $stmt = db()->prepare("
        SELECT COUNT(*) AS cnt
        FROM security_events
        WHERE event_type = ?
          AND identity_hash = ?
          AND created_at >= (NOW() - INTERVAL {$windowSeconds} SECOND)
    ");
    $stmt->execute([$eventType, $identityHash]);

    return (int) $stmt->fetchColumn();
}

function record_security_event(string $eventType, array $identityParts, ?string $detail = null): void
{
    cleanup_security_events_if_needed();
    ensure_security_events_table();
    $stmt = db()->prepare('INSERT INTO security_events (event_type, identity_hash, detail) VALUES (?, ?, ?)');
    $shortDetail = null;
    if ($detail !== null) {
        $shortDetail = 'sha256:' . hash('sha256', $detail);
    }
    $stmt->execute([$eventType, security_identity($identityParts), $shortDetail]);
}

function clear_security_events(string $eventType, array $identityParts): void
{
    ensure_security_events_table();
    $stmt = db()->prepare('DELETE FROM security_events WHERE event_type = ? AND identity_hash = ?');
    $stmt->execute([$eventType, security_identity($identityParts)]);
}

function enforce_security_rate_limit(
    string $eventType,
    array $identityParts,
    int $maxEvents,
    int $windowSeconds,
    string $message = '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.'
): void {
    if (security_event_count($eventType, security_identity($identityParts), $windowSeconds) >= $maxEvents) {
        abort_request(429, $message);
    }
}

function cleanup_security_events(): void
{
    ensure_security_events_table();
    $retentionDays = SECURITY_EVENT_RETENTION_DAYS;
    db()->exec("DELETE FROM security_events WHERE created_at < (NOW() - INTERVAL {$retentionDays} DAY)");
    prune_security_events_to_max_rows();
}

function cleanup_security_events_if_needed(): void
{
    static $checked = false;

    if ($checked) {
        return;
    }
    $checked = true;

    try {
        ensure_app_settings_table();
        $key = 'security_events_last_cleanup';
        $now = time();
        $stmt = db()->prepare('SELECT setting_value FROM app_settings WHERE setting_key = ?');
        $stmt->execute([$key]);
        $stored = $stmt->fetchColumn();
        $lastCleanup = is_string($stored) && ctype_digit($stored) ? (int) $stored : 0;

        if ($lastCleanup > $now - SECURITY_EVENT_CLEANUP_INTERVAL_SECONDS) {
            return;
        }

        cleanup_security_events();
        $upsert = db()->prepare('
            INSERT INTO app_settings (setting_key, setting_value)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
        ');
        $upsert->execute([$key, (string) $now]);
    } catch (Throwable $exception) {
        error_log('security event cleanup failed: ' . $exception->getMessage());
    }
}

function prune_security_events_to_max_rows(): void
{
    $maxRows = SECURITY_EVENT_MAX_ROWS;
    $stmt = db()->query("SELECT id FROM security_events ORDER BY id DESC LIMIT 1 OFFSET {$maxRows}");
    $cutoff = $stmt->fetchColumn();
    if ($cutoff === false) {
        return;
    }

    $delete = db()->prepare('DELETE FROM security_events WHERE id <= ?');
    $delete->execute([(int) $cutoff]);
}

function like_pattern(string $value): string
{
    return '%' . strtr($value, [
        '!' => '!!',
        '%' => '!%',
        '_' => '!_',
    ]) . '%';
}

function password_hash_value(string $password): string
{
    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 1 << 15,
            'time_cost' => 3,
            'threads' => 1,
        ]);
    }

    return password_hash($password, PASSWORD_DEFAULT);
}

function password_needs_upgrade(string $hash): bool
{
    if (defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 1 << 15,
            'time_cost' => 3,
            'threads' => 1,
        ]);
    }

    return password_needs_rehash($hash, PASSWORD_DEFAULT);
}

function text_len(string $value): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($value, 'UTF-8');
    }

    if (preg_match_all('/./us', $value, $matches) !== false) {
        return count($matches[0]);
    }

    return strlen($value);
}

function text_too_long(string $value, int $maxChars, ?int $maxBytes = null): bool
{
    if (text_len($value) > $maxChars) {
        return true;
    }

    return $maxBytes !== null && strlen($value) > $maxBytes;
}

function signed_token(string $purpose, array $parts): string
{
    return hash_hmac('sha256', $purpose . '|' . implode('|', array_map('strval', $parts)), app_secret());
}

function file_download_expires(): int
{
    return time() + FILE_DOWNLOAD_TOKEN_TTL_SECONDS;
}

function file_download_token(array $file, int $expiresAt): string
{
    return signed_token('file-download', [
        (int) $file['id'],
        (string) $file['stored_path'],
        (string) $file['created_at'],
        $expiresAt,
    ]);
}

function all_boards(): array
{
    $stmt = db()->query('SELECT id, slug, name, description FROM boards ORDER BY id ASC');
    return $stmt->fetchAll();
}

function board_by_slug(string $slug): array
{
    $stmt = db()->prepare('SELECT id, slug, name, description FROM boards WHERE slug = ?');
    $stmt->execute([$slug]);
    $board = $stmt->fetch();

    if (!$board) {
        abort_request(404, '게시판을 찾을 수 없습니다.');
    }

    return $board;
}

function format_date(?string $value): string
{
    if (!$value) {
        return '';
    }

    return date('Y-m-d H:i', strtotime($value));
}

function format_bytes(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    $size = (float) $bytes;
    $unit = 0;

    while ($size >= 1024 && $unit < count($units) - 1) {
        $size /= 1024;
        $unit++;
    }

    return $unit === 0 ? "{$bytes} {$units[$unit]}" : sprintf('%.1f %s', $size, $units[$unit]);
}

function flash_class(string $type): string
{
    return match ($type) {
        'success' => 'alert-success',
        'error' => 'alert-danger',
        default => 'alert-primary',
    };
}

function render(string $title, callable $content): void
{
    $user = current_user();
    $flashes = consume_flashes();
    $boards = [];

    try {
        $boards = all_boards();
    } catch (Throwable) {
        $boards = [];
    }

    http_response_code(http_response_code() ?: 200);
    ?>
<!doctype html>
<html lang="ko">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($title) ?> · <?= h(APP_NAME) ?></title>
    <link href="/assets/vendor/bootstrap/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/styles.css">
</head>
<body class="app-body">
    <header class="navbar navbar-expand-lg bg-white border-bottom sticky-top app-navbar">
        <div class="container-xl gap-3">
            <a class="navbar-brand fw-bold" href="/boards/free/posts">Knock Boards</a>
            <nav class="d-flex flex-wrap align-items-center gap-2 me-auto">
                <?php foreach ($boards as $board): ?>
                    <a class="nav-link app-nav-link px-2" href="/boards/<?= h($board['slug']) ?>/posts"><?= h($board['name']) ?></a>
                <?php endforeach; ?>
                <a class="nav-link app-nav-link px-2" href="/users">유저 검색</a>
            </nav>
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <?php if ($user): ?>
                    <span class="badge rounded-pill text-bg-light border text-dark"><?= h($user['username']) ?></span>
                    <form method="post" action="/logout" class="m-0">
                        <?= csrf_field() ?>
                        <button type="submit" class="btn btn-link p-0 text-decoration-none">로그아웃</button>
                    </form>
                <?php else: ?>
                    <a class="btn btn-outline-secondary btn-sm" href="/login">로그인</a>
                    <a class="btn btn-primary btn-sm" href="/register">회원가입</a>
                <?php endif; ?>
            </div>
        </div>
    </header>

    <main class="container-xl py-4 py-lg-5">
        <?php foreach ($flashes as $flash): ?>
            <div class="alert <?= h(flash_class((string) ($flash['type'] ?? 'info'))) ?> shadow-sm" role="alert"><?= h($flash['message'] ?? '') ?></div>
        <?php endforeach; ?>

        <?php $content(); ?>
    </main>
    <script src="/assets/vendor/bootstrap/bootstrap.bundle.min.js"></script>
    <script src="/assets/app.js"></script>
</body>
</html>
    <?php
}

function render_error(int $status, string $message = ''): void
{
    http_response_code($status);
    $title = status_text($status);
    $body = $message !== '' ? $message : $title;

    render($title, function () use ($status, $title, $body): void {
        ?>
        <section class="card app-card app-card-narrow">
            <div class="card-body">
            <p class="eyebrow">HTTP <?= h((string) $status) ?></p>
            <h1><?= h($title) ?></h1>
            <p><?= h($body) ?></p>
            <a class="btn btn-primary" href="/boards/free/posts">게시판으로 돌아가기</a>
            </div>
        </section>
        <?php
    });
}
