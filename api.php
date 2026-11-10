<?php
/* Who Will Prevail: server for standalone hosting.
   A small document store on MySQL / MariaDB (SQLite works as a fallback: db.driver = 'sqlite') that replaces the
   claude.ai artifact database, plus the server side of the game's security: sessions and sign-in (security.php),
   who may read / write what, and the invitation / reset / new-move emails (mailer.php).
   Settings live in config.php. */

declare(strict_types=1);
define('WWP', 1);
/* warnings and notices must never leak into a JSON answer or onto the page: they go to the server log instead */
@ini_set('display_errors', '0'); @ini_set('log_errors', '1'); error_reporting(E_ALL);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');

$CFG = require __DIR__ . '/config.php';
/* config.local.php (optional, never committed): secrets kept out of git, e.g. the Zoho client. Same layout as config.php. */
if (is_file(__DIR__ . '/config.local.php')) $CFG = array_replace_recursive($CFG, (array)require __DIR__ . '/config.local.php');
const JF = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
const SCHEMA_VERSION = 3; /* 3: {secrets} (Zoho CRM connection) */

/* every JSON answer also carries who the server thinks you are, so the page notices an expired or revoked sign-in */
function out($a, int $code = 200): void {
  if (isset($GLOBALS['WWP_SESSPUB']) && is_array($a) && !array_key_exists('sess', $a)) $a['sess'] = $GLOBALS['WWP_SESSPUB'];
  http_response_code($code); echo json_encode($a, JF); exit;
}
function fail(string $code, string $msg, int $http = 400): void { out(['error' => $msg, 'code' => $code], $http); }

set_exception_handler(function ($e) { error_log('wwp: ' . $e->getMessage()); fail('server_error', 'Server error', 500); });

$setupKey = (string)($CFG['setup_key'] ?? '');

/* ---------- database ---------- */
function dbc(): array { global $CFG; return (array)($CFG['db'] ?? []); }
function isMy(): bool { return strtolower((string)(dbc()['driver'] ?? 'mysql')) !== 'sqlite'; }
/* '{docs}' etc. in SQL become the real (prefixed) table names */
function q(string $sql): string {
  $p = preg_replace('/[^A-Za-z0-9_]/', '', (string)(dbc()['prefix'] ?? 'wwp_'));
  $m = [];
  foreach (['docs', 'colrev', 'docrev', 'leases', 'meta', 'mail_log', 'rl', 'sessions', 'secmatrix', 'seclog', 'secrets'] as $t) $m['{' . $t . '}'] = $p . $t;
  return strtr($sql, $m);
}
/* INSERT ... or UPDATE the non-key columns when the key exists (MySQL and SQLite spell this differently) */
function upsert(PDO $pdo, string $table, string $pk, array $row): void {
  $cols = array_keys($row);
  $ph = implode(',', array_fill(0, count($cols), '?'));
  $upd = array_values(array_filter($cols, function ($c) use ($pk) { return $c !== $pk; }));
  if (isMy()) $tail = 'ON DUPLICATE KEY UPDATE ' . implode(',', array_map(function ($c) { return "$c=VALUES($c)"; }, $upd));
  else $tail = "ON CONFLICT($pk) DO UPDATE SET " . implode(',', array_map(function ($c) { return "$c=excluded.$c"; }, $upd));
  $pdo->prepare(q("INSERT INTO $table(" . implode(',', $cols) . ") VALUES($ph) $tail"))->execute(array_values($row));
}
/* run $f inside a transaction; retry a few times on deadlocks / lock timeouts */
function tx(PDO $pdo, callable $f) {
  for ($i = 0;; $i++) {
    $began = false;
    try {
      if (isMy()) $pdo->beginTransaction(); else $pdo->exec('BEGIN IMMEDIATE');
      $began = true;
      $r = $f();
      if (isMy()) $pdo->commit(); else $pdo->exec('COMMIT');
      return $r;
    } catch (Throwable $e) {
      if ($began) { try { if (isMy()) { if ($pdo->inTransaction()) $pdo->rollBack(); } else $pdo->exec('ROLLBACK'); } catch (Throwable $x) {} }
      $m = $e->getMessage();
      if ($i < 3 && (stripos($m, 'deadlock') !== false || stripos($m, 'lock wait timeout') !== false || stripos($m, 'database is locked') !== false)) { usleep(60000 * ($i + 1)); continue; }
      throw $e;
    }
  }
}
function openDb(): PDO {
  $c = dbc();
  if (isMy()) {
    if (!extension_loaded('pdo_mysql')) throw new RuntimeException('The PHP extension pdo_mysql is not enabled on this hosting.');
    foreach (['name', 'user'] as $k) if (trim((string)($c[$k] ?? '')) === '') throw new RuntimeException("db.$k is empty in config.php: fill in the database details.");
    $dsn = !empty($c['socket'])
      ? 'mysql:unix_socket=' . $c['socket'] . ';dbname=' . $c['name'] . ';charset=utf8mb4'
      : 'mysql:host=' . ($c['host'] ?? 'localhost') . ';port=' . (int)($c['port'] ?? 3306) . ';dbname=' . $c['name'] . ';charset=utf8mb4';
    return new PDO($dsn, (string)$c['user'], (string)($c['pass'] ?? ''), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 8]);
  }
  global $CFG;
  $dir = (string)$CFG['data_dir'];
  if (!is_dir($dir) && !@mkdir($dir, 0775, true)) throw new RuntimeException('Cannot create data folder: ' . $dir);
  $pdo = new PDO('sqlite:' . rtrim($dir, '/\\') . '/game.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
  $pdo->exec('PRAGMA busy_timeout=5000');
  @$pdo->exec('PRAGMA journal_mode=WAL');
  return $pdo;
}
function installSchema(PDO $pdo): void {
  if (isMy()) {
    $a = 'CHARACTER SET ascii COLLATE ascii_bin NOT NULL';
    $tail = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';
    $sql = [
      "CREATE TABLE IF NOT EXISTS {docs} (path VARCHAR(400) $a, col VARCHAR(200) $a, id VARCHAR(200) $a, data LONGTEXT CHARACTER SET utf8mb4 NOT NULL, rev BIGINT NOT NULL, PRIMARY KEY (path), KEY docs_col (col)) $tail",
      "CREATE TABLE IF NOT EXISTS {colrev} (col VARCHAR(200) $a, rev BIGINT NOT NULL, PRIMARY KEY (col)) $tail",
      "CREATE TABLE IF NOT EXISTS {docrev} (path VARCHAR(400) $a, rev BIGINT NOT NULL, PRIMARY KEY (path)) $tail",
      "CREATE TABLE IF NOT EXISTS {leases} (path VARCHAR(400) $a, holder VARCHAR(100) CHARACTER SET utf8mb4 NOT NULL, expires BIGINT NOT NULL, PRIMARY KEY (path)) $tail",
      "CREATE TABLE IF NOT EXISTS {meta} (k VARCHAR(50) $a, v BIGINT NOT NULL, PRIMARY KEY (k)) $tail",
      "CREATE TABLE IF NOT EXISTS {mail_log} (ts BIGINT NOT NULL, rcpt VARCHAR(320) CHARACTER SET utf8mb4 NOT NULL, KEY mail_ts (ts)) $tail",
      "CREATE TABLE IF NOT EXISTS {rl} (b VARCHAR(120) $a, ws BIGINT NOT NULL, n INT NOT NULL, PRIMARY KEY (b)) $tail",
      "CREATE TABLE IF NOT EXISTS {sessions} (sid VARCHAR(64) $a, role VARCHAR(10) $a, subj VARCHAR(100) $a, pid VARCHAR(200) CHARACTER SET utf8mb4 NOT NULL, created BIGINT NOT NULL, expires BIGINT NOT NULL, seen BIGINT NOT NULL, ip VARCHAR(45) $a, PRIMARY KEY (sid), KEY sess_subj (subj), KEY sess_exp (expires)) $tail",
      "CREATE TABLE IF NOT EXISTS {secmatrix} (k VARCHAR(190) $a, n BIGINT NOT NULL, ts BIGINT NOT NULL, PRIMARY KEY (k)) $tail",
      "CREATE TABLE IF NOT EXISTS {seclog} (ts BIGINT NOT NULL, ip VARCHAR(45) $a, role VARCHAR(10) $a, kind VARCHAR(20) $a, detail VARCHAR(240) CHARACTER SET utf8mb4 NOT NULL, KEY sl_ts (ts)) $tail",
      "CREATE TABLE IF NOT EXISTS {secrets} (k VARCHAR(50) $a, v TEXT $a, ts BIGINT NOT NULL, PRIMARY KEY (k)) $tail",
    ];
  } else {
    $sql = [
      'CREATE TABLE IF NOT EXISTS {docs} (path TEXT PRIMARY KEY, col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, rev INTEGER NOT NULL)',
      'CREATE INDEX IF NOT EXISTS {docs}_col ON {docs}(col)',
      'CREATE TABLE IF NOT EXISTS {colrev} (col TEXT PRIMARY KEY, rev INTEGER NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {docrev} (path TEXT PRIMARY KEY, rev INTEGER NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {leases} (path TEXT PRIMARY KEY, holder TEXT NOT NULL, expires INTEGER NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {meta} (k TEXT PRIMARY KEY, v INTEGER NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {mail_log} (ts INTEGER NOT NULL, rcpt TEXT NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {rl} (b TEXT PRIMARY KEY, ws INTEGER NOT NULL, n INTEGER NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {sessions} (sid TEXT PRIMARY KEY, role TEXT NOT NULL, subj TEXT NOT NULL, pid TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, seen INTEGER NOT NULL, ip TEXT NOT NULL)',
      'CREATE INDEX IF NOT EXISTS {sessions}_subj ON {sessions}(subj)',
      'CREATE TABLE IF NOT EXISTS {secmatrix} (k TEXT PRIMARY KEY, n INTEGER NOT NULL, ts INTEGER NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {seclog} (ts INTEGER NOT NULL, ip TEXT NOT NULL, role TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)',
      'CREATE TABLE IF NOT EXISTS {secrets} (k TEXT PRIMARY KEY, v TEXT NOT NULL, ts INTEGER NOT NULL)',
    ];
  }
  foreach ($sql as $s) $pdo->exec(q($s));
}
/* Opens the database. Tables are created on the very first request (and new ones added when the game is upgraded);
   an empty database is filled from the old SQLite file (config 'import_sqlite') or from seed.json. */
function db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;
  try {
    $c = openDb();
    $fresh = false;
    try { $c->query(q('SELECT 1 FROM {docs} LIMIT 1'))->fetchAll(); }
    catch (Throwable $e) { installSchema($c); $fresh = true; }
    $v = 0; try { $x = $c->query(q("SELECT v FROM {meta} WHERE k='schema'"))->fetchColumn(); $v = $x === false ? 0 : (int)$x; } catch (Throwable $e) {}
    if ($v < SCHEMA_VERSION) { installSchema($c); upsert($c, '{meta}', 'k', ['k' => 'schema', 'v' => SCHEMA_VERSION]); }
    if ($fresh && !importSqlite($c)) seed($c);
    $pdo = $c;
  } catch (Throwable $e) {
    error_log('wwp db: ' . $e->getMessage());
    fail('server_error', 'Database error. Open api.php?diag=1&key=<setup_key from config.php> for details.', 500);
  }
  return $pdo;
}
function seed(PDO $pdo): void {
  $f = __DIR__ . '/seed.json';
  if (!is_file($f)) return;
  $docs = json_decode((string)file_get_contents($f)); /* objects, so empty {} stays {} */
  if (!is_object($docs)) return;
  tx($pdo, function () use ($pdo, $docs) {
    foreach ($docs as $path => $data) if (is_object($data) && validPath((string)$path)) writeDoc($pdo, (string)$path, $data, nextRev($pdo));
  });
}
function importSqlite(PDO $pdo): bool {
  global $CFG;
  if (!isMy() || empty($CFG['import_sqlite']) || !extension_loaded('pdo_sqlite')) return false;
  $f = rtrim((string)$CFG['data_dir'], '/\\') . '/game.sqlite';
  if (!is_file($f)) return false;
  $src = new PDO('sqlite:' . $f, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
  $rows = $src->query('SELECT path, data FROM docs')->fetchAll(PDO::FETCH_ASSOC);
  if (!$rows) return false;
  tx($pdo, function () use ($pdo, $rows) {
    foreach ($rows as $r) {
      $d = json_decode((string)$r['data']);
      if (validPath((string)$r['path']) && is_object($d)) writeDoc($pdo, (string)$r['path'], $d, nextRev($pdo));
    }
  });
  return true;
}
function validPath(string $p): bool {
  return (bool)preg_match('#^[A-Za-z0-9_\-.:@+~]{1,200}(/[A-Za-z0-9_\-.:@+~]{1,200}){1,14}$#', $p) && strpos($p, '..') === false
    && strlen($p) <= 400 && strlen(colOf($p)) <= 200 && strlen(idOf($p)) <= 200;
}
function needPath($p): string { $p = (string)$p; if (!validPath($p)) fail('invalid_argument', 'Bad path'); return $p; }
function colOf(string $p): string { return substr($p, 0, (int)strrpos($p, '/')); }
function idOf(string $p): string { return substr($p, (int)strrpos($p, '/') + 1); }
/* every write takes the next revision number first, so all writers lock rows in the same order (no deadlocks) */
function nextRev(PDO $pdo): int {
  if (isMy()) $pdo->exec(q("INSERT INTO {meta}(k,v) VALUES('rev',1) ON DUPLICATE KEY UPDATE v=v+1"));
  else $pdo->exec(q("INSERT INTO {meta}(k,v) VALUES('rev',1) ON CONFLICT(k) DO UPDATE SET v=v+1"));
  return (int)$pdo->query(q("SELECT v FROM {meta} WHERE k='rev'"))->fetchColumn();
}
function bump(PDO $pdo, string $path, int $rev): void {
  upsert($pdo, '{colrev}', 'col', ['col' => colOf($path), 'rev' => $rev]);
  upsert($pdo, '{docrev}', 'path', ['path' => $path, 'rev' => $rev]);
}
/* Documents are decoded as objects (not arrays) everywhere, so an empty {} never turns into [] on its way through PHP. */
function readDoc(PDO $pdo, string $path, bool $lock = false) {
  $s = $pdo->prepare(q('SELECT data FROM {docs} WHERE path=?' . ($lock && isMy() ? ' FOR UPDATE' : ''))); $s->execute([$path]);
  $v = $s->fetchColumn();
  return $v === false ? null : json_decode((string)$v);
}
function writeDoc(PDO $pdo, string $path, object $data, int $rev): void {
  upsert($pdo, '{docs}', 'path', ['path' => $path, 'col' => colOf($path), 'id' => idOf($path), 'data' => json_encode($data, JF), 'rev' => $rev]);
  bump($pdo, $path, $rev);
}
function deleteDoc(PDO $pdo, string $path, int $rev): void {
  $pdo->prepare(q('DELETE FROM {docs} WHERE path=?'))->execute([$path]);
  bump($pdo, $path, $rev);
}
/* update(): nested objects are merged field by field (the game sends only the changed players inside health / contrib);
   lists and plain values are replaced. */
function mergeDoc($a, object $b): object {
  if (!is_object($a)) $a = new stdClass();
  foreach ($b as $k => $v) {
    $a->{$k} = (is_object($v) && isset($a->{$k}) && is_object($a->{$k})) ? mergeDoc($a->{$k}, $v) : $v;
  }
  return $a;
}
function cmp($a, $b): int {
  if ($a === $b) return 0;
  if ($a === null) return -1; if ($b === null) return 1;
  if (is_numeric($a) && is_numeric($b)) return $a <=> $b;
  return strcmp((string)$a, (string)$b);
}
function fieldOf($d, string $f) { $v = $d; foreach (explode('.', $f) as $k) { if (!is_object($v) || !property_exists($v, $k)) return null; $v = $v->{$k}; } return $v; }
function runQuery(PDO $pdo, string $col, array $o): array {
  $s = $pdo->prepare(q('SELECT id, data FROM {docs} WHERE col=?')); $s->execute([$col]);
  $rows = [];
  foreach ($s->fetchAll(PDO::FETCH_ASSOC) as $r) $rows[] = ['id' => $r['id'], 'data' => json_decode((string)$r['data'])];
  foreach (($o['where'] ?? []) as $w) {
    [$f, $opr, $val] = $w + [null, '==', null];
    $rows = array_values(array_filter($rows, function ($r) use ($f, $opr, $val) {
      $x = fieldOf($r['data'], (string)$f);
      switch ($opr) {
        case '==': return $x === $val || (is_numeric($x) && is_numeric($val) && $x == $val);
        case '!=': return $x !== $val;
        case '<': return cmp($x, $val) < 0; case '<=': return cmp($x, $val) <= 0;
        case '>': return cmp($x, $val) > 0; case '>=': return cmp($x, $val) >= 0;
        case 'in': return is_array($val) && in_array($x, $val, true);
        case 'array-contains': return is_array($x) && in_array($val, $x, true);
      }
      return true;
    }));
  }
  if (!empty($o['orderBy'])) {
    $ob = (array)$o['orderBy']; $f = (string)$ob[0]; $dir = ($ob[1] ?? 'asc') === 'desc' ? -1 : 1;
    usort($rows, function ($a, $b) use ($f, $dir) { return $dir * cmp(fieldOf($a['data'], $f) ?? 0, fieldOf($b['data'], $f) ?? 0); });
  }
  if (!empty($o['limit'])) $rows = array_slice($rows, 0, max(1, (int)$o['limit']));
  return $rows;
}

require __DIR__ . '/security.php';
require __DIR__ . '/mailer.php';
require __DIR__ . '/zoho.php';

/* back from Zoho's sign-in (zoho-callback.php, a GET): stores the connection, then redirects to the game */
if (defined('WWP_ZOHO_CALLBACK')) { $pdo = db(); zoho_callback($pdo, sess_current($pdo)); }

/* ---------- diagnostics (GET, needs the setup key) ----------
   api.php?diag=1&key=...   api.php?seclog=1&key=...   api.php?mailtest=1&to=you@example.com&key=... */
if (isset($_GET['diag']) || isset($_GET['mailtest']) || isset($_GET['seclog'])) {
  if ($setupKey === '' || !hash_equals($setupKey, (string)($_GET['key'] ?? ''))) fail('permission_denied', 'Add &key=<setup_key from config.php>.', 403);
  if (isset($_GET['mailtest'])) {
    $r = mail_try(db(), ['to' => (string)($_GET['to'] ?? ''), 'subject' => 'Who Will Prevail? mail test',
      'text' => "If you can read this, the game can send email.\nSent " . date('c'),
      'html' => '<p><b>Who Will Prevail?</b> mail test.</p><p>If you can read this, the game can send email.</p>'], true);
    out($r, !empty($r['ok']) ? 200 : 502);
  }
  if (isset($_GET['seclog'])) {
    $pdo = db();
    $m = $pdo->query(q('SELECT k, n, ts FROM {secmatrix} ORDER BY k'))->fetchAll(PDO::FETCH_ASSOC);
    $l = $pdo->query(q('SELECT ts, ip, role, kind, detail FROM {seclog} ORDER BY ts DESC LIMIT 150'))->fetchAll(PDO::FETCH_ASSOC);
    out(['security_mode' => sec_mode(), 'your_ip_as_seen_by_the_game' => client_ip(),
         'decisions' => array_map(function ($r) { [$role, $kind, $target, $d] = array_pad(explode('|', (string)$r['k']), 4, ''); return "$d  $role  $kind  $target  x" . $r['n']; }, $m),
         'recent_events' => array_map(function ($r) { return date('Y-m-d H:i:s', (int)$r['ts']) . "  {$r['ip']}  {$r['role']}  {$r['kind']}  {$r['detail']}"; }, $l)]);
  }
  $m = mail_cfg(); $res = [];
  foreach (['hooks.zapier.com:443', 'api.brevo.com:443', 'api.sendgrid.com:443', 'api.resend.com:443', 'api.anthropic.com:443'] as $t) {
    [$h, $p] = explode(':', $t); $fp = @fsockopen($h, (int)$p, $en, $es, 4);
    $res[$t] = $fp ? 'open' : 'blocked or unreachable (' . trim((string)$es) . ')'; if ($fp) fclose($fp);
  }
  $dbi = ['driver' => isMy() ? 'mysql' : 'sqlite', 'pdo_mysql' => extension_loaded('pdo_mysql'), 'pdo_sqlite' => extension_loaded('pdo_sqlite')];
  try {
    $pdo = openDb();
    $dbi['connected'] = true;
    $dbi['version'] = (string)$pdo->query(isMy() ? 'SELECT VERSION()' : 'select sqlite_version()')->fetchColumn();
    if (isMy()) { $r = $pdo->query("SHOW VARIABLES LIKE 'max_allowed_packet'")->fetch(PDO::FETCH_NUM); $dbi['max_allowed_packet_MB'] = $r ? round(((int)$r[1]) / 1048576, 1) : null; }
    try { $dbi['tables_ready'] = true; $dbi['documents'] = (int)$pdo->query(q('SELECT COUNT(*) FROM {docs}'))->fetchColumn(); }
    catch (Throwable $e) { $dbi['tables_ready'] = false; $dbi['note'] = 'Tables are created on the first game request.'; }
    if (!empty($dbi['tables_ready'])) {
      $dbi['admin_login_exists'] = readDoc($pdo, 'settings/auth') !== null;
      $dbi['players'] = (int)$pdo->query(q("SELECT COUNT(*) FROM {docs} WHERE col='players'"))->fetchColumn();
    }
  } catch (Throwable $e) { $dbi['connected'] = false; $dbi['error'] = $e->getMessage(); }
  out(['php' => PHP_VERSION, 'curl' => function_exists('curl_init'), 'https' => is_https(), 'your_ip_as_seen_by_the_game' => client_ip(), 'security_mode' => sec_mode(), 'database' => $dbi,
    'old_sqlite_file_present' => is_file(rtrim((string)$CFG['data_dir'], '/\\') . '/game.sqlite'),
    'mail' => ['enabled' => mail_enabled(), 'provider' => $m['provider'] ?? '', 'from' => $m['from'] ?? '', 'allowed_recipients' => count((array)($m['allowed_recipients'] ?? []))],
    'ai_key_set' => trim((string)$CFG['anthropic_api_key']) !== '', 'outbound' => $res]);
}

/* ---------- API (POST only, from this site's own pages) ---------- */
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail('bad_method', 'POST only', 405);
if (($_SERVER['HTTP_X_WWP'] ?? '') !== '1') fail('forbidden', 'Missing request header.', 403);
$canSetup = $setupKey !== '' && hash_equals($setupKey, (string)($_SERVER['HTTP_X_SETUP_KEY'] ?? ''));
$raw = file_get_contents('php://input');
if (strlen($raw) > (int)$CFG['max_body_bytes']) fail('invalid_argument', 'Request too large', 413);
$in = json_decode($raw ?: '{}', true);   /* for plain fields: path, col, opts ... */
$inObj = json_decode($raw ?: '{}');      /* for document bodies, where {} and [] must stay different */
if (!is_array($in) || !is_object($inObj)) fail('invalid_argument', 'Bad JSON');
$op = $_GET['op'] ?? '';

$pdo = db();
$S = sess_current($pdo);

/* rules that hold in every mode: the game itself never needs these through the generic document calls */
function hard_write_rule(string $path, ?object $data): ?string {
  if ($path === 'settings/auth') return 'The admin login is managed by the server.';
  if (strpos($path, 'accounts/') === 0 && $data) {
    foreach (['hash', 'salt', 'iter', 'algo'] as $k) if (property_exists($data, $k)) return 'Passwords are managed by the server.';
    if (property_exists($data, 'tok') && $data->tok !== null) return 'Links are issued by the server.';
  }
  if (strpos($path, 'leases/') === 0) return 'Leases are server-managed.';
  return null;
}
function need_role(PDO $pdo, array $S, string $role, string $what): void {
  if ($S['role'] !== $role) { sec_event($pdo, $S, 'denied', $what); fail('permission_denied', $role === 'admin' ? 'Sign in as admin.' : 'Sign in first.', 403); }
}
function get_link(array $in): array { $l = (array)($in['link'] ?? []); return ['purpose' => (string)($l['purpose'] ?? ''), 'key' => (string)($l['key'] ?? ''), 'token' => (string)($l['token'] ?? '')]; }

switch ($op) {
  case 'info':
    out(['ok' => true, 'ai' => trim((string)$CFG['anthropic_api_key']) !== '', 'canSetup' => $canSetup, 'mail' => mail_enabled(),
         'needsSetup' => readDoc($pdo, 'settings/auth') === null]);

  case 'session':
    out(['ok' => true]);

  /* ----- sign in / out ----- */
  case 'login': {
    $role = (string)($in['role'] ?? 'player') === 'admin' ? 'admin' : 'player';
    $pw = (string)($in['password'] ?? ''); $keep = !empty($in['keep']); $ip = client_ip();
    /* A whole office may sign in from one address at the start of a shift, so only FAILED attempts are limited per address
       (login_fail_per_ip); the total (login_attempts_per_ip) is just a ceiling that protects the server's CPU. */
    if (($w = rl_blocked($pdo, "login:fail:$ip", sec_num('login_fail_per_ip', 60), 600)) || ($w = rl_blocked($pdo, "login:all:$ip", sec_num('login_attempts_per_ip', 600), 600))) fail_rate($w);
    rl_hit($pdo, "login:all:$ip", 600);
    if ($role === 'admin') {
      $user = strtolower(trim((string)($in['user'] ?? '')));
      if (($w = rl_blocked($pdo, "login:admin:$ip", 6, 900)) || ($w = rl_blocked($pdo, 'login:admin', 40, 3600))) fail_rate($w);
      $auth = readDoc($pdo, 'settings/auth');
      if (!is_object($auth) || $user === '' || $pw === '' || !admin_verify($auth, $user, $pw)) {
        rl_hit($pdo, "login:admin:$ip", 900); rl_hit($pdo, 'login:admin', 3600); rl_hit($pdo, "login:fail:$ip", 600); sec_event($pdo, $S, 'login_fail', 'admin');
        fail('bad_login', "That admin username and password don't match.", 401);
      }
      rl_clear($pdo, "login:admin:$ip");
      if (($auth->admin->algo ?? '') !== 'pbkdf2') { /* first sign-in since the upgrade: keep the same password, store it the stronger way */
        $new = admin_doc((string)$auth->admin->user, $pw, $auth);
        tx($pdo, function () use ($pdo, $new) { writeDoc($pdo, 'settings/auth', $new, nextRev($pdo)); });
      }
      sess_destroy($pdo); sess_create($pdo, 'admin', 'admin', '', $keep); sec_event($pdo, sess_current($pdo), 'login_ok', 'admin');
      out(['ok' => true, 'role' => 'admin']);
    }
    $email = strtolower(trim((string)($in['email'] ?? ''))); $key = email_key($email);
    if (($w = rl_blocked($pdo, "login:acct:$key:$ip", 6, 900)) || ($w = rl_blocked($pdo, "login:acct:$key", 30, 3600))) fail_rate($w);
    $a = ($email !== '' && $pw !== '') ? readDoc($pdo, 'accounts/' . $key) : null;
    $ok = is_object($a) && ($a->status ?? '') === 'active' && !empty($a->hash) && pw_check($pw, (string)($a->salt ?? ''), (int)($a->iter ?? PBKDF2_ITER), (string)$a->hash);
    if (!is_object($a) || empty($a->hash)) pw_check($pw, '', PBKDF2_ITER, 'x'); /* same effort whether or not the account exists */
    if (!$ok) { rl_hit($pdo, "login:acct:$key:$ip", 900); rl_hit($pdo, "login:acct:$key", 3600); rl_hit($pdo, "login:fail:$ip", 600); sec_event($pdo, $S, 'login_fail', 'player ' . substr($key, 0, 8)); fail('bad_login', "That email and password don't match.", 401); }
    rl_clear($pdo, "login:acct:$key:$ip");
    sess_destroy($pdo); $N = sess_create($pdo, 'player', $key, (string)$a->pid, $keep); sec_event($pdo, $N, 'login_ok', 'player ' . substr($key, 0, 8));
    out(['ok' => true, 'role' => 'player', 'key' => $key, 'pid' => (string)$a->pid]);
  }

  case 'logout':
    sess_destroy($pdo);
    out(['ok' => true]);

  /* ----- admin login: first-time setup and later changes ----- */
  case 'setup_admin': {
    if (!$canSetup) fail('permission_denied', 'First-time setup needs the setup link (?setup=YOUR_KEY from config.php).', 403);
    if (readDoc($pdo, 'settings/auth') !== null) fail('permission_denied', 'The admin login already exists.', 403);
    $user = strtolower(trim((string)($in['user'] ?? ''))); $pw = (string)($in['password'] ?? '');
    if ($user === '') fail('invalid_argument', 'The admin login needs a username.');
    if (strlen($pw) < 8) fail('invalid_argument', 'The admin password needs at least 8 characters.');
    $doc = admin_doc($user, $pw, null);
    $made = tx($pdo, function () use ($pdo, $doc) { $rev = nextRev($pdo); if (readDoc($pdo, 'settings/auth', true) !== null) return false; writeDoc($pdo, 'settings/auth', $doc, $rev); return true; });
    if (!$made) fail('permission_denied', 'The admin login already exists.', 403);
    sess_destroy($pdo); $N = sess_create($pdo, 'admin', 'admin', '', false); sec_event($pdo, $N, 'setup', 'admin login created');
    out(['ok' => true, 'role' => 'admin']);
  }
  case 'change_admin': {
    need_role($pdo, $S, 'admin', 'change_admin');
    $user = strtolower(trim((string)($in['user'] ?? ''))); $pw = (string)($in['password'] ?? '');
    if ($user === '') fail('invalid_argument', 'The admin login needs a username.');
    if ($pw !== '' && strlen($pw) < 8) fail('invalid_argument', 'The admin password needs at least 8 characters.');
    $auth = readDoc($pdo, 'settings/auth'); if (!is_object($auth)) fail('invalid_argument', 'No admin login yet.');
    if ($pw !== '') $doc = admin_doc($user, $pw, $auth);
    else { $doc = clone $auth; $doc->admin = clone $auth->admin; $doc->admin->user = $user; $doc->updated = now_ms(); }
    tx($pdo, function () use ($pdo, $doc) { writeDoc($pdo, 'settings/auth', $doc, nextRev($pdo)); });
    if ($pw !== '') sess_revoke($pdo, 'admin', $S['sid']);
    sec_event($pdo, $S, 'admin_change', $pw !== '' ? 'username and password' : 'username');
    out(['ok' => true]);
  }

  /* ----- invitation and reset links ----- */
  case 'link_state': {
    if ($w = rl_blocked($pdo, 'link:' . client_ip(), sec_num('link_checks_per_ip', 600), 600)) fail_rate($w);
    rl_hit($pdo, 'link:' . client_ip(), 600);
    [$bad, $a, $p] = link_check($pdo, get_link($in));
    if ($bad) out(['bad' => $bad]);
    out(['acct' => ['email' => (string)$a->email], 'player' => $p ? ['name' => (string)($p->name ?? '')] : null]);
  }
  case 'redeem': {
    $l = get_link($in); $pw = (string)($in['password'] ?? '');
    if ($w = rl_blocked($pdo, 'redeem:' . client_ip(), sec_num('link_redeems_per_ip', 200), 600)) fail_rate($w);
    rl_hit($pdo, 'redeem:' . client_ip(), 600);
    if ($pr = pw_problem($pw)) fail('invalid_argument', $pr);
    $n = pw_new($pw); $key = $l['key'];
    $res = tx($pdo, function () use ($pdo, $l, $n, $key) {
      $rev = nextRev($pdo); [$bad, $a] = link_check($pdo, $l, true); if ($bad) return ['bad' => $bad];
      $patch = json_decode(json_encode(['salt' => $n['salt'], 'hash' => $n['hash'], 'iter' => $n['iter'], 'status' => 'active', 'activatedAt' => (int)($a->activatedAt ?? 0) ?: now_ms(), 'v' => rhex(6), 'tok' => null, 'failReason' => null, 'resetRequestedAt' => null], JF));
      writeDoc($pdo, 'accounts/' . $key, mergeDoc($a, $patch), $rev);
      return ['pid' => (string)$a->pid];
    });
    if (isset($res['bad'])) fail('bad_link', $res['bad'], 400);
    sess_revoke($pdo, $key); sess_destroy($pdo); $N = sess_create($pdo, 'player', $key, $res['pid'], false); sec_event($pdo, $N, 'link_ok', $l['purpose'] . ' ' . substr($key, 0, 8));
    out(['ok' => true, 'role' => 'player', 'key' => $key, 'pid' => $res['pid']]);
  }
  case 'request_reset': {
    $email = strtolower(trim((string)($in['email'] ?? ''))); $ip = client_ip();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || rl_blocked($pdo, "reset:ip:$ip", sec_num('reset_requests_per_ip', 30), 3600)) out(['ok' => true]);
    rl_hit($pdo, "reset:ip:$ip", 3600);
    $key = email_key($email); $a = readDoc($pdo, 'accounts/' . $key);
    $cool = 5 * 60 * 1000;
    $last = is_object($a) ? max((int)($a->resetRequestedAt ?? 0), (int)($a->resetIssuedAt ?? 0)) : 0; /* the latest request or the latest email sent */
    if (is_object($a) && ($a->status ?? '') === 'active' && now_ms() - $last >= $cool) {
      doc_patch($pdo, 'accounts/' . $key, ['resetRequestedAt' => now_ms()]);
      sec_event($pdo, $S, 'reset_request', substr($key, 0, 8));
      if (mail_enabled()) issue_link($pdo, $key, 'reset'); /* emailed right away, but only when the game's address is configured (Branding Game link or security.game_url); otherwise the admin's page picks the request up */
    }
    out(['ok' => true]);
  }
  case 'issue_link': {
    need_role($pdo, $S, 'admin', 'issue_link');
    $key = (string)($in['key'] ?? ''); $purpose = (string)($in['purpose'] ?? '') === 'reset' ? 'reset' : 'invite';
    if (!preg_match('/^[0-9a-f]{32}$/', $key)) fail('invalid_argument', 'Bad account.');
    $r = issue_link($pdo, $key, $purpose, (string)($in['base'] ?? '')); if (($r['error'] ?? '') === 'no_game_url') fail('no_game_url', 'Set the Game link in Branding (or game_url in config.php) first, so the emails know where to point.', 409);
    if (isset($r['error'])) fail('not_found', 'No such account.', 404);
    sec_event($pdo, $S, 'link_issued', $purpose . ' ' . substr($key, 0, 8));
    out($r);
  }
  case 'send_move_email': {
    need_role($pdo, $S, 'admin', 'send_move_email');
    $id = (string)($in['id'] ?? ''); if (!preg_match('/^[0-9a-f]{20}$/', $id)) fail('invalid_argument', 'Bad move.');
    $r = send_move_email($pdo, $id, max(1, (int)($in['tries'] ?? 1)), (string)($in['base'] ?? '')); if (($r['error'] ?? '') === 'no_game_url') fail('no_game_url', 'Set the Game link in Branding (or game_url in config.php) first, so the emails know where to point.', 409);
    if (isset($r['error'])) fail('not_found', 'No such move.', 404);
    out($r);
  }
  case 'move_link_check': { /* does this emailed move link belong to a real move, and is it mine? (the secret stays on the server) */
    need_role($pdo, $S, 'player', 'move_link_check');
    $id = (string)($in['id'] ?? ''); $tok = (string)($in['token'] ?? '');
    if (!preg_match('/^[0-9a-f]{20}$/', $id) || !preg_match('/^[0-9a-f]{64}$/', $tok)) out(['exists' => false, 'tokOk' => false]);
    $m = readDoc($pdo, 'moves/' . $id);
    out(['exists' => is_object($m), 'tokOk' => is_object($m) && isset($m->tok) && is_object($m->tok) && hash_equals((string)($m->tok->h ?? ''), hash('sha256', $tok))]);
  }

  /* ----- the document store ----- */
  case 'get': {
    $p = needPath($in['path'] ?? ''); $d = readDoc($pdo, $p); $data = null;
    if ($d !== null) { [$col, $id] = explode('/', $p, 2); [$data, $ok] = acl_view($S, $col, $id, $d); sec_read_note($pdo, $S, $p, $ok ? 0 : 1); }
    out(['data' => $data]);
  }
  case 'query': {
    $col = (string)($in['col'] ?? '');
    out(['data' => acl_filter($pdo, $S, $col, runQuery($pdo, $col, (array)($in['opts'] ?? [])))]);
  }
  case 'watch': {
    $res = []; $rk = rolekey($S);
    foreach ((array)($in['queries'] ?? []) as $qy) {
      $qq = (array)($qy['q'] ?? []); $id = (string)($qy['id'] ?? '');
      if (($qq['type'] ?? '') === 'doc') {
        $p = needPath($qq['path'] ?? '');
        $s = $pdo->prepare(q('SELECT rev FROM {docrev} WHERE path=?')); $s->execute([$p]); $rev = ((int)$s->fetchColumn()) . '.' . $rk;
        if (($qy['rev'] ?? null) !== null && (string)$qy['rev'] === $rev) continue;
        $d = readDoc($pdo, $p); $data = null;
        if ($d !== null) { [$col, $did] = explode('/', $p, 2); [$data, $ok] = acl_view($S, $col, $did, $d); sec_read_note($pdo, $S, $p, $ok ? 0 : 1); }
        $res[] = ['id' => $id, 'rev' => $rev, 'data' => $data];
      } else {
        $col = (string)($qq['col'] ?? '');
        $s = $pdo->prepare(q('SELECT rev FROM {colrev} WHERE col=?')); $s->execute([$col]); $rev = ((int)$s->fetchColumn()) . '.' . $rk;
        if (($qy['rev'] ?? null) !== null && (string)$qy['rev'] === $rev) continue;
        $res[] = ['id' => $id, 'rev' => $rev, 'data' => acl_filter($pdo, $S, $col, runQuery($pdo, $col, (array)($qq['opts'] ?? [])))];
      }
    }
    out(['results' => $res]);
  }

  case 'set': case 'update': case 'delete': {
    $p = needPath($in['path'] ?? '');
    $data = null;
    if ($op !== 'delete') {
      if (!isset($inObj->data) || !is_object($inObj->data)) fail('invalid_argument', 'data must be an object');
      $data = $inObj->data;
    }
    if ($op === 'delete' && $p === 'settings/auth') fail('permission_denied', 'The admin login cannot be deleted', 403);
    if ($why = hard_write_rule($p, $data)) { sec_event($pdo, $S, 'denied', "write $op " . norm_target($p) . " ($why)"); fail('permission_denied', $why, 403); }
    $deny = acl_write($pdo, $S, $op, $p, $data);
    if (sec_decide($pdo, $S, 'write ' . $op, $p, $deny)) fail('permission_denied', $deny ?? 'Not allowed.', 403);
    if ($op === 'delete') { tx($pdo, function () use ($pdo, $p) { deleteDoc($pdo, $p, nextRev($pdo)); }); if (strpos($p, 'accounts/') === 0) sess_revoke($pdo, idOf($p)); out(['ok' => true]); }
    if ($op === 'set') { tx($pdo, function () use ($pdo, $p, $data) { $rev = nextRev($pdo); writeDoc($pdo, $p, $data, $rev); }); out(['ok' => true]); }
    $missing = tx($pdo, function () use ($pdo, $p, $data) {
      $rev = nextRev($pdo);
      $cur = readDoc($pdo, $p, true);
      if ($cur === null) return true;
      writeDoc($pdo, $p, mergeDoc($cur, $data), $rev);
      return false;
    });
    if ($missing) fail('invalid_argument', 'Document does not exist');
    out(['ok' => true]);
  }

  case 'lease': {
    $p = needPath($in['path'] ?? '');
    if (sec_decide($pdo, $S, 'lease', $p, $S['role'] === 'anon' ? 'Sign in first.' : null)) fail('permission_denied', 'Sign in first.', 403);
    $holder = substr((string)($in['holder'] ?? 'anon'), 0, 80);
    $ttl = max(1000, min(120000, (int)($in['ttlMs'] ?? 15000)));
    $now = (int)floor(microtime(true) * 1000);
    $pdo->prepare(q((isMy() ? 'INSERT IGNORE' : 'INSERT OR IGNORE') . ' INTO {leases}(path,holder,expires) VALUES(?,?,0)'))->execute([$p, '']);
    $res = tx($pdo, function () use ($pdo, $p, $holder, $ttl, $now) {
      $s = $pdo->prepare(q('SELECT holder, expires FROM {leases} WHERE path=?' . (isMy() ? ' FOR UPDATE' : ''))); $s->execute([$p]);
      $l = $s->fetch(PDO::FETCH_ASSOC);
      if ($l && (int)$l['expires'] > $now && $l['holder'] !== $holder) {
        $e = (int)$l['expires'];
        return ['acquired' => false, 'holder' => $l['holder'], 'expiresAt' => gmdate('Y-m-d\TH:i:s', intdiv($e, 1000)) . sprintf('.%03dZ', $e % 1000)];
      }
      $exp = $now + $ttl;
      $pdo->prepare(q('UPDATE {leases} SET holder=?, expires=? WHERE path=?'))->execute([$holder, $exp, $p]);
      return ['acquired' => true, 'holder' => $holder, 'expiresAt' => gmdate('Y-m-d\TH:i:s', intdiv($exp, 1000)) . sprintf('.%03dZ', $exp % 1000)];
    });
    out($res);
  }

  case 'ai_info':
    out(['images' => trim((string)$CFG['anthropic_api_key']) !== '']);

  case 'ai':
    if (sec_decide($pdo, $S, 'ai', 'claude', $S['role'] === 'admin' ? null : 'Admins only.')) fail('permission_denied', 'Sign in as admin.', 403);
    $key = trim((string)$CFG['anthropic_api_key']);
    if ($key === '') fail('sampling_disabled', 'Claude API key is not configured', 403);
    $content = [];
    foreach (array_slice((array)($in['images'] ?? []), 0, 2) as $img) {
      $mt = (string)($img['media_type'] ?? 'image/jpeg');
      if (!in_array($mt, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'], true)) $mt = 'image/jpeg';
      $content[] = ['type' => 'image', 'source' => ['type' => 'base64', 'media_type' => $mt, 'data' => (string)($img['data'] ?? '')]];
    }
    $content[] = ['type' => 'text', 'text' => substr((string)($in['prompt'] ?? ''), 0, 60000)];
    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
      CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 120,
      CURLOPT_HTTPHEADER => ['content-type: application/json', 'x-api-key: ' . $key, 'anthropic-version: 2023-06-01'],
      CURLOPT_POSTFIELDS => json_encode(['model' => $CFG['anthropic_model'], 'max_tokens' => 4096,
        'messages' => [['role' => 'user', 'content' => $content]]]),
    ]);
    $resp = curl_exec($ch); $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $cerr = curl_error($ch); if (PHP_VERSION_ID < 80000) curl_close($ch);
    if ($resp === false) fail('server_error', 'Could not reach the Claude API: ' . $cerr, 502);
    if ($http === 429 || $http === 529) fail('rate_limited', 'Claude is busy', 429);
    $j = json_decode((string)$resp, true);
    if ($http !== 200) fail('server_error', 'Claude API error: ' . ($j['error']['message'] ?? $http), 502);
    $text = '';
    foreach (($j['content'] ?? []) as $c) if (($c['type'] ?? '') === 'text') $text .= $c['text'];
    $text = trim(preg_replace('~^```(?:json)?\s*|\s*```$~', '', trim($text)));
    $data = json_decode($text, true);
    if ($data === null) {
      $a = strpos($text, '{'); $b = strrpos($text, '}');
      if ($a !== false && $b !== false) $data = json_decode(substr($text, $a, $b - $a + 1), true);
    }
    if ($data === null) fail('server_error', 'Claude did not return JSON', 502);
    out(['data' => $data]);

  /* ----- Zoho CRM player import (admin only; see zoho.php) ----- */
  case 'zoho_status':
    need_role($pdo, $S, 'admin', 'zoho');
    out(['ok' => true] + zoho_status($pdo));

  case 'zoho_connect':
    need_role($pdo, $S, 'admin', 'zoho');
    try { out(['ok' => true, 'url' => zoho_auth_url($pdo, $S)]); }
    catch (ZohoError $e) { fail($e->zcode, $e->getMessage(), 409); }

  case 'zoho_users':
    need_role($pdo, $S, 'admin', 'zoho');
    try { out(['ok' => true, 'users' => zoho_users($pdo)]); }
    catch (ZohoError $e) { fail($e->zcode, $e->getMessage(), $e->zcode === 'zoho_error' ? 502 : 409); }

  case 'zoho_disconnect':
    need_role($pdo, $S, 'admin', 'zoho');
    zoho_disconnect($pdo); sec_event($pdo, $S, 'zoho', 'disconnected');
    out(['ok' => true]);

  default:
    fail('invalid_argument', 'Unknown operation');
}
