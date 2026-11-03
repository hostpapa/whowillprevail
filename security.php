<?php
/* Who Will Prevail: security layer (sessions, sign-in, roles, masking, rate limits, security log).
   Loaded by api.php; it is not meant to be opened directly. */
defined('WWP') or exit;

/* ---------- configuration ---------- */
function sec_cfg(): array { global $CFG; return (array)($CFG['security'] ?? []); }
/* 'off' = no permission checks, 'log' = check and log, but let everything through (learning mode), 'enforce' = block */
function sec_mode(): string { $m = (string)(sec_cfg()['mode'] ?? 'enforce'); return in_array($m, ['off', 'log', 'enforce'], true) ? $m : 'enforce'; }
function sec_num(string $k, int $d): int { $v = sec_cfg()[$k] ?? $d; return is_numeric($v) ? (int)$v : $d; }
function rhex(int $bytes): string { return bin2hex(random_bytes($bytes)); }

function client_ip(): string {
  $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
  if (!empty(sec_cfg()['trust_forwarded_for']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $f = trim(explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    if (filter_var($f, FILTER_VALIDATE_IP)) $ip = $f;
  }
  return substr($ip, 0, 45);
}
function is_https(): bool {
  if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') return true;
  return !empty(sec_cfg()['trust_forwarded_for']) && strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}
function cookie_path(): string { return rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/') . '/'; }

/* ---------- rate limits (fixed windows kept in the database) ---------- */
function sec_incr(PDO $pdo, string $table, string $pk, string $key, int $now, array $extra = []): void {
  $cols = array_merge([$pk => $key, 'n' => 1, 'ts' => $now], $extra);
  $names = implode(',', array_keys($cols)); $ph = implode(',', array_fill(0, count($cols), '?'));
  $tail = isMy() ? 'ON DUPLICATE KEY UPDATE n=n+1,ts=VALUES(ts)' : "ON CONFLICT($pk) DO UPDATE SET n=n+1,ts=excluded.ts";
  $pdo->prepare(q("INSERT INTO $table($names) VALUES($ph) $tail"))->execute(array_values($cols));
}
function rl_state(PDO $pdo, string $b, int $win): array {
  $s = $pdo->prepare(q('SELECT ws, n FROM {rl} WHERE b=?')); $s->execute([$b]); $r = $s->fetch(PDO::FETCH_ASSOC); $now = time();
  if (!$r || (int)$r['ws'] + $win <= $now) return [$now, 0];
  return [(int)$r['ws'], (int)$r['n']];
}
/* seconds to wait, or 0 when the bucket still has room */
function rl_blocked(PDO $pdo, string $b, int $limit, int $win): int {
  [$ws, $n] = rl_state($pdo, $b, $win);
  return $n >= $limit ? max(1, $ws + $win - time()) : 0;
}
function rl_hit(PDO $pdo, string $b, int $win): void {
  [$ws, $n] = rl_state($pdo, $b, $win);
  upsert($pdo, '{rl}', 'b', ['b' => substr($b, 0, 120), 'ws' => $ws, 'n' => $n + 1]);
  if (random_int(1, 60) === 1) $pdo->exec(q('DELETE FROM {rl} WHERE ws < ' . (time() - 86400)));
}
function rl_clear(PDO $pdo, string $b): void { $pdo->prepare(q('DELETE FROM {rl} WHERE b=?'))->execute([substr($b, 0, 120)]); }
function fail_rate(int $wait): void { out(['error' => "Too many tries. Wait $wait seconds and try again.", 'code' => 'rate_limited', 'retryAfter' => $wait], 429); }

/* ---------- security log ---------- */
function norm_target(string $t): string {
  $t = preg_replace('~^(players|moves|accounts|events|seasons|salesBatches|audit)/[^/]+$~', '$1/*', $t);
  return substr(preg_replace('~^leases/(reset|sales).*~', 'leases/$1-*', preg_replace('~^leases/moves/.*~', 'leases/moves/*', $t)), 0, 150);
}
/* Records a decision. 'log' mode records everything (a who-does-what matrix); other modes only the denials. */
function sec_note(PDO $pdo, array $S, string $kind, string $target, bool $allowed, string $why = ''): void {
  $mode = sec_mode(); if ($mode === 'off') return;
  if ($allowed && $mode !== 'log') return;
  $target = norm_target($target); $now = time();
  sec_incr($pdo, '{secmatrix}', 'k', substr($S['role'] . '|' . $kind . '|' . $target . '|' . ($allowed ? 'allow' : 'deny'), 0, 190), $now);
  if (!$allowed) sec_event($pdo, $S, 'denied', $kind . ' ' . $target . ($why !== '' ? ' (' . $why . ')' : ''));
}
function sec_event(PDO $pdo, array $S, string $kind, string $detail): void {
  try {
    $pdo->prepare(q('INSERT INTO {seclog}(ts,ip,role,kind,detail) VALUES(?,?,?,?,?)'))->execute([time(), client_ip(), (string)($S['role'] ?? 'anon'), substr($kind, 0, 20), substr($detail, 0, 240)]);
    if (random_int(1, 80) === 1) $pdo->exec(q('DELETE FROM {seclog} WHERE ts < ' . (time() - 30 * 86400)));
  } catch (Throwable $e) { error_log('wwp seclog: ' . $e->getMessage()); }
}

/* reading a collection the role may only partly see is normal (the page asks for everything, the server filters), so it is not a denial;
   learning mode just counts it */
function sec_read_note(PDO $pdo, array $S, string $target, int $hidden): void {
  if (sec_mode() !== 'log') return;
  sec_incr($pdo, '{secmatrix}', 'k', substr($S['role'] . '|read|' . norm_target($target) . '|' . ($hidden ? 'filter' : 'allow'), 0, 190), time());
}

/* ---------- sessions (random token in an httpOnly cookie; only its SHA-256 is stored) ---------- */
function sess_public(array $S): array { return $S['role'] === 'anon' ? ['role' => null] : ['role' => $S['role'], 'key' => $S['key'], 'pid' => $S['pid']]; }
function sess_cookie(string $val, int $expires): void {
  setcookie('wwp_sid', $val, ['expires' => $expires, 'path' => cookie_path(), 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
}
function sess_anon(): array { return ['role' => 'anon', 'key' => null, 'pid' => null, 'sid' => null]; }
function sess_set_current(array $S): array { $GLOBALS['WWP_SESS'] = $S; $GLOBALS['WWP_SESSPUB'] = sess_public($S); return $S; }
function sess_current(PDO $pdo): array {
  if (isset($GLOBALS['WWP_SESS'])) return $GLOBALS['WWP_SESS'];
  $tok = (string)($_COOKIE['wwp_sid'] ?? '');
  if (!preg_match('/^[0-9a-f]{64}$/', $tok)) return sess_set_current(sess_anon());
  $sid = hash('sha256', $tok);
  $s = $pdo->prepare(q('SELECT role, subj, pid, expires, seen FROM {sessions} WHERE sid=?')); $s->execute([$sid]); $r = $s->fetch(PDO::FETCH_ASSOC);
  $now = time();
  if (!$r || (int)$r['expires'] < $now) return sess_set_current(sess_anon());
  if ($r['role'] === 'player') {
    $a = readDoc($pdo, 'accounts/' . $r['subj']);
    if (!is_object($a) || ($a->status ?? '') !== 'active') { $pdo->prepare(q('DELETE FROM {sessions} WHERE sid=?'))->execute([$sid]); return sess_set_current(sess_anon()); }
    $S = ['role' => 'player', 'key' => (string)$r['subj'], 'pid' => (string)($a->pid ?? $r['pid']), 'sid' => $sid];
  } elseif ($r['role'] === 'admin') {
    if (!is_object(readDoc($pdo, 'settings/auth'))) return sess_set_current(sess_anon());
    $S = ['role' => 'admin', 'key' => null, 'pid' => null, 'sid' => $sid];
  } else return sess_set_current(sess_anon());
  if ($now - (int)$r['seen'] > 300) $pdo->prepare(q('UPDATE {sessions} SET seen=? WHERE sid=?'))->execute([$now, $sid]);
  return sess_set_current($S);
}
function sess_create(PDO $pdo, string $role, string $subj, string $pid, bool $keep): array {
  $tok = rhex(32); $now = time();
  $ttl = $keep ? sec_num('session_keep_days', 30) * 86400 : sec_num('session_hours', 12) * 3600;
  upsert($pdo, '{sessions}', 'sid', ['sid' => hash('sha256', $tok), 'role' => $role, 'subj' => $subj, 'pid' => $pid, 'created' => $now, 'expires' => $now + $ttl, 'seen' => $now, 'ip' => client_ip()]);
  sess_cookie($tok, $keep ? $now + $ttl : 0);
  if (random_int(1, 25) === 1) $pdo->exec(q('DELETE FROM {sessions} WHERE expires < ' . $now));
  return sess_set_current(['role' => $role, 'key' => $role === 'player' ? $subj : null, 'pid' => $role === 'player' ? $pid : null, 'sid' => hash('sha256', $tok)]);
}
function sess_destroy(PDO $pdo): void {
  $S = sess_current($pdo);
  if ($S['sid']) $pdo->prepare(q('DELETE FROM {sessions} WHERE sid=?'))->execute([$S['sid']]);
  sess_cookie('', time() - 86400);
  sess_set_current(sess_anon());
}
/* sign a person out everywhere (password change / reset / removed account), optionally keeping the current session */
function sess_revoke(PDO $pdo, string $subj, ?string $exceptSid = null): void {
  if ($exceptSid) $pdo->prepare(q('DELETE FROM {sessions} WHERE subj=? AND sid<>?'))->execute([$subj, $exceptSid]);
  else $pdo->prepare(q('DELETE FROM {sessions} WHERE subj=?'))->execute([$subj]);
}

/* ---------- passwords ---------- */
const PBKDF2_ITER = 600000;
function pw_new(string $pw): array { $salt = rhex(16); return ['salt' => $salt, 'iter' => PBKDF2_ITER, 'hash' => hash_pbkdf2('sha256', $pw, hex2bin($salt), PBKDF2_ITER, 64, false)]; }
function pw_check(string $pw, string $salt, int $iter, string $hash): bool {
  if ($salt === '' || strlen($salt) % 2 || !preg_match('/^[0-9a-fA-F]+$/', $salt)) $salt = str_repeat('0', 32);
  $h = hash_pbkdf2('sha256', $pw, hex2bin($salt), max(1000, min($iter ?: PBKDF2_ITER, 2000000)), 64, false);
  return $hash !== '' && hash_equals($hash, $h);
}
function pw_problem(string $pw): ?string {
  if (strlen($pw) < 10) return 'Use at least 10 characters.';
  if (!preg_match('/[A-Za-z]/', $pw) || !preg_match('/\d/', $pw)) return 'Use at least one letter and one number.';
  return null;
}
function email_key(string $email): string { return substr(hash('sha256', 'wwp-email|' . strtolower(trim($email))), 0, 32); }

/* admin login: PBKDF2 once upgraded; the original salted SHA-256 is still accepted (and upgraded on the first sign-in) */
function admin_verify(?object $auth, string $user, string $pw): bool {
  $a = is_object($auth) ? ($auth->admin ?? null) : null;
  if (!is_object($a)) { pw_check($pw, '', PBKDF2_ITER, 'x'); return false; }
  $userOk = hash_equals(strtolower((string)($a->user ?? '')), strtolower($user));
  if (($a->algo ?? '') === 'pbkdf2') $pwOk = pw_check($pw, (string)($a->psalt ?? ''), (int)($a->iter ?? PBKDF2_ITER), (string)($a->hash ?? ''));
  else $pwOk = hash_equals((string)($a->hash ?? ''), hash('sha256', (string)($auth->salt ?? '') . '|admin|' . $pw));
  return $userOk && $pwOk;
}
function admin_doc(string $user, string $pw, ?object $prev): object {
  $n = pw_new($pw);
  $doc = $prev ? clone $prev : new stdClass();
  $doc->salt = $doc->salt ?? rhex(16);
  $doc->admin = (object)['user' => $user, 'algo' => 'pbkdf2', 'psalt' => $n['salt'], 'iter' => $n['iter'], 'hash' => $n['hash'], 'v' => rhex(4)];
  $doc->updated = (int)(microtime(true) * 1000);
  return $doc;
}

/* ---------- masking: secrets never leave the server ---------- */
function mask_account(object $d): object {
  $o = clone $d; unset($o->hash, $o->salt, $o->iter, $o->algo);
  if (isset($o->tok) && is_object($o->tok)) $o->tok = (object)array_filter(['purpose' => $o->tok->purpose ?? null, 'exp' => $o->tok->exp ?? null, 'at' => $o->tok->at ?? null], function ($v) { return $v !== null; });
  return $o;
}
function mask_move(object $d): object { $o = clone $d; unset($o->tok); return $o; }
function mask_player(object $d): object { $o = clone $d; unset($o->email, $o->acct); return $o; }
function mask_auth(array $S, object $d): object {
  if ($S['role'] === 'admin') return (object)['admin' => (object)['user' => (string)(($d->admin->user ?? ''))]];
  return (object)['ok' => true];
}
function public_season(object $d): object { return (object)array_filter(['name' => $d->name ?? null, 'status' => $d->status ?? null, 'endAt' => $d->endAt ?? null], function ($v) { return $v !== null; }); }
/* secrets are always removed, whatever the mode */
function strip_secrets(array $S, string $col, string $id, object $d): object {
  if ($col === 'settings' && $id === 'auth') return mask_auth($S, $d);
  if ($col === 'accounts') return mask_account($d);
  if ($col === 'moves') return mask_move($d);
  return $d;
}

/* ---------- permissions ---------- */
/* what a role may see of one document; null = hidden */
function acl_read(array $S, string $col, string $id, object $d): ?object {
  $r = $S['role'];
  switch ($col) {
    case 'settings':
      if ($id === 'brand') return $d;
      if ($id === 'auth') return mask_auth($S, $d);
      if ($id === 'products') return $r !== 'anon' ? $d : null;
      return $r === 'admin' ? $d : null;
    case 'state':
      if ($id === 'season') return $r === 'anon' ? public_season($d) : $d;
      return $r === 'admin' ? $d : null;
    case 'players':
      if ($r === 'admin') return $d;
      if ($r === 'player' || ($r === 'anon' && !empty(sec_cfg()['public_gate_players']))) return mask_player($d);
      return null;
    case 'accounts':
      if ($r === 'admin') return mask_account($d);
      return ($r === 'player' && $id === $S['key']) ? mask_account($d) : null;
    case 'moves':
      if ($r === 'admin') return mask_move($d);
      return ($r === 'player' && (string)($d->pid ?? '') === (string)$S['pid']) ? mask_move($d) : null;
    case 'events': case 'seasons':
      return $r !== 'anon' ? $d : null;
    case 'salesBatches': case 'audit':
      return $r === 'admin' ? $d : null;
    default:
      return $r === 'admin' ? $d : null;
  }
}
/* [document to send or null, whether the role was allowed to see it].
   enforce: only what the role may see. log / off: everything (secrets are still removed). */
function acl_view(array $S, string $col, string $id, object $d): array {
  if (sec_mode() === 'off') return [strip_secrets($S, $col, $id, $d), true];
  $v = acl_read($S, $col, $id, $d);
  if ($v !== null) return [$v, true];
  return [sec_mode() === 'log' ? strip_secrets($S, $col, $id, $d) : null, false];
}
/* the visible rows of a collection query; one decision is logged for the whole query */
function acl_filter(PDO $pdo, array $S, string $col, array $rows): array {
  $out = []; $hidden = 0;
  foreach ($rows as $r) { [$d, $ok] = acl_view($S, $col, (string)$r['id'], $r['data']); if (!$ok) $hidden++; if ($d !== null) $out[] = ['id' => $r['id'], 'data' => $d]; }
  sec_read_note($pdo, $S, $col, $hidden);
  return $out;
}
function key_subset(?object $data, array $allowed): bool { if (!$data) return true; foreach ($data as $k => $v) if (!in_array($k, $allowed, true)) return false; return true; }
/* reason a write is refused, or null when it is fine */
function acl_write(PDO $pdo, array $S, string $op, string $path, ?object $data): ?string {
  $r = $S['role']; if ($r === 'anon') return 'Sign in first.';
  [$col, $id] = explode('/', $path, 2) + ['', ''];
  if ($r === 'admin') {
    if ($path === 'settings/auth') return 'The admin login is changed from Branding.';
    if ($col === 'leases') return 'Leases are server-managed.';
    if ($col === 'accounts' && $data) {
      foreach (['hash', 'salt', 'iter', 'algo'] as $k) if (property_exists($data, $k)) return 'Passwords are managed by the server.';
      if (property_exists($data, 'tok') && $data->tok !== null) return 'Links are issued by the server.';
    }
    return null;
  }
  /* players: only what the game itself does on their behalf */
  if ($path === 'state/season' && ($op === 'set' || $op === 'update')) return null;
  if ($col === 'seasons' && $op === 'set') return null;
  if ($col === 'events' && $op === 'set') return null;
  if ($col === 'players' && $op === 'update' && key_subset($data, ['rating', 'unrated'])) return null;
  if ($col === 'moves' && $op === 'update' && key_subset($data, ['status', 'completedAt', 'target', 'tok'])) {
    if ($data && property_exists($data, 'tok') && $data->tok !== null) return 'Not allowed.';
    if ($data && property_exists($data, 'status') && !in_array($data->status, ['completed', 'available'], true)) return 'Not allowed.';
    $m = readDoc($pdo, $path);
    if (is_object($m) && (string)($m->pid ?? '') === (string)$S['pid']) return null;
    return 'This move belongs to another player.';
  }
  return 'Players cannot change this.';
}
/* logs the decision; returns true when the request must be refused */
function sec_decide(PDO $pdo, array $S, string $kind, string $target, ?string $deny): bool {
  $mode = sec_mode(); if ($mode === 'off') return false;
  sec_note($pdo, $S, $kind, $target, $deny === null, (string)$deny);
  return $deny !== null && $mode === 'enforce';
}
function rolekey(array $S): string { return $S['role'] . ($S['pid'] ? ':' . $S['pid'] : ''); }

/* ---------- invitation / reset links (the secret part is only ever checked on the server) ---------- */
function link_valid_format(array $l): bool {
  return in_array(($l['purpose'] ?? ''), ['invite', 'reset'], true) && preg_match('/^[0-9a-f]{32}$/', (string)($l['key'] ?? '')) && preg_match('/^[0-9a-f]{64}$/', (string)($l['token'] ?? ''));
}
/* [error message or null, account, player] */
function link_check(PDO $pdo, array $l, bool $lock = false): array {
  $inv = ($l['purpose'] ?? '') === 'invite';
  $a = link_valid_format($l) ? readDoc($pdo, 'accounts/' . $l['key'], $lock) : null;
  if (!is_object($a)) return ["This link isn't valid. It may belong to a player who was removed. Ask your game admin for a new invitation.", null, null];
  $t = $a->tok ?? null; $h = hash('sha256', (string)$l['token']);
  if (!is_object($t) || !hash_equals((string)($t->h ?? ''), $h) || ($t->purpose ?? '') !== $l['purpose'])
    return [$inv ? (($a->status ?? '') === 'active' ? 'This invitation was already used. Sign in with your email and password, or choose Forgot password?.' : 'This invitation link is no longer valid. A newer invitation may have been sent. Ask your game admin to resend your invitation.') : 'This reset link is no longer valid. It may have been used already. Choose Forgot password? to request a new one.', null, null];
  if ((int)(microtime(true) * 1000) > (int)($t->exp ?? 0))
    return [$inv ? 'This invitation has expired. Ask your game admin to resend your invitation.' : 'This reset link has expired. Choose Forgot password? to request a new one.', null, null];
  $p = isset($a->pid) ? readDoc($pdo, 'players/' . $a->pid) : null;
  return [null, $a, is_object($p) ? $p : null];
}
function now_ms(): int { return (int)floor(microtime(true) * 1000); }
/* merge fields into a document the server owns, inside a transaction; false when the document does not exist */
function doc_patch(PDO $pdo, string $path, array $fields): bool {
  $patch = json_decode(json_encode($fields, JF));
  return (bool)tx($pdo, function () use ($pdo, $path, $patch) {
    $rev = nextRev($pdo); $cur = readDoc($pdo, $path, true);
    if (!is_object($cur)) return false;
    writeDoc($pdo, $path, mergeDoc($cur, $patch), $rev);
    return true;
  });
}
