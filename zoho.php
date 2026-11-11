<?php
/* Who Will Prevail: admin sign-in with Zoho and the Zoho CRM player import. Included by api.php.
   The Zoho client is a "Server-based Application" (Zoho API Console); its ID and secret live in config.local.php
   ('zoho' block), never in the page. "Sign in with Zoho" (admin sign-in screen) sends the admin to Zoho, which sends
   them back to zoho-callback.php with a one-time code. The server swaps it for tokens: the ID token says who signed in
   (a verified email), and only the emails in zoho.admin_emails become admins. The same sign-in gives that admin read
   access to the CRM users (scope ZohoCRM.users.READ) for "Import from Zoho CRM"; the tokens stay encrypted in the
   {secrets} table, one entry per admin, which the page can't read. Admins who sign in with a password don't get the
   Zoho import. */
if (!defined('WWP')) { http_response_code(404); exit; }

const ZOHO_SCOPE = 'ZohoCRM.users.READ';
const ZOHO_LOGIN_SCOPE = 'openid,email,' . ZOHO_SCOPE;
const ZOHO_VERSIONS = ['v8', 'v7', 'v6', 'v2']; /* newest first; the first one this account answers is remembered */
/* Zoho data centers: the sign-in server (accounts) and the API server must be one of these */
const ZOHO_ACCOUNTS_RX = '~^https://accounts\.(zoho\.(com|eu|in|com\.au|jp|sa|uk|com\.cn)|zohocloud\.ca)$~';
const ZOHO_API_RX = '~^https://(www\.)?zohoapis\.(com|eu|in|com\.au|jp|sa|uk|com\.cn|ca)$~';
const ZOHO_ISS_RX = '~^(https://)?accounts\.(zoho\.(com|eu|in|com\.au|jp|sa|uk|com\.cn)|zohocloud\.ca)$~';
const ZOHO_STATE_COOKIE = 'wwp_zst';

class ZohoError extends RuntimeException {
  public $zcode;
  public function __construct(string $zcode, string $msg) { parent::__construct($msg); $this->zcode = $zcode; }
}

function zoho_cfg(): array {
  global $CFG; $z = (array)($CFG['zoho'] ?? []);
  $acc = rtrim(trim((string)($z['accounts_url'] ?? '')), '/');
  $ru = trim((string)($z['redirect_uri'] ?? ''));
  return ['client_id' => trim((string)($z['client_id'] ?? '')), 'client_secret' => trim((string)($z['client_secret'] ?? '')),
          'accounts_url' => preg_match(ZOHO_ACCOUNTS_RX, $acc) ? $acc : 'https://accounts.zohocloud.ca',
          'redirect_uri' => preg_match('~^https?://[^\s#?@\\\\]+$~i', $ru) ? $ru : ''];
}
function zoho_configured(): bool { $c = zoho_cfg(); return $c['client_id'] !== '' && $c['client_secret'] !== ''; }

/* zoho.admin_emails: who may sign in as admin with Zoho (lower case) */
function zoho_admins(): array {
  global $CFG; $out = [];
  foreach ((array)($CFG['zoho']['admin_emails'] ?? []) as $e) { $e = strtolower(trim((string)$e)); if ($e !== '' && strpos($e, '@') !== false) $out[$e] = true; }
  return array_keys($out);
}
function zoho_is_admin(string $email): bool { return in_array(strtolower(trim($email)), zoho_admins(), true); }
/* sessions of Zoho admins have the subject "zoho:<sha1 of the email>": the email back, while it is still on the list */
function zoho_subj(string $email): string { return 'zoho:' . sha1(strtolower(trim($email))); }
function zoho_admin_by_subj(string $subj): ?string {
  foreach (zoho_admins() as $e) if (hash_equals(zoho_subj($e), $subj)) return $e;
  return null;
}
function zoho_login_enabled(PDO $pdo): bool { return zoho_configured() && zoho_admins() && zoho_redirect_uri($pdo) !== null; }

/* The address Zoho sends the admin back to; it must be listed, exactly, as a Redirect URI of the Zoho client.
   zoho.redirect_uri when set (e.g. the site's own address, whose main page forwards the code to zoho-callback.php),
   otherwise <game address>zoho-callback.php. */
function zoho_redirect_uri(PDO $pdo): ?string {
  if (($ru = zoho_cfg()['redirect_uri']) !== '') return $ru;
  $g = game_url($pdo); if ($g === null) return null;
  $path = (string)parse_url($g, PHP_URL_PATH);
  $base = preg_match('~/[^/]*\.[a-z0-9]+$~i', $path) ? preg_replace('~[^/]*$~', '', $g) : rtrim($g, '/') . '/';
  return $base . 'zoho-callback.php';
}

/* ---------- encrypted storage (table {secrets}) ---------- */
function zoho_key(): string { global $CFG; return hash('sha256', 'wwp-zoho|' . zoho_cfg()['client_secret'] . '|' . (string)($CFG['setup_key'] ?? ''), true); }
function zoho_get(PDO $pdo, string $k): ?array {
  $s = $pdo->prepare(q('SELECT v FROM {secrets} WHERE k=?')); $s->execute([$k]); $v = $s->fetchColumn();
  if ($v === false) return null;
  $raw = base64_decode((string)$v, true); if ($raw === false || strlen($raw) < 29) return null;
  $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', zoho_key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
  $d = $plain === false ? null : json_decode($plain, true);
  return is_array($d) ? $d : null; /* null also when the client secret changed: the admin signs in with Zoho again */
}
function zoho_put(PDO $pdo, string $k, array $v): void {
  $iv = random_bytes(12); $tag = '';
  $c = openssl_encrypt(json_encode($v, JF), 'aes-256-gcm', zoho_key(), OPENSSL_RAW_DATA, $iv, $tag);
  upsert($pdo, '{secrets}', 'k', ['k' => $k, 'v' => base64_encode($iv . $tag . $c), 'ts' => time()]);
}
function zoho_del(PDO $pdo, string $k): void { $pdo->prepare(q('DELETE FROM {secrets} WHERE k=?'))->execute([$k]); }
function zoho_ukey(string $email): string { return 'zu:' . sha1(strtolower(trim($email))); } /* one admin's Zoho tokens */

/* ---------- HTTP ---------- */
function zoho_http(string $method, string $url, ?array $form = null, ?string $token = null): array {
  if (!function_exists('curl_init')) throw new ZohoError('zoho_error', 'The PHP extension curl is not enabled on this hosting.');
  $ch = curl_init($url);
  $hdr = ['Accept: application/json']; if ($token !== null) $hdr[] = 'Authorization: Zoho-oauthtoken ' . $token;
  $opt = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_HTTPHEADER => $hdr];
  if ($method === 'POST') { $opt[CURLOPT_POST] = true; $opt[CURLOPT_POSTFIELDS] = http_build_query((array)$form); }
  curl_setopt_array($ch, $opt);
  $resp = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); if (PHP_VERSION_ID < 80000) curl_close($ch);
  if ($resp === false) throw new ZohoError('zoho_error', 'Zoho can\'t be reached from this server (' . $err . ').');
  $j = json_decode((string)$resp, true);
  return ['code' => $code, 'json' => is_array($j) ? $j : []];
}
function zoho_token_call(string $accounts, array $form): array {
  $c = zoho_cfg();
  return zoho_http('POST', $accounts . '/oauth/v2/token', $form + ['client_id' => $c['client_id'], 'client_secret' => $c['client_secret']]);
}
function zoho_revoke(string $accounts, string $token): void {
  try { zoho_http('POST', $accounts . '/oauth/v2/token/revoke', ['token' => $token]); } catch (Throwable $e) {} /* best effort */
}

/* The ID token's claims. It comes straight from Zoho's token endpoint over TLS, in answer to a call made with the client
   secret, so its signature doesn't need checking (OpenID Connect Core 3.1.3.7); its audience, issuer and age still do. */
function zoho_id_claims(string $jwt): ?array {
  $p = explode('.', $jwt); if (count($p) !== 3) return null;
  $b = strtr($p[1], '-_', '+/'); $b .= str_repeat('=', (4 - strlen($b) % 4) % 4);
  $c = json_decode((string)base64_decode($b, true), true); if (!is_array($c)) return null;
  $aud = (array)($c['aud'] ?? []);
  if (!in_array(zoho_cfg()['client_id'], $aud, true) || (int)($c['exp'] ?? 0) < time() - 60 || !preg_match(ZOHO_ISS_RX, (string)($c['iss'] ?? ''))) return null;
  return $c;
}

/* ---------- sign-in ---------- */
/* "Sign in with Zoho": the Zoho address to send the browser to. The state ties the answer to this browser (cookie) */
function zoho_login_url(PDO $pdo, bool $keep): string {
  if (!zoho_configured()) throw new ZohoError('zoho_not_configured', 'Sign-in with Zoho is not set up on this server.');
  if (!zoho_admins()) throw new ZohoError('zoho_off', 'Sign-in with Zoho is turned off: no admin emails are set on the server.');
  $redirect = zoho_redirect_uri($pdo);
  if ($redirect === null) throw new ZohoError('no_game_url', 'Sign-in with Zoho needs the game\'s address: set the Game link in Branding (or game_url in config.php).');
  $state = rhex(24);
  zoho_put($pdo, 'zs:' . sha1($state), ['exp' => time() + 900, 'keep' => $keep]);
  setcookie(ZOHO_STATE_COOKIE, $state, ['expires' => time() + 900, 'path' => cookie_path(), 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
  return zoho_cfg()['accounts_url'] . '/oauth/v2/auth?' . http_build_query(['scope' => ZOHO_LOGIN_SCOPE, 'client_id' => zoho_cfg()['client_id'],
    'response_type' => 'code', 'access_type' => 'offline', 'redirect_uri' => $redirect, 'state' => $state]);
}
/* zoho-callback.php: back from Zoho's sign-in. Always ends with a redirect to the game, #zoho.<result> */
function zoho_callback(PDO $pdo): void {
  $back = function (string $what) use ($pdo) {
    $g = game_url($pdo); header('Location: ' . ($g === null ? './' : preg_replace('/#.*$/', '', $g)) . '#zoho.' . $what, true, 303); exit;
  };
  $state = (string)($_GET['state'] ?? ''); $ck = (string)($_COOKIE[ZOHO_STATE_COOKIE] ?? '');
  setcookie(ZOHO_STATE_COOKIE, '', ['expires' => time() - 86400, 'path' => cookie_path(), 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
  if (!preg_match('/^[0-9a-f]{48}$/', $state) || !hash_equals($ck, $state)) $back('state');
  $st = zoho_get($pdo, 'zs:' . sha1($state)); zoho_del($pdo, 'zs:' . sha1($state));
  if (!$st || (int)$st['exp'] < time()) $back('state');
  $ip = client_ip();
  if (rl_blocked($pdo, "login:fail:$ip", sec_num('login_fail_per_ip', 60), 600)) $back('busy');
  $code = (string)($_GET['code'] ?? '');
  if (isset($_GET['error']) || !preg_match('/^[A-Za-z0-9._-]{10,300}$/', $code)) $back('denied');
  $acc = rtrim((string)($_GET['accounts-server'] ?? ''), '/'); if (!preg_match(ZOHO_ACCOUNTS_RX, $acc)) $acc = zoho_cfg()['accounts_url'];
  try {
    $r = zoho_token_call($acc, ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => (string)zoho_redirect_uri($pdo)]);
  } catch (ZohoError $e) { error_log('wwp zoho: ' . $e->getMessage()); $back('token'); }
  $j = $r['json']; $api = rtrim((string)($j['api_domain'] ?? ''), '/');
  $c = zoho_id_claims((string)($j['id_token'] ?? ''));
  if (empty($j['access_token']) || !preg_match(ZOHO_API_RX, $api) || $c === null) {
    error_log('wwp zoho: sign-in failed: ' . ($j['error'] ?? (empty($j['id_token']) ? 'no id_token' : ($c === null ? 'bad id_token' : 'HTTP ' . $r['code']))));
    $back('token');
  }
  $email = strtolower(trim((string)($c['email'] ?? '')));
  $verified = ($c['email_verified'] ?? false) === true || ($c['email_verified'] ?? '') === 'true';
  if ($email === '' || !$verified || !zoho_is_admin($email)) {
    zoho_revoke($acc, (string)($j['refresh_token'] ?? $j['access_token'])); /* the game keeps nothing from this sign-in */
    rl_hit($pdo, "login:fail:$ip", 600); sec_event($pdo, sess_current($pdo), 'login_fail', 'admin zoho ' . ($email ?: '(no email)') . ($verified ? '' : ' unverified'));
    $back($email !== '' && !$verified ? 'unverified' : 'notallowed');
  }
  /* this admin's Zoho access for the import; a new refresh token replaces (and revokes) the previous one */
  $prev = zoho_get($pdo, zoho_ukey($email));
  $refresh = (string)($j['refresh_token'] ?? '');
  if ($refresh !== '' && !empty($prev['refresh']) && $prev['refresh'] !== $refresh) zoho_revoke((string)$prev['accounts'], (string)$prev['refresh']);
  zoho_put($pdo, zoho_ukey($email), ['email' => $email, 'refresh' => $refresh !== '' ? $refresh : (string)($prev['refresh'] ?? ''), 'accounts' => $acc, 'api' => $api,
    'token' => (string)$j['access_token'], 'exp' => time() + (int)($j['expires_in'] ?? 3600), 'at' => now_ms()]);
  sess_destroy($pdo); $N = sess_create($pdo, 'admin', zoho_subj($email), '', !empty($st['keep']));
  sec_event($pdo, $N, 'login_ok', 'admin zoho ' . $email);
  $back('ok');
}
/* signing out of the game: the last session of a Zoho admin also gives the Zoho access back */
function zoho_signout(PDO $pdo, array $S): void {
  if (empty($S['zoho'])) return;
  $s = $pdo->prepare(q('SELECT COUNT(*) FROM {sessions} WHERE subj=? AND sid<>? AND expires>?')); $s->execute([zoho_subj($S['zoho']), (string)$S['sid'], time()]);
  if ((int)$s->fetchColumn() > 0) return;
  $u = zoho_get($pdo, zoho_ukey($S['zoho']));
  if ($u && !empty($u['refresh'])) zoho_revoke((string)$u['accounts'], (string)$u['refresh']);
  zoho_del($pdo, zoho_ukey($S['zoho']));
}

/* A valid access token and the API server of the signed-in Zoho admin; refreshed when it is about to expire */
function zoho_access(PDO $pdo, string $email, bool $fresh = false): array {
  $again = 'Your Zoho sign-in has expired. Sign out, then sign in with Zoho again to import from Zoho CRM.';
  $u = zoho_get($pdo, zoho_ukey($email));
  if (!$u) throw new ZohoError('zoho_signin', $again);
  if (!$fresh && (int)$u['exp'] > time() + 60) return [(string)$u['token'], (string)$u['api']];
  if (empty($u['refresh'])) throw new ZohoError('zoho_signin', $again);
  $r = zoho_token_call((string)$u['accounts'], ['grant_type' => 'refresh_token', 'refresh_token' => (string)$u['refresh']]);
  $j = $r['json'];
  if (!empty($j['access_token'])) {
    $u['token'] = (string)$j['access_token']; $u['exp'] = time() + (int)($j['expires_in'] ?? 3600);
    zoho_put($pdo, zoho_ukey($email), $u);
    return [$u['token'], (string)$u['api']];
  }
  if (in_array($j['error'] ?? '', ['invalid_code', 'invalid_token'], true)) { zoho_del($pdo, zoho_ukey($email)); throw new ZohoError('zoho_signin', $again); } /* revoked in Zoho, or the client changed */
  throw new ZohoError('zoho_error', 'Zoho refused the connection (' . ($j['error'] ?? ('HTTP ' . $r['code'])) . ').');
}

/* The active users of the CRM, read as the signed-in Zoho admin: [{id, name, email, role, profile}] */
function zoho_users(PDO $pdo, string $email): array {
  [$tok, $api] = zoho_access($pdo, $email);
  $known = zoho_get($pdo, 'zoho_ver')['v'] ?? null;
  $versions = array_values(array_unique(array_filter(array_merge([$known], ZOHO_VERSIONS))));
  $retried = false;
  foreach ($versions as $v) {
    $out = [];
    for ($page = 1; $page <= 25; $page++) {
      $r = zoho_http('GET', "$api/crm/$v/users?" . http_build_query(['type' => 'ActiveUsers', 'page' => $page, 'per_page' => 200]), null, $tok);
      $zc = (string)($r['json']['code'] ?? '');
      if ($r['code'] === 401 && !$retried) { $retried = true; [$tok] = zoho_access($pdo, $email, true); $page--; continue; }
      if ($page === 1 && ($r['code'] === 404 || in_array($zc, ['INVALID_URL_PATTERN', 'API_NOT_SUPPORTED'], true))) continue 2; /* this API version doesn't exist (any more) */
      if ($r['code'] === 204) break;
      if ($r['code'] === 401 || $zc === 'OAUTH_SCOPE_MISMATCH' || $zc === 'NO_PERMISSION')
        throw new ZohoError('zoho_error', 'Your Zoho account may not read the CRM users (' . ($zc ?: 'HTTP 401') . '). Ask the Zoho CRM admins for access to the users list.');
      if ($r['code'] !== 200) throw new ZohoError('zoho_error', 'Zoho CRM answered with an error (' . ($zc ?: 'HTTP ' . $r['code']) . ').');
      foreach ((array)($r['json']['users'] ?? []) as $u) {
        if (!is_array($u) || strtolower((string)($u['status'] ?? 'active')) !== 'active') continue;
        $name = trim((string)($u['full_name'] ?? '')) ?: trim(((string)($u['first_name'] ?? '')) . ' ' . ((string)($u['last_name'] ?? '')));
        $out[] = ['id' => (string)($u['id'] ?? ''), 'name' => $name, 'email' => strtolower(trim((string)($u['email'] ?? ''))),
                  'role' => (string)($u['role']['name'] ?? ''), 'profile' => (string)($u['profile']['name'] ?? '')];
      }
      if (empty($r['json']['info']['more_records'])) break;
    }
    if ($v !== $known) zoho_put($pdo, 'zoho_ver', ['v' => $v]);
    return $out;
  }
  throw new ZohoError('zoho_error', 'This Zoho CRM account doesn\'t answer any known API version.');
}
