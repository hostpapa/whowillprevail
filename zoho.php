<?php
/* Who Will Prevail: Zoho CRM connection for the player import (admin only). Included by api.php.
   The Zoho client is a "Server-based Application" (Zoho API Console); its ID and secret live in config.local.php
   ('zoho' block), never in the page. An admin connects once ("Connect Zoho CRM"): Zoho sends them back to
   zoho-callback.php, which swaps the one-time code for a refresh token. The token is kept encrypted in the {secrets}
   table, which the page can't read. The import only reads the active CRM users (scope ZohoCRM.users.READ). */
if (!defined('WWP')) { http_response_code(404); exit; }

const ZOHO_SCOPE = 'ZohoCRM.users.READ';
const ZOHO_VERSIONS = ['v8', 'v7', 'v6', 'v2']; /* newest first; the first one this account answers is remembered */
/* Zoho data centers: the sign-in server (accounts) and the API server must be one of these */
const ZOHO_ACCOUNTS_RX = '~^https://accounts\.(zoho\.(com|eu|in|com\.au|jp|sa|uk|com\.cn)|zohocloud\.ca)$~';
const ZOHO_API_RX = '~^https://(www\.)?zohoapis\.(com|eu|in|com\.au|jp|sa|uk|com\.cn|ca)$~';

class ZohoError extends RuntimeException {
  public $zcode;
  public function __construct(string $zcode, string $msg) { parent::__construct($msg); $this->zcode = $zcode; }
}

function zoho_cfg(): array {
  global $CFG; $z = (array)($CFG['zoho'] ?? []);
  $acc = rtrim(trim((string)($z['accounts_url'] ?? '')), '/');
  return ['client_id' => trim((string)($z['client_id'] ?? '')), 'client_secret' => trim((string)($z['client_secret'] ?? '')),
          'accounts_url' => preg_match(ZOHO_ACCOUNTS_RX, $acc) ? $acc : 'https://accounts.zohocloud.ca'];
}
function zoho_configured(): bool { $c = zoho_cfg(); return $c['client_id'] !== '' && $c['client_secret'] !== ''; }

/* The address Zoho sends the admin back to; it must be listed as a Redirect URI of the Zoho client */
function zoho_redirect_uri(PDO $pdo): ?string {
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
  return is_array($d) ? $d : null; /* null also when the client secret changed: the admin connects again */
}
function zoho_put(PDO $pdo, string $k, array $v): void {
  $iv = random_bytes(12); $tag = '';
  $c = openssl_encrypt(json_encode($v, JF), 'aes-256-gcm', zoho_key(), OPENSSL_RAW_DATA, $iv, $tag);
  upsert($pdo, '{secrets}', 'k', ['k' => $k, 'v' => base64_encode($iv . $tag . $c), 'ts' => time()]);
}
function zoho_del(PDO $pdo, string $k): void { $pdo->prepare(q('DELETE FROM {secrets} WHERE k=?'))->execute([$k]); }

/* ---------- HTTP ---------- */
function zoho_http(string $method, string $url, ?array $form = null, ?string $token = null): array {
  if (!function_exists('curl_init')) throw new ZohoError('zoho_error', 'The PHP extension curl is not enabled on this hosting.');
  $ch = curl_init($url);
  $hdr = ['Accept: application/json']; if ($token !== null) $hdr[] = 'Authorization: Zoho-oauthtoken ' . $token;
  $opt = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_HTTPHEADER => $hdr];
  if ($method === 'POST') { $opt[CURLOPT_POST] = true; $opt[CURLOPT_POSTFIELDS] = http_build_query((array)$form); }
  curl_setopt_array($ch, $opt);
  $resp = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); if (PHP_VERSION_ID < 80000) curl_close($ch);
  if ($resp === false) throw new ZohoError('zoho_error', 'Zoho CRM can\'t be reached from this server (' . $err . ').');
  $j = json_decode((string)$resp, true);
  return ['code' => $code, 'json' => is_array($j) ? $j : []];
}
function zoho_token_call(string $accounts, array $form): array {
  $c = zoho_cfg();
  return zoho_http('POST', $accounts . '/oauth/v2/token', $form + ['client_id' => $c['client_id'], 'client_secret' => $c['client_secret']]);
}

/* ---------- connection ---------- */
function zoho_status(PDO $pdo): array {
  $conn = zoho_configured() ? zoho_get($pdo, 'zoho') : null;
  return ['configured' => zoho_configured(), 'connected' => !empty($conn['refresh']), 'connectedAt' => $conn['at'] ?? null,
          'redirectUri' => zoho_redirect_uri($pdo)];
}
function zoho_auth_url(PDO $pdo, array $S): string {
  if (!zoho_configured()) throw new ZohoError('zoho_not_configured', 'Zoho CRM is not set up on this server.');
  $redirect = zoho_redirect_uri($pdo);
  if ($redirect === null) throw new ZohoError('no_game_url', 'Set the Game link in Branding (or game_url in config.php) first, so Zoho knows where to send you back.');
  $state = rhex(24);
  zoho_put($pdo, 'zoho_state', ['state' => $state, 'sid' => $S['sid'], 'exp' => time() + 900]);
  return zoho_cfg()['accounts_url'] . '/oauth/v2/auth?' . http_build_query(['scope' => ZOHO_SCOPE, 'client_id' => zoho_cfg()['client_id'],
    'response_type' => 'code', 'access_type' => 'offline', 'prompt' => 'consent', 'redirect_uri' => $redirect, 'state' => $state]);
}
/* zoho-callback.php: back from Zoho's sign-in. Always ends with a redirect to the game, #zoho.<result> */
function zoho_callback(PDO $pdo, array $S): void {
  $back = function (string $what) use ($pdo) {
    $g = game_url($pdo); header('Location: ' . ($g === null ? './' : preg_replace('/#.*$/', '', $g)) . '#zoho.' . $what, true, 303); exit;
  };
  if ($S['role'] !== 'admin') $back('signin');
  $st = zoho_get($pdo, 'zoho_state'); zoho_del($pdo, 'zoho_state');
  if (!$st || !hash_equals((string)$st['state'], (string)($_GET['state'] ?? '')) || ($st['sid'] ?? '') !== $S['sid'] || (int)$st['exp'] < time()) $back('state');
  $code = (string)($_GET['code'] ?? '');
  if (isset($_GET['error']) || !preg_match('/^[A-Za-z0-9._-]{10,300}$/', $code)) $back('denied');
  $acc = rtrim((string)($_GET['accounts-server'] ?? ''), '/'); if (!preg_match(ZOHO_ACCOUNTS_RX, $acc)) $acc = zoho_cfg()['accounts_url'];
  try {
    $r = zoho_token_call($acc, ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => (string)zoho_redirect_uri($pdo)]);
  } catch (ZohoError $e) { error_log('wwp zoho: ' . $e->getMessage()); $back('token'); }
  $j = $r['json']; $api = rtrim((string)($j['api_domain'] ?? ''), '/');
  if (empty($j['refresh_token']) || empty($j['access_token']) || !preg_match(ZOHO_API_RX, $api)) {
    error_log('wwp zoho: token exchange failed: ' . ($j['error'] ?? ('HTTP ' . $r['code']))); $back('token');
  }
  zoho_put($pdo, 'zoho', ['refresh' => (string)$j['refresh_token'], 'accounts' => $acc, 'api' => $api, 'at' => now_ms()]);
  zoho_put($pdo, 'zoho_at', ['token' => (string)$j['access_token'], 'exp' => time() + (int)($j['expires_in'] ?? 3600)]);
  sec_event($pdo, $S, 'zoho', 'connected');
  $back('ok');
}
function zoho_disconnect(PDO $pdo): void {
  $conn = zoho_get($pdo, 'zoho');
  if ($conn && !empty($conn['refresh'])) {
    try { zoho_http('POST', $conn['accounts'] . '/oauth/v2/token/revoke', ['token' => $conn['refresh']]); } catch (Throwable $e) {} /* best effort */
  }
  foreach (['zoho', 'zoho_at', 'zoho_state', 'zoho_ver'] as $k) zoho_del($pdo, $k);
}

/* A valid access token and the API server; refreshed with the stored refresh token when it is about to expire */
function zoho_access(PDO $pdo, bool $fresh = false): array {
  $conn = zoho_get($pdo, 'zoho');
  if (!$conn || empty($conn['refresh'])) throw new ZohoError('zoho_not_connected', 'Connect Zoho CRM first.');
  $at = $fresh ? null : zoho_get($pdo, 'zoho_at');
  if ($at && (int)$at['exp'] > time() + 60) return [(string)$at['token'], (string)$conn['api']];
  $r = zoho_token_call((string)$conn['accounts'], ['grant_type' => 'refresh_token', 'refresh_token' => (string)$conn['refresh']]);
  $j = $r['json'];
  if (!empty($j['access_token'])) {
    zoho_put($pdo, 'zoho_at', ['token' => (string)$j['access_token'], 'exp' => time() + (int)($j['expires_in'] ?? 3600)]);
    return [(string)$j['access_token'], (string)$conn['api']];
  }
  if (in_array($j['error'] ?? '', ['invalid_code', 'invalid_token'], true)) { /* revoked in Zoho, or the client changed */
    foreach (['zoho', 'zoho_at'] as $k) zoho_del($pdo, $k);
    throw new ZohoError('zoho_not_connected', 'The Zoho CRM connection has expired or was removed in Zoho. Connect again.');
  }
  throw new ZohoError('zoho_error', 'Zoho CRM refused the connection (' . ($j['error'] ?? ('HTTP ' . $r['code'])) . ').');
}

/* The active users of the CRM: [{id, name, email, role, profile}] */
function zoho_users(PDO $pdo): array {
  [$tok, $api] = zoho_access($pdo);
  $known = zoho_get($pdo, 'zoho_ver')['v'] ?? null;
  $versions = array_values(array_unique(array_filter(array_merge([$known], ZOHO_VERSIONS))));
  $retried = false;
  foreach ($versions as $v) {
    $out = [];
    for ($page = 1; $page <= 25; $page++) {
      $r = zoho_http('GET', "$api/crm/$v/users?" . http_build_query(['type' => 'ActiveUsers', 'page' => $page, 'per_page' => 200]), null, $tok);
      $zc = (string)($r['json']['code'] ?? '');
      if ($r['code'] === 401 && !$retried) { $retried = true; [$tok] = zoho_access($pdo, true); $page--; continue; }
      if ($page === 1 && ($r['code'] === 404 || in_array($zc, ['INVALID_URL_PATTERN', 'API_NOT_SUPPORTED'], true))) continue 2; /* this API version doesn't exist (any more) */
      if ($r['code'] === 204) break;
      if ($r['code'] === 401 || $zc === 'OAUTH_SCOPE_MISMATCH' || $zc === 'NO_PERMISSION')
        throw new ZohoError('zoho_error', 'The connected Zoho account may not read the CRM users (' . ($zc ?: 'HTTP 401') . '). Connect with an account that can, or ask the Zoho admins to allow ' . ZOHO_SCOPE . '.');
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
