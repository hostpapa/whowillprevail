<?php
/* Who Will Prevail: emails. The server writes the invitation / password-reset / new-move emails itself (same text as
   the game always used), creates their one-time links, and sends them through the service set in config.php.
   Loaded by api.php; it is not meant to be opened directly. */
defined('WWP') or exit;

function mail_cfg(): array { global $CFG; return (array)($CFG['mail'] ?? []); }
function mail_enabled(): bool { $m = mail_cfg(); return !empty($m['provider']) && (!empty($m['key']) || !empty($m['url'])); }

/* One message through an email service over HTTPS (the usual SMTP ports are blocked on many hostings). */
function http_mail(array $m, string $from, string $fromName, string $to, string $subject, string $html, string $text): void {
  $key = (string)($m['key'] ?? '');
  switch (strtolower((string)$m['provider'])) {
    case 'webhook': /* e.g. a Zapier "Catch Hook"; the Zap then sends the email */
      $url = (string)($m['url'] ?? ''); $hdr = [];
      if (!preg_match('~^(https://|http://(127\.0\.0\.1|localhost)[:/])~', $url)) throw new RuntimeException('webhook url must start with https://');
      $body = ['to' => $to, 'from' => $from, 'from_name' => $fromName, 'subject' => $subject, 'html' => $html, 'text' => $text];
      if (!empty($m['secret'])) $body['secret'] = (string)$m['secret']; /* lets the Zap ignore calls that don't carry it */
      break;
    case 'brevo':
      $url = 'https://api.brevo.com/v3/smtp/email'; $hdr = ['api-key: ' . $key];
      $body = ['sender' => ['name' => $fromName, 'email' => $from], 'to' => [['email' => $to]], 'subject' => $subject, 'htmlContent' => $html, 'textContent' => $text];
      break;
    case 'sendgrid':
      $url = 'https://api.sendgrid.com/v3/mail/send'; $hdr = ['Authorization: Bearer ' . $key];
      $body = ['personalizations' => [['to' => [['email' => $to]]]], 'from' => ['email' => $from, 'name' => $fromName], 'subject' => $subject,
               'content' => [['type' => 'text/plain', 'value' => $text], ['type' => 'text/html', 'value' => $html]]];
      break;
    case 'resend':
      $url = 'https://api.resend.com/emails'; $hdr = ['Authorization: Bearer ' . $key];
      $body = ['from' => "$fromName <$from>", 'to' => [$to], 'subject' => $subject, 'html' => $html, 'text' => $text];
      break;
    default: throw new RuntimeException('unknown provider "' . $m['provider'] . '" (use webhook, brevo, sendgrid or resend)');
  }
  $ch = curl_init($url);
  curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 8,
    CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json', 'Accept: application/json'], $hdr),
    CURLOPT_POSTFIELDS => json_encode($body, JF)]);
  $resp = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); if (PHP_VERSION_ID < 80000) curl_close($ch); /* a no-op (and deprecated) since PHP 8 */
  if ($resp === false) throw new RuntimeException('cannot reach the service (' . $err . ')');
  if ($code < 200 || $code >= 300) throw new RuntimeException("HTTP $code " . substr(trim((string)$resp), 0, 300));
}

/* Tries to send one email. Returns ['ok'=>true] or ['ok'=>false,'err'=>why]; it never ends the request, so callers can
   fall back to the admin outbox. Only players that have an account may be emailed (and, while testing, only the
   addresses in mail.allowed_recipients). $test skips the account check, for the diagnostics page. */
function mail_try(PDO $pdo, array $msg, bool $test = false): array {
  $m = mail_cfg();
  $to = strtolower(trim((string)($msg['to'] ?? '')));
  if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return ['ok' => false, 'err' => 'Bad recipient address.'];
  $allow = array_map('strtolower', (array)($m['allowed_recipients'] ?? []));
  if ($allow && !in_array($to, $allow, true)) return ['ok' => false, 'err' => 'This address is not on mail.allowed_recipients in config.php.'];
  if ($test) { if (!$allow) return ['ok' => false, 'err' => 'For the mail test, put the address into mail.allowed_recipients in config.php first.']; }
  else {
    $known = false;
    foreach ($pdo->query(q("SELECT data FROM {docs} WHERE col='accounts'"))->fetchAll(PDO::FETCH_COLUMN) as $j) {
      $d = json_decode((string)$j);
      if (is_object($d) && strtolower((string)($d->email ?? '')) === $to) { $known = true; break; }
    }
    if (!$known) return ['ok' => false, 'err' => 'No player account has this address.'];
  }
  $now = time();
  $pdo->exec(q('DELETE FROM {mail_log} WHERE ts < ' . ($now - 3600)));
  $all = (int)$pdo->query(q('SELECT COUNT(*) FROM {mail_log} WHERE ts >= ' . ($now - 60)))->fetchColumn();
  $st = $pdo->prepare(q('SELECT COUNT(*) FROM {mail_log} WHERE ts >= ? AND rcpt=?')); $st->execute([$now - 60, $to]);
  if ($all >= (int)($m['max_per_minute'] ?? 300) || (int)$st->fetchColumn() >= (int)($m['max_per_recipient_per_minute'] ?? 20))
    return ['ok' => false, 'err' => 'Too many emails in a minute.'];
  $gu = game_url($pdo); $host = $gu ? (string)parse_url($gu, PHP_URL_HOST) : ''; if ($host === '') $host = 'localhost'; /* never from the request */
  $from = (string)($m['from'] ?? ''); if ($from === '') $from = 'noreply@' . $host;
  $fromName = (string)($m['from_name'] ?? 'Who Will Prevail?');
  $subject = substr(str_replace(["\r", "\n"], ' ', (string)($msg['subject'] ?? '')), 0, 300);
  $html = substr((string)($msg['html'] ?? ''), 0, 300000); $text = substr((string)($msg['text'] ?? ''), 0, 100000);
  try { http_mail($m, $from, $fromName, $to, $subject, $html, $text); }
  catch (Throwable $e) { return ['ok' => false, 'err' => 'Email service: ' . $e->getMessage()]; }
  $pdo->prepare(q('INSERT INTO {mail_log}(ts,rcpt) VALUES(?,?)'))->execute([$now, $to]);
  return ['ok' => true, 'to' => $to, 'from' => $from, 'provider' => $m['provider']];
}

/* The address the links in emails point to. It is NEVER taken from the request (a forged Host header could aim the
   one-time links at someone else's server). In order: Branding "Game link", config security.game_url, and, only for calls
   an admin makes while signed in, $hint (the address of the page the admin is looking at). null = not known. */
function game_url(PDO $pdo, ?string $hint = null): ?string {
  $clean = function (string $u): ?string { return preg_match('~^https?://[^\s/#?@\\\\]+(/[^\s#?\\\\]*)?$~i', $u) ? preg_replace('/#.*$/', '', $u) : null; };
  $b = readDoc($pdo, 'settings/brand'); $u = is_object($b) ? trim((string)($b->gameUrl ?? '')) : '';
  if (preg_match('~^https://~i', $u) && ($r = $clean($u))) return $r;
  if (($r = $clean(trim((string)(sec_cfg()['game_url'] ?? ''))))) return $r;
  if ($hint !== null && ($r = $clean(trim($hint)))) return $r;
  return null;
}

/* ---------- text of the emails ---------- */
function h(string $s): string { return strtr($s, ['&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;', "'" => '&#39;']); } /* the same escapes the game used */
function mail_tz(): DateTimeZone { try { return new DateTimeZone((string)(sec_cfg()['timezone'] ?? 'UTC')); } catch (Throwable $e) { return new DateTimeZone('UTC'); } }
/* en-US / es-MX / pt-BR date strings like the browser produced ($exact adds the weekday and the time zone) */
function fmt_dt(int $ms, string $loc, bool $exact): string {
  $d = (new DateTime('@' . intdiv($ms, 1000)))->setTimezone(mail_tz());
  $mo = (int)$d->format('n') - 1; $wd = (int)$d->format('w'); $day = $d->format('j'); $yr = $d->format('Y');
  $h24 = (int)$d->format('G'); $mi = $d->format('i'); $off = (int)round($d->getOffset() / 3600);
  $zEn = $d->format('T'); $zGmt = $off === 0 ? 'UTC' : 'GMT' . ($off > 0 ? '+' : '') . $off;
  if ($loc === 'es-MX') {
    $M = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic']; $W = ['dom', 'lun', 'mar', 'mié', 'jue', 'vie', 'sáb'];
    $t = (($h24 % 12) ?: 12) . ':' . $mi . ' ' . ($h24 < 12 ? 'a.m.' : 'p.m.');
    return ($exact ? $W[$wd] . ', ' . "$day de {$M[$mo]} de $yr, $t $zGmt" : "$day {$M[$mo]} $yr, $t");
  }
  if ($loc === 'pt-BR') {
    $M = ['jan.', 'fev.', 'mar.', 'abr.', 'mai.', 'jun.', 'jul.', 'ago.', 'set.', 'out.', 'nov.', 'dez.']; $W = ['dom.', 'seg.', 'ter.', 'qua.', 'qui.', 'sex.', 'sáb.'];
    return ($exact ? $W[$wd] . ', ' : '') . "$day de {$M[$mo]} de $yr, " . sprintf('%02d:%s', $h24, $mi) . ($exact ? " $zGmt" : '');
  }
  $M = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']; $W = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return ($exact ? $W[$wd] . ', ' : '') . "{$M[$mo]} $day, $yr, " . (($h24 % 12) ?: 12) . ':' . $mi . ' ' . ($h24 < 12 ? 'AM' : 'PM') . ($exact ? " $zEn" : '');
}
/* what an admin may see on screen: the link with its secret part hidden */
function mask_link(string $l): string {
  return preg_replace('/(#mv\.)[0-9a-f]{20}\.[0-9a-f]{64}$/', '$1••••••••', preg_replace('/(#(?:inv|rst)\.)[0-9a-f]{32}\.[0-9a-f]{64}$/', '$1••••••••', $l));
}
function mail_frame(string $inner): string {
  return '<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;background:#e9eef3;padding:16px">
<div style="background:#15151c;border-radius:8px 8px 0 0;padding:16px 20px"><div style="font-family:Impact,\'Arial Black\',sans-serif;font-size:30px;letter-spacing:1px;color:#ffd319">Who Will <span style="color:#fff">Prevail?</span></div></div>
<div style="background:#fff;border:3px solid #15151c;border-top:0;border-radius:0 0 8px 8px;padding:20px;color:#15151c;font-size:15px;line-height:1.5">
' . $inner . '
</div></div>';
}
function tpl_invite(string $kind, string $name, string $link, int $expMs): array {
  $exp = fmt_dt($expMs, 'en-US', false); $expEs = fmt_dt($expMs, 'es-MX', false); $expPt = fmt_dt($expMs, 'pt-BR', false);
  $inv = $kind === 'invite'; $n = h($name);
  $subject = $inv ? "You're invited to Who Will Prevail? Create your password" : 'Reset your Who Will Prevail? password';
  $btn = $inv ? 'Create your password' : 'Reset your password';
  $lead = $inv ? "$n, you've been drafted into <b>Who Will Prevail?</b>, the sales showdown where every sale is a move in the battle between Heroes and Villains." : "$n, we received a request to reset your password for <b>Who Will Prevail?</b>.";
  $leadEs = $inv ? "$n, te invitaron a <b>¿Quién Prevalecerá?</b>, el duelo de ventas donde cada venta es una jugada en la batalla entre Héroes y Villanos." : "$n, recibimos una solicitud para restablecer tu contraseña de <b>¿Quién Prevalecerá?</b>.";
  $leadPt = $inv ? "$n, você foi convocado para o <b>Quem Vai Prevalecer?</b>, o duelo de vendas em que cada venda é uma jogada na batalha entre Heróis e Vilões." : "$n, recebemos um pedido para redefinir sua senha do <b>Quem Vai Prevalecer?</b>.";
  $html = function (string $lk) use ($inv, $lead, $leadEs, $leadPt, $btn, $exp, $expEs, $expPt): string {
    return mail_frame('<p style="margin:0 0 12px">' . $lead . '</p>
<p style="margin:0 0 18px">' . ($inv ? "Set your own password to join the Arena. You'll sign in with this email address." : "Choose a new password with the button below. If you didn't ask for this, you can ignore this email and your password stays the same.") . '</p>
<p style="margin:0 0 18px;text-align:center"><a href="' . h($lk) . '" style="display:inline-block;background:#ffd319;color:#15151c;border:3px solid #15151c;border-radius:6px;padding:12px 22px;font-weight:bold;text-decoration:none;font-size:16px">' . $btn . '</a></p>
<p style="margin:0 0 6px;font-size:13px;color:#4a4e5c">This link works once and expires ' . h($exp) . '. If it has expired or was already used, ' . ($inv ? 'ask your game admin to resend your invitation' : 'go to the sign-in page and choose Forgot password? again') . '.</p>
<p style="margin:0 0 14px;font-size:12px;color:#4a4e5c;word-break:break-all">If the button doesn\'t work, copy this link into your browser: ' . h($lk) . '</p>
<hr style="border:0;border-top:2px dashed #cfd5de;margin:14px 0">
<p style="margin:0 0 6px;font-size:13px">' . $leadEs . '</p>
<p style="margin:0;font-size:12px;color:#4a4e5c">' . ($inv ? 'Usa el botón para crear tu contraseña.' : 'Usa el botón para elegir una nueva contraseña.') . ' El enlace funciona una sola vez y vence el ' . h($expEs) . '. ' . ($inv ? 'Si venció, pídele a tu admin del juego que reenvíe la invitación.' : 'Si venció, vuelve a elegir ¿Olvidaste tu contraseña? en la pantalla de inicio de sesión.') . '</p>
<hr style="border:0;border-top:2px dashed #cfd5de;margin:14px 0">
<p style="margin:0 0 6px;font-size:13px">' . $leadPt . '</p>
<p style="margin:0;font-size:12px;color:#4a4e5c">' . ($inv ? 'Use o botão para criar sua senha.' : 'Use o botão para escolher uma nova senha.') . ' O link funciona uma única vez e expira em ' . h($expPt) . '. ' . ($inv ? 'Se tiver expirado, peça ao admin do jogo para reenviar o convite.' : 'Se tiver expirado, escolha Esqueceu a senha? de novo na tela de entrada.') . '</p>');
  };
  $text = ($inv ? "$name, you've been invited to Who Will Prevail?, the sales showdown. Set your own password to join; you'll sign in with this email address." : "$name, we received a request to reset your Who Will Prevail? password. If you didn't ask for this, ignore this email.")
    . "\n\n$btn: $link\n\nThis link works once and expires $exp. " . ($inv ? 'If it expires, ask your game admin to resend your invitation.' : 'If it expires, choose Forgot password? on the sign-in page again.')
    . "\n\n— " . ($inv ? 'Te invitaron a ¿Quién Prevalecerá? Crea tu contraseña con el enlace de arriba.' : 'Usa el enlace de arriba para restablecer tu contraseña.') . " El enlace funciona una sola vez y vence el $expEs."
    . "\n\n— " . ($inv ? 'Você foi convidado para o Quem Vai Prevalecer? Crie sua senha com o link acima.' : 'Use o link acima para redefinir sua senha.') . " O link funciona uma única vez e expira em $expPt.";
  return ['subject' => $subject, 'html' => $html($link), 'text' => $text, 'preview' => $html(mask_link($link))];
}
function tpl_move(string $name, object $prod, string $domain, int $expMs, string $link): array {
  $exp = fmt_dt($expMs, 'en-US', true); $expEs = fmt_dt($expMs, 'es-MX', true); $expPt = fmt_dt($expMs, 'pt-BR', true);
  $subject = "You've Earned a New Move! Your 72-Hour Countdown Starts Now";
  $pn = (string)($prod->name ?? ''); $n = h($name);
  $row = function (string $k, string $v): string { return '<tr><td style="padding:6px 10px;font-size:13px;color:#4a4e5c;white-space:nowrap">' . $k . '</td><td style="padding:6px 10px;font-weight:bold">' . h($v) . '</td></tr>'; };
  $html = function (string $lk) use ($n, $pn, $domain, $exp, $expEs, $expPt, $row): string {
    return mail_frame('<p style="margin:0 0 12px">' . $n . ', your sale just earned you a <b>new move</b> in Who Will Prevail? Your 72-hour countdown has started.</p>
<table style="border-collapse:collapse;width:100%;margin:0 0 16px;border:2px solid #15151c;border-radius:6px">' . $row('Product sold', $pn) . $row('Customer domain', $domain) . $row('Make your move by', $exp) . '</table>
<p style="margin:0 0 18px;text-align:center"><a href="' . h($lk) . '" style="display:inline-block;background:#ffd319;color:#15151c;border:3px solid #15151c;border-radius:6px;padding:12px 26px;font-weight:bold;text-decoration:none;font-size:18px;letter-spacing:1px">MAKE YOUR MOVE</a></p>
<p style="margin:0 0 6px;font-size:13px;color:#4a4e5c">The button opens the game\'s sign-in page. Sign in with your email address and password and this move will be waiting for you. The link only works for your account. If the move isn\'t made by the time above, it expires.</p>
<p style="margin:0 0 14px;font-size:12px;color:#4a4e5c;word-break:break-all">If the button doesn\'t work, copy this link into your browser: ' . h($lk) . '</p>
<hr style="border:0;border-top:2px dashed #cfd5de;margin:14px 0">
<p style="margin:0 0 6px;font-size:13px">' . $n . ', tu venta te ganó una <b>nueva jugada</b> en ¿Quién Prevalecerá? (' . h($pn) . ' · ' . h($domain) . ').</p>
<p style="margin:0;font-size:12px;color:#4a4e5c">Usa el botón MAKE YOUR MOVE para iniciar sesión con tu correo y contraseña. Tienes hasta el ' . h($expEs) . '.</p>
<hr style="border:0;border-top:2px dashed #cfd5de;margin:14px 0">
<p style="margin:0 0 6px;font-size:13px">' . $n . ', sua venda rendeu uma <b>nova jogada</b> no Quem Vai Prevalecer? (' . h($pn) . ' · ' . h($domain) . ').</p>
<p style="margin:0;font-size:12px;color:#4a4e5c">Use o botão MAKE YOUR MOVE para entrar com seu e-mail e senha. Você tem até ' . h($expPt) . '.</p>');
  };
  $text = "$name, your sale just earned you a new move in Who Will Prevail? Your 72-hour countdown has started.\n\nProduct sold: $pn\nCustomer domain: $domain\nMake your move by: $exp\n\nMAKE YOUR MOVE: $link\n\nThe link opens the game's sign-in page. Sign in with your email address and password and the move will be waiting for you. It only works for your account.\n\n— Tu venta te ganó una nueva jugada ($pn · $domain). Inicia sesión con el enlace de arriba antes del $expEs.\n\n— Sua venda rendeu uma nova jogada ($pn · $domain). Entre pelo link acima até $expPt.";
  return ['subject' => $subject, 'html' => $html($link), 'text' => $text, 'preview' => $html(mask_link($link))];
}

/* ---------- links and emails the server creates on request ---------- */
/* a fresh single-use invitation / reset link for an account (any earlier link stops working), emailed if a service is set up.
   When it cannot be emailed, the message is handed back so the admin can use the outbox. */
function issue_link(PDO $pdo, string $key, string $purpose, ?string $base = null): array {
  $a = readDoc($pdo, 'accounts/' . $key); if (!is_object($a)) return ['error' => 'no-account'];
  $gu = game_url($pdo, $base); if ($gu === null) return ['error' => 'no_game_url']; /* before anything is changed */
  $p = isset($a->pid) ? readDoc($pdo, 'players/' . $a->pid) : null;
  $token = rhex(32); $now = now_ms();
  $exp = $now + ($purpose === 'invite' ? sec_num('invite_ttl_hours', 168) : sec_num('reset_ttl_hours', 24)) * 3600000;
  $fields = ['tok' => ['h' => hash('sha256', $token), 'purpose' => $purpose, 'exp' => $exp]]
    + ($purpose === 'invite' ? ['status' => 'pending', 'invitedAt' => $now, 'sentAt' => null, 'failReason' => null] : ['resetRequestedAt' => null, 'resetIssuedAt' => $now]);
  doc_patch($pdo, 'accounts/' . $key, $fields);
  $link = $gu . '#' . ($purpose === 'invite' ? 'inv' : 'rst') . '.' . $key . '.' . $token;
  $name = (is_object($p) && ($p->name ?? '') !== '') ? (string)$p->name : (string)$a->email;
  $msg = ['to' => (string)$a->email, 'key' => $key, 'purpose' => $purpose, 'name' => $name, 'exp' => $exp] + tpl_invite($purpose, $name, $link, $exp) + ['link' => $link];
  $res = mail_enabled() ? mail_try($pdo, $msg) : ['ok' => false, 'err' => null];
  if (!empty($res['ok'])) {
    $cur = readDoc($pdo, 'accounts/' . $key);
    if ($purpose === 'invite') { if (!is_object($cur) || ($cur->status ?? '') !== 'active') doc_patch($pdo, 'accounts/' . $key, ['status' => 'sent', 'sentAt' => now_ms(), 'failReason' => null]); }
    else doc_patch($pdo, 'accounts/' . $key, ['resetSentAt' => now_ms()]);
    return ['ok' => true, 'queued' => false];
  }
  return ['ok' => true, 'queued' => true, 'msg' => $msg, 'mailError' => $res['err'] ?? null];
}
/* the "new move" email for an existing move, with a fresh link (the earlier one stops working) */
function send_move_email(PDO $pdo, string $id, int $tries, ?string $base = null): array {
  $m = readDoc($pdo, 'moves/' . $id); if (!is_object($m)) return ['error' => 'gone'];
  $gu = game_url($pdo, $base); if ($gu === null) return ['error' => 'no_game_url'];
  $token = rhex(32); $now = now_ms();
  doc_patch($pdo, 'moves/' . $id, ['tok' => ['h' => hash('sha256', $token), 'at' => $now], 'mail' => ['status' => 'pending', 'at' => $now, 'tries' => $tries, 'reason' => null]]);
  $link = $gu . '#mv.' . $id . '.' . $token;
  $msg = ['to' => (string)($m->email ?? ''), 'key' => $id, 'purpose' => 'move', 'name' => (string)($m->rep ?? ''), 'exp' => (int)($m->expiresAt ?? 0)]
    + tpl_move((string)($m->rep ?? ''), is_object($m->product ?? null) ? $m->product : new stdClass(), (string)($m->domain ?? ''), (int)($m->expiresAt ?? 0), $link) + ['link' => $link];
  $res = mail_enabled() ? mail_try($pdo, $msg) : ['ok' => false, 'err' => null];
  if (!empty($res['ok'])) { doc_patch($pdo, 'moves/' . $id, ['mail' => ['status' => 'sent', 'at' => now_ms()]]); return ['ok' => true, 'queued' => false]; }
  return ['ok' => true, 'queued' => true, 'msg' => $msg, 'mailError' => $res['err'] ?? null];
}
