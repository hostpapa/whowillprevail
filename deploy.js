/* Who Will Prevail: FTP deploy into the site root (/public = https://whowillprevail.com/).
     npm run deploy:dry        shows the plan, changes nothing
     npm run deploy -- --yes   deploys
   FTP access: configFtp in configs.js (gitignored, never uploaded): { user, password, host, port, remoteRoot, secure,
   siteUrl }. remoteRoot is the site root (/public). secure: true (default) = FTPS with a verified certificate; false =
   plain FTP (the password travels unencrypted: set it only if the hosting has no FTPS).

   FIRST DEPLOY (the root has no _backup/ folder yet): the game moves from /whowill26 to the root.
     1. the new files are uploaded into _deploy-new/ (the site keeps running meanwhile), with the live config.php of
        /whowill26 (the server's own settings: database, mail, setup key);
     2. the old React app of the root (OLD_APP) and the old game (whowill26/) move into _backup/<date>/; _backup/ is
        closed to the web, so the old copy of the server code can't run there;
     3. the game's data/ folder (old SQLite file, if any) moves to the root, the new files move into place
        (renames: the site is down for a few seconds);
     4. whowill26/ becomes a page that sends visitors to the root, keeping ?query and #hash, so the invitation, reset
        and move links in emails already sent keep working.
   The root also gets a service-worker.js that removes the old React app's service worker from visitors' browsers
   (it would keep showing them the cached old site).
   LATER DEPLOYS upload the game files over the old ones. config.php is uploaded only with --with-config (the server's
   copy holds the live settings); config.local.php (Zoho client) when it exists locally. */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const ftp = require('basic-ftp');

const FILES = ['index.html', 'claude-shim.js', 'api.php', 'security.php', 'mailer.php', 'zoho.php', 'zoho-callback.php',
  '.htaccess', 'web.config'];
const OPTIONAL = ['config.local.php'];
const DIRS = ['audio'];
const OLD_APP = ['api', 'fonts', 'static', 'asset-manifest.json', 'favicon.ico', 'index.html', 'robots.txt',
  'service-worker.js', /^precache-manifest\..*\.js$/];
const OLD_GAME = 'whowill26';

const KILL_SW = `/* Who Will Prevail. This address used to host a React app whose service worker served its cached pages. This
   replacement deletes those caches, removes itself and reloads the open tabs, so visitors get the game. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  for (const k of await caches.keys()) await caches.delete(k);
  await self.registration.unregister();
  for (const c of await self.clients.matchAll({ type: 'window' })) c.navigate(c.url);
})()));
`;
const MOVED = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Who Will Prevail?</title>
<script>location.replace("/" + location.search + location.hash) /* the game moved to the root; links from emails keep their #link */</script>
<noscript><meta http-equiv="refresh" content="0; url=/"></noscript></head>
<body><p>The game has moved to <a href="/">whowillprevail.com</a>.</p></body></html>
`;
const DENY_HTACCESS = '<IfModule mod_authz_core.c>\r\n  Require all denied\r\n</IfModule>\r\n<IfModule !mod_authz_core.c>\r\n  Order allow,deny\r\n  Deny from all\r\n</IfModule>\r\n';
const DENY_WEBCONFIG = '<?xml version="1.0" encoding="UTF-8"?>\r\n<configuration><system.webServer><security><requestFiltering>\r\n  <fileExtensions allowUnlisted="false"/>\r\n</requestFiltering></security></system.webServer></configuration>\r\n';

const args = new Set(process.argv.slice(2));
const dry = !args.has('--yes');
const withConfig = args.has('--with-config');

const cfg = (() => {
  const f = path.join(__dirname, 'configs.js');
  if (!fs.existsSync(f)) throw new Error('configs.js with configFtp is missing');
  return new Function(fs.readFileSync(f, 'utf8') + '; return typeof configFtp === "undefined" ? null : configFtp;')();
})();
if (!cfg || !cfg.host || !cfg.user || !cfg.password) throw new Error('configFtp in configs.js needs host, user and password');
const root = String(cfg.remoteRoot || '').replace(/\/+$/, '');
if (!/^\/[A-Za-z0-9._\/-]+$/.test(root) || root.split('/').includes('..')) throw new Error('configFtp.remoteRoot must be the site root folder, e.g. /public');
const siteUrl = String(cfg.siteUrl || 'https://whowillprevail.com/').replace(/\/?$/, '/');
const secure = cfg.secure !== false;

const local = (rel) => path.join(__dirname, rel);
const files = [...FILES, ...OPTIONAL.filter((f) => fs.existsSync(local(f))), ...(withConfig ? ['config.php'] : [])];
for (const f of files) if (!fs.existsSync(local(f))) throw new Error(`missing local file ${f}`);
const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-');
const R = (...p) => path.posix.join(root, ...p);
const say = (s) => console.log(s);
const isOld = (name) => OLD_APP.some((m) => (m instanceof RegExp ? m.test(name) : m === name));

async function putText(c, text, remotePath) {
  const tmp = path.join(os.tmpdir(), `wwp-deploy-${process.pid}-${Date.now()}`);
  fs.writeFileSync(tmp, text);
  try { await c.uploadFrom(tmp, remotePath); } finally { fs.unlinkSync(tmp); }
}
async function copyRemote(c, from, to) {
  const tmp = path.join(os.tmpdir(), `wwp-deploy-${process.pid}-${Date.now()}`);
  try { await c.downloadTo(tmp, from); await c.uploadFrom(tmp, to); } finally { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); }
}
const names = async (c, dir) => (await c.list(dir)).filter((i) => !/^\.\.?$/.test(i.name));
async function uploadGame(c, dest) {
  for (const f of files) { await c.uploadFrom(local(f), path.posix.join(dest, f)); say(`  uploaded ${f}`); }
  for (const d of DIRS) if (fs.existsSync(local(d))) { await c.uploadFromDir(local(d), path.posix.join(dest, d)); await c.cd('/'); say(`  uploaded ${d}/`); }
  await putText(c, KILL_SW, path.posix.join(dest, 'service-worker.js')); say('  uploaded service-worker.js (removes the old one)');
}

async function main() {
  const c = new ftp.Client(60000);
  await c.access({ host: cfg.host, port: cfg.port || 21, user: cfg.user, password: cfg.password, secure });
  say(`connected to ${cfg.host} (${secure ? 'FTPS' : 'plain FTP'}), site root ${root}${dry ? '   [DRY RUN: nothing is changed]' : ''}`);
  try {
    const items = await names(c, root);
    if (!items.length) throw new Error(`${root} is empty or doesn't exist: check configFtp.remoteRoot (the site root, e.g. /public)`);
    const first = !items.some((i) => i.isDirectory && i.name === '_backup');
    if (!first) {
      say(`upload over the current files: ${[...files, ...DIRS.map((d) => d + '/'), 'service-worker.js'].join(', ')}`);
      if (!dry) await uploadGame(c, root);
    } else {
      const game = items.find((i) => i.isDirectory && i.name === OLD_GAME);
      const gameItems = game ? await names(c, R(OLD_GAME)) : [];
      if (!gameItems.some((i) => i.name === 'config.php') && !withConfig)
        throw new Error(`${OLD_GAME}/config.php not found: run with --with-config to upload the local config.php instead`);
      const oldApp = items.filter((i) => isOld(i.name));
      const backup = `_backup/${stamp}`;
      say(`FIRST DEPLOY: the game moves from /${OLD_GAME} to the root`);
      say(`  into ${backup}/old-react-app/: ${oldApp.map((i) => i.name + (i.isDirectory ? '/' : '')).join(', ') || '-'}`);
      say(`  into ${backup}/${OLD_GAME}/: the old game (${gameItems.length} items)${gameItems.some((i) => i.name === 'data') ? '; its data/ moves to the root' : ''}`);
      say(`  live config.php: ${withConfig ? 'local config.php (--with-config)' : `copied from /${OLD_GAME}/config.php`}`);
      say(`  stays as is: ${items.filter((i) => !isOld(i.name) && i.name !== OLD_GAME).map((i) => i.name + (i.isDirectory ? '/' : '')).join(', ') || '-'}`);
      say(`  new in the root: ${[...files, ...DIRS.map((d) => d + '/'), 'service-worker.js'].join(', ')}`);
      say(`  /${OLD_GAME}/ becomes a redirect to the root (keeps ?query and #hash)`);
      if (dry) return;

      /* 1. stage the new site */
      const stage = R('_deploy-new');
      await c.ensureDir(stage); await c.cd('/');
      await uploadGame(c, stage);
      if (!withConfig) { await copyRemote(c, R(OLD_GAME, 'config.php'), path.posix.join(stage, 'config.php')); say(`  copied the live ${OLD_GAME}/config.php`); }
      /* 2. backup folder, closed to the web */
      await c.ensureDir(R(backup, 'old-react-app')); await c.cd('/');
      await putText(c, DENY_HTACCESS, R('_backup', '.htaccess'));
      await putText(c, DENY_WEBCONFIG, R('_backup', 'web.config'));
      /* 3. swap: old out, new in (renames) */
      for (const i of oldApp) await c.rename(R(i.name), R(backup, 'old-react-app', i.name));
      if (game) await c.rename(R(OLD_GAME), R(backup, OLD_GAME));
      if (gameItems.some((i) => i.name === 'data')) await c.rename(R(backup, OLD_GAME, 'data'), R('data'));
      for (const i of await names(c, stage)) await c.rename(path.posix.join(stage, i.name), R(i.name));
      await c.removeDir(stage);
      /* 4. old address -> root */
      await c.ensureDir(R(OLD_GAME)); await c.cd('/');
      await putText(c, MOVED, R(OLD_GAME, 'index.html'));
      say(`done: the old React app and the old game are in ${backup}/`);
    }
  } finally { c.close(); }

  /* smoke test: the server answers and its database works; the old address redirects */
  try {
    const r = await fetch(siteUrl + 'api.php?op=info', { method: 'POST', headers: { 'X-WWP': '1', 'Content-Type': 'application/json' }, body: '{}' });
    const t = await r.text();
    say(`check ${siteUrl}api.php?op=info -> HTTP ${r.status} ${/"ok":true/.test(t) ? 'OK' : t.slice(0, 160)}`);
    const m = await fetch(siteUrl + OLD_GAME + '/');
    say(`check ${siteUrl}${OLD_GAME}/ -> HTTP ${m.status} ${/location\.replace/.test(await m.text()) ? 'redirect page OK' : 'no redirect page'}`);
    if (!/"ok":true/.test(t)) process.exitCode = 1;
  } catch (e) { say(`check ${siteUrl}: couldn't reach the site (${e.cause?.code || e.message}); open it in a browser`); process.exitCode = 1; }
}

main().catch((e) => { console.error('DEPLOY FAILED:', e.message); process.exitCode = 1; });
