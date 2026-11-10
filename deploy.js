/* Who Will Prevail: FTP deploy.
     npm run deploy:dry        shows the plan, changes nothing
     npm run deploy -- --yes   deploys
   FTP access: configFtp in configs.js (gitignored, never uploaded): { user, password, host, port, remoteRoot,
   secure, siteUrl }. secure: true (default) = FTPS with a verified certificate; false = plain FTP (the password travels
   unencrypted: set it only if the hosting has no FTPS).

   First deploy (the remote folder has no _backup-* yet, or --backup): everything already there is moved into
   _backup-<date>, except config.php (the server's own settings) and data/ (the old database), which stay in place; a
   copy of config.php goes into the backup too. To keep the game down for only a few seconds, the new files are
   uploaded into _deploy-new/ first and then moved into place. Later deploys upload the game files over the old ones.

   Uploaded: the game files below and audio/. Never uploaded: configs.js, .env, .git, node_modules, docs, this script.
   config.php is uploaded only with --with-config (the server's copy holds the live settings). */
'use strict';
const fs = require('fs');
const path = require('path');
const ftp = require('basic-ftp');

const FILES = ['index.html', 'claude-shim.js', 'api.php', 'security.php', 'mailer.php', 'zoho.php', 'zoho-callback.php',
  '.htaccess', 'web.config'];
const OPTIONAL = ['config.local.php']; /* uploaded when present locally */
const DIRS = ['audio'];
const KEEP = ['config.php', 'data']; /* stay where they are on the first deploy */

const args = new Set(process.argv.slice(2));
const dry = !args.has('--yes');
const withConfig = args.has('--with-config');
const forceBackup = args.has('--backup');

const cfg = (() => {
  const f = path.join(__dirname, 'configs.js');
  if (!fs.existsSync(f)) throw new Error('configs.js with configFtp is missing');
  return new Function(fs.readFileSync(f, 'utf8') + '; return typeof configFtp === "undefined" ? null : configFtp;')();
})();
if (!cfg || !cfg.host || !cfg.user || !cfg.password) throw new Error('configFtp in configs.js needs host, user and password');
const root = String(cfg.remoteRoot || '').replace(/\/+$/, '');
if (!root.startsWith('/') || root === '' || root.split('/').includes('..')) throw new Error('configFtp.remoteRoot must be an absolute folder, e.g. /public_html/whowill26');
const siteUrl = String(cfg.siteUrl || 'https://whowillprevail.com/whowill26/').replace(/\/?$/, '/');
const secure = cfg.secure !== false;

const local = (rel) => path.join(__dirname, rel);
const files = [...FILES, ...OPTIONAL.filter((f) => fs.existsSync(local(f))), ...(withConfig ? ['config.php'] : [])];
for (const f of files) if (!fs.existsSync(local(f))) throw new Error(`missing local file ${f}`);
const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-');
const remote = (...p) => path.posix.join(root, ...p);
const say = (s) => console.log(s);

async function main() {
  const c = new ftp.Client(60000);
  await c.access({ host: cfg.host, port: cfg.port || 21, user: cfg.user, password: cfg.password, secure });
  say(`connected to ${cfg.host} (${secure ? 'FTPS' : 'plain FTP'}), folder ${root}${dry ? '  [DRY RUN: nothing is changed]' : ''}`);
  try {
    const items = (await c.list(root)).filter((i) => !/^\.\.?$/.test(i.name));
    const backups = items.filter((i) => i.isDirectory && i.name.startsWith('_backup-')).map((i) => i.name);
    const first = forceBackup || backups.length === 0;
    if (!first) say(`backups already there: ${backups.join(', ')}; uploading over the current files`);

    if (first) {
      const move = items.filter((i) => !KEEP.includes(i.name) && !i.name.startsWith('_backup-') && i.name !== '_deploy-new');
      const backup = `_backup-${stamp}`;
      say(`FIRST DEPLOY: back up into ${backup}/`);
      say(`  move (${move.length}): ${move.map((i) => i.name + (i.isDirectory ? '/' : '')).join(', ') || '-'}`);
      say(`  stay in place: ${items.filter((i) => KEEP.includes(i.name)).map((i) => i.name).join(', ') || '-'}`
        + (items.some((i) => i.name === 'config.php') ? ' (+ a copy of config.php in the backup)' : ''));
      say(`  new: ${[...files, ...DIRS.map((d) => d + '/')].join(', ')}`);
      if (dry) return;
      /* 1. new files into _deploy-new/ (the live game keeps running meanwhile) */
      const stage = remote('_deploy-new');
      await c.ensureDir(stage); await c.cd('/');
      for (const f of files) { await c.uploadFrom(local(f), path.posix.join(stage, f)); say(`  uploaded ${f}`); }
      for (const d of DIRS) if (fs.existsSync(local(d))) { await c.uploadFromDir(local(d), path.posix.join(stage, d)); await c.cd('/'); say(`  uploaded ${d}/`); }
      /* 2. backup folder with a copy of config.php */
      await c.ensureDir(remote(backup)); await c.cd('/');
      if (items.some((i) => i.name === 'config.php')) {
        const tmp = path.join(require('os').tmpdir(), `wwp-config-${Date.now()}.php`);
        await c.downloadTo(tmp, remote('config.php')); await c.uploadFrom(tmp, remote(backup, 'config.php')); fs.unlinkSync(tmp);
      }
      /* 3. old files into the backup, 4. new files into place (renames: a few seconds) */
      for (const i of move) await c.rename(remote(i.name), remote(backup, i.name));
      for (const i of (await c.list(stage)).filter((x) => !/^\.\.?$/.test(x.name))) await c.rename(path.posix.join(stage, i.name), remote(i.name));
      await c.removeDir(stage);
      say(`done: old files are in ${backup}/`);
    } else {
      if (dry) { say(`  upload: ${[...files, ...DIRS.map((d) => d + '/')].join(', ')}`); return; }
      for (const f of files) { await c.uploadFrom(local(f), remote(f)); say(`  uploaded ${f}`); }
      for (const d of DIRS) if (fs.existsSync(local(d))) { await c.uploadFromDir(local(d), remote(d)); await c.cd('/'); say(`  uploaded ${d}/`); }
    }
  } finally { c.close(); }

  /* smoke test: the server answers and its database works */
  const r = await fetch(siteUrl + 'api.php?op=info', { method: 'POST', headers: { 'X-WWP': '1', 'Content-Type': 'application/json' }, body: '{}' });
  const t = await r.text();
  say(`check ${siteUrl}api.php?op=info -> HTTP ${r.status} ${/"ok":true/.test(t) ? 'OK' : t.slice(0, 160)}`);
  if (!/"ok":true/.test(t)) process.exitCode = 1;
}

main().catch((e) => { console.error('DEPLOY FAILED:', e.message); process.exitCode = 1; });
