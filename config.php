<?php
/* Who Will Prevail: settings. Keep this file private (it is blocked from the web by .htaccess). */
return [
  /* Claude API key for generating card names, powers, stories and reading headshots.
     Get one at https://console.anthropic.com (usage is billed). Leave empty to use the built-in generator. */
  'anthropic_api_key' => '',
  'anthropic_model'   => 'claude-sonnet-4-5',

  /* One-time setup key. Needed (1) to create the admin login if it doesn't exist yet:
     open  https://your-site/who-will-prevail/?setup=THIS_KEY
     and (2) to open the diagnostics:  api.php?diag=1&key=THIS_KEY  */
  'setup_key' => '76969f7d97297320cb7609becaa39100',

  /* DATABASE (MySQL / MariaDB). Create an empty database and a user in your hosting panel, then fill in the four
     values below. The tables are created automatically on the first request (the user needs CREATE rights). */
  'db' => [
    'driver' => 'mysql',
    'host'   => 'sql5c40c.carrierzone.com',
    'port'   => 3306,
    'name'   => 'whowill26_4oxwfgjjmy702978',
    'user'   => '4oxwfgjjmy702978', 
    'pass'   => 'pg*?L2Jga@-g6?9', 
    'prefix' => 'wwp_',        /* table name prefix; lets the game share a database with other apps */
  ],

  /* First run on an empty MySQL database: copy the data from the old SQLite file (data/game.sqlite: admin login,
     cards, season, ...) if it exists, otherwise load seed.json. Set to false to ignore the SQLite file. */
  'import_sqlite' => true,
  'data_dir' => __DIR__ . '/data',   /* where the old game.sqlite is (also the database folder if driver is 'sqlite') */

  'max_body_bytes' => 12 * 1024 * 1024,

  /* SECURITY. The server signs people in (httpOnly cookie sessions) and decides who may read and write what.
       mode  'log'     : learning mode. Everything is allowed, but each "would be refused" request is recorded
                           (see api.php?seclog=1&key=SETUP_KEY). Use it while you try the game, then switch to enforce.
             'enforce' : refuse what a role may not do (use this before the game is opened to players).
             'off'     : no permission checks (not recommended).
       Sign-in, passwords and emails are handled by the server in every mode. */
  'security' => [
    'mode' => 'enforce',
    'session_hours' => 12,            /* sign-in lasts this long unless "Keep me signed in" is ticked */
    'session_keep_days' => 30,        /* ...and this long when it is */
    'invite_ttl_hours' => 168,        /* how long an invitation link works (7 days) */
    'reset_ttl_hours' => 24,          /* how long a password-reset link works */
    'timezone' => 'UTC',             /* dates in emails, e.g. America/Toronto, America/Mexico_City, America/Sao_Paulo */
    'public_gate_players' => false,   /* true: the sign-in screen shows the real players' cards (names are visible to anyone with the link) */
    'trust_forwarded_for' => false,   /* true only if the hosting puts every visitor behind a proxy (check "your_ip_as_seen_by_the_game" in the diagnostics) */
    'game_url' => '',                  /* address of the game for the links in emails, e.g. 'https://whowillprevail.com/whowill26/'. Used when Branding has no Game link.
                                          The address is never taken from the request, so set this (or Branding > Game link) before players are invited. */
    'login_fail_per_ip' => 60,         /* failed sign-ins allowed per address in 10 minutes (successful ones are not counted, so an office can sign in together) */
    'login_attempts_per_ip' => 600,    /* ceiling on all sign-in attempts per address in 10 minutes (protects the server) */
    'link_checks_per_ip' => 600,       /* invitation / reset link look-ups per address in 10 minutes */
    'link_redeems_per_ip' => 200,      /* passwords set from links per address in 10 minutes */
    'reset_requests_per_ip' => 30,     /* "Forgot password?" requests per address in an hour */
  ],

  /* EMAIL. Invitation, password-reset and new-move emails are sent through an email service over HTTPS
     (SMTP is blocked on this hosting). If 'provider' is empty or fails, the game does what it always did:
     the email waits in "Emails ready to send" and you press "Open in email app" / "Copy email".
       provider 'webhook'  : a Zapier "Catch Hook" (put its URL in 'url'); the Zap sends the email.
                             The hook receives: to, from, from_name, subject, html, text.
       provider 'brevo' | 'sendgrid' | 'resend' : put the service's API key in 'key'; 'from' must be a verified sender. */
  'mail' => [
    'provider' => 'webhook',
    'url' => 'https://hooks.zapier.com/hooks/catch/4559531/41jlfay/',
    'key' => '',
    'from' => '',                       /* empty = noreply@<your site domain> (ignored by Zapier's Gmail step) */
    'from_name' => 'Who Will Prevail?',
    /* While testing, only these addresses may receive emails. Empty list [] = every player who has an account. */
    'allowed_recipients' => [],
    'secret' => '',                      /* webhook only: sent along with every email so the Zap can ignore calls without it */
    'max_per_minute' => 300,
    'max_per_recipient_per_minute' => 20,
  ],

  /* ZOHO CRM. "Import from Zoho CRM" (Card forge > Bulk import) adds the CRM's active users as players.
     In the Zoho API Console create a "Server-based Applications" client with this Redirect URI:
       <the game's address>zoho-callback.php     e.g. https://whowillprevail.com/zoho-callback.php
     (the import screen shows the exact address). Put its Client ID and Client Secret in config.local.php,
     not here, so they never end up in git:  <?php return ['zoho' => ['client_id' => '...', 'client_secret' => '...']];
     accounts_url is the Zoho sign-in server of your data center (Canada: https://accounts.zohocloud.ca). */
  'zoho' => [
    'client_id' => '',
    'client_secret' => '',
    'accounts_url' => 'https://accounts.zohocloud.ca',
  ],
];
