/* Who Will Prevail: standalone runtime.
   Gives the page the same window.claude.use("db" | "sample" | "user") interface it had on claude.ai,
   backed by api.php on your own hosting (SQLite database + optional Claude API for card generation). */
(function () {
  "use strict";
  var API = "api.php";
  var POLL_MS = 3000;
  var setupKey = (function () { try { return new URLSearchParams(location.search).get("setup") || ""; } catch (e) { return ""; } })();

  function err(code, message) { var e = new Error(message || code); e.code = code; return e; }

  function call(op, body) {
    var gen = window.__wwpGen ? window.__wwpGen() : 0; /* the page's sign-in generation when this request was sent */
    return fetch(API + "?op=" + encodeURIComponent(op), {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Setup-Key": setupKey, "X-WWP": "1" },
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.text().then(function (t) {
        var j; try { j = JSON.parse(t); } catch (e) { throw err("server_error", "Bad server reply (" + r.status + "): " + t.slice(0, 200)); }
        if (j && j.sess !== undefined && window.__wwpSess) { try { window.__wwpSess(j.sess, gen); } catch (e) {} } /* the page notices a sign-in that expired or was revoked */
        if (!r.ok || j.error) { var e = err(j.code || "server_error", j.error || ("HTTP " + r.status)); if (j.retryAfter) e.retryAfter = j.retryAfter; throw e; }
        return j;
      });
    });
  }

  function randId() {
    var a = new Uint8Array(10); crypto.getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }

  /* ---------- live queries: one polling loop for every listener ---------- */
  var listeners = {}, nextId = 1, timer = null, polling = false;

  var pollP = Promise.resolve();
  function poll() {
    if (polling) return pollP;
    var ids = Object.keys(listeners);
    if (!ids.length) return Promise.resolve();
    polling = true;
    var qs = ids.map(function (id) { var l = listeners[id]; return { id: id, q: l.q, rev: l.rev }; });
    pollP = call("watch", { queries: qs }).then(function (res) {
      (res.results || []).forEach(function (r) {
        var l = listeners[r.id]; if (!l) return;
        l.rev = r.rev;
        try { l.deliver(r.data); } catch (e) { console.warn("listener", e); }
      });
    }).catch(function (e) {
      ids.forEach(function (id) { var l = listeners[id]; if (l && l.onErr) try { l.onErr(e); } catch (x) {} });
    }).then(function () { polling = false; });
    return pollP;
  }
  function kick() { if (!timer) timer = setInterval(poll, POLL_MS); setTimeout(poll, 0); }
  document.addEventListener("visibilitychange", function () { if (!document.hidden) poll(); });

  function listen(q, deliver, onErr) {
    var id = String(nextId++);
    listeners[id] = { q: q, rev: null, deliver: deliver, onErr: onErr };
    kick();
    return function () { delete listeners[id]; };
  }
  /* after any write, refresh listeners right away instead of waiting for the next tick */
  function afterWrite(x) { setTimeout(poll, 30); return x; }

  /* ---------- document / collection references (Firestore-like) ---------- */
  function docSnap(id, data) {
    return { id: id, exists: data != null, data: function () { return data == null ? undefined : JSON.parse(JSON.stringify(data)); } };
  }
  function lastSeg(p) { var s = p.split("/"); return s[s.length - 1]; }

  function DocRef(path) { this.path = path; this.id = lastSeg(path); }
  DocRef.prototype.get = function () { var p = this.path; return call("get", { path: p }).then(function (r) { return docSnap(lastSeg(p), r.data); }); };
  DocRef.prototype.set = function (d) { return call("set", { path: this.path, data: d }).then(afterWrite); };
  DocRef.prototype.update = function (d) { return call("update", { path: this.path, data: d }).then(afterWrite); };
  DocRef.prototype.delete = function () { return call("delete", { path: this.path }).then(afterWrite); };
  DocRef.prototype.acquire = function (o) { return call("lease", { path: this.path, holder: (o && o.holder) || "anon", ttlMs: (o && o.ttlMs) || 15000 }); };
  DocRef.prototype.onSnapshot = function (cb, onErr) {
    var id = this.id;
    return listen({ type: "doc", path: this.path }, function (data) { cb(docSnap(id, data)); }, onErr);
  };

  function Query(col, opts) { this.col = col; this.o = opts || {}; }
  Query.prototype._with = function (k, v) { var o = JSON.parse(JSON.stringify(this.o)); o[k] = v; return new Query(this.col, o); };
  Query.prototype.where = function (f, op, v) { var w = (this.o.where || []).slice(); w.push([f, op, v]); return this._with("where", w); };
  Query.prototype.orderBy = function (f, dir) { return this._with("orderBy", [f, dir || "asc"]); };
  Query.prototype.limit = function (n) { return this._with("limit", n); };
  Query.prototype.doc = function (id) { return new DocRef(this.col + "/" + (id || randId())); };
  Query.prototype.get = function () {
    return call("query", { col: this.col, opts: this.o }).then(function (r) {
      var docs = r.data.map(function (d) { return docSnap(d.id, d.data); });
      return { docs: docs, size: docs.length, empty: !docs.length };
    });
  };
  Query.prototype.onSnapshot = function (cb, onErr) {
    return listen({ type: "col", col: this.col, opts: this.o }, function (rows) {
      var docs = rows.map(function (d) { return docSnap(d.id, d.data); });
      cb({ docs: docs, size: docs.length, empty: !docs.length });
    }, onErr);
  };

  var db = {
    doc: function (p) { return new DocRef(p); },
    collection: function (c) { return new Query(c); }
  };

  /* ---------- Claude (card generation) through the server ---------- */
  function blobToB64(blob) {
    return new Promise(function (res, rej) {
      var fr = new FileReader();
      fr.onload = function () { var s = String(fr.result); res({ media_type: blob.type || "image/jpeg", data: s.slice(s.indexOf(",") + 1) }); };
      fr.onerror = rej; fr.readAsDataURL(blob);
    });
  }
  var sample = {
    limits: function () { return call("ai_info").then(function (r) { return { images: !!r.images }; }); },
    json: function (prompt, opts) {
      var imgs = (opts && opts.images) || [];
      return Promise.all(imgs.map(blobToB64)).then(function (images) {
        return call("ai", { prompt: String(prompt), images: images }).then(function (r) { return r.data; });
      });
    }
  };

  var user = {
    canEdit: function () { return call("info").then(function (r) { return !!r.canSetup; }); }
  };

  var infoP = null;
  function info() { if (!infoP) infoP = call("info"); return infoP; }

  window.claude = window.claude || {};
  /* server operations that are not plain document reads/writes: sign-in, sessions, invitation links, emails */
  window.claude.server = { call: function (op, body) { return call(op, body || {}); }, refresh: function () { return (polling ? pollP : Promise.resolve()).then(function () { return poll(); }); } }; /* resolves once every listener has been re-read (e.g. after signing in) */
  window.claude.use = function (name) {
    if (name === "db") return info().then(function () { return db; });
    if (name === "sample") return info().then(function (r) { if (!r.ai) throw err("sampling_disabled", "Claude API key is not configured"); return sample; });
    if (name === "user") return info().then(function () { return user; });
    return Promise.reject(err("not_granted", name + " is not available on this hosting"));
  };
})();
