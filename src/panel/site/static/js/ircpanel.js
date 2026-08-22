/* Swaygo WebPanel — all panel JS (external because CSP forbids inline scripts).
   Handles: no-flash theme init, theme toggle, mobile sidebar, global search. */

/* No-flash theme: runs immediately (script is render-blocking in <head>). */
(function () {
  try {
    var t = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();

document.addEventListener('DOMContentLoaded', function () {
  /* Panel theme picker (InspIRCd / InspIRCd Nuit / Aurora) */
  var tbtn = document.getElementById('ircpTheme');
  var pop = document.getElementById('upThemePop');
  if (tbtn && pop) {
    var mark = function () {
      var cur = document.body.getAttribute('data-panel-theme') || 'inspircd';
      pop.querySelectorAll('.up-theme-opt').forEach(function (b) {
        b.classList.toggle('is-active', b.getAttribute('data-pt') === cur);
      });
    };
    tbtn.addEventListener('click', function (e) {
      e.stopPropagation();
      pop.hidden = !pop.hidden;
      if (!pop.hidden) mark();
    });
    pop.querySelectorAll('.up-theme-opt').forEach(function (b) {
      b.addEventListener('click', function () {
        var t = b.getAttribute('data-pt');
        document.body.setAttribute('data-panel-theme', t);
        try { localStorage.setItem('ircpanel-theme', t); } catch (e) {}
        mark();
        pop.hidden = true;
      });
    });
    document.addEventListener('click', function (e) {
      if (!e.target.closest('.up-theme')) pop.hidden = true;
    });
  }

  /* Language picker */
  var lbtn = document.getElementById('ircpLang');
  var lpop = document.getElementById('upLangPop');
  if (lbtn && lpop) {
    lbtn.addEventListener('click', function (e) { e.stopPropagation(); lpop.hidden = !lpop.hidden; });
    document.addEventListener('click', function (e) { if (!e.target.closest('.up-lang')) lpop.hidden = true; });
  }

  /* Mobile sidebar */
  var sb = document.getElementById('upSidebar'),
      ov = document.getElementById('upOverlay'),
      bg = document.getElementById('upBurger');
  if (sb && ov && bg) {
    var toggle = function () { sb.classList.toggle('is-open'); ov.classList.toggle('is-open'); };
    bg.addEventListener('click', toggle);
    ov.addEventListener('click', toggle);
  }

  /* Header nav dropdowns (Protection / Système) — click to toggle (touch),
     hover handled by CSS. */
  document.querySelectorAll('.up-nav-trigger').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      var grp = btn.closest('.up-nav-group');
      var open = grp.classList.contains('open');
      document.querySelectorAll('.up-nav-group.open').forEach(function (g) { g.classList.remove('open'); });
      if (!open) grp.classList.add('open');
    });
  });
  document.addEventListener('click', function (e) {
    if (!e.target.closest('.up-nav-group')) {
      document.querySelectorAll('.up-nav-group.open').forEach(function (g) { g.classList.remove('open'); });
    }
  });

  /* Global search */
  var input = document.getElementById('upSearch'),
      box = document.getElementById('upSearchResults');
  if (input && box) {
    var d = input.dataset;
    var timer = null;
    function esc(s) { var e = document.createElement('div'); e.textContent = s; return e.innerHTML; }
    function group(label, items, urlFor) {
      if (!items || !items.length) return '';
      var h = '<div class="up-sr-group">' + label + '</div>';
      items.forEach(function (it) {
        h += '<a class="up-sr-item" href="' + urlFor(it.name) + '"><b>' + esc(it.name) + '</b>' +
             (it.info ? '<span>' + esc(it.info) + '</span>' : '') + '</a>';
      });
      return h;
    }
    function render(data) {
      var h = group('Utilisateurs', data.users, function (n) { return d.users + encodeURIComponent(n) + '/'; })
            + group('Salons', data.channels, function (n) { return d.chans + encodeURIComponent(n) + '/'; })
            + group('Serveurs', data.servers, function (n) { return d.servers + encodeURIComponent(n) + '/'; })
            + group('Bans', data.bans, function () { return d.bans; });
      box.innerHTML = h || '<div class="up-sr-empty">Aucun résultat</div>';
      box.hidden = false;
    }
    input.addEventListener('input', function () {
      var q = input.value.trim();
      clearTimeout(timer);
      if (q.length < 2) { box.hidden = true; return; }
      timer = setTimeout(function () {
        fetch(d.search + '?q=' + encodeURIComponent(q), { headers: { 'X-Requested-With': 'fetch' } })
          .then(function (r) { return r.json(); })
          .then(render)
          .catch(function () { box.hidden = true; });
      }, 220);
    });
    document.addEventListener('click', function (e) {
      if (!input.parentNode.contains(e.target)) box.hidden = true;
    });
  }

  /* Spamfilter edit: load a row into the add form */
  var sfForm = document.getElementById('sfForm');
  if (sfForm) {
    var set = function (id, v) { var el = document.getElementById(id); if (el) el.value = v; };
    document.querySelectorAll('.sf-edit').forEach(function (btn) {
      btn.addEventListener('click', function () {
        set('sf_original', btn.dataset.pattern);
        set('sf_pattern', btn.dataset.pattern);
        set('sf_action', btn.dataset.action || 'block');
        set('sf_flags', btn.dataset.flags || '*');
        set('sf_reason', btn.dataset.reason || '');
        var t = document.getElementById('sfFormTitle'); if (t) t.textContent = 'Modifier le filtre';
        var c = document.getElementById('sfCancel'); if (c) c.style.display = '';
        document.getElementById('sf_pattern').focus();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    });
    var cancel = document.getElementById('sfCancel');
    if (cancel) cancel.addEventListener('click', function () {
      sfForm.reset();
      set('sf_original', '');
      var t = document.getElementById('sfFormTitle'); if (t) t.textContent = 'Ajouter un filtre';
      cancel.style.display = 'none';
    });
  }

  /* Access page: "Modifier" loads a grant into the form */
  var editGrants = document.querySelectorAll('.up-edit-grant');
  if (editGrants.length) {
    var acUser = document.getElementById('acUser');
    editGrants.forEach(function (b) {
      b.addEventListener('click', function () {
        if (acUser) { acUser.value = b.dataset.user; }
        var perms = (b.dataset.perms || '').split(',');
        document.querySelectorAll('.up-perm input[type=checkbox]').forEach(function (cb) {
          cb.checked = perms.indexOf(cb.dataset.key) !== -1;
        });
        if (acUser) { acUser.scrollIntoView({ behavior: 'smooth' }); acUser.focus(); }
      });
    });
  }

  /* Live log viewer: poll log.tail and keep the view pinned to the bottom */
  var logBox = document.getElementById('logBox');
  if (logBox) {
    var url = logBox.dataset.url;
    var auto = document.getElementById('logAuto');
    var status = document.getElementById('logStatus');
    var refresh = function () {
      fetch(url + '?lines=300', { headers: { 'X-Requested-With': 'fetch' } })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var atBottom = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 40;
          logBox.textContent = (d.lines || []).join('\n') || '(journal vide)';
          if (atBottom) logBox.scrollTop = logBox.scrollHeight;
          if (status) status.textContent = (d.lines ? d.lines.length : 0) + ' lignes · ' + new Date().toLocaleTimeString();
        })
        .catch(function () { if (status) status.textContent = 'erreur de chargement'; });
    };
    refresh();
    logBox.scrollTop = logBox.scrollHeight;
    setInterval(function () { if (!auto || auto.checked) refresh(); }, 4000);
  }

  /* Structured json-log event viewer (UnrealIRCd-panel style): incremental poll
     of log.events, newest on top, color-coded by level/subsystem. */
  var logEvents = document.getElementById('logEvents');
  if (logEvents) {
    var eurl = logEvents.dataset.url;
    var tbody = logEvents.querySelector('tbody');
    var eauto = document.getElementById('logAuto');
    var estatus = document.getElementById('logStatus');
    var efilter = document.getElementById('logFilter');
    var eempty = document.getElementById('logEmpty');
    var lastId = 0;
    var MAXROWS = 500;

    var levelClass = function (lvl, sub) {
      lvl = (lvl || '').toLowerCase(); sub = (sub || '').toLowerCase();
      if (lvl === 'error' || lvl === 'fatal' || sub === 'kill') return 'jl-red';
      if (lvl === 'warn' || sub === 'oper' || sub === 'xline') return 'jl-yellow';
      if (sub === 'connect') return 'jl-green';
      if (sub === 'quit') return 'jl-grey';
      return 'jl-blue';
    };
    var fmtTime = function (ts) {
      var d = ts ? new Date(ts) : new Date();
      return isNaN(d.getTime()) ? (ts || '') : d.toLocaleTimeString();
    };
    var applyFilter = function (row) {
      if (!efilter || !efilter.value) { row.style.display = ''; return; }
      row.style.display = row.dataset.search.indexOf(efilter.value.toLowerCase()) >= 0 ? '' : 'none';
    };
    var td = function (cls, txt) {
      var c = document.createElement('td');
      if (cls) c.className = cls;
      c.textContent = txt;
      return c;
    };
    var addRow = function (ev) {
      var sub = ev.subsystem || '', eid = ev.event_id || '', msg = ev.msg || '', lvl = ev.level || 'info';
      var tr = document.createElement('tr');
      tr.className = 'jl-row ' + levelClass(lvl, sub);
      tr.dataset.search = (sub + ' ' + eid + ' ' + msg + ' ' + lvl).toLowerCase();
      tr.appendChild(td('jl-time', fmtTime(ev.timestamp)));
      var lvltd = document.createElement('td');
      var b = document.createElement('span');
      b.className = 'jl-badge';
      b.textContent = lvl;
      lvltd.appendChild(b);
      tr.appendChild(lvltd);
      tr.appendChild(td('jl-sub', sub + (eid ? ' · ' + eid : '')));
      tr.appendChild(td('jl-msg', msg));
      applyFilter(tr);
      return tr;
    };
    var refreshE = function () {
      fetch(eurl + '?since=' + lastId, { headers: { 'X-Requested-With': 'fetch' } })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.error) { if (estatus) estatus.textContent = d.error; return; }
          var evs = d.events || [];
          if (evs.length && eempty) eempty.style.display = 'none';
          evs.forEach(function (ev) { tbody.insertBefore(addRow(ev), tbody.firstChild); });
          if (typeof d.last_id === 'number') lastId = d.last_id;
          while (tbody.children.length > MAXROWS) tbody.removeChild(tbody.lastChild);
          if (estatus) estatus.textContent = tbody.children.length + ' événements · ' + new Date().toLocaleTimeString();
        })
        .catch(function () { if (estatus) estatus.textContent = 'erreur de chargement'; });
    };
    if (efilter) efilter.addEventListener('input', function () {
      Array.prototype.forEach.call(tbody.children, applyFilter);
    });
    refreshE();
    setInterval(function () { if (!eauto || eauto.checked) refreshE(); }, 3000);
  }
});
