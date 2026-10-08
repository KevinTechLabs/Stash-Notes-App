(() => {
  const VAULT_KEY = 'stash.v2.vault';
  const ITER = 600000;          // PBKDF2 rounds for new keys (matches v1 / OWASP guidance)
  const LEGACY_ITER = 310000;   // older v2 data; upgraded on next unlock
  const MIN_PW = 12;
  // Master password keys use Argon2id (RFC 9106): 64 MiB of memory and 3 passes, so every
  // guess is slow and memory-hungry even on powerful hardware. The recovery code is 120 bits
  // of randomness, so it keeps PBKDF2.
  const ARGON = {m: 65536, t: 3, p: 1};
  const CLIP_CLEAR_MS = 30 * 1000;   // copied passwords are wiped from the clipboard after this
  const REVEAL_MS = 20 * 1000;       // revealed passwords hide themselves after this
  const IDLE_MS = 5 * 60 * 1000;
  const FOLDERS = ['Personal','Gaming','Shopping','Social Media','Banking','Homelab','Other'];
  const AVATARS = [['#4C8DFF','#1F5EFF'],['#38BDF8','#0284C7'],['#818CF8','#4F46E5'],['#34D399','#059669'],['#F472B6','#DB2777'],['#FB923C','#EA580C'],['#A78BFA','#7C3AED'],['#2DD4BF','#0D9488'],['#94A3B8','#475569']];
  const enc = new TextEncoder(), dec = new TextDecoder();
  const $ = id => document.getElementById(id);
  const SHEETS = ['detailScrim','editScrim','menuScrim','pwScrim'];

  let dk = null, dkRaw = null, wrapPw = null, wrapRc = null, entries = [], filter = 'All', detailId = null, editingId = null, idleTimer = null, storageOK = true;

  // ---------- storage ----------
  function readVault(){ try { const s = localStorage.getItem(VAULT_KEY); return s ? JSON.parse(s) : null; } catch(e){ storageOK = false; return null; } }
  function writeVault(v){ try { localStorage.setItem(VAULT_KEY, JSON.stringify(v)); return true; } catch(e){ storageOK = false; return false; } }
  function wipeVault(){ try { localStorage.removeItem(VAULT_KEY); } catch(e){} }

  // ---------- crypto ----------
  const b64 = buf => { let s=''; const b=new Uint8Array(buf); for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s); };
  const unb64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));
  async function deriveKey(pw, saltBytes, iterations = ITER){
    const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt:saltBytes, iterations, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
  }
  self.loadArgon2WasmBinary = () => fetch('vendor/argon2.wasm').then(r => { if (!r.ok) throw new Error('argon2 load'); return r.arrayBuffer(); }).then(b => new Uint8Array(b));
  self.loadArgon2WasmModule = () => new Promise((res, rej) => { const sc = document.createElement('script'); sc.src = 'vendor/argon2-glue.js'; sc.onload = res; sc.onerror = rej; document.head.append(sc); });
  async function argonKey(secret, saltBytes, prm){
    const out = await self.argon2.hash({pass: enc.encode(secret), salt: saltBytes, time: prm.t, mem: prm.m, parallelism: prm.p, hashLen: 32, type: self.argon2.ArgonType.Argon2id});
    const key = await crypto.subtle.importKey('raw', out.hash, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
    out.hash.fill(0);
    return key;
  }
  // Vault v2: a random data key encrypts the logins. That key is stored twice,
  // once locked by the master password and once by the recovery code.
  const importDK = raw => crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  async function wrap(raw, secret, kdf = 'pbkdf2'){
    const s = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    if (kdf === 'argon2id'){
      const k = await argonKey(secret, s, ARGON);
      return {kdf:'argon2id', m:ARGON.m, t:ARGON.t, p:ARGON.p, salt:b64(s), iv:b64(iv), ct:b64(await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, raw))};
    }
    const k = await deriveKey(secret, s);
    return {iter:ITER, salt:b64(s), iv:b64(iv), ct:b64(await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, raw))};
  }
  const isArgon = w => w && w.kdf === 'argon2id';
  async function unwrap(w, secret){
    const k = isArgon(w) ? await argonKey(secret, unb64(w.salt), {m:w.m, t:w.t, p:w.p}) : await deriveKey(secret, unb64(w.salt), w.iter || LEGACY_ITER);
    return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(w.iv)}, k, unb64(w.ct)));
  }
  async function decryptEntries(v, key){
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(v.iv)}, key, unb64(v.data));
    const d = JSON.parse(dec.decode(pt)); return Array.isArray(d) ? d : [];
  }
  async function useDataKey(raw){ dkRaw = raw; dk = await importDK(raw); }
  async function persist(){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, dk, enc.encode(JSON.stringify(entries)));
    const v = {v:2, app:'stash', pw:wrapPw, rc:wrapRc, iv:b64(iv), data:b64(ct)};
    if (!writeVault(v)) toast("Couldn't save in this browser", false);
    return v;
  }
  const isV2 = v => v && v.v === 2 && v.pw && v.iv && v.data;
  const isV1 = v => v && v.v !== 2 && v.salt && v.iv && v.data;
  // Opens a vault with the master password. Older (v1) stashes are upgraded; returns true if a recovery code must be created.
  async function unlockWithPassword(v, pw){
    if (isV2(v)){
      await useDataKey(await unwrap(v.pw, pw));
      entries = await decryptEntries(v, dk);
      wrapPw = v.pw; wrapRc = v.rc || null;
      if (!isArgon(v.pw)){ wrapPw = await wrap(dkRaw, pw, 'argon2id'); await persist(); }
      return !wrapRc;
    }
    const oldKey = await deriveKey(pw, unb64(v.salt), v.iter || LEGACY_ITER);
    entries = await decryptEntries(v, oldKey);
    await useDataKey(crypto.getRandomValues(new Uint8Array(32)));
    wrapPw = await wrap(dkRaw, pw, 'argon2id'); wrapRc = null;
    await persist();
    return true;
  }

  // ---------- saving files (works inside Claude and as a standalone phone app) ----------
  async function saveFile(filename, text, mime){
    holdLock(5 * 60 * 1000);
    try { return await saveFileInner(filename, text, mime); } finally { setTimeout(releaseLock, 1500); }
  }
  async function saveFileInner(filename, text, mime){
    try { const dl = window.claude && await window.claude.use('downloads'); if (dl){ await dl.save({filename, data:text}); return 'saved'; } }
    catch(err){ if (err && err.code === 'declined') return 'cancelled'; }
    try {
      const file = new File([text], filename, {type:mime});
      if (navigator.canShare && navigator.canShare({files:[file]})){ await navigator.share({files:[file], title:filename}); return 'saved'; }
    } catch(err){ if (err && err.name === 'AbortError') return 'cancelled'; }
    try {
      const url = URL.createObjectURL(new Blob([text], {type:mime}));
      const a = el('a',{href:url, download:filename}); document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000); return 'saved';
    } catch(err){ return 'failed'; }
  }

  // ---------- recovery codes ----------
  const RC_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function newRecoveryCode(){
    const b = crypto.getRandomValues(new Uint8Array(24));
    const chars = [...b].map(x => RC_ALPHA[x % 32]).join('');
    return chars.match(/.{4}/g).join('-');
  }
  const normCode = c => c.toUpperCase().replace(/[^A-Z0-9]/g,'');
  async function issueRecoveryCode(){
    const code = newRecoveryCode();
    wrapRc = await wrap(dkRaw, normCode(code));
    await persist();
    return code;
  }
  let rcResolve = null, rcCode = '';
  function showRecovery(code){
    rcCode = code;
    const g = code.split('-'); $('rcCode').textContent = g.slice(0,3).join('-') + '\n' + g.slice(3).join('-');
    $('rcAck').checked = false; $('rcDone').disabled = true;
    $('rcScrim').classList.remove('hidden');
    return new Promise(res => { rcResolve = res; });
  }
  $('rcAck').addEventListener('change', () => { $('rcDone').disabled = !$('rcAck').checked; });
  $('rcDone').addEventListener('click', () => { $('rcScrim').classList.add('hidden'); rcCode = ''; const r = rcResolve; rcResolve = null; if (r) r(); });
  $('rcCopy').addEventListener('click', () => copy(rcCode, 'Recovery code copied', true));
  $('rcSave').addEventListener('click', async () => {
    const text = `Stash recovery code\n\n${rcCode}\n\nUse this on the Stash unlock screen (Forgot password?) to set a new master password.\nKeep it somewhere safe and private.\n`;
    const r = await saveFile('stash-recovery-code.txt', text, 'text/plain');
    if (r === 'saved') toast('Recovery code saved'); else if (r === 'failed') toast("Couldn't save — copy it instead", false);
  });

  // ---------- wrong-attempt delay ----------
  const FAIL_KEY = 'stash.v2.fails', FREE_TRIES = 5, MAX_WAIT = 15 * 60 * 1000;
  function readFails(){ try { return JSON.parse(localStorage.getItem(FAIL_KEY)) || {n:0, until:0}; } catch(e){ return {n:0, until:0}; } }
  function writeFails(f){ try { localStorage.setItem(FAIL_KEY, JSON.stringify(f)); } catch(e){} }
  function noteFail(){ const f = readFails(); f.n++; if (f.n >= FREE_TRIES) f.until = Date.now() + Math.min(30000 * 2 ** (f.n - FREE_TRIES), MAX_WAIT); writeFails(f); return f; }
  function clearFails(){ try { localStorage.removeItem(FAIL_KEY); } catch(e){} }
  const waitLeft = () => Math.max(0, readFails().until - Date.now());
  const fmtWait = ms => { const s = Math.ceil(ms / 1000); return s >= 60 ? `${Math.ceil(s / 60)} min` : `${s}s`; };
  let waitTimer = null;
  function showWait(){
    clearInterval(waitTimer);
    const tick = () => {
      const left = waitLeft();
      ['lockBtn','recBtn'].forEach(id => { $(id).disabled = left > 0; });
      const msg = left > 0 ? `Too many wrong attempts. Try again in ${fmtWait(left)}.` : '';
      [$('lockMsg'), $('recMsg')].forEach(m => { if (left > 0 || m.dataset.wait) { m.textContent = msg; m.dataset.wait = left > 0 ? '1' : ''; } });
      if (left <= 0) clearInterval(waitTimer);
    };
    tick(); waitTimer = setInterval(tick, 1000);
  }

  // ---------- lock screen ----------
  function showLock(){
    clearClip();
    dk = null; dkRaw = null; wrapPw = null; wrapRc = null; entries = []; detailId = null;
    closeAll(); $('rcScrim').classList.add('hidden'); rcCode = ''; rcResolve = null;
    setRecoverMode(false);
    $('app').classList.add('hidden'); $('lock').classList.remove('hidden');
    $('lockIcon').classList.remove('open');
    $('mp1').value = ''; $('mp2').value = ''; $('lockMsg').textContent = '';
    const setup = !readVault();
    $('mp2').classList.toggle('hidden', !setup);
    $('mp2').required = setup;
    $('mp1').placeholder = setup ? 'Create master password' : 'Master password';
    $('lockBtn').textContent = setup ? 'Create Stash' : 'Unlock';
    $('lockSub').textContent = setup ? 'Your passwords, locked with one key' : 'Enter your master password';
    let note = setup ? "Everything is encrypted on this device. Next, you'll get a recovery code in case you ever forget this password." : '';
    if (!storageOK) note += " This browser is blocking storage, so nothing will be kept after you close the page.";
    $('lockNote').textContent = note.trim();
    $('resetBtn').classList.toggle('hidden', setup);
    if (!setup && waitLeft() > 0) showWait();
    setTimeout(() => $('mp1').focus(), 60);
  }
  function lockError(t){
    $('lockMsg').textContent = t;
    const g = $('lockGroup'); g.classList.remove('shake'); void g.offsetWidth; g.classList.add('shake');
  }
  $('lockForm').addEventListener('submit', async e => {
    e.preventDefault();
    const pw = $('mp1').value, v = readVault(), btn = $('lockBtn');
    if (v && waitLeft() > 0) return showWait();
    $('lockMsg').textContent = '';
    if (!v){
      if (pw.length < MIN_PW) return lockError(`Use at least ${MIN_PW} characters`);
      if (pw !== $('mp2').value) return lockError("Passwords don't match");
    }
    btn.disabled = true; const label = btn.textContent; btn.textContent = v ? 'Unlocking…' : 'Creating…';
    try {
        let needCode = false;
      if (!v){
        await useDataKey(crypto.getRandomValues(new Uint8Array(32)));
        wrapPw = await wrap(dkRaw, pw, 'argon2id'); wrapRc = null; entries = [];
        await persist();
        needCode = true;
      } else {
        try { needCode = await unlockWithPassword(v, pw); }
        catch(err){
          btn.textContent = label;
          const f = noteFail();
          lockError(f.n >= FREE_TRIES ? 'Incorrect password' : `Incorrect password (${FREE_TRIES - f.n} ${FREE_TRIES - f.n === 1 ? 'try' : 'tries'} before a wait)`);
          $('mp1').select();
          if (f.n >= FREE_TRIES) setTimeout(showWait, 1200);
          return;
        }
        clearFails();
        if (pw.length < MIN_PW) setTimeout(() => toast(`Tip: change to a ${MIN_PW}+ character master password in Settings`, false), 900);
      }
      $('lockIcon').classList.add('open');
      setTimeout(async () => {
        enterApp();
        if (needCode){ const code = await issueRecoveryCode(); await showRecovery(code); }
      }, 320);
    } finally { btn.disabled = false; }
  });
  async function eraseAndStartOver(msg){
    if (await askConfirm({title:'Start over?', message:msg, ok:'Erase and Start Over'})){ wipeVault(); showLock(); }
  }
  function setRecoverMode(on){
    $('lockForm').classList.toggle('hidden', on);
    $('recoverForm').classList.toggle('hidden', !on);
    $('backBtn').classList.toggle('hidden', !on);
    $('lostBtn').classList.toggle('hidden', !on);
    $('resetBtn').classList.toggle('hidden', on || !readVault());
    $('lockSub').textContent = on ? 'Enter your recovery code and pick a new master password' : (readVault() ? 'Enter your master password' : 'Your passwords, locked with one key');
    $('lockNote').classList.toggle('hidden', on);
    ['recCode','recPw1','recPw2'].forEach(i => $(i).value = ''); $('recMsg').textContent = '';
    if (on) setTimeout(() => $('recCode').focus(), 60);
  }
  $('resetBtn').addEventListener('click', () => {
    const v = readVault();
    if (isV2(v) && v.rc) setRecoverMode(true);
    else eraseAndStartOver("This Stash doesn't have a recovery code yet, so a forgotten password can't be reset. Starting over erases every login.");
  });
  $('backBtn').addEventListener('click', () => { setRecoverMode(false); setTimeout(() => $('mp1').focus(), 60); });
  $('lostBtn').addEventListener('click', () => eraseAndStartOver("Without your master password or recovery code, your logins can't be unlocked by anyone. Starting over erases them."));
  $('recCode').addEventListener('input', e => {
    const n = normCode(e.target.value).slice(0,24);
    const f = n.match(/.{1,4}/g)?.join('-') || '';
    if (f !== e.target.value) e.target.value = f;
  });
  $('recoverForm').addEventListener('submit', async e => {
    e.preventDefault();
    const v = readVault(), btn = $('recBtn'), m = $('recMsg');
    const err = t => { m.textContent = t; const g = $('recGroup'); g.classList.remove('shake'); void g.offsetWidth; g.classList.add('shake'); };
    m.textContent = '';
    if (waitLeft() > 0) return showWait();
    const code = normCode($('recCode').value), p1 = $('recPw1').value;
    if (code.length !== 24) return err('Recovery codes are 24 letters and numbers');
    if (p1.length < MIN_PW) return err(`Use at least ${MIN_PW} characters for the new password`);
    if (p1 !== $('recPw2').value) return err("New passwords don't match");
    btn.disabled = true; btn.textContent = 'Checking…';
    try {
      try { await useDataKey(await unwrap(v.rc, code)); entries = await decryptEntries(v, dk); }
      catch(x){ dk = null; dkRaw = null; const f = noteFail(); err("That recovery code isn't right"); if (f.n >= FREE_TRIES) setTimeout(showWait, 1200); return; }
      clearFails();
      wrapRc = (v.rc.iter || LEGACY_ITER) < ITER ? await wrap(dkRaw, code) : v.rc;
      wrapPw = await wrap(dkRaw, p1, 'argon2id');
      await persist();
      $('lockIcon').classList.add('open');
      setTimeout(() => { enterApp(); toast('Master password reset'); }, 320);
    } finally { btn.disabled = false; btn.textContent = 'Reset Password'; }
  });
  function enterApp(){
    $('lock').classList.add('hidden'); $('app').classList.remove('hidden');
    $('q').value = ''; filter = 'All'; window.scrollTo(0,0);
    render(); bumpIdle();
  }

  // ---------- idle lock ----------
  function bumpIdle(){ if (!dk) return; clearTimeout(idleTimer); idleTimer = setTimeout(() => { if (!dk) return; if (rcResolve){ bumpIdle(); return; } showLock(); }, IDLE_MS); }
  ['pointerdown','keydown','scroll','touchstart'].forEach(ev => window.addEventListener(ev, bumpIdle, {passive:true}));
  // Lock as soon as Stash leaves the screen. Exceptions: while a file picker or share sheet that
  // Stash opened is showing, while the recovery code is on screen (so it can be written down), and
  // while a login is being edited, where you get 60 seconds to copy something from another app.
  const EDIT_GRACE_MS = 60 * 1000;
  let holdUntil = 0, hiddenAt = 0;
  const holdLock = ms => { holdUntil = Date.now() + ms; };
  const releaseLock = () => { holdUntil = 0; };
  function onHide(){
    if (!dk) return;
    if (Date.now() < holdUntil || rcResolve || !$('editScrim').classList.contains('hidden')){ hiddenAt = hiddenAt || Date.now(); return; }
    showLock();
  }
  function onShow(){
    if (dk && hiddenAt && Date.now() - hiddenAt > EDIT_GRACE_MS && !rcResolve && Date.now() >= holdUntil) showLock();
    hiddenAt = 0;
  }
  document.addEventListener('visibilitychange', () => document.visibilityState === 'hidden' ? onHide() : onShow());
  window.addEventListener('pagehide', onHide);
  $('lockNow').addEventListener('click', showLock);
  window.addEventListener('scroll', () => $('navbar').classList.toggle('scrolled', window.scrollY > 4), {passive:true});

  // ---------- helpers ----------
  const cats = () => { const s = new Set(); entries.forEach(e => e.cat && s.add(e.cat)); return [...s].sort((a,b)=>a.localeCompare(b)); };
  function el(tag, props={}, ...kids){ const n=document.createElement(tag); Object.assign(n, props); kids.forEach(k => k!=null && n.append(k)); return n; }
  function icon(id){ const s=document.createElementNS('http://www.w3.org/2000/svg','svg'); const u=document.createElementNS('http://www.w3.org/2000/svg','use'); u.setAttribute('href','#'+id); s.append(u); return s; }
  function avatar(title){
    let h=0; for (const c of (title||'?').toLowerCase()) h = (h*31 + c.charCodeAt(0))>>>0;
    const [a,b] = AVATARS[h % AVATARS.length];
    const d = el('div',{className:'avatar',textContent:(title.trim()[0]||'?').toUpperCase()});
    d.style.background = `linear-gradient(145deg,${a},${b})`;
    return d;
  }
  function strength(p){
    if (!p) return null;
    let pool = 0; if (/[a-z]/.test(p)) pool+=26; if (/[A-Z]/.test(p)) pool+=26; if (/\d/.test(p)) pool+=10; if (/[^a-zA-Z0-9]/.test(p)) pool+=32;
    const bits = p.length * Math.log2(Math.max(pool,1));
    return bits < 40 ? {t:'Weak',w:'28%',c:'var(--danger)',weak:true} : bits < 70 ? {t:'Fair',w:'62%',c:'var(--warn)',weak:false} : {t:'Strong',w:'100%',c:'var(--ok)',weak:false};
  }

  // ---------- 2FA codes (TOTP, RFC 6238) ----------
  // Accepts a base32 setup key, or an otpauth://totp/... link (as found in QR codes and exports).
  function parseTotp(raw){
    raw = (raw || '').trim();
    if (!raw) return null;
    let secret = raw, digits = 6, period = 30, algo = 'SHA-1';
    if (/^otpauth:\/\//i.test(raw)){
      let u; try { u = new URL(raw); } catch(e){ throw new Error("That link isn't a valid 2FA link"); }
      if (u.host.toLowerCase() !== 'totp') throw new Error('Only time-based (TOTP) codes are supported');
      secret = u.searchParams.get('secret') || '';
      digits = parseInt(u.searchParams.get('digits') || '6', 10);
      period = parseInt(u.searchParams.get('period') || '30', 10);
      const a = (u.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-','');
      algo = {SHA1:'SHA-1', SHA256:'SHA-256', SHA512:'SHA-512'}[a];
      if (!algo) throw new Error('Unsupported 2FA algorithm');
    }
    secret = secret.toUpperCase().replace(/[\s=-]/g,'');
    if (!/^[A-Z2-7]+$/.test(secret) || secret.length < 16) throw new Error("That doesn't look like a 2FA setup key");
    if (![6,7,8].includes(digits) || !(period >= 15 && period <= 120)) throw new Error('Unsupported 2FA settings');
    return {secret, digits, period, algo};
  }
  function b32(str){
    const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits=0, val=0; const out=[];
    for (const ch of str){ val = (val<<5) | A.indexOf(ch); bits += 5; if (bits >= 8){ out.push((val >>> (bits-8)) & 255); bits -= 8; } }
    return new Uint8Array(out);
  }
  const totpKeys = new Map();
  async function totpCode(cfg, t = Date.now()){
    const id = cfg.algo + cfg.secret;
    let key = totpKeys.get(id);
    if (!key){ key = await crypto.subtle.importKey('raw', b32(cfg.secret), {name:'HMAC', hash:cfg.algo}, false, ['sign']); totpKeys.set(id, key); }
    const ctr = Math.floor(t / 1000 / cfg.period), msg = new DataView(new ArrayBuffer(8));
    msg.setUint32(0, Math.floor(ctr / 2**32)); msg.setUint32(4, ctr >>> 0);
    const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg.buffer));
    const o = h[h.length-1] & 15;
    const n = ((h[o]&127)<<24 | h[o+1]<<16 | h[o+2]<<8 | h[o+3]) % 10**cfg.digits;
    return String(n).padStart(cfg.digits,'0');
  }
  const fmtCode = c => c.length === 6 ? c.slice(0,3)+' '+c.slice(3) : c.length === 8 ? c.slice(0,4)+' '+c.slice(4) : c;
  let otpTimer = null;
  function stopOtp(){ clearInterval(otpTimer); otpTimer = null; }
  function otpRow(raw){
    const g = el('div',{className:'form-group'});
    let cfg; try { cfg = parseTotp(raw); } catch(e){ g.append(el('div',{className:'otp'}, el('div',{className:'otp-err',textContent:'2FA key is invalid. Edit this login to fix it.'}))); return g; }
    const code = el('div',{className:'otp-code',textContent:'••• •••'});
    const ns = 'http://www.w3.org/2000/svg', R = 15.5, C = 2*Math.PI*R;
    const svg = document.createElementNS(ns,'svg'); svg.setAttribute('viewBox','0 0 38 38');
    for (const cls of ['trk','arc']){ const c = document.createElementNS(ns,'circle'); c.setAttribute('cx','19'); c.setAttribute('cy','19'); c.setAttribute('r',R); c.setAttribute('class',cls); svg.append(c); }
    const arc = svg.lastChild; arc.style.strokeDasharray = C;
    const secs = el('span'); const ring = el('div',{className:'otp-ring'}); ring.append(svg, secs);
    const cp = el('button',{className:'iconbtn',type:'button'}); cp.setAttribute('aria-label','Copy 2FA code'); cp.append(icon('i-copy'));
    let current = '';
    cp.onclick = async () => { if (current) copy(await totpCode(cfg), '2FA code copied', true); };
    g.append(el('div',{className:'otp'}, el('div',{className:'otp-main'}, el('div',{className:'drow-label',textContent:'2FA code'}), code), ring, cp));
    let lastCtr = -1;
    const tick = async () => {
      const now = Date.now(), left = cfg.period - Math.floor(now/1000) % cfg.period, ctr = Math.floor(now/1000/cfg.period);
      if (ctr !== lastCtr){ lastCtr = ctr; current = await totpCode(cfg, now); code.textContent = fmtCode(current); }
      secs.textContent = left;
      arc.style.strokeDashoffset = C * (1 - left / cfg.period);
      const ending = left <= 5; code.classList.toggle('ending', ending); ring.classList.toggle('ending', ending);
    };
    stopOtp(); tick(); otpTimer = setInterval(() => { if (!g.isConnected) return stopOtp(); tick(); }, 1000);
    return g;
  }

  // ---------- list ----------
  function render(){
    const all = cats();
    $('count').textContent = entries.length ? `${entries.length} ${entries.length === 1 ? 'login' : 'logins'}` : '';
    const chips = $('chips'); chips.textContent = '';
    if (filter !== 'All' && !all.includes(filter)) filter = 'All';
    if (all.length){
      ['All', ...all].forEach(c => {
        const b = el('button', {className:'chip', type:'button', textContent:c});
        b.setAttribute('aria-pressed', String(c === filter));
        b.onclick = () => { filter = c; render(); };
        chips.append(b);
      });
    }
    chips.classList.toggle('hidden', !all.length);

    const q = $('q').value.trim().toLowerCase();
    const shown = entries
      .filter(e => filter === 'All' || e.cat === filter)
      .filter(e => !q || [e.title,e.user,e.url,e.notes,e.cat].some(x => (x||'').toLowerCase().includes(q)))
      .sort((a,b) => a.title.localeCompare(b.title, undefined, {sensitivity:'base'}));

    const list = $('list'); list.textContent = '';
    if (!entries.length || !shown.length){
      const ic = el('div',{className:'appicon'}); ic.innerHTML = $('lockIcon').innerHTML;
      list.append(el('div',{className:'empty'}, ic,
        el('strong',{textContent: entries.length ? 'No results' : 'No logins yet'}),
        entries.length ? 'Try another search or folder.' : 'Tap + to stash your first login.'));
      return;
    }
    // group by first letter
    let letter = null, group = null;
    shown.forEach(e => {
      const L = /[a-z]/i.test(e.title[0]) ? e.title[0].toUpperCase() : '#';
      if (L !== letter){ letter = L; list.append(el('div',{className:'section-label',textContent:L})); group = el('div',{className:'group'}); list.append(group); }
      const s = strength(e.pass);
      const item = el('button',{className:'item',type:'button'},
        avatar(e.title),
        el('div',{className:'item-meta'}, el('div',{className:'item-title',textContent:e.title}), el('div',{className:'item-sub',textContent:e.user || e.url || 'No username'})),
        e.totp ? el('span',{className:'tfa',textContent:'2FA',title:'Has a 2FA code'}) : null,
        s && s.weak ? el('span',{className:'weakdot',title:'Weak password'}) : null,
        (() => { const c = icon('i-chev'); c.setAttribute('class','chev'); return c; })()
      );
      item.onclick = () => openDetail(e.id);
      group.append(item);
    });
  }
  $('q').addEventListener('input', render);

  // ---------- detail ----------
  function openDetail(id){
    detailId = id;
    const e = entries.find(x => x.id === id); if (!e) return;
    const body = $('detailBody'); body.textContent = '';
    const hero = el('div',{className:'detail-hero'}, avatar(e.title), el('h3',{id:'dTitle',textContent:e.title}));
    if (e.cat) hero.append(el('div'), el('span',{className:'cat',textContent:e.cat}));
    body.append(hero);

    const g = el('div',{className:'form-group'});
    g.append(drow('Username', e.user, {copy:true}));
    g.append(drow('Password', e.pass, {copy:true, secret:true}));
    if (e.url) g.append(drow('Website', e.url, {link:true}));
    body.append(g);
    if (e.totp) body.append(otpRow(e.totp));

    const s = strength(e.pass);
    if (s && s.weak){
      const w = el('div',{className:'form-group'});
      const r = el('div',{className:'drow'}, el('span',{className:'weakdot'}), el('div',{className:'drow-main'}, el('div',{className:'drow-val',textContent:'Weak password'}), el('div',{className:'drow-label',textContent:'Consider changing it on the site and updating it here.'})));
      w.append(r); body.append(w);
    }
    if (e.notes){
      body.append(el('div',{className:'section-label',textContent:'Notes'}));
      body.append(el('div',{className:'form-group'}, el('div',{className:'notes-text',textContent:e.notes})));
    }
    const del = el('button',{className:'destructive',type:'button',textContent:'Delete Login'});
    del.onclick = async () => {
      if (!(await askConfirm({title:`Delete ${e.title}?`, message:'This login will be permanently removed.', ok:'Delete Login'}))) return;
      entries = entries.filter(x => x.id !== e.id);
      await persist(); $('detailScrim').classList.add('hidden'); render(); toast('Login deleted');
    };
    body.append(del);
    if (e.updated) body.append(el('div',{className:'updated',textContent:'Last edited ' + new Date(e.updated).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'})}));
    $('detailScrim').classList.remove('hidden');
  }
  function drow(label, value, opts){
    const r = el('div',{className:'drow'});
    const val = el('div',{className:'drow-val' + (opts.secret ? ' mono' : '')});
    let shown = !opts.secret;
    const paint = () => {
      val.textContent = '';
      if (!value){ val.textContent = '—'; val.style.color='var(--muted)'; return; }
      if (opts.link){
        const safe = /^https?:\/\//i.test(value) ? value : 'https://' + value;
        val.append(el('a',{href:safe,target:'_blank',rel:'noopener noreferrer',textContent:value.replace(/^https?:\/\//i,'')}));
      } else val.textContent = shown ? value : '•'.repeat(Math.min(value.length, 12));
    };
    paint();
    r.append(el('div',{className:'drow-main'}, el('div',{className:'drow-label',textContent:label}), val));
    if (value && opts.secret){
      const t = el('button',{className:'iconbtn',type:'button'}); t.setAttribute('aria-label','Show password'); t.append(icon('i-eye'));
      let hideTimer = null;
      const setShown = v => { shown = v; t.textContent=''; t.append(icon(shown?'i-eyeoff':'i-eye')); t.setAttribute('aria-label', shown?'Hide password':'Show password'); paint();
        clearTimeout(hideTimer); if (shown) hideTimer = setTimeout(() => setShown(false), REVEAL_MS); };
      t.onclick = () => setShown(!shown);
      r.append(t);
    }
    if (value && opts.copy){
      const c = el('button',{className:'iconbtn',type:'button'}); c.setAttribute('aria-label','Copy ' + label.toLowerCase()); c.append(icon('i-copy'));
      c.onclick = () => copy(value, `${label} copied`, !!opts.secret);
      r.append(c);
    }
    if (value && opts.link){
      const safe = /^https?:\/\//i.test(value) ? value : 'https://' + value;
      const a = el('a',{className:'iconbtn',href:safe,target:'_blank',rel:'noopener noreferrer'}); a.setAttribute('aria-label','Open website'); a.append(icon('i-open'));
      r.append(a);
    }
    return r;
  }
  $('dClose').addEventListener('click', () => { stopOtp(); $('detailScrim').classList.add('hidden'); });
  $('dEdit').addEventListener('click', () => { $('detailScrim').classList.add('hidden'); openEditor(detailId); });

  // ---------- clipboard ----------
  let clipTimer = null, clipPending = false;
  async function writeClip(text){
    try { await navigator.clipboard.writeText(text); return true; } catch(e){}
    const ta = el('textarea',{value:text}); ta.style.position='fixed'; ta.style.opacity='0';
    document.body.append(ta); ta.select();
    let ok = false; try { ok = document.execCommand('copy'); } catch(e){}
    ta.remove(); return ok;
  }
  async function clearClip(){
    if (!clipPending) return;
    // Browsers only allow clipboard writes while Stash is in front; if it isn't, try again when it comes back.
    if (document.hasFocus && !document.hasFocus()) return;
    if (await writeClip(' ')) { clipPending = false; clearTimeout(clipTimer); }
  }
  window.addEventListener('focus', clearClip);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') setTimeout(clearClip, 300); });
  async function copy(text, msg, sensitive = false){
    const ok = await writeClip(text);
    if (ok && sensitive){
      clipPending = true; clearTimeout(clipTimer);
      clipTimer = setTimeout(clearClip, CLIP_CLEAR_MS);
      msg += ' · clears in 30s';
    } else if (ok){ clipPending = false; clearTimeout(clipTimer); }
    toast(ok ? msg : "Couldn't copy — tap the eye to reveal it", ok);
  }

  // ---------- editor ----------
  function openEditor(id){
    editingId = id || null;
    const e = entries.find(x => x.id === id) || {};
    $('editTitle').textContent = id ? 'Edit Login' : 'New Login';
    $('fTitle').value = e.title || ''; $('fUser').value = e.user || ''; $('fPass').value = e.pass || '';
    $('fUrl').value = e.url || ''; $('fNotes').value = e.notes || ''; $('fTotp').value = e.totp || ''; $('totpMsg').textContent = '';
    const sel = $('fCat'); sel.textContent = '';
    const current = e.cat || (FOLDERS.includes(filter) ? filter : 'Personal');
    const opts = FOLDERS.includes(current) ? FOLDERS : [...FOLDERS, current];
    opts.forEach(c => sel.append(el('option',{value:c,textContent:c})));
    sel.value = current;
    setPwVisible(false);
    updateMeter(); updateSave();
    $('editScrim').classList.remove('hidden');
    setTimeout(() => $('fTitle').focus(), 60);
  }
  let editHideTimer = null;
  function setPwVisible(v){ clearTimeout(editHideTimer); if (v) editHideTimer = setTimeout(() => setPwVisible(false), REVEAL_MS); $('fPass').type = v ? 'text' : 'password'; const b=$('fShow'); b.textContent=''; b.append(icon(v?'i-eyeoff':'i-eye')); b.setAttribute('aria-label', v?'Hide password':'Show password'); }
  function updateSave(){ $('editSave').disabled = !$('fTitle').value.trim(); }
  $('fTitle').addEventListener('input', updateSave);
  $('addBtn').addEventListener('click', () => openEditor(null));
  $('editCancel').addEventListener('click', () => { $('editScrim').classList.add('hidden'); if (editingId) openDetail(editingId); });
  $('fShow').addEventListener('click', () => setPwVisible($('fPass').type === 'password'));
  $('fGen').addEventListener('click', () => { $('fPass').value = generate(20); setPwVisible(true); updateMeter(); });
  $('fPass').addEventListener('input', updateMeter);
  $('editForm').addEventListener('submit', async ev => {
    ev.preventDefault();
    const data = {
      title: $('fTitle').value.trim(), user: $('fUser').value.trim(), pass: $('fPass').value,
      url: $('fUrl').value.trim(), cat: $('fCat').value.trim(), notes: $('fNotes').value.trim(), totp: $('fTotp').value.trim(), updated: Date.now()
    };
    if (!data.title) return;
    try { parseTotp(data.totp); $('totpMsg').textContent = ''; }
    catch(err){ $('totpMsg').textContent = err.message; $('fTotp').focus(); return; }
    if (!data.totp) delete data.totp;
    let id = editingId;
    if (id) entries = entries.map(x => { if (x.id !== id) return x; const n = {...x, ...data}; if (!data.totp) delete n.totp; return n; });
    else { id = crypto.getRandomValues(new Uint32Array(2)).join('-'); entries.push({id, ...data}); }
    await persist();
    $('editScrim').classList.add('hidden'); render();
    toast(editingId ? 'Changes saved' : 'Login saved');
    openDetail(id);
  });
  function generate(n){
    const lower='abcdefghijkmnopqrstuvwxyz', upper='ABCDEFGHJKLMNPQRSTUVWXYZ', digits='23456789', sym='!@#$%^&*-_=+?';
    const all = lower+upper+digits+sym;
    const pick = set => { const lim = 256 - (256 % set.length); let b; do { b = crypto.getRandomValues(new Uint8Array(1))[0]; } while (b >= lim); return set[b % set.length]; };
    const out = [pick(lower), pick(upper), pick(digits), pick(sym)];
    while (out.length < n) out.push(pick(all));
    for (let i = out.length-1; i > 0; i--){ const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i+1); [out[i],out[j]]=[out[j],out[i]]; }
    return out.join('');
  }
  function updateMeter(){
    const s = strength($('fPass').value);
    $('meterBar').style.width = s ? s.w : '0'; $('meterBar').style.background = s ? s.c : 'transparent';
    $('meterLabel').textContent = s ? s.t : ''; $('meterLabel').style.color = s ? s.c : '';
  }

  // ---------- settings ----------
  $('menuBtn').addEventListener('click', () => $('menuScrim').classList.remove('hidden'));
  $('menuClose').addEventListener('click', () => $('menuScrim').classList.add('hidden'));
  $('mExport').addEventListener('click', async () => {
    const v = readVault() || await persist();
    const filename = `stash-backup-${new Date().toISOString().slice(0,10)}.json`;
    const r = await saveFile(filename, JSON.stringify(v, null, 2), 'application/json');
    if (r === 'saved') toast('Backup saved'); else if (r === 'failed') toast("Couldn't save the backup", false);
  });
  $('mImport').addEventListener('click', () => { holdLock(5 * 60 * 1000); $('importFile').click(); });
  $('importFile').addEventListener('cancel', () => setTimeout(releaseLock, 1500));
  $('importFile').addEventListener('change', async ev => {
    setTimeout(releaseLock, 1500);
    const f = ev.target.files[0]; ev.target.value = '';
    if (!f) return;
    let v; try { v = JSON.parse(await f.text()); } catch(e){ toast("That file isn't a Stash backup", false); return; }
    if (!v || v.app !== 'stash' || !(isV2(v) || isV1(v))){ toast("That file isn't a Stash backup", false); return; }
    if (!(await askConfirm({title:'Restore this backup?', message:"It replaces everything here. You'll unlock it with the master password (or recovery code) it was saved with.", ok:'Restore'}))) return;
    writeVault(v); showLock(); toast('Backup restored — unlock with its password');
  });
  $('mWipe').addEventListener('click', async () => {
    if (await askConfirm({title:'Erase Stash?', message:'Every login will be permanently deleted. This cannot be undone.', ok:'Erase Everything'})){ wipeVault(); showLock(); }
  });
  $('mRecovery').addEventListener('click', async () => {
    if (!(await askConfirm({title:'Create a new recovery code?', message:'Your current recovery code will stop working. Backups saved earlier still open with the old one.', ok:'Create New Code', danger:false}))) return;
    $('menuScrim').classList.add('hidden');
    const code = await issueRecoveryCode();
    await showRecovery(code);
    toast('New recovery code is active');
  });
  $('mChange').addEventListener('click', () => {
    $('menuScrim').classList.add('hidden');
    ['pwOld','pwNew','pwNew2'].forEach(i => $(i).value=''); $('pwMsg').textContent='';
    $('pwScrim').classList.remove('hidden'); setTimeout(()=>$('pwOld').focus(),60);
  });
  $('pwCancel').addEventListener('click', () => $('pwScrim').classList.add('hidden'));
  $('pwForm').addEventListener('submit', async ev => {
    ev.preventDefault();
    const m = $('pwMsg'); m.textContent = '';
    try { await unwrap(wrapPw, $('pwOld').value); } catch(e){ m.textContent = 'Current password is incorrect'; return; }
    const n = $('pwNew').value;
    if (n.length < MIN_PW){ m.textContent = `Use at least ${MIN_PW} characters`; return; }
    if (n !== $('pwNew2').value){ m.textContent = "New passwords don't match"; return; }
    wrapPw = await wrap(dkRaw, n, 'argon2id');
    await persist(); $('pwScrim').classList.add('hidden'); toast('Master password changed');
  });

  SHEETS.forEach(id => $(id).addEventListener('click', e => { if (e.target.id === id) $(id).classList.add('hidden'); }));
  document.addEventListener('keydown', e => { if (e.key !== 'Escape') return; if (confirmResolve) finishConfirm(false); else closeAll(); });
  function closeAll(){ stopOtp(); SHEETS.forEach(id => $(id).classList.add('hidden')); }

  // In-app confirm (browser confirm() popups are blocked inside published pages)
  let confirmResolve = null;
  function askConfirm({title, message, ok, danger = true}){
    if (confirmResolve) confirmResolve(false);
    $('cTitle').textContent = title; $('cMsg').textContent = message || '';
    $('cMsg').classList.toggle('hidden', !message);
    const b = $('cOk'); b.textContent = ok; b.classList.toggle('danger', danger);
    $('confirmScrim').classList.remove('hidden');
    setTimeout(() => $('cCancel').focus(), 30);
    return new Promise(res => { confirmResolve = res; });
  }
  function finishConfirm(v){ $('confirmScrim').classList.add('hidden'); const r = confirmResolve; confirmResolve = null; if (r) r(v); }
  $('cOk').addEventListener('click', () => finishConfirm(true));
  $('cCancel').addEventListener('click', () => finishConfirm(false));
  $('confirmScrim').addEventListener('click', e => { if (e.target.id === 'confirmScrim') finishConfirm(false); });

  let toastT;
  function toast(t, ok = true){
    const n=$('toast'); n.textContent='';
    if (ok) n.append(icon('i-check'));
    n.append(document.createTextNode(t));
    n.classList.remove('hidden'); clearTimeout(toastT); toastT=setTimeout(()=>n.classList.add('hidden'),2200);
  }

  if (!window.crypto || !crypto.subtle){
    $('lockSub').textContent = "This browser can't encrypt, so Stash can't run here.";
    $('lockForm').classList.add('hidden');
  } else showLock();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')){
    window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
  }
})();
