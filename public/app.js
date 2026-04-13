// === DOM ===
const mainButtons          = document.getElementById('main-buttons');
const statusMessage        = document.getElementById('status-message');
const welcomeScreen        = document.getElementById('welcome-screen');
const btnCreateWallet      = document.getElementById('btn-create-wallet');
const btnRestoreWallet     = document.getElementById('btn-restore-wallet');
const setupScreen          = document.getElementById('setup-screen');
const seedPhraseBox        = document.getElementById('seed-phrase');
const btnSeedSaved         = document.getElementById('btn-seed-saved');
const btnCopySeedSetup     = document.getElementById('btn-copy-seed-setup');
const btnToggleSeed        = document.getElementById('btn-toggle-seed');
const btnSavePasswords     = document.getElementById('btn-save-passwords');
const seedSaveUsername     = document.getElementById('seed-save-username');
const seedSavePassword     = document.getElementById('seed-save-password');
const restoreScreen        = document.getElementById('restore-screen');
const restoreInput         = document.getElementById('restore-input');
const btnToggleRestore     = document.getElementById('btn-toggle-restore');
const restoreError         = document.getElementById('restore-error');
const btnRestoreConfirm    = document.getElementById('btn-restore-confirm');
const btnRestoreBack       = document.getElementById('btn-restore-back');
const amountInputSection   = document.getElementById('amount-input-section');
const invoiceAmount        = document.getElementById('invoice-amount');
const btnGenerateInvoice   = document.getElementById('btn-generate-invoice');
const btnCancelReceive     = document.getElementById('btn-cancel-receive');
const qrDisplayContainer   = document.getElementById('qr-display-container');
const qrDisplay            = document.getElementById('qr-display');
const invoiceStringDisplay = document.getElementById('invoice-string-display');
const btnCloseQr           = document.getElementById('btn-close-qr');
const payConfirmSection    = document.getElementById('pay-confirm-section');
const payAmountDisplay     = document.getElementById('pay-amount-display');
const payDescDisplay       = document.getElementById('pay-desc-display');
const payInvoicePreview    = document.getElementById('pay-invoice-preview');
const btnConfirmPay        = document.getElementById('btn-confirm-pay');
const btnCancelPay         = document.getElementById('btn-cancel-pay');
const lnurlpSection        = document.getElementById('lnurlp-section');
const lnurlpTitle          = document.getElementById('lnurlp-title');
const lnurlpDomain         = document.getElementById('lnurlp-domain');
const lnurlpDescription    = document.getElementById('lnurlp-description');
const lnurlpAmountInput    = document.getElementById('lnurlp-amount');
const lnurlpSlider         = document.getElementById('lnurlp-slider');
const lnurlpHint           = document.getElementById('lnurlp-hint');
const btnLnurlpConfirm     = document.getElementById('btn-lnurlp-confirm');
const btnLnurlpCancel      = document.getElementById('btn-lnurlp-cancel');
const sendInputSection     = document.getElementById('send-input-section');
const sendInput            = document.getElementById('send-input');
const btnSendConfirm       = document.getElementById('btn-send-confirm');
const btnSendCancel        = document.getElementById('btn-send-cancel');
const btnSendScan          = document.getElementById('btn-send-scan');
const scanSection          = document.getElementById('scan-section');
const btnCancelScan        = document.getElementById('btn-cancel-scan');
const bcurProgress         = document.getElementById('bcur-progress');
const successOverlay       = document.getElementById('success-overlay');
const txDetailOverlay      = document.getElementById('tx-detail-overlay');
const txDetailTitle        = document.getElementById('tx-detail-title');
const txDetailBody         = document.getElementById('tx-detail-body');
const btnCloseTxDetail     = document.getElementById('btn-close-tx-detail');
const settingsOverlay      = document.getElementById('settings-overlay');
const btnSettings          = document.getElementById('btn-settings');
const btnCloseSettings     = document.getElementById('btn-close-settings');
const seedDisplay          = document.getElementById('seed-display');
const seedWords            = seedDisplay.querySelector('.seed-words');
const btnRevealSeed        = document.getElementById('btn-reveal-seed');
const btnCopySeed          = document.getElementById('btn-copy-seed');
const btnLogout            = document.getElementById('btn-logout');
const logoutConfirm        = document.getElementById('logout-confirm');
const btnLogoutCancel      = document.getElementById('btn-logout-cancel');
const btnLogoutConfirm     = document.getElementById('btn-logout-confirm');
const balanceDisplay       = document.getElementById('balance-display');
const balanceSpinner       = document.getElementById('balance-spinner');
const txHistory            = document.getElementById('tx-history');
const lnAddressRow         = document.getElementById('ln-address-row');
const lnAddressDisplay     = document.getElementById('ln-address-display');
const btnCopyLnAddress     = document.getElementById('btn-copy-lnaddress');
const btnSend              = document.getElementById('btn-send');
const btnReceive           = document.getElementById('btn-receive');
const btnScan              = document.getElementById('btn-scan');

// === STAV ===
let html5QrCode    = null;
let bcurDecoder    = null;
let userKeys       = { inkey: null, adminkey: null };
let currentInvoice = null;
let lnurlpState    = null;
let balanceInterval  = null;
let receiveInterval  = null;
let busy           = false; // ochrana před dvojklikem
let currentLnAddress = null;
let txCache = [];

// === HELPERS ===
const ALL_PANELS = [amountInputSection, qrDisplayContainer, payConfirmSection, lnurlpSection, sendInputSection, scanSection, mainButtons];

async function postJson(url, body) {
    const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    return r.json();
}

function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function walletHeaders() {
    return { 'X-Wallet-Key': userKeys.inkey || '', 'X-Admin-Key': userKeys.adminkey || '' };
}
async function walletGet(url) {
    return fetch(url, { headers: walletHeaders() }).then(r => r.json());
}
async function walletPost(url, body = {}) {
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...walletHeaders() },
        body: JSON.stringify(body)
    }).then(r => r.json());
}

// === SEED ŠIFROVÁNÍ (WebCrypto AES-GCM + PBKDF2) ===
const SEED_KDF_SALT = new TextEncoder().encode('gwallet-v1-salt');

async function deriveSeedKey(seed) {
    const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(seed), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: SEED_KDF_SALT, iterations: 100_000, hash: 'SHA-256' },
        raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
}
async function encryptSeed(seed) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveSeedKey(seed);
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(seed));
    return JSON.stringify({ iv: [...iv], ct: [...new Uint8Array(ct)] });
}
async function decryptSeed(stored, seed) {
    const { iv, ct } = JSON.parse(stored);
    const key = await deriveSeedKey(seed);
    const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, new Uint8Array(ct));
    return new TextDecoder().decode(pt);
}
async function storeSeed(seed) {
    sessionStorage.setItem('gwallet_seed', seed);
    localStorage.setItem('gwallet_seed_enc', await encryptSeed(seed));
}
function getSessionSeed() { return sessionStorage.getItem('gwallet_seed'); }
function hasEncryptedSeed() { return !!localStorage.getItem('gwallet_seed_enc'); }

function showPanel(panel) {
    ALL_PANELS.forEach(el => el.classList.add('hidden'));
    if (panel) panel.classList.remove('hidden');
    txHistory.classList.toggle('hidden', panel !== mainButtons);
}

function showStatus(msg, persistent = false) {
    statusMessage.textContent = msg;
    statusMessage.classList.remove('hidden');
    if (!persistent) setTimeout(() => statusMessage.classList.add('hidden'), 4000);
}

function hideStatus() { statusMessage.classList.add('hidden'); }

function showSuccess() {
    successOverlay.classList.remove('hidden', 'hiding');
    setTimeout(() => {
        successOverlay.classList.add('hiding');
        setTimeout(() => successOverlay.classList.add('hidden'), 400);
    }, 1200);
}

function stopCamera() {
    if (html5QrCode) { html5QrCode.stop().catch(() => {}); html5QrCode = null; }
    bcurDecoder = null;
    bcurProgress.classList.add('hidden');
}

function stopReceivePolling() { clearInterval(receiveInterval); receiveInterval = null; }

function resetUI() {
    stopCamera();
    stopReceivePolling();
    // Blur před clear zabraňuje iOS "Undo Typing" dialogu
    document.activeElement?.blur();
    invoiceAmount.value      = '';
    sendInput.value          = '';
    lnurlpAmountInput.value  = '';
    qrDisplay.innerHTML      = '';
    currentInvoice           = null;
    lnurlpState              = null;
    busy                     = false;
    btnLnurlpConfirm.disabled    = false;
    btnLnurlpConfirm.textContent = 'Zaplatit';
    hideStatus();
    showPanel(mainButtons);
}

// Ochrana tlačítek před dvojklikem
function guard(fn) {
    return async function (...args) {
        if (busy) return;
        busy = true;
        try { await fn.apply(this, args); }
        finally { busy = false; }
    };
}

// === ZŮSTATEK ===
async function fetchBalance() {
    if (!userKeys.inkey) return;
    try {
        const d = await walletGet('/api/balance');
        const sats = Math.floor((d.balance_msat ?? 0) / 1000);
        balanceSpinner.classList.add('hidden');
        balanceDisplay.textContent = sats.toLocaleString('cs-CZ');
    } catch (e) {}
}

function parseTxDate(tx) {
    const raw = tx.created_at ?? tx.time ?? tx.date ?? tx.timestamp ?? tx.paid_at;
    if (raw == null) return null;
    const d = typeof raw === 'string'
        ? new Date(raw.replace(/(\.\d{3})\d+/, '$1'))  // ořež mikrosekundy → ms
        : new Date(raw > 1e12 ? raw : raw * 1000);
    return isNaN(d) ? null : d;
}

function renderTxItem(tx, today) {
    const received = tx.amount > 0;
    const fee  = Math.abs(tx.fee || 0);
    const sats = Math.floor((Math.abs(tx.amount) + (received ? 0 : fee)) / 1000);
    const memo = escHtml(tx.memo || tx.extra?.comment || (received ? 'Přijato' : 'Odesláno'));
    const d = parseTxDate(tx);
    const isToday = d && d.toDateString() === today.toDateString();
    const timeStr = !d ? '—'
        : isToday
            ? d.toLocaleTimeString('cs-CZ', { hour: '2-digit', minute: '2-digit' })
            : d.toLocaleDateString('cs-CZ', { day: 'numeric', month: 'short' });
    const failed  = tx.status === 'failed'  || tx.status === 'error';
    const pending = tx.status === 'pending' || (!tx.status && tx.pending && !failed);
    const statusLabel = failed  ? ['tx-status-failed',  'selhalo']
                      : pending ? ['tx-status-pending', 'čeká']
                      :           ['tx-status-ok',      'potvrzeno'];
    const icon = failed
        ? `<svg class="tx-failed-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`
        : pending
            ? `<svg class="tx-pending-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`
            : '';
    const cls  = failed ? ' tx-failed' : pending ? ' tx-pending' : '';
    const hash = tx.payment_hash || tx.checking_id || '';
    return `<div class="tx-item${cls}" data-hash="${escHtml(hash)}" style="cursor:pointer">
        <div class="tx-info">
            <span class="tx-memo">${memo}</span>
            <span class="tx-time">${timeStr} · <span class="${statusLabel[0]}">${statusLabel[1]}</span></span>
        </div>
        <div class="tx-right">
            ${icon}
            <span class="tx-amount ${received ? 'tx-received' : 'tx-sent'}">${received ? '+' : '−'}${sats.toLocaleString('cs-CZ')} sats</span>
        </div>
    </div>`;
}

// === HISTORIE ===
async function fetchHistory() {
    if (!userKeys.inkey) return;
    try {
        const raw = await walletGet('/api/payments');
        if (!Array.isArray(raw)) return;
        txCache = raw;
        const hourAgo = Date.now() / 1000 - 3600;
        const txs = raw.filter(tx => {
            if (!tx.pending) return true;
            const ts = tx.created_at || tx.time || 0;
            return ts > hourAgo;
        });
        if (txs.length === 0) {
            txHistory.innerHTML = '<p class="tx-empty">Žádné transakce</p>';
            return;
        }
        const today = new Date();
        txHistory.innerHTML =
            '<p class="tx-history-label">Transakce</p>' +
            txs.map(tx => renderTxItem(tx, today)).join('');
    } catch (e) {}
}

async function refreshWallet() {
    await fetchBalance();
    fetchHistory();
}

// === INIT ===
async function initWallet() {
    // Migrace z plaintextového úložiště (jen jednou)
    const legacy = localStorage.getItem('gwallet_seed');
    if (legacy) {
        await storeSeed(legacy);
        localStorage.removeItem('gwallet_seed');
    }

    const seed = getSessionSeed();
    if (seed) {
        await authenticateWithLNBits(seed);
    } else if (hasEncryptedSeed()) {
        showReturnScreen();
    } else {
        welcomeScreen.classList.remove('hidden');
    }
}

function showReturnScreen() {
    document.getElementById('restore-title').textContent = 'Vstoupit do peněženky';
    document.getElementById('restore-desc').textContent  = 'Zadej svých 12 slov pro odemčení.';
    welcomeScreen.classList.add('hidden');
    restoreScreen.classList.remove('hidden');
    setTimeout(() => restoreInput.focus(), 100);
}

// Uvítací screen — vytvořit novou
btnCreateWallet.addEventListener('click', () => {
    const wallet = ethers.Wallet.createRandom();
    const seed = wallet.mnemonic.phrase;
    const hash = ethers.utils.id(seed);
    const username = 'gw_' + hash.substring(2, 16);
    seedPhraseBox.value = seed;
    seedPhraseBox.type = 'password';
    seedSaveUsername.value = username;
    seedSavePassword.value = seed;

    btnSavePasswords.onclick = () => {
        document.getElementById('seed-save-submit').click();
        btnSavePasswords.textContent = 'Uloženo ✓';
        setTimeout(() => { btnSavePasswords.textContent = 'Uložit do hesel'; }, 2000);
    };
    welcomeScreen.classList.add('hidden');
    setupScreen.classList.remove('hidden');

    btnToggleSeed.onclick = () => {
        const visible = seedPhraseBox.type === 'text';
        seedPhraseBox.type = visible ? 'password' : 'text';
        btnToggleSeed.style.color = visible ? '' : 'var(--orange)';
    };

    btnCopySeedSetup.onclick = () => {
        navigator.clipboard.writeText(seed).then(() => {
            btnCopySeedSetup.style.color = 'var(--green)';
            setTimeout(() => { btnCopySeedSetup.style.color = ''; }, 1500);
        });
    };

    btnSeedSaved.onclick = async () => {
        await storeSeed(seed);
        setupScreen.classList.add('hidden');
        await authenticateWithLNBits(seed);
    };
});

// Uvítací screen — obnovit
btnRestoreWallet.addEventListener('click', () => {
    restoreInput.value = '';
    restoreError.classList.add('hidden');
    welcomeScreen.classList.add('hidden');
    restoreScreen.classList.remove('hidden');
    setTimeout(() => restoreInput.focus(), 100);
});

btnToggleRestore.addEventListener('click', () => {
    const visible = restoreInput.type === 'text';
    restoreInput.type = visible ? 'password' : 'text';
    btnToggleRestore.style.color = visible ? '' : 'var(--orange)';
});

btnRestoreBack.addEventListener('click', () => {
    restoreScreen.classList.add('hidden');
    welcomeScreen.classList.remove('hidden');
});

btnRestoreConfirm.addEventListener('click', async () => {
    const seed = restoreInput.value.trim().toLowerCase().replace(/\s+/g, ' ');
    const words = seed.split(' ');
    if (words.length !== 12 && words.length !== 24) {
        restoreError.textContent = 'Zadej 12 nebo 24 slov oddělených mezerami.';
        restoreError.classList.remove('hidden');
        return;
    }
    try {
        // Ověří platnost seedu přes ethers
        ethers.utils.HDNode.fromMnemonic(seed);
    } catch (e) {
        restoreError.textContent = 'Neplatná fráze — zkontroluj pravopis slov.';
        restoreError.classList.remove('hidden');
        return;
    }
    restoreError.classList.add('hidden');
    if (hasEncryptedSeed()) {
        try {
            await decryptSeed(localStorage.getItem('gwallet_seed_enc'), seed);
        } catch {
            restoreError.textContent = 'Nesprávná fráze — klíč neodpovídá uloženým datům.';
            restoreError.classList.remove('hidden');
            return;
        }
    }
    await storeSeed(seed);
    restoreScreen.classList.add('hidden');
    await authenticateWithLNBits(seed);
});

async function authenticateWithLNBits(seed) {
    showStatus('Přihlašuji…', true);
    const hash     = ethers.utils.id(seed);
    const username = 'gw_' + hash.substring(2, 16);
    const password = hash.substring(16, 48);
    try {
        const data = await postJson('/api/auth', { username, password });
        if (data.wallets && data.wallets.length > 0) {
            userKeys.inkey    = data.wallets[0].inkey;
            userKeys.adminkey = data.wallets[0].adminkey;
            currentLnAddress = `${username}@${window.location.host}`;
            lnAddressDisplay.textContent = currentLnAddress;
            lnAddressRow.classList.remove('hidden');
            showPanel(mainButtons);
            hideStatus();
            refreshWallet();
            balanceInterval = setInterval(refreshWallet, 30000);
        } else {
            showStatus('Chyba: peněženka se nenačetla.');
        }
    } catch (e) { showStatus('Chyba spojení se serverem.'); }
}

// === DETEKCE TYPU SKENU ===
function detectType(raw) {
    const s = raw.trim();
    const lower = s.toLowerCase().replace(/^lightning:/, '');
    if (/^lnbc|^lntb|^lnsb|^lnbcrt/.test(lower)) return { type: 'bolt11', value: lower };
    if (lower.startsWith('lnurl1'))                  return { type: 'lnurl',  value: lower };
    if (s.startsWith('cashuA') || s.startsWith('cashuB')) return { type: 'cashu', value: s };
    if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s))    return { type: 'lnaddress', value: s };
    if (s.startsWith('https://') || s.startsWith('http://')) {
        try {
            const url = new URL(s);
            const t = url.searchParams.get('token') || url.hash.slice(1);
            if (t && (t.startsWith('cashuA') || t.startsWith('cashuB'))) return { type: 'cashu', value: t };
        } catch (e) {}
        return { type: 'lnurl_url', value: s };
    }
    return { type: 'unknown', value: s };
}

// === SCAN ===
function startScan() {
    if (busy) return;
    busy = true;

    startCamera();
}

function startCamera() {
    showPanel(scanSection);
    html5QrCode = new Html5Qrcode('qr-reader');

    // Timeout pro případ odmítnutí kamery (iOS promise nikdy neodmítne)
    const fallback = setTimeout(() => {
        if (busy) { busy = false; showStatus('Kamera není dostupná.'); resetUI(); }
    }, 8000);

    html5QrCode.start(
        { facingMode: 'environment' },
        { fps: 15, qrbox: (w, h) => ({ width: Math.min(w, h) - 40, height: Math.min(w, h) - 40 }) },
        (_text) => {
            clearTimeout(fallback);
            // Stripni případné obklopující uvozovky a normalizuj na lowercase
            const text = _text.trim().replace(/^["']|["']$/g, '').toLowerCase();
            // BC-UR animovaný QR (ur:bytes/...)
            if (text.startsWith('ur:')) {
                try {
                    if (!bcurDecoder) bcurDecoder = new BCUR.URDecoder();
                    const ok = bcurDecoder.receivePart(text);
                    if (bcurDecoder.isComplete()) {
                        if (!bcurDecoder.isSuccess()) throw new Error(bcurDecoder.resultError());
                        const ur = bcurDecoder.resultUR();
                        const raw = new TextDecoder('utf-8', { fatal: false }).decode(ur.cbor);
                        // Extrahuj známý formát z CBOR wrapperu
                        const match = raw.match(/cashu[ABab][A-Za-z0-9+/_-]+|lnbc[a-z0-9]+|lnurl1[a-z0-9]+|ln[a-z0-9]+@[^\s"]+/i);
                        const decoded = match ? match[0] : raw.replace(/^["'\s\x00-\x1f\x80-\xff]*/u, '').replace(/["'\s]+$/g, '');
                        stopCamera();
                        busy = false;
                        handleScan(decoded);
                    } else {
                        const pct = Math.round(bcurDecoder.estimatedPercentComplete() * 100);
                        bcurProgress.textContent = `Načítám… ${pct}%`;
                        bcurProgress.classList.remove('hidden');
                    }
                } catch (e) {
                    console.error('[BC-UR] error:', e);
                    stopCamera();
                    busy = false;
                    showStatus('Chyba BC-UR: ' + e.message);
                    resetUI();
                }
                return;
            }
            stopCamera();
            busy = false;
            handleScan(text);
        },
        () => {}
    ).then(() => clearTimeout(fallback))
     .catch(() => { clearTimeout(fallback); busy = false; showStatus('Kamera není dostupná.'); resetUI(); });
}

async function handleScan(raw) {
    const { type, value } = detectType(raw);

    if (type === 'bolt11') {
        await showPayConfirm(value);

    } else if (type === 'lnurl' || type === 'lnurl_url') {
        showStatus('Načítám LNURL…', true);
        try {
            const data = await postJson('/api/lnurl/resolve', { lnurl: value });
            if (data.error) throw new Error(data.error);
            hideStatus();

            if (data.tag === 'withdrawRequest') {
                await handleLnurlw(data);
            } else if (data.tag === 'payRequest') {
                showLnurlp(data, 'LNURL platba');
            } else {
                showStatus('Nepodporovaný typ LNURL: ' + (data.tag || '?'));
                resetUI();
            }
        } catch (e) { showStatus('Chyba LNURL: ' + e.message); resetUI(); }

    } else if (type === 'cashu') {
        await handleCashu(value);

    } else if (type === 'lnaddress') {
        showStatus('Načítám Lightning adresu…', true);
        try {
            const data = await postJson('/api/lnaddress', { address: value });
            if (data.error) throw new Error(data.error);
            hideStatus();
            showLnurlp(data, value);
        } catch (e) { showStatus('Chyba adresy: ' + e.message); resetUI(); }

    } else {
        showStatus('Neznámý formát QR kódu.');
        resetUI();
    }
}

// === BOLT11 platba ===
async function showPayConfirm(invoice) {
    showStatus('Dekóduji…', true);
    try {
        const d = await walletPost('/api/decode', { invoice });
        if (d.detail) throw new Error(d.detail);

        const sats = Math.floor((d.amount_msat || 0) / 1000);
        payAmountDisplay.textContent = sats.toLocaleString('cs-CZ') + ' sats';
        payDescDisplay.textContent   = d.description || '';
        payInvoicePreview.textContent = invoice.slice(0, 20) + '…' + invoice.slice(-10);
        currentInvoice = invoice;
        hideStatus();
        showPanel(payConfirmSection);
    } catch (e) { showStatus('Nelze dekódovat: ' + e.message); resetUI(); }
}

// === LNURL-w (withdraw) ===
// Společná funkce pro zobrazení panelu s částkou (pay i withdraw)
function showAmountPanel({ title, domain, description, minSats, maxSats, mode }) {
    const hasRange = maxSats > minSats;

    lnurlpTitle.textContent       = title;
    lnurlpDomain.textContent      = domain;
    lnurlpDescription.textContent = description;
    lnurlpAmountInput.value       = minSats;
    lnurlpAmountInput.min         = minSats;
    lnurlpAmountInput.max         = maxSats;
    btnLnurlpConfirm.textContent  = mode === 'withdraw' ? 'Přijmout' : 'Zaplatit';

    if (hasRange) {
        lnurlpSlider.min   = minSats;
        lnurlpSlider.max   = maxSats;
        lnurlpSlider.value = minSats;
        lnurlpHint.textContent = `${minSats.toLocaleString('cs-CZ')} – ${maxSats.toLocaleString('cs-CZ')} sats`;
        lnurlpSlider.classList.remove('hidden');
    } else {
        lnurlpHint.textContent = `${minSats.toLocaleString('cs-CZ')} sats`;
        lnurlpSlider.classList.add('hidden');
    }

    showPanel(lnurlpSection);
    lnurlpAmountInput.focus();
}

// Slider → input
lnurlpSlider.addEventListener('input', () => {
    lnurlpAmountInput.value = lnurlpSlider.value;
});

// Input → slider (clamp na min/max)
lnurlpAmountInput.addEventListener('input', () => {
    const v = parseInt(lnurlpAmountInput.value) || 0;
    const clamped = Math.min(Math.max(v, parseInt(lnurlpSlider.min) || 0), parseInt(lnurlpSlider.max) || v);
    if (!lnurlpSlider.classList.contains('hidden')) lnurlpSlider.value = clamped;
});

// === LNURL-w (withdraw) ===
async function handleLnurlw(data) {
    const minSats = Math.ceil((data.minWithdrawable || 0) / 1000);
    const maxSats = Math.floor(data.maxWithdrawable / 1000);

    lnurlpState = { ...data, _mode: 'withdraw' };
    showAmountPanel({
        title: 'Přijmout sats',
        domain: data.defaultDescription || 'LNURL-withdraw',
        description: '',
        minSats, maxSats,
        mode: 'withdraw'
    });
}

async function doWithdraw(data, sats) {
    showStatus(`Přijímám ${sats} sats…`, true);
    try {
        const inv = await walletPost('/api/invoice', { amount: sats });
        if (inv.error) throw new Error(inv.error);

        const w = await postJson('/api/lnurl/withdraw', { callback: data.callback, k1: data.k1, invoice: inv.payment_request });
        if (w.error) throw new Error(w.error);

        await refreshWallet();
        resetUI();
        showSuccess();
    } catch (e) { showStatus('LNURL-w chyba: ' + e.message); resetUI(); }
}

// === LNURL-p (pay) ===
function showLnurlp(data, label) {
    const minSats = Math.ceil(data.minSendable / 1000);
    const maxSats = Math.floor(data.maxSendable / 1000);
    lnurlpState = { ...data, _mode: 'pay' };
    showAmountPanel({
        title: label.includes('@') ? 'Lightning adresa' : 'LNURL platba',
        domain: label,
        description: extractLnurlpDescription(data.metadata),
        minSats, maxSats,
        mode: 'pay'
    });
}

async function doLnurlPay(data, sats) {
    showStatus('Platím…', true);
    try {
        const d = await postJson('/api/lnurl/pay', { callback: data.callback, amount_msat: sats * 1000 });
        if (d.error) throw new Error(d.error);

        const pd = await walletPost('/api/pay', { invoice: d.pr });
        if (pd.error) throw new Error(pd.error);

        await refreshWallet();
        resetUI();
        showSuccess();
    } catch (e) { showStatus('Chyba: ' + e.message); resetUI(); }
}

function extractLnurlpDescription(metadata) {
    try {
        const arr = JSON.parse(metadata);
        const text = arr.find(([t]) => t === 'text/plain');
        return text ? text[1] : '';
    } catch (e) { return ''; }
}

btnLnurlpConfirm.addEventListener('click', guard(async () => {
    if (!lnurlpState) return;

    const sats = parseInt(lnurlpAmountInput.value);
    const minSats = parseInt(lnurlpAmountInput.min) || 0;
    const maxSats = parseInt(lnurlpAmountInput.max) || Infinity;
    if (!sats || sats < minSats || sats > maxSats) {
        return showStatus(`Zadejte částku ${minSats}–${maxSats} sats`);
    }

    btnLnurlpConfirm.disabled = true;

    const state = lnurlpState;
    lnurlpState = null;
    if (state._mode === 'withdraw') {
        await doWithdraw(state, sats);
    } else {
        await doLnurlPay(state, sats);
    }
}));

btnLnurlpCancel.addEventListener('click', resetUI);

// === CASHU ===
async function handleCashu(token) {
    showStatus('Vyměňuji Cashu token…', true);
    try {
        const d = await walletPost('/api/cashu/redeem', { token });
        if (d.error) throw new Error(d.error);
        await refreshWallet();
        resetUI();
        showSuccess();
    } catch (e) { showStatus('Cashu chyba: ' + e.message); resetUI(); }
}

// === PŘÍJEM ===
btnReceive.addEventListener('click', () => {
    if (busy) return;
    showPanel(amountInputSection);
    invoiceAmount.focus(); // okamžitě otevře klávesnici
});

btnCopyLnAddress.addEventListener('click', () => {
    if (!currentLnAddress) return;
    navigator.clipboard.writeText(currentLnAddress).then(() => {
        btnCopyLnAddress.style.color = 'var(--green)';
        setTimeout(() => { btnCopyLnAddress.style.color = ''; }, 1500);
    });
});

btnCancelReceive.addEventListener('click', resetUI);
btnCloseQr.addEventListener('click', resetUI);

invoiceStringDisplay.addEventListener('click', () => {
    if (!currentInvoice) return;
    navigator.clipboard.writeText(currentInvoice)
        .then(() => showStatus('Invoice zkopírován!'))
        .catch(() => showStatus('Kopírování selhalo — zkopírujte ručně.'));
});

btnGenerateInvoice.addEventListener('click', guard(async () => {
    const amount = parseInt(invoiceAmount.value);
    if (!amount || amount <= 0) return showStatus('Zadejte platnou částku.');
    if (!userKeys.inkey)        return showStatus('Peněženka není připojena.');

    showStatus('Generuji invoice…', true);
    try {
        const data = await walletPost('/api/invoice', { amount });
        if (data.error) throw new Error(data.error);

        currentInvoice = data.payment_request;
        invoiceStringDisplay.value = currentInvoice;
        showPanel(qrDisplayContainer);
        hideStatus();

        const qrSize = qrDisplay.offsetWidth - 24; // mínus padding
        new QRCode(qrDisplay, {
            text: `lightning:${currentInvoice}`,
            width: qrSize, height: qrSize,
            colorDark: '#000000', colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
        });

        // Polling — čekáme na platbu
        receiveInterval = setInterval(async () => {
            try {
                const p = await walletGet(`/api/checkpayment?payment_hash=${data.payment_hash}`);
                if (p.paid) {
                    stopReceivePolling();
                    await refreshWallet();
                    resetUI();
                    showSuccess();
                }
            } catch (e) {}
        }, 3000);

    } catch (e) { showStatus('Chyba: ' + e.message); }
}));

// === ODESLÁNÍ / SKENOVÁNÍ ===
btnSend.addEventListener('click', () => {
    if (busy) return;
    sendInput.value = '';
    showPanel(sendInputSection);
    setTimeout(() => sendInput.focus(), 100);
});

btnSendScan.addEventListener('click', startScan);

btnSendConfirm.addEventListener('click', guard(async () => {
    const val = sendInput.value.trim();
    if (!val) return showStatus('Zadejte invoice nebo adresu.');
    resetUI();
    await handleScan(val);
}));

btnSendCancel.addEventListener('click', resetUI);

btnScan.addEventListener('click', startScan);
btnCancelScan.addEventListener('click', () => { busy = false; stopCamera(); resetUI(); });

// === POTVRDIT PLATBU ===
btnConfirmPay.addEventListener('click', guard(async () => {
    if (!currentInvoice || !userKeys.adminkey) return;
    btnConfirmPay.disabled = true;
    showStatus('Odesílám platbu…', true);
    try {
        const d = await walletPost('/api/pay', { invoice: currentInvoice });
        if (d.error) throw new Error(d.error);
        await refreshWallet();
        resetUI();
        showSuccess();
    } catch (e) {
        showStatus('Chyba: ' + e.message);
        btnConfirmPay.disabled = false;
    }
}));

btnCancelPay.addEventListener('click', resetUI);

// === DETAIL TRANSAKCE ===
txHistory.addEventListener('click', e => {
    const item = e.target.closest('[data-hash]');
    if (!item) return;
    const tx = txCache.find(t => (t.payment_hash || t.checking_id) === item.dataset.hash);
    if (tx) showTxDetail(tx);
});

function showTxDetail(tx) {
    const received = tx.amount > 0;
    const fee      = Math.abs(tx.fee || 0);
    const sats     = Math.floor((Math.abs(tx.amount) + (received ? 0 : fee)) / 1000);
    const feeSats  = Math.round(fee / 1000);
    const d2       = parseTxDate(tx);
    const dateStr  = d2 ? d2.toLocaleString('cs-CZ') : '—';
    const failed   = tx.status === 'failed' || tx.status === 'error';
    const pending  = tx.status === 'pending' || (!tx.status && tx.pending && !failed);
    const statusCs = failed ? 'Selhalo' : pending ? 'Čeká na potvrzení' : 'Potvrzeno';
    const statusCls = failed ? 'tx-status-failed' : pending ? 'tx-status-pending' : 'tx-status-ok';

    txDetailTitle.textContent = received ? 'Přijatá platba' : 'Odeslaná platba';

    const row = (label, value, mono = false, copyable = false, rawHtml = false) => {
        const display = rawHtml ? String(value) : escHtml(String(value));
        return `<div class="tx-detail-row">
            <span class="tx-detail-label">${label}</span>
            <span class="tx-detail-value${mono ? ' mono' : ''}${copyable ? ' copyable' : ''}"${copyable ? ` data-copy="${escHtml(String(value))}"` : ''}>${display}</span>
        </div>`;
    };

    const invoice = tx.bolt11 || tx.payment_request || '';
    const hash    = tx.payment_hash || tx.checking_id || '';
    const preimage = tx.preimage || '';
    const extra   = tx.extra ? JSON.stringify(tx.extra, null, 2) : '';

    txDetailBody.innerHTML =
        row('Směr',    received ? '↓ Přijato' : '↑ Odesláno') +
        row('Stav',    `<span class="${statusCls}">${statusCs}</span>`, false, false, true) +
        row('Částka',  `${sats.toLocaleString('cs-CZ')} sats`) +
        (feeSats > 0 ? row('Poplatek', `${feeSats} sats`) : '') +
        row('Datum',   dateStr) +
        (tx.memo ? row('Memo', tx.memo) : '') +
        (hash    ? row('Payment hash', hash,    true, true) : '') +
        (invoice ? row('Invoice',      invoice, true, true) : '') +
        (preimage ? row('Preimage',    preimage,true, true) : '') +
        (extra   ? `<details class="tx-detail-extra"><summary>Extra data</summary><pre>${escHtml(extra)}</pre></details>` : '') +
        (pending && invoice
            ? `<button class="btn btn-secondary full-width" id="btn-show-tx-qr" style="margin-top:1rem">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;vertical-align:middle;margin-right:6px">
                    <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
                    <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
                    <rect x="7" y="7" width="3" height="3" fill="currentColor" stroke="none"/>
                    <rect x="14" y="7" width="3" height="3" fill="currentColor" stroke="none"/>
                    <rect x="7" y="14" width="3" height="3" fill="currentColor" stroke="none"/>
                    <path d="M14 14h3v3"/>
                </svg><span class="btn-qr-label">Zobrazit QR</span></button>
              <div id="tx-detail-qr" class="hidden" style="background:white;padding:12px;border-radius:12px;margin-top:0.75rem"></div>`
            : '');

    txDetailOverlay.classList.remove('hidden');

    if (pending && invoice) {
        const btnQr = document.getElementById('btn-show-tx-qr');
        const qrEl  = document.getElementById('tx-detail-qr');

        btnQr.addEventListener('click', () => {
            const visible = !qrEl.classList.contains('hidden');
            if (visible) {
                qrEl.classList.add('hidden');
                btnQr.querySelector('span.btn-qr-label').textContent = 'Zobrazit QR';
                return;
            }
            qrEl.innerHTML = '';
            qrEl.classList.remove('hidden');
            btnQr.querySelector('span.btn-qr-label').textContent = 'Skrýt QR';
            // Počkej na layout, pak vykresli QR a scrollni do pohledu
            requestAnimationFrame(() => {
                const size = txDetailBody.offsetWidth - 24;
                new QRCode(qrEl, {
                    text: `lightning:${invoice}`,
                    width: size, height: size,
                    colorDark: '#000000', colorLight: '#ffffff',
                    correctLevel: QRCode.CorrectLevel.M
                });
                qrEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            });
        });

        // Polling na potvrzení platby
        const hash = tx.payment_hash || tx.checking_id;
        const pollInterval = setInterval(async () => {
            try {
                const p = await walletGet(`/api/checkpayment?payment_hash=${hash}`);
                if (p.paid) {
                    clearInterval(pollInterval);
                    txDetailOverlay.classList.add('hidden');
                    await refreshWallet();
                    showSuccess();
                }
            } catch (e) {}
        }, 3000);

        // Zastav polling při zavření overlay
        const stopPoll = () => clearInterval(pollInterval);
        btnCloseTxDetail.addEventListener('click', stopPoll, { once: true });
        txDetailOverlay.addEventListener('click', stopPoll, { once: true });
    }
}

txDetailBody.addEventListener('click', e => {
    const el = e.target.closest('.copyable');
    if (!el) return;
    navigator.clipboard.writeText(el.dataset.copy).then(() => {
        const orig = el.textContent;
        el.textContent = 'Zkopírováno ✓';
        setTimeout(() => { el.textContent = orig; }, 1500);
    });
});

btnCloseTxDetail.addEventListener('click', () => txDetailOverlay.classList.add('hidden'));
txDetailOverlay.addEventListener('click', e => {
    if (e.target === txDetailOverlay) txDetailOverlay.classList.add('hidden');
});

// === NASTAVENÍ ===
btnSettings.addEventListener('click', () => {
    seedDisplay.classList.add('seed-hidden');
    seedWords.classList.add('hidden');
    btnRevealSeed.textContent = 'Zobrazit';
    logoutConfirm.classList.add('hidden');
    btnLogout.classList.remove('hidden');
    settingsOverlay.classList.remove('hidden');
});

btnCloseSettings.addEventListener('click', () => {
    settingsOverlay.classList.add('hidden');
});

settingsOverlay.addEventListener('click', (e) => {
    if (e.target === settingsOverlay) settingsOverlay.classList.add('hidden');
});

btnRevealSeed.addEventListener('click', () => {
    const isHidden = seedDisplay.classList.toggle('seed-hidden');
    btnRevealSeed.textContent = isHidden ? 'Zobrazit' : 'Skrýt';
    if (!isHidden) {
        seedWords.textContent = getSessionSeed() || '';
        seedWords.classList.remove('hidden');
    } else {
        seedWords.classList.add('hidden');
    }
});

btnCopySeed.addEventListener('click', () => {
    const seed = getSessionSeed();
    if (!seed) return;
    navigator.clipboard.writeText(seed)
        .then(() => {
            btnCopySeed.textContent = 'Zkopírováno ✓';
            setTimeout(() => { btnCopySeed.textContent = 'Kopírovat'; }, 2000);
        })
        .catch(() => showStatus('Kopírování selhalo.'));
});

btnLogout.addEventListener('click', () => {
    logoutConfirm.classList.remove('hidden');
    btnLogout.classList.add('hidden');
});

btnLogoutCancel.addEventListener('click', () => {
    logoutConfirm.classList.add('hidden');
    btnLogout.classList.remove('hidden');
});

btnLogoutConfirm.addEventListener('click', () => {
    localStorage.removeItem('gwallet_seed_enc');
    sessionStorage.removeItem('gwallet_seed');
    location.reload();
});

// === PUSH NOTIFIKACE ===
const btnNotify = document.getElementById('btn-notify');

async function subscribePush() {
    if (!('Notification' in window) || !('serviceWorker' in navigator)) return;
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') { showStatus('Notifikace zamítnuty.'); return; }

    const reg = await navigator.serviceWorker.ready;
    const { key } = await fetch('/api/push/vapid-key').then(r => r.json());

    const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: key,
    });

    const result = await walletPost('/api/push/subscribe', { subscription: sub.toJSON() });
    if (result.ok) {
        localStorage.setItem('push-enabled', '1');
        if (btnNotify) { btnNotify.textContent = 'Notifikace: zapnuto'; btnNotify.classList.add('active'); }
        showStatus('Notifikace zapnuty ✓');
    }
}

async function unsubscribePush() {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) await sub.unsubscribe();
    await walletPost('/api/push/unsubscribe', {});
    localStorage.removeItem('push-enabled');
    if (btnNotify) { btnNotify.textContent = 'Notifikace: vypnuto'; btnNotify.classList.remove('active'); }
    showStatus('Notifikace vypnuty.');
}

if (btnNotify) {
    const enabled = localStorage.getItem('push-enabled') === '1';
    btnNotify.textContent = enabled ? 'Notifikace: zapnuto' : 'Notifikace: vypnuto';
    if (enabled) btnNotify.classList.add('active');

    btnNotify.addEventListener('click', async () => {
        const enabled = localStorage.getItem('push-enabled') === '1';
        if (enabled) await unsubscribePush(); else await subscribePush();
    });
}

// === SERVICE WORKER ===
if ('serviceWorker' in navigator) {
    const updateBanner = document.getElementById('update-banner');
    const btnUpdate    = document.getElementById('btn-update');

    navigator.serviceWorker.register('/sw.js').then(reg => {
        const onUpdateFound = () => {
            const sw = reg.installing;
            if (!sw) return;
            sw.addEventListener('statechange', () => {
                if (sw.state === 'installed' && navigator.serviceWorker.controller) {
                    updateBanner.classList.remove('hidden');
                }
            });
        };
        reg.addEventListener('updatefound', onUpdateFound);

        // Kontroluj každých 5 minut
        setInterval(() => reg.update(), 5 * 60 * 1000);

        // Kontroluj při přepnutí zpět na tab
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') reg.update();
        });
    }).catch(() => {});

    btnUpdate.addEventListener('click', () => location.reload());
}

// === ADD TO HOME SCREEN ===
const a2hsBanner  = document.getElementById('a2hs-banner');
const a2hsHint    = document.getElementById('a2hs-hint');
const a2hsAdd     = document.getElementById('a2hs-add');
const a2hsDismiss = document.getElementById('a2hs-dismiss');
let deferredPrompt = null;

function isStandalone() {
    return window.matchMedia('(display-mode: standalone)').matches
        || window.navigator.standalone === true;
}

function isIos() {
    return /iphone|ipad|ipod/i.test(navigator.userAgent);
}

function showA2hs() {
    if (isStandalone() || sessionStorage.getItem('a2hs-dismissed')) return;
    if (isIos()) {
        a2hsHint.textContent = 'Klepni na sdílet ↑ → Přidat na plochu';
        a2hsAdd.classList.add('hidden');
    } else {
        a2hsHint.textContent = 'Spusť jako aplikaci bez prohlížeče';
    }
    a2hsBanner.classList.remove('hidden');
}

// Android: zachytíme nativní prompt
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    setTimeout(showA2hs, 3000);
});

// iOS: zobrazíme banner po 3s (nativní prompt neexistuje)
if (isIos() && !isStandalone()) {
    setTimeout(showA2hs, 3000);
}

async function triggerA2hs() {
    if (deferredPrompt) {
        deferredPrompt.prompt();
        const { outcome } = await deferredPrompt.userChoice;
        deferredPrompt = null;
        if (outcome === 'accepted') a2hsBanner.classList.add('hidden');
    }
}

a2hsAdd.addEventListener('click', triggerA2hs);

// Celý banner je klikatelný na Androidu
a2hsBanner.addEventListener('click', (e) => {
    if (e.target === a2hsDismiss || a2hsDismiss.contains(e.target)) return;
    triggerA2hs();
});

a2hsDismiss.addEventListener('click', () => {
    a2hsBanner.classList.add('hidden');
    sessionStorage.setItem('a2hs-dismissed', '1');
});

// === START ===
window.onload = initWallet;
