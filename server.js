import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { getDecodedToken } from '@cashu/cashu-ts';
import webpush from 'web-push';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3232;
const LNBITS_URL = process.env.LNBITS_URL || 'https://lnbits.cz';

// === Web Push ===
webpush.setVapidDetails(
    process.env.VAPID_EMAIL,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

const SUBS_FILE = path.join(__dirname, 'push-subscriptions.json');
// Map: inkey → { subscription, lastHash }
const pushSubs = new Map(
    fs.existsSync(SUBS_FILE) ? JSON.parse(fs.readFileSync(SUBS_FILE, 'utf8')) : []
);

function savePushSubs() {
    fs.writeFileSync(SUBS_FILE, JSON.stringify([...pushSubs]));
}

async function sendPush(inkey, state, payload) {
    try {
        await webpush.sendNotification(state.subscription, JSON.stringify(payload));
        console.log(`[push] odesláno: ${payload.title}`);
    } catch (err) {
        console.error(`[push] chyba odesílání (${err.statusCode}):`, err.body || err.message);
        if (err.statusCode === 410 || err.statusCode === 404) {
            pushSubs.delete(inkey);
            savePushSubs();
        }
    }
}

async function checkIncomingPayments() {
    for (const [inkey, state] of pushSubs) {
        try {
            const r = await fetch(`${LNBITS_URL}/api/v1/payments?limit=20`, {
                headers: { 'X-Api-Key': inkey }
            });
            if (!r.ok) continue;
            const payments = await r.json();
            if (!Array.isArray(payments)) continue;

            // Jen potvrzené příchozí platby
            const received = payments.filter(p => p.amount > 0 && p.status === 'success');
            if (received.length === 0) continue;

            const latestHash = received[0].payment_hash;

            if (state.lastHash === null) {
                state.lastHash = latestHash;
                savePushSubs();
                continue;
            }

            // Najdi všechny nové platby od lastHash
            const newPayments = [];
            for (const p of received) {
                if (p.payment_hash === state.lastHash) break;
                newPayments.push(p);
            }

            for (const p of newPayments) {
                const sats = Math.floor(p.amount / 1000);
                const memo = p.memo || 'Platba přijata';
                await sendPush(inkey, state, {
                    title: `+${sats.toLocaleString('cs-CZ')} sats`,
                    body: memo,
                });
            }

            if (newPayments.length > 0) {
                state.lastHash = latestHash;
                savePushSubs();
            }
        } catch (e) {
            console.error('[push] check error:', e.message);
        }
    }
}

setInterval(checkIncomingPayments, 30_000);

// Při každém startu serveru obnov timestamp v sw.js → klienti dostanou update notifikaci
const swPath = path.join(__dirname, 'public', 'sw.js');
const swContent = fs.readFileSync(swPath, 'utf8').replace(/\/\/ built:.*/, '');
fs.writeFileSync(swPath, `// built: ${Date.now()}\n` + swContent.replace(/^\n/, ''));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc:     ["'self'"],
            scriptSrc:      ["'self'", "https://cdnjs.cloudflare.com", "https://unpkg.com", "'unsafe-eval'"],
            styleSrc:       ["'self'", "'unsafe-inline'"],
            imgSrc:         ["'self'", "data:", "blob:"],
            connectSrc:     ["'self'"],
            mediaSrc:       ["'self'"],
            objectSrc:      ["'none'"],
            frameAncestors: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Příliš mnoho požadavků, zkus za chvíli.' }
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', apiLimiter);

// === Bezpečnostní helpers ===
function assertSafeUrl(urlStr) {
    let url;
    try { url = new URL(urlStr); } catch { throw new Error('Neplatná URL'); }
    if (url.protocol !== 'https:' && url.protocol !== 'http:')
        throw new Error('Nepodporovaný protokol');
    const h = url.hostname.toLowerCase();
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|0\.0\.0\.0|fd[0-9a-f]{2}:)/.test(h))
        throw new Error('Interní síťová adresa není povolena');
}

function validateAmount(val, max = 21_000_000_000) {
    const n = parseInt(val);
    if (!Number.isFinite(n) || n < 1 || n > max) throw new Error('Neplatná částka');
    return n;
}

// === LNURL bech32 dekodér ===
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function decodeLnurl(lnurl) {
    const str = lnurl.toLowerCase();
    const pos = str.lastIndexOf('1');
    const bits5 = [];
    for (let i = pos + 1; i < str.length - 6; i++) {
        const d = BECH32_CHARSET.indexOf(str[i]);
        if (d === -1) throw new Error('Neplatný LNURL');
        bits5.push(d);
    }
    let acc = 0, bits = 0;
    const bytes = [];
    for (const v of bits5) {
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8) { bits -= 8; bytes.push((acc >> bits) & 0xff); }
    }
    return Buffer.from(bytes).toString('utf8');
}

// === Cashu token parser (v3 JSON + v4 CBOR via @cashu/cashu-ts) ===
function parseCashuToken(token) {
    return getDecodedToken(token.trim());
}

// === HTTP helper ===
async function postJson(url, body, headers = {}) {
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body)
    });
}

// ==================== ENDPOINTS ====================

// Mapa username → inkey (pro Lightning adresy)
const lnAddressMap = new Map();

// Auth
app.post('/api/auth', async (req, res) => {
    const { username, password } = req.body;
    try {
        let response = await postJson(`${LNBITS_URL}/api/v1/auth`, { username, password });
        if (!response.ok) {
            response = await postJson(`${LNBITS_URL}/api/v1/auth/register`, { username, password, password_repeat: password });
        }
        if (!response.ok) throw new Error(await response.text());

        const authData = await response.json();
        const accessToken = authData.access_token;
        if (!accessToken) throw new Error('LNBits nevrátilo access_token');

        const walletRes = await fetch(`${LNBITS_URL}/api/v1/wallets`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        if (!walletRes.ok) throw new Error(await walletRes.text());

        const wallets = await walletRes.json();
        const walletList = Array.isArray(wallets) ? wallets : [wallets];
        lnAddressMap.set(username, walletList[0].inkey);
        res.json({ wallets: walletList });
    } catch (error) {
        console.error('Auth chyba:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Lightning adresa — LNURL-p metadata
app.get('/.well-known/lnurlp/:username', (req, res) => {
    const { username } = req.params;
    if (!lnAddressMap.has(username)) return res.status(404).json({ status: 'ERROR', reason: 'User not found' });
    const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
    const host  = req.headers['x-forwarded-host'] || req.headers.host;
    const callback = `${proto}://${host}/api/lnurlp/callback?user=${encodeURIComponent(username)}`;
    res.json({
        tag: 'payRequest',
        callback,
        minSendable: 1000,
        maxSendable: 100000000000,
        metadata: JSON.stringify([['text/plain', username]])
    });
});

// Lightning adresa — callback (vytvoří invoice)
app.get('/api/lnurlp/callback', async (req, res) => {
    const { user, amount } = req.query;
    const inkey = lnAddressMap.get(user);
    if (!inkey) return res.status(404).json({ status: 'ERROR', reason: 'User not found' });
    try {
        const amountSats = Math.ceil(validateAmount(amount, 21_000_000_000_000) / 1000);
        const r = await postJson(`${LNBITS_URL}/api/v1/payments`,
            { out: false, amount: amountSats, memo: user },
            { 'X-Api-Key': inkey }
        );
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail);
        res.json({ pr: d.payment_request, routes: [] });
    } catch (e) {
        res.status(500).json({ status: 'ERROR', reason: e.message });
    }
});

// Zůstatek
app.get('/api/balance', async (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    try {
        const r = await fetch(`${LNBITS_URL}/api/v1/wallet`, { headers: { 'X-Api-Key': inkey } });
        const d = await r.json();
        res.json({ balance_msat: d.balance_msat ?? d.balance ?? 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Vytvořit invoice (příjem)
app.post('/api/invoice', async (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    try {
        const amount = validateAmount(req.body.amount);
        const r = await postJson(`${LNBITS_URL}/api/v1/payments`, { out: false, amount, memo: 'BleskWallet' }, { 'X-Api-Key': inkey });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail);
        res.json(d);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Dekódovat invoice
app.post('/api/decode', async (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    const { invoice } = req.body;
    try {
        const r = await postJson(`${LNBITS_URL}/api/v1/payments/decode`, { data: invoice }, { 'X-Api-Key': inkey });
        res.json(await r.json());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Zaplatit invoice
app.post('/api/pay', async (req, res) => {
    const adminkey = req.headers['x-admin-key'];
    const { invoice } = req.body;
    try {
        const r = await postJson(`${LNBITS_URL}/api/v1/payments`, { out: true, bolt11: invoice }, { 'X-Api-Key': adminkey });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail);
        res.json(d);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Historie plateb
app.get('/api/payments', async (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    try {
        const r = await fetch(`${LNBITS_URL}/api/v1/payments?limit=50`, {
            headers: { 'X-Api-Key': inkey }
        });
        res.json(await r.json());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Zkontrolovat platbu
app.get('/api/checkpayment', async (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    const { payment_hash } = req.query;
    try {
        const r = await fetch(`${LNBITS_URL}/api/v1/payments/${payment_hash}`, {
            headers: { 'X-Api-Key': inkey }
        });
        const d = await r.json();
        res.json({ paid: d.paid });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Rozluštit LNURL (bech32 → URL → fetch dat)
app.post('/api/lnurl/resolve', async (req, res) => {
    const { lnurl } = req.body;
    try {
        let url = lnurl.toLowerCase().startsWith('lnurl1')
            ? decodeLnurl(lnurl)
            : lnurl;
        assertSafeUrl(url);
        const r = await fetch(url);
        if (!r.ok) throw new Error(`LNURL endpoint vrátil ${r.status}`);
        const data = await r.json();
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// LNURL-w: zavolat callback (mint nám zaplatí náš invoice)
app.post('/api/lnurl/withdraw', async (req, res) => {
    const { callback, k1, invoice } = req.body;
    try {
        assertSafeUrl(callback);
        const sep = callback.includes('?') ? '&' : '?';
        const r = await fetch(`${callback}${sep}k1=${k1}&pr=${invoice}`);
        const d = await r.json();
        if (d.status === 'ERROR') throw new Error(d.reason);
        res.json(d);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// LNURL-p: zavolat callback pro invoice (platíme my)
app.post('/api/lnurl/pay', async (req, res) => {
    const { callback, amount_msat } = req.body;
    try {
        assertSafeUrl(callback);
        const sep = callback.includes('?') ? '&' : '?';
        const r = await fetch(`${callback}${sep}amount=${amount_msat}`);
        const d = await r.json();
        if (d.status === 'ERROR') throw new Error(d.reason);
        res.json(d); // vrací { pr: "lnbc..." }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Lightning adresa → LNURL-p data
app.post('/api/lnaddress', async (req, res) => {
    const { address } = req.body;
    try {
        const parts = address.split('@');
        if (parts.length !== 2) throw new Error('Neplatná Lightning adresa');
        const [user, domain] = parts;
        const lnUrl = `https://${domain}/.well-known/lnurlp/${encodeURIComponent(user)}`;
        assertSafeUrl(lnUrl);
        const r = await fetch(lnUrl);
        if (!r.ok) throw new Error(`Adresa nenalezena (${r.status})`);
        res.json(await r.json());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Starší minty vrací paid:true, novější state:"PAID"
function meltPaid(melt) {
    return melt.paid === true || melt.state === 'PAID';
}

// Cashu token: roztavit proofs → satoshi na Lightning
app.post('/api/cashu/redeem', async (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    const { token } = req.body;
    try {
        const parsed = parseCashuToken(token);
        let totalRedeemed = 0;

        // getDecodedToken vrací { mint, proofs } nebo staré { token: [{mint, proofs}] }
        const entries = parsed.token ? parsed.token : [{ mint: parsed.mint, proofs: parsed.proofs }];

        for (const entry of entries) {
            const mintUrl = entry.mint.replace(/\/$/, '');
            assertSafeUrl(mintUrl);
            const proofs  = entry.proofs;
            const amount  = proofs.reduce((s, p) => s + p.amount, 0);

            // Iterativně: pokud mint odpoví "not enough inputs", snížíme invoice o deficit
            let invoiceAmount = amount;
            let redeemed = false;
            for (let attempt = 0; attempt < 8; attempt++) {
                if (invoiceAmount <= 0) throw new Error('Token je příliš malý na pokrytí poplatků');
                const invData = await (await postJson(`${LNBITS_URL}/api/v1/payments`, { out: false, amount: invoiceAmount, memo: 'Cashu redeem' }, { 'X-Api-Key': inkey })).json();
                const quote = await (await postJson(`${mintUrl}/v1/melt/quote/bolt11`, { unit: 'sat', request: invData.payment_request })).json();
                if (quote.detail) throw new Error(quote.detail);

                const melt = await (await postJson(`${mintUrl}/v1/melt/bolt11`, { quote: quote.quote, inputs: proofs })).json();
                if (meltPaid(melt)) {
                    totalRedeemed += invoiceAmount;
                    redeemed = true;
                    break;
                }
                // Parsujeme "needed: X" z chyby a snížíme invoice o deficit
                const match = (melt.detail || '').match(/needed:\s*(\d+)/);
                if (!match) throw new Error('Mint neproplatil: ' + JSON.stringify(melt));
                const needed = parseInt(match[1]);
                invoiceAmount -= (needed - amount);
            }
            if (!redeemed) throw new Error('Nepodařilo se proplatit token po několika pokusech');
        }

        res.json({ redeemed: totalRedeemed });
    } catch (e) {
        console.error('Cashu redeem chyba:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// Noop pro iOS password save form
app.post('/api/save-noop', (_req, res) => res.send(''));

// Push — vrátí VAPID public key
app.get('/api/push/vapid-key', (_req, res) => {
    res.json({ key: process.env.VAPID_PUBLIC_KEY });
});

// Push — přihlásit odběr
app.post('/api/push/subscribe', (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    const { subscription } = req.body;
    if (!inkey || !subscription) return res.status(400).json({ error: 'Chybí data' });
    pushSubs.set(inkey, { subscription, lastHash: null });
    savePushSubs();
    res.json({ ok: true });
});

// Push — odhlásit odběr
app.post('/api/push/unsubscribe', (req, res) => {
    const inkey = req.headers['x-wallet-key'];
    pushSubs.delete(inkey);
    savePushSubs();
    res.json({ ok: true });
});

// Fallback pro PWA
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`BleskWallet běží na http://0.0.0.0:${PORT}`);
});
