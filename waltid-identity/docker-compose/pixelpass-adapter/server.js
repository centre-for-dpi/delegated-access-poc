'use strict';

const express = require('express');
const session = require('express-session');
const { encode: cborEncode } = require('cbor-x');
const QRCode = require('qrcode');
const zlib = require('zlib');

const PORT = process.env.PORT || 7110;
const WALLET_API_URL = process.env.WALLET_API_URL || 'http://wallet-api:7001';
const INJI_VERIFY_URL = process.env.INJI_VERIFY_URL || 'http://localhost:7109';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'pixelpass-adapter-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 },
}));

// --- PixelPass encoding (CBOR + zlib deflate + Base45) ---

const BASE45_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

function base45Encode(buf) {
  let result = '';
  for (let i = 0; i < buf.length; i += 2) {
    if (i + 1 < buf.length) {
      const n = buf[i] * 256 + buf[i + 1];
      result += BASE45_ALPHABET[n % 45] +
                BASE45_ALPHABET[Math.floor(n / 45) % 45] +
                BASE45_ALPHABET[Math.floor(n / 2025)];
    } else {
      const n = buf[i];
      result += BASE45_ALPHABET[n % 45] + BASE45_ALPHABET[Math.floor(n / 45)];
    }
  }
  return result;
}

function pixelPassEncode(data) {
  const cbor = cborEncode(data);
  const compressed = zlib.deflateSync(cbor);
  return base45Encode(compressed);
}

// --- Wallet API helpers ---

async function walletLogin(email, password) {
  const res = await fetch(`${WALLET_API_URL}/wallet-api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, type: 'email' }),
  });
  if (!res.ok) throw new Error(`Login failed: ${res.status}`);
  const data = await res.json();
  return data.token;
}

async function walletGetWallets(token) {
  const res = await fetch(`${WALLET_API_URL}/wallet-api/wallet/accounts/wallets`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`Get wallets failed: ${res.status}`);
  const data = await res.json();
  return data.wallets || [];
}

async function walletListCredentials(token, walletId) {
  const res = await fetch(`${WALLET_API_URL}/wallet-api/wallet/${walletId}/credentials`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`List credentials failed: ${res.status}`);
  return res.json();
}

async function walletGetCredential(token, walletId, credentialId) {
  const res = await fetch(
    `${WALLET_API_URL}/wallet-api/wallet/${walletId}/credentials/${encodeURIComponent(credentialId)}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!res.ok) throw new Error(`Get credential failed: ${res.status}`);
  return res.json();
}

// --- HTML helpers ---

const pageStyle = `
  body { font-family: Inter, system-ui, sans-serif; background: #F5F7FA; margin: 0; padding: 2rem; color: #1F2933; }
  .card { background: white; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.1); padding: 2rem; max-width: 680px; margin: 2rem auto; }
  h1 { font-size: 1.5rem; font-weight: 700; color: #03449E; margin: 0 0 1rem; }
  label { display: block; font-weight: 500; margin-bottom: .25rem; }
  input[type=email], input[type=password] { width: 100%; box-sizing: border-box; padding: .5rem .75rem; border: 1px solid #CBD2D9; border-radius: 6px; font-size: 1rem; margin-bottom: .75rem; }
  button, .btn { display: inline-block; padding: .5rem 1.25rem; border-radius: 6px; border: none; cursor: pointer; font-size: .95rem; font-weight: 600; text-decoration: none; }
  .btn-primary { background: #0573F0; color: white; }
  .btn-primary:hover { background: #0552B5; }
  .btn-sm { padding: .3rem .8rem; font-size: .85rem; }
  .error { color: #E12D39; background: #FFE3E3; padding: .5rem .75rem; border-radius: 6px; margin-bottom: 1rem; }
  .warn { color: #7D4A00; background: #FFF3CD; padding: .5rem .75rem; border-radius: 6px; font-size: .85rem; }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th { text-align: left; padding: .5rem; border-bottom: 2px solid #E4E7EB; color: #616E7C; font-weight: 600; }
  td { padding: .5rem; border-bottom: 1px solid #E4E7EB; word-break: break-all; }
  .badge { display: inline-block; font-size: .75rem; padding: .15rem .5rem; border-radius: 4px; background: #E6F6FF; color: #03449E; font-weight: 500; }
  .badge-ldp { background: #E3FCEC; color: #0A6640; }
  .footer { text-align: center; margin-top: 1.5rem; font-size: .85rem; color: #9AA5B1; }
  img.qr { display: block; margin: 1rem auto; border: 1px solid #CBD2D9; border-radius: 8px; }
  .qr-note { font-size: .85rem; color: #616E7C; text-align: center; margin-top: .5rem; }
  .nav { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
  .nav a { color: #0573F0; text-decoration: none; font-size: .9rem; }
`;

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — PixelPass Adapter</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>${pageStyle}</style>
</head>
<body>${body}</body>
</html>`;
}

// --- Routes ---

app.get('/', (req, res) => {
  if (req.session.token) return res.redirect('/credentials');
  const error = req.query.error ? `<div class="error">${req.query.error}</div>` : '';
  res.send(page('Login', `
    <div class="card">
      <h1>PixelPass Adapter</h1>
      <p style="color:#616E7C;margin:0 0 1.5rem">
        Generate PixelPass QR codes from ldp_vc wallet credentials for offline verification with
        <a href="${INJI_VERIFY_URL}" target="_blank" style="color:#0573F0">Inji Verify</a>.
      </p>
      ${error}
      <form method="POST" action="/login">
        <label for="email">Wallet email</label>
        <input type="email" id="email" name="email" required placeholder="user@example.com">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required placeholder="••••••••">
        <button type="submit" class="btn btn-primary" style="width:100%">Sign in to wallet</button>
      </form>
      <div class="footer">Wallet API: <code>${WALLET_API_URL}</code></div>
    </div>
  `));
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const token = await walletLogin(email, password);
    const wallets = await walletGetWallets(token);
    if (!wallets.length) throw new Error('No wallets found for this account');
    req.session.token = token;
    req.session.walletId = wallets[0].id;
    req.session.email = email;
    res.redirect('/credentials');
  } catch (err) {
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/credentials', async (req, res) => {
  if (!req.session.token) return res.redirect('/');
  const { token, walletId, email } = req.session;

  let credentials = [];
  let fetchError = '';
  try {
    credentials = await walletListCredentials(token, walletId);
  } catch (err) {
    fetchError = err.message;
  }

  const rows = credentials.length === 0 && !fetchError
    ? '<tr><td colspan="5" style="text-align:center;color:#9AA5B1;padding:1.5rem">No credentials found in this wallet.</td></tr>'
    : credentials.map(cred => {
        const parsed = cred.parsedDocument || {};
        const vc = parsed.vc || parsed;
        const types = (vc.type || []).filter(t => t !== 'VerifiableCredential');
        const format = cred.format || 'unknown';
        const isLdp = format === 'ldp_vc';
        const addedOn = cred.addedOn ? new Date(cred.addedOn).toLocaleDateString() : '—';
        const encodedId = encodeURIComponent(cred.id);
        const action = isLdp
          ? `<a href="/qr/${encodedId}" class="btn btn-primary btn-sm">Generate QR</a>`
          : `<span class="warn" title="Only ldp_vc credentials can be verified offline">ldp_vc required</span>`;
        return `<tr>
          <td><span class="badge">${types.join(', ') || 'VC'}</span></td>
          <td style="font-size:.75rem;color:#9AA5B1;max-width:180px;overflow:hidden;text-overflow:ellipsis">${cred.id}</td>
          <td><span class="badge ${isLdp ? 'badge-ldp' : ''}">${format}</span></td>
          <td>${addedOn}</td>
          <td>${action}</td>
        </tr>`;
      }).join('');

  res.send(page('Credentials', `
    <div class="card">
      <div class="nav">
        <h1 style="margin:0">Wallet Credentials</h1>
        <a href="/logout">Sign out (${email})</a>
      </div>
      <p style="color:#616E7C;margin:0 0 1rem">
        Select an <strong>ldp_vc</strong> credential to generate a PixelPass QR code for offline verification with
        <a href="${INJI_VERIFY_URL}" target="_blank">Inji Verify</a>.
      </p>
      ${fetchError ? `<div class="error">${fetchError}</div>` : ''}
      <table>
        <thead><tr><th>Type</th><th>ID</th><th>Format</th><th>Added</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="footer">Wallet ID: <code>${walletId}</code></div>
    </div>
  `));
});

app.get('/qr/:credentialId', async (req, res) => {
  if (!req.session.token) return res.redirect('/');
  const { token, walletId } = req.session;
  const credentialId = decodeURIComponent(req.params.credentialId);

  let qrDataUrl = '';
  let encoded = '';
  let credType = '';
  let errorMsg = '';

  try {
    const cred = await walletGetCredential(token, walletId, credentialId);
    const parsed = cred.parsedDocument || {};
    const vc = parsed.vc || parsed;
    const types = (vc.type || []).filter(t => t !== 'VerifiableCredential');
    credType = types[types.length - 1] || 'Credential';

    if (!parsed['@context']) {
      throw new Error('Credential has no parsedDocument with @context');
    }
    if (!parsed.proof) {
      throw new Error(
        `This credential is stored as ${cred.format || 'unknown'} format and has no embedded proof. ` +
        'Only credentials issued as ldp_vc (with an embedded Ed25519Signature2020 proof) can be verified offline with Inji Verify.'
      );
    }

    // The credential was signed at issuance — encode directly as PixelPass.
    // CBOR-encoding the JSON object (not a string) causes Inji Verify to route
    // it to the LDP_VC validation path.
    encoded = pixelPassEncode(parsed);
    qrDataUrl = await QRCode.toDataURL(encoded, { errorCorrectionLevel: 'M', width: 400 });
  } catch (err) {
    errorMsg = err.message;
    console.error('QR generation error:', err);
  }

  const qrSection = errorMsg
    ? `<div class="error">${errorMsg}</div>`
    : `
      <p style="color:#616E7C;margin:0 0 1rem">
        Scan this QR code in Inji Verify's offline scan tab to verify the credential without a network round-trip.
      </p>
      <img class="qr" src="${qrDataUrl}" alt="PixelPass QR code" width="300" height="300">
      <p class="qr-note">ldp_vc · Ed25519Signature2020 · PixelPass (CBOR + zlib + Base45) · ${encoded.length} chars</p>
      <div style="text-align:center;margin-top:1rem">
        <a href="${INJI_VERIFY_URL}" target="_blank" class="btn btn-primary">Open Inji Verify →</a>
      </div>
      <details style="margin-top:1.5rem">
        <summary style="cursor:pointer;font-size:.85rem;color:#616E7C">Show raw PixelPass string</summary>
        <textarea rows="4" style="width:100%;box-sizing:border-box;margin-top:.5rem;font-family:monospace;font-size:.75rem;border:1px solid #CBD2D9;border-radius:6px;padding:.5rem" readonly>${encoded}</textarea>
      </details>
    `;

  res.send(page('QR Code', `
    <div class="card">
      <div class="nav">
        <h1 style="margin:0">${credType || 'Credential'} — Offline QR</h1>
        <a href="/credentials">← Back to credentials</a>
      </div>
      ${qrSection}
    </div>
  `));
});

// JSON API: encode a pre-signed ldp_vc parsedDocument as PixelPass QR
app.post('/api/qr', async (req, res) => {
  const { parsedDocument } = req.body;
  if (!parsedDocument) return res.status(400).json({ error: 'parsedDocument field required' });
  if (!parsedDocument.proof) return res.status(400).json({ error: 'parsedDocument has no proof — only signed ldp_vc credentials can be encoded' });
  try {
    const encoded = pixelPassEncode(parsedDocument);
    const qr = await QRCode.toDataURL(encoded, { errorCorrectionLevel: 'M', width: 400 });
    res.json({ encoded, qr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// JSON API: encode multiple pre-signed ldp_vc credentials as a single PixelPass QR
app.post('/api/qr/multi', async (req, res) => {
  const { credentials } = req.body;
  if (!Array.isArray(credentials) || credentials.length < 2) {
    return res.status(400).json({ error: 'credentials array with at least 2 items required' });
  }
  for (let i = 0; i < credentials.length; i++) {
    if (!credentials[i].proof) {
      const types = (credentials[i].type || []).filter(t => t !== 'VerifiableCredential');
      return res.status(400).json({ error: `Credential ${i} (${types[0] || 'unknown'}) has no proof — only signed ldp_vc credentials can be encoded` });
    }
  }
  try {
    const encoded = pixelPassEncode(credentials);
    const qr = await QRCode.toDataURL(encoded, { errorCorrectionLevel: 'L', width: 500 });
    res.json({ encoded, qr, count: credentials.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Same-subject DID constraint check ---

// Recursively search an object for string values matching any of the target DIDs.
function findDidMatches(obj, targetDids, path = '') {
  const matches = [];
  if (typeof obj === 'string') {
    if (targetDids.includes(obj)) matches.push({ path, did: obj });
    return matches;
  }
  if (obj && typeof obj === 'object') {
    for (const [key, val] of Object.entries(obj)) {
      const childPath = path ? `${path}.${key}` : key;
      matches.push(...findDidMatches(val, targetDids, childPath));
    }
  }
  return matches;
}

function checkSameSubject(credentials) {
  // For each credential, check if its credentialSubject.id appears (as a
  // cross-reference) anywhere in another credential's credentialSubject
  // (excluding that other credential's own id field).
  for (let i = 0; i < credentials.length; i++) {
    const subjA = credentials[i].credentialSubject;
    if (!subjA || typeof subjA.id !== 'string' || !subjA.id.startsWith('did:')) continue;
    const didA = subjA.id;
    const typeA = (credentials[i].type || []).filter(t => t !== 'VerifiableCredential')[0] || 'unknown';

    for (let j = 0; j < credentials.length; j++) {
      if (i === j) continue;
      const subjB = credentials[j].credentialSubject;
      if (!subjB) continue;

      // Search credential B's subject (excluding its own id) for credential A's DID
      const searchObj = { ...subjB };
      delete searchObj.id;
      const matches = findDidMatches(searchObj, [didA]);
      if (matches.length > 0) {
        const typeB = (credentials[j].type || []).filter(t => t !== 'VerifiableCredential')[0] || 'unknown';
        return {
          matched: true,
          identityDid: didA,
          matchPath: `credentialSubject.${matches[0].path}`,
          identityType: typeA,
          delegationType: typeB,
        };
      }
    }
  }

  return { matched: false, reason: 'No cross-credential DID reference found' };
}

// Verify a single credential via inji-verify-service
async function verifySingleCredential(credential) {
  const body = JSON.stringify(credential);
  const upstream = await fetch(`${INJI_VERIFY_SERVICE_URL}/v1/verify/vc-verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/vc+ld+json', 'Content-Length': Buffer.byteLength(body) },
    body,
  });
  return upstream.json();
}

// --- vc-verification proxy ---
//
// @mosip/pixelpass.decode() always returns a STRING, so Inji Verify UI always
// sends Content-Type: application/vc+sd-jwt for PixelPass-decoded credentials.
// We detect JSON-LD objects (ldp_vc) by checking for @context and re-submit
// them to inji-verify-service as application/vc+ld+json.
// Arrays of credentials are verified individually with same_subject constraint.
const INJI_VERIFY_SERVICE_URL = process.env.INJI_VERIFY_SERVICE_URL || 'http://inji-verify-service:8080';

app.post('/v1/verify/vc-verification', async (req, res) => {
  let rawBody = '';
  req.on('data', chunk => { rawBody += chunk; });
  req.on('end', async () => {
    const contentType = req.headers['content-type'] || '';
    let parsed = null;

    if (contentType.includes('vc+sd-jwt') || contentType.includes('json')) {
      try { parsed = JSON.parse(rawBody); } catch (_) { /* not JSON */ }
    }

    // Handle array of credentials (combined QR)
    if (Array.isArray(parsed)) {
      console.log(`[vc-verify] Credential array detected (${parsed.length} credentials) — verifying individually`);
      try {
        const results = await Promise.all(parsed.map(cred => verifySingleCredential(cred)));
        const credentialResults = parsed.map((cred, i) => {
          const types = (cred.type || []).filter(t => t !== 'VerifiableCredential');
          return {
            type: types[0] || 'unknown',
            verificationStatus: results[i].verificationStatus || 'ERROR',
          };
        });
        const allValid = credentialResults.every(r => r.verificationStatus === 'SUCCESS');
        const sameSubject = checkSameSubject(parsed);
        const overallStatus = allValid && sameSubject.matched ? 'SUCCESS' : 'INVALID';

        console.log(`[vc-verify] Combined result: ${overallStatus} (signatures: ${allValid}, sameSubject: ${sameSubject.matched})`);
        res.setHeader('Content-Type', 'application/json');
        return res.json({
          verificationStatus: overallStatus,
          credentialResults,
          sameSubject,
        });
      } catch (err) {
        console.error('[vc-verify] Combined verification error:', err.message);
        return res.status(502).json({ verificationStatus: 'ERROR', error: err.message });
      }
    }

    // Handle single JSON-LD credential
    if (parsed && typeof parsed === 'object' && parsed['@context']) {
      console.log('[vc-verify] JSON-LD detected — forwarding as vc+ld+json');
      try {
        const result = await verifySingleCredential(parsed);
        res.setHeader('Content-Type', 'application/json');
        return res.json(result);
      } catch (err) {
        console.error('[vc-verify] Forward error:', err.message);
        return res.status(502).json({ verificationStatus: 'ERROR', error: err.message });
      }
    }

    // Pass-through for other formats
    console.log(`[vc-verify] Pass-through (Content-Type: ${contentType})`);
    try {
      const upstream = await fetch(`${INJI_VERIFY_SERVICE_URL}/v1/verify/vc-verification`, {
        method: 'POST',
        headers: { 'Content-Type': contentType, 'Content-Length': Buffer.byteLength(rawBody) },
        body: rawBody,
      });
      const result = await upstream.text();
      res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/json');
      return res.status(upstream.status).send(result);
    } catch (err) {
      return res.status(502).json({ verificationStatus: 'ERROR', error: err.message });
    }
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok', walletApi: WALLET_API_URL }));

app.listen(PORT, () => {
  console.log(`PixelPass adapter listening on :${PORT}`);
  console.log(`Wallet API: ${WALLET_API_URL}`);
  console.log(`Inji Verify: ${INJI_VERIFY_URL}`);
});
