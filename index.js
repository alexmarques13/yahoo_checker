const crypto = require('crypto');
const { createCuimpHttp } = require('cuimp');

// Login credentials
const LOGIN_INFO = {
  email: 'constellations4@yahoo.it',
  password: 'Gia01699345960',
};

// Proxy: host:port:user:pass
const PROXY = {
  host: 'proxy.bottingtools.net',
  port: 1337,
  username: 'BrainWith_country-FR_fastmode-true',
  password: 'BrainWith',
};

const PROXY_URL =
  `http://${encodeURIComponent(PROXY.username)}:${encodeURIComponent(PROXY.password)}` +
  `@${PROXY.host}:${PROXY.port}`;

const IPQS_LEARN_PATH =
  '/api/*/Z6zn1EFDPjFfpfhcrY9lhKf34Sr5jq4H79qMV5ZrKQoNE8mofcWGXBWlPjLFj6NGbNAwRTuX5fyCKvS9oEJMmQnGRRFMePUlbchjKe3lqnUGnwJ5yab9XcrIzAQ3cGyDOAtKl0Womp7vVBOWPDtNL8VFMVsLJK0VnWDAXlaFdokaHZoBwtdzyVtIsP2IjIAo2pu6Va56MAarg9yez1Rxvy7jzEFI3dRR21PUo1bT8703DzbpRappGVNpe0MGfaha/learn/fetch';

const IPQS_HOSTS = [
  'dtproxy5.yahoo.nc.clients.ipqs.com',
  'dtproxy6.yahoo.nc.clients.ipqs.com',
  'fn.nc.ipqualityscore.com',
];

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36';

const client = createCuimpHttp({
  descriptor: { browser: 'chrome', version: '146' },
  cookieJar: true,
  proxy: PROXY_URL,
});

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
};

const log = {
  title: (msg) => console.log(`${c.bold}${c.cyan}${msg}${c.reset}`),
  step: (msg) => console.log(`${c.bold}${c.blue}${msg}${c.reset}`),
  info: (msg) => console.log(`${c.gray}  ${msg}${c.reset}`),
  kv: (key, value) =>
    console.log(`${c.gray}  ${key}=${c.reset}${c.white}${value}${c.reset}`),
  ok: (msg) => console.log(`${c.green}  ✓ ${msg}${c.reset}`),
  warn: (msg) => console.log(`${c.yellow}  ! ${msg}${c.reset}`),
  err: (msg) => console.log(`${c.red}${c.bold}✗ ${msg}${c.reset}`),
  success: (msg) => console.log(`${c.bold}${c.green}${msg}${c.reset}`),
  blank: () => console.log(''),
};

function bodyAsText(res) {
  if (res.rawBody && Buffer.isBuffer(res.rawBody) && res.rawBody.length) {
    return res.rawBody.toString('utf8');
  }
  if (typeof res.data === 'string') return res.data;
  if (Buffer.isBuffer(res.data)) return res.data.toString('utf8');
  if (res.data && typeof res.data === 'object') return JSON.stringify(res.data);
  return String(res.data ?? '');
}

function parseJson(res) {
  if (res.data && typeof res.data === 'object' && !Buffer.isBuffer(res.data)) {
    return res.data;
  }
  try {
    return JSON.parse(bodyAsText(res));
  } catch {
    return null;
  }
}

function pick(html, key) {
  const escaped = html.match(new RegExp(`\\\\"${key}\\\\":\\\\"([^\\\\]+)\\\\"`));
  if (escaped) return escaped[1];
  const plain = html.match(new RegExp(`"${key}":"([^"]+)"`));
  return plain ? plain[1] : '';
}

function extractContext(html) {
  const sessionIndex = pick(html, 'sessionIndex');
  const acrumb = pick(html, 'acrumb');
  const crumb = pick(html, 'crumb');
  if (!sessionIndex || !acrumb || !crumb) {
    throw new Error('Could not parse Yahoo login page tokens');
  }
  return { sessionIndex, acrumb, crumb };
}

function extractPassContext(html) {
  return {
    ...extractContext(html),
    displayName: pick(html, 'displayName') || LOGIN_INFO.email,
    passwordContext: pick(html, 'passwordContext') || 'normal',
    ipqsSessionId: pick(html, 'ipqsSessionId'),
  };
}

function browserFpData() {
  return JSON.stringify({
    language: 'en-US',
    colorDepth: 24,
    deviceMemory: 8,
    pixelRatio: 1,
    hardwareConcurrency: 8,
    timezoneOffset: -60,
    timezone: 'Europe/Rome',
    sessionStorage: 1,
    localStorage: 1,
    indexedDb: 1,
    openDatabase: 1,
    cpuClass: 'unknown',
    platform: 'Win32',
    doNotTrack: 'unknown',
    plugins: { count: 5, hash: '2c21d957e91c20ea' },
    canvas: 'canvas winding:yes~canvas',
    webgl: 1,
    webglVendorAndRenderer: 'Google Inc. (NVIDIA)~ANGLE',
    adBlock: 0,
    hasLiedLanguages: 0,
    hasLiedResolution: 0,
    hasLiedOs: 0,
    hasLiedBrowser: 0,
    touchSupport: { points: 0, event: 0, start: 0 },
    fonts: { count: 50, hash: 'edeefd360161b4bf' },
    audio: '124.04347527516074',
    resolution: { w: '1920', h: '1080' },
    availableResolution: { w: '1040', h: '1920' },
    ts: { serve: Date.now(), render: Date.now() + 80 },
  });
}

function xhrHeaders(referer) {
  return {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: '*/*',
    'X-Requested-With': 'XMLHttpRequest',
    Origin: 'https://login.yahoo.com',
    Referer: referer || 'https://login.yahoo.com/',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
  };
}

function toAbsoluteUrl(url) {
  if (!url) return '';
  if (url.startsWith('http')) return url;
  return `https://login.yahoo.com${url}`;
}

function appendValidate(url) {
  const u = new URL(toAbsoluteUrl(url));
  u.pathname = `${u.pathname.replace(/\/$/, '')}/validate`;
  return u.toString();
}

function extractUdid(raw) {
  const m = String(raw).match(/"udid"\s*:\s*(\d+)/);
  return m ? m[1] : '';
}

function buildIpqsBody(vars) {
  const parts = [];
  for (const [k, v] of Object.entries(vars)) {
    if (v === null || v === undefined) parts.push(`${k}=null`);
    else if (Array.isArray(v)) {
      for (const item of v) {
        parts.push(`${k}[]=${encodeURIComponent(JSON.stringify(item))}`);
      }
    } else {
      parts.push(`${k}=${encodeURIComponent(String(v))}`);
    }
  }
  return parts.join('&');
}

function fingerprintHash(parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 32);
}

async function fetchIpqsUdid() {
  const res = await client.get('https://dtproxy5.yahoo.nc.clients.ipqs.com/udid/udid.json', {
    maxRedirects: 3,
    headers: {
      Accept: '*/*',
      Origin: 'https://login.yahoo.com',
      Referer: 'https://login.yahoo.com/',
    },
  });
  const udid = extractUdid(bodyAsText(res));
  if (!udid) throw new Error('IPQS udid missing');
  return udid;
}

async function fetchIpqsRequestId(ipqsSessionId, referer) {
  const started = Date.now();
  const udid = await fetchIpqsUdid();
  log.kv('ipqsd(udid)', udid);

  const dtoo = fingerprintHash([
    UA,
    'Win32',
    '24',
    '1',
    '1920x1080',
    '1920x1040',
    'en-US',
    '-60',
    udid,
    ipqsSessionId,
  ]);

  // Reversed from ipqs.js ProcessStorage + Learn collectors (minimum set that returns request_id)
  const vars = {
    ipqsd: udid,
    dta: [{ key: 'sessionId', value: ipqsSessionId }],
    dtb: UA,
    dtc: 'Win32',
    dtd: 24,
    dte: 1,
    dtf: 'false',
    dtg: '1920x1080',
    dth: '1920x1040',
    dti: 'en-US',
    dtj: -60,
    dtk: 1,
    dtl: 1,
    dtnn: 0,
    dtm: 1,
    dtn: 0,
    dto: 0,
    dtp: 'unknown',
    dtq: 'Win32',
    dtr: 'false',
    dtt: 'false',
    dtu: 'false',
    dtv: 'false',
    dtw: 'false',
    dtx: [],
    dty: [],
    dtz: 'false',
    dtaa: 'false',
    dtqq: dtoo,
    dtoo,
    dtpc: 1,
    dtam: 'am',
    dts: 1,
    dtss: 1,
    dtmm: '',
    dtii: [],
    dtkk: 0,
    dtff: 0,
    dtvv: 0,
    dtww: 0,
    dtrr: 0,
    dtll: 0,
  };

  const body = buildIpqsBody(vars);
  let lastErr;

  for (const host of IPQS_HOSTS) {
    const url = `https://${host}${IPQS_LEARN_PATH}`;
    try {
      const res = await client.post(url, body, {
        maxRedirects: 0,
        timeout: 30000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: '*/*',
          Origin: 'https://login.yahoo.com',
          Referer: referer || 'https://login.yahoo.com/',
          'X-Requested-With': 'XMLHttpRequest',
        },
      });

      const raw = bodyAsText(res);
      if (!raw || raw[0] !== '{') {
        lastErr = new Error(`${host} empty/non-json body (status ${res.status})`);
        continue;
      }

      const json = JSON.parse(raw);
      if (!json.request_id) {
        lastErr = new Error(`${host} no request_id: ${raw.slice(0, 200)}`);
        continue;
      }

      return {
        iri: json.request_id,
        ipl: String(Date.now() - started),
        udid,
        host,
        raw: json,
      };
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error('IPQS learn/fetch failed');
}

async function yahooHttpLogin() {
  log.step('[1/4] GET login page...');
  const pageRes = await client.get('https://login.yahoo.com/', {
    maxRedirects: 5,
    headers: {
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });

  const pageHtml = bodyAsText(pageRes);
  log.kv('status', pageRes.status);
  log.kv('bytes', pageHtml.length);
  const ctx = extractContext(pageHtml);
  log.kv('sessionIndex', ctx.sessionIndex);
  log.kv('acrumb', ctx.acrumb);

  const validateUrl =
    `https://login.yahoo.com/validate?` +
    new URLSearchParams({
      done: 'https://mail.yahoo.com/',
      sessionIndex: ctx.sessionIndex,
      acrumb: ctx.acrumb,
      display: 'login',
      authMechanism: 'primary',
    }).toString();

  const usernameBody = new URLSearchParams({
    'browser-fp-data': browserFpData(),
    crumb: ctx.crumb,
    acrumb: ctx.acrumb,
    sessionIndex: ctx.sessionIndex,
    displayName: '',
    deviceCapability: JSON.stringify({ pa: { status: false } }),
    username: LOGIN_INFO.email,
    passwd: '',
    signin: 'Next',
    persistent: 'y',
  });

  log.step('[2/4] POST /validate (username)...');
  const userRes = await client.post(validateUrl, usernameBody.toString(), {
    maxRedirects: 0,
    headers: xhrHeaders('https://login.yahoo.com/'),
  });

  const userJson = parseJson(userRes);
  log.kv('status', userRes.status);
  log.info(`response=${JSON.stringify(userJson || bodyAsText(userRes)).slice(0, 400)}`);

  if (!userJson) throw new Error('Username step did not return JSON');
  if (userJson.error) throw new Error(`Username rejected: ${JSON.stringify(userJson.error)}`);

  const passUrl = toAbsoluteUrl(userJson.redirect || userJson.location || '');
  if (!passUrl || !/password/i.test(passUrl)) {
    throw new Error(`Unexpected next step: ${passUrl || JSON.stringify(userJson)}`);
  }
  log.ok(`next=${passUrl}`);

  log.step('[3/4] GET password page + IPQS fingerprint...');
  const passPage = await client.get(passUrl, {
    maxRedirects: 5,
    headers: {
      Accept: 'text/html,application/xhtml+xml',
      Referer: 'https://login.yahoo.com/',
    },
  });
  const passCtx = extractPassContext(bodyAsText(passPage));
  log.kv('displayName', passCtx.displayName);
  log.kv('crumb', passCtx.crumb);
  log.kv('ipqsSessionId', passCtx.ipqsSessionId || '(none)');

  if (!passCtx.ipqsSessionId) {
    throw new Error('Password page missing ipqsSessionId');
  }

  const ipqs = await fetchIpqsRequestId(passCtx.ipqsSessionId, passUrl);
  log.ok(`iri(request_id)=${ipqs.iri}`);
  log.kv('ipqs host', ipqs.host);

  log.step('[4/4] POST password /validate with iri...');
  const passValidateUrl = appendValidate(passUrl);
  const passBody = new URLSearchParams({
    'browser-fp-data': browserFpData(),
    crumb: passCtx.crumb,
    acrumb: passCtx.acrumb,
    sessionIndex: passCtx.sessionIndex,
    displayName: passCtx.displayName,
    passwordContext: passCtx.passwordContext,
    isShowButtonClicked: '',
    showButtonStatus: '',
    prefersReducedMotion: '',
    password: LOGIN_INFO.password,
    validate: 'Next',
    persistent: 'y',
    // IPQS success fields (from Yahoo React wrapper after AfterResult)
    isl: 'true',
    ipl: ipqs.ipl,
    irc: 'true',
    iri: ipqs.iri,
  });

  log.kv('url', passValidateUrl);
  const passRes = await client.post(passValidateUrl, passBody.toString(), {
    maxRedirects: 0,
    headers: xhrHeaders(passUrl),
  });

  const passJson = parseJson(passRes);
  log.kv('status', passRes.status);
  log.info(`response=${JSON.stringify(passJson || bodyAsText(passRes)).slice(0, 500)}`);

  if (!passJson) throw new Error('Password step did not return JSON');
  if (passJson.error) throw new Error(`Password rejected: ${JSON.stringify(passJson.error)}`);

  const redirect = toAbsoluteUrl(passJson.redirect || passJson.location || '');
  if (/challenge\/fail/i.test(redirect)) {
    throw new Error(`Yahoo rejected password step (device check). redirect=${redirect}`);
  }
  if (/[?&]e=true/i.test(redirect) && /pcn=password/i.test(redirect)) {
    throw new Error(`Invalid password (IPQS passed). redirect=${redirect}`);
  }
  if (/challenge\/password/i.test(redirect) && /[?&]e=true/i.test(redirect)) {
    throw new Error(`Password challenge failed. redirect=${redirect}`);
  }

  if (redirect) {
    log.info(`following: ${redirect}`);
    await client.get(redirect, { maxRedirects: 5 });
  }

  const mailRes = await client.get('https://mail.yahoo.com/', { maxRedirects: 5 });
  const mailUrl = mailRes.request?.url || '';
  const cookies = client.getCookieJar().getCookies();
  const cookieNames = [...new Set(cookies.map((c) => c.name || c.key).filter(Boolean))];

  const loggedIn =
    cookieNames.some((n) => /^(Y|T|SSL)$/i.test(n)) ||
    (/mail\.yahoo\.com/i.test(mailUrl) && !/login\.yahoo\.com/i.test(mailUrl));

  if (!loggedIn) {
    throw new Error(
      `No auth session. redirect=${redirect || '(none)'} mailUrl=${mailUrl} cookies=[${cookieNames.join(', ')}]`
    );
  }

  return {
    status: passRes.status,
    redirect: redirect || mailUrl,
    cookies: cookieNames,
    iri: ipqs.iri,
  };
}

async function main() {
  log.title('Yahoo HTTP auto login (cuimp + reversed IPQS)');
  log.kv('Account', LOGIN_INFO.email);
  log.kv('Proxy', `${PROXY.host}:${PROXY.port}`);
  log.kv('Proxy user', PROXY.username);
  log.blank();

  try {
    const result = await yahooHttpLogin();
    log.blank();
    log.success('Login successful');
    log.kv('Status', result.status);
    log.kv('iri', result.iri);
    log.kv('Redirect', result.redirect);
    log.kv('Cookies', result.cookies.join(', '));
  } catch (err) {
    log.blank();
    log.err(`Login failed: ${err.message || err}`);
    process.exitCode = 1;
  } finally {
    try {
      client.clearCookies();
    } catch {
      // ignore
    }
  }
}

main();
