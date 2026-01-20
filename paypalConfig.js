const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const PAYPAL_ENV = process.env.PAYPAL_ENV || (process.env.NODE_ENV === 'production' ? 'live' : 'sandbox');
const PAYPAL_API_BASE = PAYPAL_ENV === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID;

console.log('[PayPal] runtime config', {
  env: PAYPAL_ENV,
  apiBase: PAYPAL_API_BASE,
  client: PAYPAL_CLIENT_ID ? `${PAYPAL_CLIENT_ID.slice(0, 6)}…${PAYPAL_CLIENT_ID.slice(-4)}` : null,
  webhook: PAYPAL_WEBHOOK_ID || null,
});

const planConfig = [
  { envKey: 'PAYPAL_PRO_MONTHLY_PLAN_ID', tier: 'pro', interval: 'monthly' },
  { envKey: 'PAYPAL_PRO_ANNUAL_PLAN_ID', tier: 'pro', interval: 'annual' },
  { envKey: 'PAYPAL_LEGEND_MONTHLY_PLAN_ID', tier: 'legend', interval: 'monthly' },
  { envKey: 'PAYPAL_LEGEND_ANNUAL_PLAN_ID', tier: 'legend', interval: 'annual' },
  { envKey: 'PAYPAL_PRO_PLAN_ID', tier: 'pro', interval: 'monthly' }, // legacy fallbacks
  { envKey: 'PAYPAL_LEGEND_PLAN_ID', tier: 'legend', interval: 'monthly' },
];

const planIdToMeta = {};
const tierToDefaultMeta = {};
planConfig.forEach(({ envKey, tier, interval }) => {
  const value = process.env[envKey];
  if (value) {
    const meta = { tier, interval, planId: value };
    planIdToMeta[value] = meta;
    if (!tierToDefaultMeta[tier]) {
      tierToDefaultMeta[tier] = meta;
    }
  }
});

const PAYPAL_ENABLED = Boolean(
  PAYPAL_CLIENT_ID &&
  PAYPAL_CLIENT_SECRET &&
  PAYPAL_WEBHOOK_ID,
);

let cachedToken = null;
let cachedTokenExpiry = 0;

async function getPayPalAccessToken() {
  if (!PAYPAL_ENABLED) {
    throw new Error('PayPal is not fully configured');
  }

  const now = Date.now();
  if (cachedToken && cachedTokenExpiry - now > 60_000) {
    return cachedToken;
  }

  const basicAuth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
  const response = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basicAuth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error_description || data?.error || 'Failed to retrieve PayPal token');
  }

  cachedToken = data.access_token;
  cachedTokenExpiry = now + (Number(data.expires_in) || 0) * 1000;
  return cachedToken;
}

function normalizeHeader(headers = {}, key) {
  if (!headers) return undefined;
  const lowerKey = key.toLowerCase();
  const entries = Object.entries(headers);
  for (const [headerKey, headerValue] of entries) {
    if (headerKey.toLowerCase() === lowerKey) {
      return headerValue;
    }
  }
  return undefined;
}

async function verifyPayPalWebhook(headers = {}, rawBody = '{}') {
  if (!PAYPAL_ENABLED) {
    return { verified: false, reason: 'paypal_not_configured' };
  }

  const bodyString = typeof rawBody === 'string' ? rawBody : rawBody?.toString('utf8') || '{}';
  let parsedEvent;
  try {
    parsedEvent = JSON.parse(bodyString);
  } catch (error) {
    return { verified: false, reason: 'invalid_json', error };
  }

  const transmissionId = normalizeHeader(headers, 'paypal-transmission-id');
  const transmissionTime = normalizeHeader(headers, 'paypal-transmission-time');
  const certUrl = normalizeHeader(headers, 'paypal-cert-url');
  const authAlgo = normalizeHeader(headers, 'paypal-auth-algo');
  const transmissionSig = normalizeHeader(headers, 'paypal-transmission-sig');

  if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig) {
    return { verified: false, reason: 'missing_headers' };
  }

  try {
    const accessToken = await getPayPalAccessToken();
    const response = await fetch(`${PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        transmission_id: transmissionId,
        transmission_time: transmissionTime,
        cert_url: certUrl,
        auth_algo: authAlgo,
        transmission_sig: transmissionSig,
        webhook_id: PAYPAL_WEBHOOK_ID,
        webhook_event: parsedEvent,
      }),
    });

    const data = await response.json();
    const verified = data?.verification_status === 'SUCCESS';
    return { verified, verificationStatus: data?.verification_status, data };
  } catch (error) {
    return { verified: false, reason: 'verification_failed', error };
  }
}

function getPlanMeta(planId) {
  if (!planId) return null;
  return planIdToMeta[String(planId)] || null;
}

function getTierForPlanId(planId) {
  const meta = getPlanMeta(planId);
  return meta?.tier || null;
}

function getPlanMetaForTier(tier) {
  if (!tier) return null;
  return tierToDefaultMeta[String(tier).toLowerCase()] || null;
}

module.exports = {
  PAYPAL_ENABLED,
  PAYPAL_API_BASE,
  verifyPayPalWebhook,
  getTierForPlanId,
  getPlanMeta,
  getPlanMetaForTier,
};
