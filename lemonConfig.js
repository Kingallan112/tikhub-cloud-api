const variantConfig = [
  { envKey: 'LEMON_PRO_MONTHLY_VARIANT_ID', tier: 'pro', interval: 'monthly' },
  { envKey: 'LEMON_PRO_ANNUAL_VARIANT_ID', tier: 'pro', interval: 'annual' },
  { envKey: 'LEMON_LEGEND_MONTHLY_VARIANT_ID', tier: 'legend', interval: 'monthly' },
  { envKey: 'LEMON_LEGEND_ANNUAL_VARIANT_ID', tier: 'legend', interval: 'annual' },
  { envKey: 'LEGEND_MONTHLY_VARIANT_ID', tier: 'legend', interval: 'monthly' }, // Legacy fallbacks
  { envKey: 'LEGEND_ANNUAL_VARIANT_ID', tier: 'legend', interval: 'annual' },
];

const variantIdToMeta = {};

variantConfig.forEach(({ envKey, tier, interval }) => {
  const value = process.env[envKey];
  if (value) {
    variantIdToMeta[value] = { tier, interval, variantId: value };
  }
});

function getVariantMeta(variantId) {
  if (!variantId) return null;
  return variantIdToMeta[String(variantId)] || null;
}

function getTierForVariantId(variantId) {
  const meta = getVariantMeta(variantId);
  return meta?.tier || null;
}

module.exports = {
  getVariantMeta,
  getTierForVariantId,
  lemonWebhookSecret: process.env.LEMON_WEBHOOK_SECRET,
  lemonStoreId: process.env.LEMON_STORE_ID,
};
