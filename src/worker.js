const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const PRODUCTS = {
  license_1: { quantity: 1, amount_irr: 300000 },
  license_3: { quantity: 3, amount_irr: 700000 },
  license_10: { quantity: 10, amount_irr: 2000000 },
};
function json(data, status = 200) { return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS }); }
function cors(request, response) {
  const origin = request.headers.get('Origin');
  const headers = new Headers(response.headers);
  if (origin && (origin.startsWith('https://') || origin.startsWith('http://localhost'))) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Vary', 'Origin');
  }
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  headers.set('Access-Control-Max-Age', '86400');
  return new Response(response.body, { status: response.status, headers });
}
async function handler(request, env) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
    'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400'
  }});
  if (url.pathname === '/' || url.pathname === '/health') return json({ service: 'senarist-api', status: 'ready', mode: 'scaffold', paymentsEnabled: false });
  if (url.pathname === '/api/catalog' && request.method === 'GET') {
    return json({ currency: 'IRR', products: Object.entries(PRODUCTS).map(([id, p]) => ({ id, quantity: p.quantity, amount_irr: p.amount_irr })) });
  }
  if (url.pathname === '/api/me' && request.method === 'GET') {
    return json({ error: 'authentication_not_implemented', message: 'احراز هویت تا تنظیم امن توکن و تکمیل مسیرهای حساب فعال نیست.' }, 501);
  }
  if (url.pathname === '/api/purchases/verify' && request.method === 'POST') {
    // Fail closed: never credit a user based only on client-supplied purchase claims.
    return json({ error: 'verification_not_configured', message: 'پرداخت تا اتصال روش رسمی اعتبارسنجی رسید مایکت غیرفعال است؛ هیچ مجوزی اضافه نشد.' }, 501);
  }
  return json({ error: 'not_found' }, 404);
}
export default { async fetch(request, env) { try { return cors(request, await handler(request, env)); } catch (e) { return cors(request, json({ error: 'internal_error' }, 500)); } } };
