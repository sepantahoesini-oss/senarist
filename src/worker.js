const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const PRODUCTS = {
  license_1: { quantity: 1, amount_irr: 300000 },
  license_3: { quantity: 3, amount_irr: 700000 },
  license_10: { quantity: 10, amount_irr: 2000000 },
};

const TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const PBKDF2_ITERATIONS = 210000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS,
  });
}

function isAllowedOrigin(origin) {
  return Boolean(origin) &&
    (origin.startsWith("https://") ||
      /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin));
}

function cors(request, response) {
  const origin = request.headers.get("Origin");
  const headers = new Headers(response.headers);

  if (isAllowedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  }

  headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Max-Age", "86400");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function id(prefix) {
  return prefix + crypto.randomUUID();
}

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded =
    base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);

  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function normalizePhone(value) {
  if (typeof value !== "string") return null;

  let phone = value.trim().replace(/[\s()-]/g, "");

  phone = phone.replace(/[۰-۹]/g, (d) =>
    String("۰۱۲۳۴۵۶۷۸۹".indexOf(d))
  );

  phone = phone.replace(/[٠-٩]/g, (d) =>
    String("٠١٢٣٤٥٦٧٨٩".indexOf(d))
  );

  if (phone.startsWith("+98")) {
    phone = "0" + phone.slice(3);
  }

  if (phone.startsWith("0098")) {
    phone = "0" + phone.slice(4);
  }

  return /^09\d{9}$/.test(phone) ? phone : null;
}

function cleanName(value) {
  if (typeof value !== "string") return null;

  const name = value.trim().replace(/\s+/g, " ");

  return name.length >= 2 && name.length <= 50
    ? name
    : null;
}

async function derivePassword(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS,
    },
    material,
    256
  );

  return b64url(new Uint8Array(bits));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  return `pbkdf2-sha256$${b64url(salt)}$${await derivePassword(
    password,
    salt
  )}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;

  const parts = stored.split("$");

  if (parts.length !== 3 || parts[0] !== "pbkdf2-sha256") {
    return false;
  }

  try {
    const candidate = await derivePassword(
      password,
      unb64url(parts[1])
    );

    const a = new TextEncoder().encode(candidate);
    const b = new TextEncoder().encode(parts[2]);

    if (a.length !== b.length) return false;

    let diff = 0;

    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }

    return diff === 0;
  } catch {
    return false;
  }
}

async function getHmacKey(env) {
  if (!env.AUTH_SECRET || env.AUTH_SECRET.length < 32) {
    throw new Error("Missing or weak AUTH_SECRET");
  }

  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.AUTH_SECRET),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"]
  );
}

async function makeToken(user, env) {
  const payload = b64url(
    new TextEncoder().encode(
      JSON.stringify({
        sub: user.id,
        exp: now() + TOKEN_TTL_SECONDS,
      })
    )
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    await getHmacKey(env),
    new TextEncoder().encode(payload)
  );

  return `${payload}.${b64url(new Uint8Array(signature))}`;
}

async function tokenPayload(request, env) {
  const match = (
    request.headers.get("Authorization") || ""
  ).match(/^Bearer\s+([A-Za-z0-9._-]+)$/i);

  if (!match) return null;

  const parts = match[1].split(".");
  if (parts.length !== 2) return null;

  try {
    const valid = await crypto.subtle.verify(
      "HMAC",
      await getHmacKey(env),
      unb64url(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(unb64url(parts[0]))
    );

    return payload.sub && payload.exp > now()
      ? payload
      : null;
  } catch {
    return null;
  }
}

async function authUser(request, env) {
  const payload = await tokenPayload(request, env);

  if (!payload) return null;

  return env.DB.prepare(
    `SELECT id, phone, display_name, role, approved, credits, created_at
     FROM users WHERE id = ?`
  )
    .bind(payload.sub)
    .first();
}

function publicUser(user) {
  return {
    id: user.id,
    phone: user.phone,
    display_name: user.display_name,
    role: user.role,
    approved: Boolean(user.approved),
    credits: user.credits,
    created_at: user.created_at,
  };
}

async function bodyJson(request) {
  const contentType =
    request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return null;
  }

  try {
    const data = await request.json();

    return data &&
      typeof data === "object" &&
      !Array.isArray(data)
      ? data
      : null;
  } catch {
    return null;
  }
}

/* =========================
   ثبت‌نام
========================= */

async function register(request, env) {
  const body = await bodyJson(request);

  if (!body) {
    return json({
      error: "invalid_json",
      message: "بدنه درخواست معتبر نیست.",
    }, 400);
  }

  const phone = normalizePhone(body.phone);
  const displayName = cleanName(body.display_name);
  const password = body.password;

  if (!phone) {
    return json({
      error: "invalid_phone",
      message: "شماره موبایل باید معتبر و به شکل 09xxxxxxxxx باشد.",
    }, 400);
  }

  if (!displayName) {
    return json({
      error: "invalid_display_name",
      message: "نام نمایشی باید بین ۲ تا ۵۰ نویسه باشد.",
    }, 400);
  }

  if (
    typeof password !== "string" ||
    password.length < 8 ||
    password.length > 128
  ) {
    return json({
      error: "invalid_password",
      message: "رمز عبور باید حداقل ۸ نویسه داشته باشد.",
    }, 400);
  }

  const exists = await env.DB.prepare(
    "SELECT id FROM users WHERE phone = ?"
  )
    .bind(phone)
    .first();

  if (exists) {
    return json({
      error: "phone_already_registered",
      message: "این شماره قبلاً ثبت‌نام کرده است.",
    }, 409);
  }

  const user = {
    id: id("usr_"),
    phone,
    display_name: displayName,
    role: "user",
    approved: 0,
    credits: 0,
    created_at: now(),
  };

  try {
    const passwordHash = await hashPassword(password);

    await env.DB.prepare(
      `INSERT INTO users
       (id, phone, password_hash, display_name, role, approved, credits, created_at)
       VALUES (?, ?, ?, ?, 'user', 0, 0, ?)`
    )
      .bind(
        user.id,
        phone,
        passwordHash,
        displayName,
        user.created_at
      )
      .run();
  } catch (error) {
    const duplicate = await env.DB.prepare(
      "SELECT id FROM users WHERE phone = ?"
    )
      .bind(phone)
      .first();

    if (duplicate) {
      return json({
        error: "phone_already_registered",
        message: "این شماره قبلاً ثبت‌نام کرده است.",
      }, 409);
    }

    throw error;
  }

  return json({
    message: "ثبت‌نام انجام شد؛ حساب برای فعال شدن نیاز به تأیید مدیر دارد.",
    token: await makeToken(user, env),
    user: publicUser(user),
  }, 201);
}

/* =========================
   ورود
========================= */

async function login(request, env) {
  const body = await bodyJson(request);

  if (!body) {
    return json({
      error: "invalid_json",
      message: "بدنه درخواست معتبر نیست.",
    }, 400);
  }

  const phone = normalizePhone(body.phone);
  const password = body.password;

  if (
    !phone ||
    typeof password !== "string" ||
    password.length > 128
  ) {
    return json({
      error: "invalid_credentials",
      message: "شماره یا رمز عبور نادرست است.",
    }, 401);
  }

  const user = await env.DB.prepare(
    `SELECT id, phone, password_hash, display_name, role,
            approved, credits, created_at
     FROM users WHERE phone = ?`
  )
    .bind(phone)
    .first();

  if (
    !user ||
    !(await verifyPassword(password, user.password_hash))
  ) {
    return json({
      error: "invalid_credentials",
      message: "شماره یا رمز عبور نادرست است.",
    }, 401);
  }

  return json({
    token: await makeToken(user, env),
    user: publicUser(user),
  });
}

/* =========================
   فهرست سناریوهای تأییدشده
========================= */

async function listScenarios(request, env) {
  const url = new URL(request.url);

  const rawLimit = Number(
    url.searchParams.get("limit") || 20
  );

  const rawOffset = Number(
    url.searchParams.get("offset") || 0
  );

  const limit = Number.isInteger(rawLimit)
    ? Math.max(1, Math.min(50, rawLimit))
    : 20;

  const offset = Number.isInteger(rawOffset)
    ? Math.max(0, Math.min(100000, rawOffset))
    : 0;

  const result = await env.DB.prepare(
    `SELECT s.id, s.author_id, u.display_name AS author_name,
            s.title, s.description, s.players, s.teams_json,
            s.likes_count, s.views_count, s.created_at, s.updated_at
     FROM scenarios s
     JOIN users u ON u.id = s.author_id
     WHERE s.status = 'approved' AND u.approved = 1
     ORDER BY s.created_at DESC
     LIMIT ? OFFSET ?`
  )
    .bind(limit, offset)
    .all();

  const scenarios = (result.results || []).map((row) => {
    let teams = {};

    try {
      teams = JSON.parse(row.teams_json);
    } catch {}

    return {
      id: row.id,
      author_id: row.author_id,
      author_name: row.author_name,
      title: row.title,
      description: row.description,
      players: row.players,
      teams,
      likes_count: row.likes_count,
      views_count: row.views_count,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  });

  return json({ scenarios, limit, offset });
}

/* =========================
   ثبت سناریو
========================= */

async function createScenario(request, env, user) {
  if (!user.approved) {
    return json({
      error: "account_not_approved",
      message: "حساب شما هنوز توسط مدیر تأیید نشده است.",
    }, 403);
  }

  const body = await bodyJson(request);

  if (!body) {
    return json({
      error: "invalid_json",
      message: "بدنه درخواست معتبر نیست.",
    }, 400);
  }

  const title =
    typeof body.title === "string"
      ? body.title.trim()
      : "";

  const description =
    typeof body.description === "string"
      ? body.description.trim()
      : "";

  const players = Number(body.players);
  const teams = body.teams;

  if (title.length < 3 || title.length > 100) {
    return json({
      error: "invalid_title",
      message: "عنوان باید بین ۳ تا ۱۰۰ نویسه باشد.",
    }, 400);
  }

  if (description.length > 5000) {
    return json({
      error: "description_too_long",
      message: "توضیحات بیش از حد طولانی است.",
    }, 400);
  }

  if (
    !Number.isInteger(players) ||
    players < 4 ||
    players > 100
  ) {
    return json({
      error: "invalid_players",
      message: "تعداد بازیکنان باید بین ۴ تا ۱۰۰ باشد.",
    }, 400);
  }

  if (
    !teams ||
    typeof teams !== "object" ||
    Array.isArray(teams)
  ) {
    return json({
      error: "invalid_teams",
      message: "ساختار تیم‌ها معتبر نیست.",
    }, 400);
  }

  const teamsJson = JSON.stringify(teams);

  if (teamsJson.length > 20000) {
    return json({
      error: "teams_too_large",
      message: "اطلاعات تیم‌ها بیش از حد حجیم است.",
    }, 400);
  }

  const createdAt = now();
  const scenarioId = id("scn_");

  await env.DB.prepare(
    `INSERT INTO scenarios
     (id, author_id, title, description, players, teams_json,
      status, likes_count, views_count, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?)`
  )
    .bind(
      scenarioId,
      user.id,
      title,
      description,
      players,
      teamsJson,
      createdAt,
      createdAt
    )
    .run();

  return json({
    message: "سناریو ثبت شد و پس از بررسی مدیر نمایش داده می‌شود.",
    scenario: {
      id: scenarioId,
      author_id: user.id,
      title,
      description,
      players,
      teams,
      status: "pending",
      created_at: createdAt,
      updated_at: createdAt,
    },
  }, 201);
}

/* =========================
   سناریوهای خود کاربر
========================= */

async function myScenarios(env, user) {
  const result = await env.DB.prepare(
    `SELECT id, author_id, title, description, players,
            teams_json, status, rejection_reason, likes_count,
            views_count, created_at, updated_at
     FROM scenarios
     WHERE author_id = ?
     ORDER BY created_at DESC
     LIMIT 100`
  )
    .bind(user.id)
    .all();

  const scenarios = (result.results || []).map((row) => {
    let teams = {};

    try {
      teams = JSON.parse(row.teams_json);
    } catch {}

    return {
      id: row.id,
      author_id: row.author_id,
      title: row.title,
      description: row.description,
      players: row.players,
      teams,
      status: row.status,
      rejection_reason: row.rejection_reason,
      likes_count: row.likes_count,
      views_count: row.views_count,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  });

  return json({ scenarios });
}

/* =========================
   مسیریابی API
========================= */

async function handler(request, env) {
  const { pathname } = new URL(request.url);
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    const origin = request.headers.get("Origin") || "";

    return new Response(null, {
      status: 204,
      headers: {
        ...(isAllowedOrigin(origin)
          ? {
              "Access-Control-Allow-Origin": origin,
              Vary: "Origin",
            }
          : {}),
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  if (pathname === "/" || pathname === "/health") {
    return json({
      service: "senarist-api",
      status: "ready",
      mode: "d1-auth-scenarios",
      paymentsEnabled: false,
    });
  }

  if (pathname === "/api/catalog" && method === "GET") {
    return json({
      currency: "IRR",
      products: Object.entries(PRODUCTS).map(
        ([productId, product]) => ({
          id: productId,
          quantity: product.quantity,
          amount_irr: product.amount_irr,
        })
      ),
    });
  }

  if (pathname === "/api/register" && method === "POST") {
    return register(request, env);
  }

  if (pathname === "/api/login" && method === "POST") {
    return login(request, env);
  }

  if (pathname === "/api/me" && method === "GET") {
    const user = await authUser(request, env);

    if (!user) {
      return json({
        error: "unauthorized",
        message: "برای ادامه وارد حساب شوید.",
      }, 401);
    }

    return json({ user: publicUser(user) });
  }

  if (pathname === "/api/scenarios" && method === "GET") {
    return listScenarios(request, env);
  }

  if (pathname === "/api/scenarios" && method === "POST") {
    const user = await authUser(request, env);

    if (!user) {
      return json({
        error: "unauthorized",
        message: "برای ثبت سناریو وارد حساب شوید.",
      }, 401);
    }

    return createScenario(request, env, user);
  }

  if (
    pathname === "/api/my/scenarios" &&
    method === "GET"
  ) {
    const user = await authUser(request, env);

    if (!user) {
      return json({
        error: "unauthorized",
        message: "برای دیدن سناریوهای خود وارد حساب شوید.",
      }, 401);
    }

    return myScenarios(env, user);
  }

  if (
    pathname === "/api/purchases/verify" &&
    method === "POST"
  ) {
    // پرداخت تا اتصال اعتبارسنجی رسمی رسید مایکت غیرفعال است.
    // هیچ مجوزی صرفاً با ادعای خرید کاربر فعال نمی‌شود.
    return json({
      error: "verification_not_configured",
      message:
        "اعتبارسنجی رسمی رسید مایکت هنوز پیکربندی نشده است؛ هیچ مجوزی اضافه نشد.",
    }, 501);
  }

  return json({
    error: "not_found",
    message: "مسیر موردنظر پیدا نشد.",
  }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return cors(request, await handler(request, env));
    } catch (error) {
      // جزئیات دیتابیس و اطلاعات محرمانه به کاربر ارسال نمی‌شود.
      return cors(
        request,
        json({
          error: "internal_error",
          message: "خطای داخلی سرور رخ داد.",
        }, 500)
      );
    }
  },
};
