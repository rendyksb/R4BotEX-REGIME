const PBKDF2_ITERATIONS = 210000;
const MIN_PASSWORD_LENGTH = 10;
const MAX_PASSWORD_LENGTH = 128;
const MAX_BODY_BYTES = 8192;

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function normalizeName(value) {
  return String(value ?? "").trim().replace(/\s+/g, " ");
}

function normalizeEmail(value) {
  return String(value ?? "").trim().toLowerCase();
}

function validEmail(email) {
  return (
    email.length >= 5 &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS
    },
    key,
    256
  );

  return [
    "pbkdf2-sha256",
    PBKDF2_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(new Uint8Array(bits))
  ].join("$");
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      console.error("Missing D1 binding: DB");
      return json({ ok: false, message: "Konfigurasi server belum lengkap." }, 500);
    }

    const contentType = request.headers.get("content-type") || "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return json({ ok: false, message: "Content-Type harus application/json." }, 415);
    }

    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > MAX_BODY_BYTES) {
      return json({ ok: false, message: "Data request terlalu besar." }, 413);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, message: "Format JSON tidak valid." }, 400);
    }

    const fullName = normalizeName(body.name ?? body.fullName);
    const email = normalizeEmail(body.email);
    const password = typeof body.password === "string" ? body.password : "";

    if (fullName.length < 2 || fullName.length > 100) {
      return json({ ok: false, message: "Nama lengkap harus 2-100 karakter." }, 400);
    }

    if (!validEmail(email)) {
      return json({ ok: false, message: "Format email tidak valid." }, 400);
    }

    if (
      password.length < MIN_PASSWORD_LENGTH ||
      password.length > MAX_PASSWORD_LENGTH
    ) {
      return json(
        { ok: false, message: "Password harus 10-128 karakter." },
        400
      );
    }

    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return json(
        { ok: false, message: "Password minimal harus mengandung huruf dan angka." },
        400
      );
    }

    const existing = await env.DB
      .prepare("SELECT id FROM users WHERE email = ?1 LIMIT 1")
      .bind(email)
      .first();

    if (existing) {
      return json(
        {
          ok: false,
          code: "EMAIL_EXISTS",
          message: "Email sudah terdaftar."
        },
        409
      );
    }

    const id = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    try {
      await env.DB
        .prepare(
          `INSERT INTO users (id, full_name, email, password_hash)
           VALUES (?1, ?2, ?3, ?4)`
        )
        .bind(id, fullName, email, passwordHash)
        .run();
    } catch (error) {
      const text = String(error?.message || error);
      if (text.includes("UNIQUE") || text.includes("users.email")) {
        return json(
          { ok: false, code: "EMAIL_EXISTS", message: "Email sudah terdaftar." },
          409
        );
      }
      throw error;
    }

    return json(
      {
        ok: true,
        message: "Registrasi berhasil.",
        user: {
          id,
          fullName,
          email,
          licenseStatus: "Aktif"
        }
      },
      201
    );
  } catch (error) {
    console.error("REGISTER_ERROR", error);
    return json(
      { ok: false, message: "Terjadi kesalahan pada server. Silakan coba lagi." },
      500
    );
  }
}

export function onRequest() {
  return json({ ok: false, message: "Method tidak diizinkan." }, 405);
}
