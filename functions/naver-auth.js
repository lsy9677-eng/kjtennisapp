export const onRequestGet = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get("action") || "start";

  try {
    if (action === "start") {
      return await handleStart(request, env, url);
    }
    if (action === "callback") {
      return await handleCallback(request, env, url);
    }
    return json({ ok: false, error: "Unsupported action" }, 400);
  } catch (error) {
    console.error("NAVER_AUTH_ERROR", error);
    return json({ ok: false, error: error.message || "Unknown error" }, 500);
  }
};

async function handleStart(request, env, url) {
  requireEnv(env, [
    "NAVER_CLIENT_ID",
    "NAVER_CLIENT_SECRET",
    "NAVER_REDIRECT_URI",
    "NAVER_STATE_SECRET",
    "FIREBASE_PROJECT_ID",
    "FIREBASE_CLIENT_EMAIL",
    "FIREBASE_PRIVATE_KEY",
  ]);

  const mode = url.searchParams.get("mode") || "login";
  const next = url.searchParams.get("next") || env.APP_BASE_URL || getOriginFromRedirect(env.NAVER_REDIRECT_URI);

  const statePayload = {
    mode,
    next,
    ts: Date.now(),
  };
  const state = await signState(statePayload, env.NAVER_STATE_SECRET);

  const authorizeUrl = new URL("https://nid.naver.com/oauth2.0/authorize");
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", env.NAVER_CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", env.NAVER_REDIRECT_URI);
  authorizeUrl.searchParams.set("state", state);

  return Response.redirect(authorizeUrl.toString(), 302);
}

async function handleCallback(request, env, url) {
  requireEnv(env, [
    "NAVER_CLIENT_ID",
    "NAVER_CLIENT_SECRET",
    "NAVER_REDIRECT_URI",
    "NAVER_STATE_SECRET",
    "FIREBASE_PROJECT_ID",
    "FIREBASE_CLIENT_EMAIL",
    "FIREBASE_PRIVATE_KEY",
  ]);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  const errorDescription = url.searchParams.get("error_description") || "";

  if (error) {
    throw new Error(`Naver returned error: ${error} ${errorDescription}`.trim());
  }
  if (!code || !state) {
    throw new Error("Missing code/state from Naver callback.");
  }

  const verifiedState = await verifyState(state, env.NAVER_STATE_SECRET);
  const mode = verifiedState.mode || "login";
  const next = verifiedState.next || env.APP_BASE_URL || getOriginFromRedirect(env.NAVER_REDIRECT_URI);

  const tokenResponse = await fetch("https://nid.naver.com/oauth2.0/token?" + new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env.NAVER_CLIENT_ID,
    client_secret: env.NAVER_CLIENT_SECRET,
    code,
    state,
  }).toString(), {
    method: "GET",
    headers: { "Accept": "application/json" },
  });

  const tokenJson = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenJson.access_token) {
    throw new Error(`Failed to exchange Naver code: ${JSON.stringify(tokenJson)}`);
  }

  const profileResponse = await fetch("https://openapi.naver.com/v1/nid/me", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${tokenJson.access_token}`,
      "Accept": "application/json",
    },
  });

  const profileJson = await profileResponse.json();
  if (!profileResponse.ok || profileJson.resultcode !== "00" || !profileJson.response) {
    throw new Error(`Failed to read Naver profile: ${JSON.stringify(profileJson)}`);
  }

  const profile = profileJson.response;
  const providerUid = String(profile.id || "").trim();
  if (!providerUid) {
    throw new Error("Naver profile did not include a stable user id.");
  }

  const normalizedEmail = String(profile.email || "").trim().toLowerCase();
  const existingUid = normalizedEmail ? await findExistingUserUidByEmail(env, normalizedEmail) : null;
  const firebaseUid = existingUid || `naver:${providerUid}`;
  const customToken = await createFirebaseCustomToken(env, firebaseUid, {
    provider: "naver",
    providerUid,
    linkedByEmail: !!existingUid,
  });

  const redirectParams = new URLSearchParams({
    naverCustomToken: customToken,
    naverUid: providerUid,
    naverName: profile.name || profile.nickname || "",
    naverEmail: profile.email || "",
    naverMobile: sanitizeMobile(profile.mobile || profile.mobile_e164 || ""),
    naverMode: mode,
  });

  const finalUrl = new URL(next);
  finalUrl.hash = redirectParams.toString();

  return Response.redirect(finalUrl.toString(), 302);
}

async function findExistingUserUidByEmail(env, email) {
  const accessToken = await getGoogleAccessToken(env);
  const endpoint = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(env.FIREBASE_PROJECT_ID)}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'users' }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'email' },
          op: 'EQUAL',
          value: { stringValue: email }
        }
      },
      limit: 1
    }
  };

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(`Failed to query existing Firebase user document: ${JSON.stringify(result)}`);
  }

  const firstDoc = Array.isArray(result)
    ? result.find((row) => row && row.document && row.document.name)
    : null;
  if (!firstDoc) return null;

  const docName = firstDoc.document.name || '';
  return docName.split('/').pop() || null;
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: 'https://oauth2.googleapis.com/token',
    scope: 'https://www.googleapis.com/auth/datastore',
    iat: now,
    exp: now + 3600,
  };

  const unsigned = `${base64UrlEncodeUtf8(JSON.stringify(header))}.${base64UrlEncodeUtf8(JSON.stringify(payload))}`;
  const signature = await signRs256(unsigned, normalizePrivateKey(env.FIREBASE_PRIVATE_KEY));
  const assertion = `${unsigned}.${base64UrlEncode(new Uint8Array(signature))}`;

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }).toString(),
  });

  const tokenJson = await response.json();
  if (!response.ok || !tokenJson.access_token) {
    throw new Error(`Failed to fetch Google access token: ${JSON.stringify(tokenJson)}`);
  }
  return tokenJson.access_token;
}

function sanitizeMobile(value) {
  return String(value || "")
    .replace(/\+82/g, "0")
    .replace(/[^\d]/g, "")
    .replace(/(\d{3})(\d{4})(\d{4})/, "$1-$2-$3");
}

function getOriginFromRedirect(redirectUri) {
  const u = new URL(redirectUri);
  return `${u.origin}/`;
}

function requireEnv(env, keys) {
  const missing = keys.filter((key) => !env[key] || String(env[key]).trim() === "");
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

async function signState(payload, secret) {
  const encoder = new TextEncoder();
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadB64));
  return `${payloadB64}.${base64UrlEncode(new Uint8Array(signature))}`;
}

async function verifyState(state, secret) {
  const [payloadB64, sigB64] = String(state || "").split(".");
  if (!payloadB64 || !sigB64) {
    throw new Error("Invalid state format.");
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    base64UrlDecode(sigB64),
    encoder.encode(payloadB64)
  );
  if (!ok) {
    throw new Error("Invalid state signature.");
  }

  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
  if (!payload.ts || Date.now() - Number(payload.ts) > 10 * 60 * 1000) {
    throw new Error("State expired.");
  }
  return payload;
}

async function createFirebaseCustomToken(env, uid, claims = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
  };
  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 60 * 60,
    uid,
    claims,
  };

  const unsigned = `${base64UrlEncodeUtf8(JSON.stringify(header))}.${base64UrlEncodeUtf8(JSON.stringify(payload))}`;
  const signature = await signRs256(unsigned, normalizePrivateKey(env.FIREBASE_PRIVATE_KEY));
  return `${unsigned}.${base64UrlEncode(new Uint8Array(signature))}`;
}

function normalizePrivateKey(rawKey) {
  return String(rawKey || "").replace(/\\n/g, "\n");
}

async function signRs256(data, pem) {
  const keyData = pemToArrayBuffer(pem);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  return await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(data)
  );
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64UrlEncodeUtf8(value) {
  return base64UrlEncode(new TextEncoder().encode(value));
}

function base64UrlEncode(bytes) {
  let binary = "";
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i += 1) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
