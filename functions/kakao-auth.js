// Cloudflare Pages Function: /kakao-auth
// 목적: Kakao access token을 서버에서 검증한 뒤 Firebase Custom Token 발급
// 배치 위치: functions/kakao-auth.js

const FIREBASE_AUDIENCE = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';
const KAKAO_USER_ME_URL = 'https://kapi.kakao.com/v2/user/me';
const KAKAO_AUTH_URL = 'https://kauth.kakao.com/oauth/authorize';
const KAKAO_TOKEN_URL = 'https://kauth.kakao.com/oauth/token';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

function redirect(location, status = 302) {
  return new Response(null, {
    status,
    headers: {
      Location: location,
      'Cache-Control': 'no-store'
    }
  });
}

function base64UrlEncode(input) {
  let bytes;
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else {
    bytes = new TextEncoder().encode(JSON.stringify(input));
  }

  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function pemToArrayBuffer(pem) {
  if (!pem) throw new Error('FIREBASE_PRIVATE_KEY가 없습니다.');

  // Cloudflare Secret에 \n 문자로 들어간 경우와 실제 줄바꿈으로 들어간 경우 모두 지원
  const normalized = String(pem)
    .replace(/\\n/g, '\n')
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');

  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importPrivateKey(privateKeyPem) {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function signJwt(payload, env) {
  const clientEmail = env.FIREBASE_CLIENT_EMAIL;
  const privateKey = env.FIREBASE_PRIVATE_KEY;

  if (!clientEmail) throw new Error('FIREBASE_CLIENT_EMAIL이 없습니다.');
  if (!privateKey) throw new Error('FIREBASE_PRIVATE_KEY가 없습니다.');

  const header = { alg: 'RS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const key = await importPrivateKey(privateKey);
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    new TextEncoder().encode(unsignedToken)
  );

  return `${unsignedToken}.${base64UrlEncode(signature)}`;
}

async function createFirebaseCustomToken(uid, claims, env) {
  const clientEmail = env.FIREBASE_CLIENT_EMAIL;
  const now = Math.floor(Date.now() / 1000);

  const safeClaims = claims && typeof claims === 'object' ? claims : {};
  delete safeClaims.uid;
  delete safeClaims.iss;
  delete safeClaims.sub;
  delete safeClaims.aud;
  delete safeClaims.iat;
  delete safeClaims.exp;

  return signJwt({
    iss: clientEmail,
    sub: clientEmail,
    aud: FIREBASE_AUDIENCE,
    iat: now,
    exp: now + 60 * 60,
    uid: String(uid),
    claims: safeClaims
  }, env);
}

function normalizeKakaoPhone(phone) {
  let value = String(phone || '').trim();
  if (!value) return '';
  value = value.replace(/\s/g, '').replace(/-/g, '');
  if (value.startsWith('+82')) value = '0' + value.slice(3);
  const digits = value.replace(/\D/g, '');
  if (digits.length === 11) return digits.replace(/(\d{3})(\d{4})(\d{4})/, '$1-$2-$3');
  if (digits.length === 10) return digits.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
  return phone || '';
}

async function getKakaoProfileByAccessToken(accessToken) {
  if (!accessToken) throw new Error('카카오 accessToken이 없습니다.');

  const res = await fetch(KAKAO_USER_ME_URL, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'
    }
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.msg || data.error_description || '카카오 사용자 정보 조회 실패');
  }

  const account = data.kakao_account || {};
  const profile = account.profile || {};
  const kakaoId = String(data.id || '');
  if (!kakaoId) throw new Error('카카오 사용자 ID를 확인하지 못했습니다.');

  return {
    uid: `kakao:${kakaoId}`,
    providerUid: kakaoId,
    name: profile.name || profile.nickname || '',
    email: account.email || '',
    phone: normalizeKakaoPhone(account.phone_number || ''),
    nickname: profile.nickname || '',
    raw: data
  };
}

async function handleToken(request, env) {
  if (request.method !== 'POST') {
    return json({ error: 'POST 요청만 허용됩니다.' }, 405);
  }

  const body = await request.json().catch(() => ({}));
  const accessToken = body.accessToken || body.access_token || '';
  const kakaoProfile = await getKakaoProfileByAccessToken(accessToken);

  const customToken = await createFirebaseCustomToken(kakaoProfile.uid, {
    provider: 'kakao',
    kakaoUid: kakaoProfile.providerUid,
    email: kakaoProfile.email || '',
    name: kakaoProfile.name || kakaoProfile.nickname || ''
  }, env);

  return json({
    customToken,
    profile: {
      providerUid: kakaoProfile.providerUid,
      name: kakaoProfile.name || kakaoProfile.nickname || '',
      email: kakaoProfile.email || '',
      phone: kakaoProfile.phone || ''
    }
  });
}

function makeState(env, mode) {
  const seed = `${Date.now()}.${crypto.randomUUID()}.${env.KAKAO_STATE_SECRET || ''}.${mode || 'login'}`;
  return base64UrlEncode(seed).slice(0, 96);
}

async function handleStart(request, env) {
  const url = new URL(request.url);
  const mode = url.searchParams.get('mode') || 'login';
  const restApiKey = env.KAKAO_REST_API_KEY;
  const redirectUri = env.KAKAO_REDIRECT_URI || `${url.origin}/kakao-auth`;

  if (!restApiKey) return json({ error: 'KAKAO_REST_API_KEY가 없습니다.' }, 500);

  const state = makeState(env, mode);
  const authUrl = new URL(KAKAO_AUTH_URL);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', restApiKey);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', `${mode}.${state}`);

  return redirect(authUrl.toString());
}

async function exchangeCodeForAccessToken(code, env, requestUrl) {
  const fallbackRedirectUri = `${new URL(requestUrl).origin}/kakao-auth`;
  const redirectUri = env.KAKAO_REDIRECT_URI || fallbackRedirectUri;
  if (!env.KAKAO_REST_API_KEY) throw new Error('KAKAO_REST_API_KEY가 없습니다.');
  if (!redirectUri) throw new Error('KAKAO_REDIRECT_URI가 없습니다.');

  const params = new URLSearchParams();
  params.set('grant_type', 'authorization_code');
  params.set('client_id', env.KAKAO_REST_API_KEY);
  params.set('redirect_uri', redirectUri);
  params.set('code', code);
  if (env.KAKAO_CLIENT_SECRET) params.set('client_secret', env.KAKAO_CLIENT_SECRET);

  const res = await fetch(KAKAO_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8' },
    body: params.toString()
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || '카카오 토큰 발급 실패');
  }
  return data.access_token;
}

async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code') || '';
  const state = url.searchParams.get('state') || 'login';
  const mode = String(state).split('.')[0] || 'login';
  const appBaseUrl = env.APP_BASE_URL || url.origin;

  if (!code) {
    return redirect(`${appBaseUrl}/#kakaoError=${encodeURIComponent(url.searchParams.get('error_description') || url.searchParams.get('error') || '카카오 인가 코드가 없습니다.')}`);
  }

  try {
    const accessToken = await exchangeCodeForAccessToken(code, env, request.url);
    const kakaoProfile = await getKakaoProfileByAccessToken(accessToken);
    const customToken = await createFirebaseCustomToken(kakaoProfile.uid, {
      provider: 'kakao',
      kakaoUid: kakaoProfile.providerUid,
      email: kakaoProfile.email || '',
      name: kakaoProfile.name || kakaoProfile.nickname || ''
    }, env);

    const hash = new URLSearchParams();
    hash.set('kakaoCustomToken', customToken);
    hash.set('kakaoUid', kakaoProfile.providerUid || '');
    hash.set('kakaoName', kakaoProfile.name || kakaoProfile.nickname || '');
    hash.set('kakaoEmail', kakaoProfile.email || '');
    hash.set('kakaoMobile', kakaoProfile.phone || '');
    hash.set('kakaoMode', mode);

    return redirect(`${appBaseUrl}/#${hash.toString()}`);
  } catch (err) {
    return redirect(`${appBaseUrl}/#kakaoError=${encodeURIComponent(err && err.message ? err.message : String(err))}`);
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') return json({ ok: true });

  try {
    const url = new URL(request.url);
    const action = url.searchParams.get('action') || '';

    if (action === 'start') return await handleStart(request, env);
    if (action === 'callback') return await handleCallback(request, env);

    // 카카오 Developers Redirect URI를 /kakao-auth 로 등록하면
    // 카카오가 /kakao-auth?code=...&state=... 형태로 돌아오므로 이 분기가 필요합니다.
    if (url.searchParams.get('code') || url.searchParams.get('error')) {
      return await handleCallback(request, env);
    }

    if (action === 'token' || request.method === 'POST') return await handleToken(request, env);

    return json({ error: '지원하지 않는 요청입니다. /kakao-auth?action=start 로 시작하세요.' }, 400);
  } catch (err) {
    return json({ error: err && err.message ? err.message : String(err) }, 500);
  }
}
