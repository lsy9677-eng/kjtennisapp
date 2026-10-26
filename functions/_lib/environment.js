const productionOrigin = 'https://tenniskj-app.pages.dev';
export function developmentResponse(context, kind) {
    const url = new URL(context.request.url);
    if (url.origin === productionOrigin && !url.username && !url.password) return null;
    const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname) && url.port === '4173' && !url.username && !url.password;
    const data = local
        ? kind === 'recaptcha' ? { success: true, development: true, mock: 'recaptcha' }
            : { ok: true, development: true, mock: kind, message: 'Use the synthetic Emulator member; no OAuth token issued.' }
        : { ok: false, error: 'HOST_BLOCKED' };
    return new Response(JSON.stringify(data), { status: local ? 200 : 403,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
