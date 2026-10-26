/* Runs before SDKs and application code. No query/storage override can enable production. */
(function () {
    'use strict';
    const url = new URL(location.href);
    const production = url.origin === 'https://tenniskj-app.pages.dev' && !url.username && !url.password;
    const local = url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname) && url.port === '4173' && !url.username && !url.password;
    const mode = production ? 'production' : local ? 'development' : 'blocked';
    const projectId = 'demo-kjtennis-local';
    window.APP_ENV = Object.freeze({ mode, isDevelopment: local, projectId,
        firebaseConfig: Object.freeze({ apiKey: 'demo-local-api-key', authDomain: 'localhost', projectId,
            storageBucket: projectId + '.appspot.com', appId: 'demo-local-app' }) });
    if (production) return;

    const policy = document.createElement('meta');
    policy.httpEquiv = 'Content-Security-Policy';
    policy.content = local
        ? "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:9099 http://127.0.0.1:8080 http://127.0.0.1:9199; img-src 'self' data: blob: http://127.0.0.1:9199; font-src 'self'; frame-src 'none'; worker-src 'none'; object-src 'none'; form-action 'none'; base-uri 'self'"
        : "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'";
    document.head.appendChild(policy);
    if (!local) {
        document.addEventListener('DOMContentLoaded', () => {
            document.body.textContent = '실행 중단: 허용되지 않은 호스트입니다.';
        });
        return;
    }

    // Legacy application keys are transparently namespaced only on the development origin.
    for (const store of [localStorage, sessionStorage]) {
        const proto = Object.getPrototypeOf(store);
        // Install once on the shared Storage prototype.
        if (proto.__kjDevelopmentStorage) break;
        const get = proto.getItem, set = proto.setItem, remove = proto.removeItem;
        const prefix = 'kjdev:demo-kjtennis-local:';
        proto.getItem = function (key) { return get.call(this, prefix + key); };
        proto.setItem = function (key, value) { return set.call(this, prefix + key, value); };
        proto.removeItem = function (key) { return remove.call(this, prefix + key); };
        Object.defineProperty(proto, '__kjDevelopmentStorage', { value: true });
    }
    window.__TENNISKJ_SW_DISABLED__ = true;
    window.DEV_EVENTS = [];
    window.devEffect = function (kind, detail) {
        const event = { kind, detail, at: new Date().toISOString() };
        window.DEV_EVENTS.push(event);
        const output = document.getElementById('dev-effects');
        if (output) output.textContent = JSON.stringify(window.DEV_EVENTS.slice(-8), null, 2);
        return event;
    };
    // Block accidental programmatic external requests in addition to CSP (including SDK requests).
    const nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, options) {
        const target = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
        const allowed = [location.origin, 'http://127.0.0.1:9099', 'http://127.0.0.1:8080', 'http://127.0.0.1:9199'];
        if (!allowed.includes(target.origin) || target.username || target.password) {
            window.devEffect('blocked-fetch', target.origin + target.pathname);
            return Promise.reject(new Error('개발 환경 외부 요청 차단'));
        }
        return nativeFetch(input, options);
    };
    window.IMP = { init() {}, request_pay(options, callback) {
        window.devEffect('payment-mock', options);
        callback({ success: true, imp_uid: 'dev-payment-' + Date.now() });
    } };
    window.grecaptcha = { reset() { setTimeout(() => window.onRecaptchaSuccess?.('dev-recaptcha-token'), 0); } };
    class DevNotification {
        static permission = 'granted';
        static async requestPermission() { window.devEffect('notification-permission-mock', {}); return 'granted'; }
        constructor(title, options) { window.devEffect('notification-mock', { title, options }); }
        close() {}
    }
    window.Notification = DevNotification;
    window.open = function (target) { window.devEffect('window-open-mock', String(target)); return null; };
    document.addEventListener('click', event => {
        const anchor = event.target.closest?.('a[href]');
        if (anchor && !['http:', 'blob:'].includes(new URL(anchor.href, location.href).protocol)) {
            event.preventDefault(); window.devEffect('navigation-mock', anchor.getAttribute('href'));
        } else if (anchor && new URL(anchor.href, location.href).origin !== location.origin && !anchor.href.startsWith('blob:')) {
            event.preventDefault(); window.devEffect('navigation-mock', anchor.href);
        }
    }, true);
    document.addEventListener('DOMContentLoaded', async () => {
        const panel = document.createElement('aside');
        panel.id = 'dev-panel';
        panel.style.cssText = 'position:relative;z-index:999999;background:#fff3cd;color:#332600;padding:12px;white-space:normal';
        panel.innerHTML = '<b>개발 전용 · demo-kjtennis-local · Auth 9099 / Firestore 8080 / Storage 9199</b><div>가상 데이터만 사용. 결제·환불·SMS·알림·OAuth·reCAPTCHA는 개발 대역입니다.</div><button id="dev-login">가상 회원 로그인</button> <button id="dev-refund">가상 환불 기록</button><pre id="dev-effects"></pre>';
        document.body.prepend(panel);
        document.getElementById('dev-login').onclick = () => window.devLogin();
        document.getElementById('dev-refund').onclick = () => window.devEffect('refund-mock', { amount: 1000, paymentId: 'dev-payment-example' });
        try {
            if ('serviceWorker' in navigator) {
                const regs = await navigator.serviceWorker.getRegistrations();
                await Promise.all(regs.map(reg => reg.unregister()));
                if (navigator.serviceWorker.controller) throw new Error('이 로컬 출처의 기존 서비스 워커를 해제했습니다. 탭을 닫고 다시 여세요.');
            }
            if ('caches' in window) await Promise.all((await caches.keys()).map(key => caches.delete(key)));
            const checks = await Promise.all([
                fetch('http://127.0.0.1:9099/emulator/v1/projects/' + projectId + '/config', { signal: AbortSignal.timeout(3000) }),
                fetch('http://127.0.0.1:8080/v1/projects/' + projectId + '/databases/(default)/documents/settings/global', { signal: AbortSignal.timeout(3000) }),
                fetch('http://127.0.0.1:9199/v0/b/' + projectId + '.appspot.com/o', { signal: AbortSignal.timeout(3000) })
            ]);
            if (checks.some(res => !res.ok)) throw new Error('Emulator 또는 가상 seed 데이터가 준비되지 않았습니다.');
            window.devEffect('emulators-ready', { projectId });
        } catch (err) {
            window.devEffect('emulators-unavailable', String(err.message || err));
            const stop = document.createElement('div');
            stop.id = 'dev-stopped';
            stop.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:#fff3cd;padding:40px;color:#332600';
            stop.textContent = '개발 실행 중단: ' + err.message + ' 운영 fallback은 없습니다.';
            document.body.appendChild(stop);
        }
    });
}());
