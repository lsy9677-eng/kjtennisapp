import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { developmentResponse } from '../functions/_lib/environment.js';
import { onRequest } from '../functions/kakao-auth.js';
import { onRequestGet } from '../functions/naver-auth.js';
import { onRequestPost, onRequestOptions } from '../functions/verify-recaptcha.js';

const source = file => fs.readFileSync(new URL('../' + file, import.meta.url), 'utf8');
function environment(href) {
    const writes = [], listeners = {};
    class Store { constructor() { this.data = new Map(); } getItem(k) { return this.data.get(k) ?? null; } setItem(k,v) { this.data.set(k,String(v)); } removeItem(k) { this.data.delete(k); } }
    const context = { URL, Object, Date, JSON, Promise, Error, setTimeout,
        location: { href, origin: new URL(href).origin },
        localStorage: new Store(), sessionStorage: new Store(),
        document: { createElement: () => ({}), head: { appendChild: node => writes.push(node) },
            addEventListener: (name, fn) => { listeners[name] = fn; }, getElementById: () => null },
        fetch: async input => { writes.push(String(input)); return { ok: true }; } };
    context.window = context;
    vm.createContext(context); vm.runInContext(source('js/environment.js'), context);
    return { context, writes, listeners };
}
test('only the exact HTTPS production origin enables production; lookalikes and preview hosts stop', () => {
    for (const href of ['https://tenniskj-app.pages.dev/', 'https://tenniskj-app.pages.dev:443/x?dev=1'])
        assert.equal(environment(href).context.APP_ENV.mode, 'production');
    for (const href of ['http://tenniskj-app.pages.dev/', 'https://tenniskj-app.pages.dev.evil.invalid/', 'https://preview.tenniskj-app.pages.dev/', 'https://tenniskj-app.pages.dev:444/', 'http://localhost:9999/', 'file:///index.html', 'https://user:pass@tenniskj-app.pages.dev/', 'http://user:pass@localhost:4173/'])
        assert.equal(environment(href).context.APP_ENV.mode, 'blocked', href);
    for (const href of ['http://127.0.0.1:4173/', 'http://localhost:4173/']) assert.equal(environment(href).context.APP_ENV.mode, 'development');
});
test('local storage namespace and fetch whitelist reject production, arbitrary ports, credential URLs', async () => {
    const { context, writes } = environment('http://127.0.0.1:4173/');
    context.localStorage.setItem('isAdm', 'true');
    assert.equal(context.localStorage.data.get('kjdev:demo-kjtennis-local:isAdm'), 'true');
    assert.equal(context.localStorage.data.has('isAdm'), false);
    for (const url of ['https://tenniskj-app.pages.dev/verify-recaptcha', 'https://firestore.googleapis.com/', 'https://api.iamport.kr/', 'http://127.0.0.1:9999/', 'http://user:pass@127.0.0.1:8080/'])
        await assert.rejects(context.fetch(url), /차단/);
    await context.fetch('http://127.0.0.1:8080/v1/projects/demo-kjtennis-local');
    assert.equal(writes.filter(v => typeof v === 'string').length, 1);
});
test('payment, refund and notifications are visible local events with no native request', () => {
    const { context } = environment('http://localhost:4173/');
    let payment;
    context.IMP.request_pay({ amount: 100 }, result => { payment = result; });
    assert.equal(payment.success, true); assert.match(payment.imp_uid, /^dev-payment-/);
    context.devEffect('refund-mock', { amount: 90 });
    new context.Notification('synthetic', { body: 'test' });
    assert.deepEqual(Array.from(context.DEV_EVENTS, x => x.kind), ['payment-mock', 'refund-mock', 'notification-mock']);
});
test('all three SDK emulators connect before persistence or application operations; rejects real project', () => {
    const calls = [];
    const context = { APP_ENV: { isDevelopment: true, projectId: 'demo-kjtennis-local' },
        navigator: {}, firebase: { auth: { Auth: { Persistence: { SESSION: 'session' } } } }, devEffect() {} };
    context.window = context; vm.createContext(context); vm.runInContext(source('js/firebase-environment.js'), context);
    const app = { options: { projectId: 'demo-kjtennis-local' },
        auth: () => ({ useEmulator: (...args) => calls.push(['auth', ...args]), setPersistence: p => calls.push(['persistence',p]) }),
        firestore: () => ({ useEmulator: (...args) => calls.push(['firestore', ...args]) }),
        storage: () => ({ useEmulator: (...args) => calls.push(['storage', ...args]) }) };
    context.connectDevelopmentEmulators(app);
    assert.deepEqual(calls.map(x => x[0]), ['auth','firestore','storage','persistence']);
    assert.equal(calls[0][1], 'http://127.0.0.1:9099');
    assert.deepEqual(calls[1].slice(1), ['127.0.0.1',8080]);
    assert.deepEqual(calls[2].slice(1), ['127.0.0.1',9199]);
    app.options.projectId = 'tenniskj'; assert.throws(() => context.connectDevelopmentEmulators(app), /차단/);
});
test('Pages Function branches never read credentials or fetch externally on local and blocked hosts', async () => {
    const original = globalThis.fetch; let count = 0;
    globalThis.fetch = () => { count++; throw new Error('EXTERNAL_NETWORK_FORBIDDEN'); };
    const env = new Proxy({}, { get() { throw new Error('CREDENTIAL_ACCESS_FORBIDDEN'); } });
    try {
        for (const origin of ['http://127.0.0.1:4173', 'http://localhost:4173', 'https://preview.tenniskj-app.pages.dev', 'http://localhost:9999']) {
            for (const [path, handler] of [['kakao-auth',onRequest], ['naver-auth',onRequestGet], ['verify-recaptcha',onRequestPost], ['verify-recaptcha',onRequestOptions]]) {
                for (const action of ['start','callback','token']) {
                    const response = await handler({ request: new Request(`${origin}/${path}?action=${action}&code=synthetic`), env });
                    assert.equal(response.status, origin.startsWith('http:') && origin.endsWith(':4173') ? 200 : 403);
                }
            }
        }
        assert.equal(count, 0);
        // Classify the production branch without invoking any production handler.
        assert.equal(developmentResponse({ request: new Request('https://tenniskj-app.pages.dev/kakao-auth') }, 'oauth'), null);
    } finally { globalThis.fetch = original; }
});
test('production scripts retain original providers; development SDKs are local assets only', () => {
    for (const [isDevelopment, expected] of [[true,'/vendor/'],[false,'https://']]) {
        const written=[];
        vm.runInNewContext(source('js/sdk-loader.js'), { APP_ENV:{ mode:isDevelopment?'development':'production',isDevelopment }, document:{write:x=>written.push(x)} });
        assert.ok(written.every(x=>x.includes(expected)));
        if(isDevelopment) assert.ok(written.every(x=>!x.includes('https://')));
    }
    const html=source('index.html');
    assert.ok(html.indexOf('environment.js') < html.indexOf('sdk-loader.js'));
    assert.equal(/<script[^>]+src="https?:/.test(html),false);
    // Every legacy SMS navigation remains guarded, without changing production expression.
    for(const file of ['admin-actions','booking-helpers','my-reservations','reservation-ui']) {
        for(const line of source('js/'+file+'.js').split('\n').filter(x=>/location.href\s*=.*(?:sms:|smsLink)/.test(x)))
            assert.ok(line.includes("APP_ENV.isDevelopment) devEffect('sms-mock'"), file+': '+line);
    }
});
