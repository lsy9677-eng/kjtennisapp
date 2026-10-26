import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { onRequestGet } from '../functions/naver-auth.js';
import { onRequest } from '../functions/kakao-auth.js';
import { onRequestPost, onRequestOptions } from '../functions/verify-recaptcha.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const vendors = Object.fromEntries(['app', 'auth', 'firestore', 'storage'].map(name =>
    [`/vendor/firebase-${name}-compat.js`, `node_modules/firebase/firebase-${name}-compat.js`]));
vendors['/vendor/chart.umd.js'] = 'node_modules/chart.js/dist/chart.umd.js';
vendors['/vendor/html2canvas.min.js'] = 'node_modules/html2canvas/dist/html2canvas.min.js';
export const localCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:9099 http://127.0.0.1:8080 http://127.0.0.1:9199; img-src 'self' data: blob: http://127.0.0.1:9199; font-src 'self'; worker-src 'none'; frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'self'";

export function createLocalServer() {
    return http.createServer(async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Content-Security-Policy', localCSP);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Referrer-Policy', 'no-referrer');
        if (!['127.0.0.1:4173', 'localhost:4173'].includes(req.headers.host)) {
            res.writeHead(403); res.end('HOST_BLOCKED'); return;
        }
        const url = new URL(req.url, 'http://' + req.headers.host);
        try {
            if (['/naver-auth', '/kakao-auth', '/verify-recaptcha'].includes(url.pathname)) {
                const chunks = [];
                for await (const chunk of req) chunks.push(chunk);
                const request = new Request(url, { method: req.method, headers: req.headers,
                    ...(!['GET', 'HEAD'].includes(req.method) ? { body: Buffer.concat(chunks) } : {}) });
                const context = { request, env: Object.freeze({}) }; // Never inherit process.env or .dev.vars.
                const handler = url.pathname === '/naver-auth' ? onRequestGet : url.pathname === '/kakao-auth' ? onRequest
                    : req.method === 'OPTIONS' ? onRequestOptions : onRequestPost;
                const result = await handler(context);
                res.writeHead(result.status, Object.fromEntries(result.headers)); res.end(await result.text()); return;
            }
            const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
            const permitted = /^(js\/[a-z-]+\.js|css\/app\.bundle\.css|index\.html|manifest\.json|court_map\.jpg|abc-(192|512)\.png)$/.test(name);
            const target = vendors[url.pathname] || (permitted ? name : null);
            if (!target) { res.writeHead(404); res.end('Not found'); return; }
            const types = { '.js': 'text/javascript; charset=utf-8', '.html': 'text/html; charset=utf-8', '.json': 'application/json', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg' };
            res.setHeader('Content-Type', types[path.extname(target)] || 'application/octet-stream');
            res.end(await fs.readFile(path.join(root, target)));
        } catch (err) { res.writeHead(503); res.end('Local dependency unavailable: ' + err.code); }
    });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    createLocalServer().listen(4173, '127.0.0.1', () => console.log('Development only: http://127.0.0.1:4173 (no external proxy)'));
}
