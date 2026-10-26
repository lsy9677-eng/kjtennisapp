import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {root} from './tools.mjs';
import {publicAssets} from './pages-assets.mjs';
import {buildPagesRelease,listFiles} from './build-pages.mjs';
import {isolatedToolEnvironment} from './prepare-pages.mjs';

const release=await buildPagesRelease();
// Prove a rebuild cannot retain a stale test fixture, secret-shaped filename or log.
for(const file of ['dev/should-not-ship.js','js/README.md','.env','tests/stale.txt','logs/stale.log']) {
    await fs.mkdir(path.dirname(path.join(release.output,file)),{recursive:true});
    await fs.writeFile(path.join(release.output,file),'SYNTHETIC STALE FILE');
}
await buildPagesRelease();
assert.deepEqual(await listFiles(release.output),[...publicAssets,'_worker.js','_routes.json'].sort());
for(const file of publicAssets)assert.deepEqual(await fs.readFile(path.join(release.output,file)),await fs.readFile(path.join(root,file)),file);
const routes=JSON.parse(await fs.readFile(path.join(release.output,'_routes.json'),'utf8'));
assert.deepEqual([...routes.include].sort(),['/kakao-auth','/naver-auth','/verify-recaptcha']);
assert.equal(routes.version,1);
process.env.PATH=isolatedToolEnvironment().PATH;
const {Miniflare,convertV4MiniflareOptions}=await import('miniflare');let outbound=0;
const options=convertV4MiniflareOptions({host:'127.0.0.1',port:0,name:'release-local-only',modules:true,
    scriptPath:path.join(release.output,'_worker.js'),compatibilityDate:release.compatibilityDate,
    assets:{directory:release.output,binding:'ASSETS',run_worker_first:true},
    outboundService:()=>{outbound++;return new Response('EXTERNAL_REQUEST_BLOCKED',{status:502});}});
options.workers[0].config.assets.hasUserWorker=true;options.telemetry={enabled:false};options.cf=false;
options.resourcePersistencePath=path.join(root,'dev/artifacts/release-runtime');
const runtime=new Miniflare(options);
async function dispatch(url,init){const r=await runtime.dispatchFetch(url,init);const data=await r.arrayBuffer();return new Response(data,{status:r.status,headers:r.headers});}
try {
    await runtime.ready;
    for(const file of ['/','/js/booking-core.js','/.well-known/assetlinks.json'])assert.equal((await dispatch('https://tenniskj-app.pages.dev'+file)).status,200,file);
    assert.equal((await dispatch('https://tenniskj-app.pages.dev/verify-recaptcha',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status,400);
    assert.equal((await dispatch('https://unapproved.invalid/kakao-auth')).status,403);
    assert.equal(outbound,0);
} finally {await runtime.dispose();}
await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['dev/production-browser-check.mjs'],{cwd:root,env:{...process.env,KJ_PRODUCTION_ASSET_ROOT:release.output},stdio:'inherit',windowsHide:true});
    child.once('error',reject);child.once('exit',code=>code===0?resolve():reject(new Error('Release browser check failed: '+code)));
});
await fs.writeFile(path.join(root,'dev/artifacts/release-report.json'),JSON.stringify({passed:true,project:release.projectName,compatibilityDate:release.compatibilityDate,files:await listFiles(release.output),sourceBytesPreserved:true,staleFilesRemoved:true,workerRoutes:routes.include,externalRequests:outbound,uploaded:false},null,2));
console.log('PASS: release allowlist, clean rebuild, actual workerd assets/Functions and memory-only initialization; no upload');
