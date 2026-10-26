import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolveTool } from './tools.mjs';
import { createLocalServer } from './server.mjs';
import { fileURLToPath } from 'node:url';
process.env.PLAYWRIGHT_BROWSERS_PATH = fileURLToPath(new URL('./artifacts/browsers', import.meta.url));
const { chromium } = await import(pathToFileURL(resolveTool('node_modules/playwright/index.mjs')).href);
let closeServer;
const usePages=process.argv.includes('--pages');
const transferOnly=process.argv.includes('--transfer-only');
if(usePages) {
    const {createPagesRuntime}=await import('./pages-runtime.mjs');
    const runtime=await createPagesRuntime({port:4173});
    closeServer=()=>runtime.mf.dispose();
} else {
    const server=createLocalServer();
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(4173,'127.0.0.1',resolve);});
    closeServer=()=>new Promise(resolve=>server.close(resolve));
}
const requests=[], violations=[], errors=[], dialogs=[];
const allowed=new Set(['http://127.0.0.1:4173','http://127.0.0.1:8080','http://127.0.0.1:9099','http://127.0.0.1:9199']);
let browser;
try {
    browser=await chromium.launch({headless:true});
    const context=await browser.newContext({serviceWorkers:'block'});
    await context.addInitScript(value=>{window.__TRANSFER_ONLY_TEST__=value;},transferOnly);
    await context.addInitScript(() => {
        // Simulate an old local session. The development namespace must ignore it.
        if (!sessionStorage.getItem('fixture-installed')) {
            localStorage.setItem('isAdm','true');
            sessionStorage.setItem('fixture-installed','true');
        }
    });
    await context.route('**/*',route=>{
        const url=route.request().url();requests.push({url,method:route.request().method()});
        if(!allowed.has(new URL(url).origin)){violations.push(url);return route.abort('blockedbyclient');}
        return route.continue();
    });
    const page=await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    page.on('dialog',dialog=>{dialogs.push(dialog.message());return dialog.accept();});
    await page.goto('http://127.0.0.1:4173/',{waitUntil:'load'});
    await page.waitForFunction(()=>window.DEV_EVENTS?.some(x=>x.kind==='emulators-ready') || document.getElementById('dev-stopped'),{timeout:15000});
    assert.equal(await page.locator('#dev-stopped').count(),0,await page.locator('#dev-stopped').textContent().catch(()=>''));
    assert.equal(await page.evaluate(()=>isAdmin),false,'Must ignore unprefixed administrator state');
    await page.click('#dev-login');
    await page.waitForFunction(()=>typeof currentUser!=='undefined' && currentUser?.name==='가상회원');
    const sdk=await page.evaluate(async()=>{
        const ref=db.collection('development_checks').doc('browser');
        await ref.set({synthetic:true});
        const data=(await ref.get()).data();
        const upload=storage.ref('fixtures/browser.txt');
        await upload.put(new Blob(['SYNTHETIC ONLY'],{type:'text/plain'}));
        const download=await upload.getDownloadURL();
        const text=await (await fetch(download)).text();
        await upload.delete(); await ref.delete();
        return {project:firebaseApp.options.projectId,authName:auth.app.name,data,text,download};
    });
    assert.equal(sdk.project,'demo-kjtennis-local');assert.equal(sdk.authName,'kjtennis-development');
    assert.equal(sdk.data.synthetic,true);assert.equal(sdk.text,'SYNTHETIC ONLY');
    assert.ok(sdk.download.startsWith('http://127.0.0.1:9199/'));
    const pricingReadiness=await page.evaluate(async()=>{
        const originalLoadConfig=loadConfig;
        const config=await loadConfig();await loadSeasonalPricings();
        const originalSeasons=window.seasonalPricings;
        const payments=()=>DEV_EVENTS.filter(event=>event.kind==='payment-mock').length;
        const before=payments();
        try {
            loadConfig=async()=>config;
            let release;
            seasonalPricingLoadPromise=new Promise(resolve=>{release=resolve;});
            document.getElementById('hiddenDate').value='2030-11-04';selected=[{c:2,t:18}];
            const opening=openBook();
            document.getElementById('chkAutomationPolicy').checked=true;onRecaptchaSuccess('dev-recaptcha-token');
            await new Promise(resolve=>setTimeout(resolve,0));
            if(!document.getElementById('btnDoPay').disabled || document.getElementById('txtPrice').innerText!=='확인 중')throw Error('Price enabled during delayed load');
            await doPay();
            window.seasonalPricings=[{start:'2030-11-01',end:'2030-11-30',nightStart:18,dayPrice:111,nightPrice:222}];
            release(window.seasonalPricings);
            if(!await opening || document.getElementById('btnDoPay').disabled)throw Error('Price did not become ready after load');
            if(!document.getElementById('txtPrice').parentElement.innerHTML.includes('평일야간'))throw Error('Wrong weekday/night description');
            seasonalPricingLoadPromise=Promise.resolve(null); // Synthetic server-read failure result.
            if(await openBook())throw Error('Failed read unexpectedly succeeded');
            document.getElementById('chkAutomationPolicy').checked=true;onRecaptchaSuccess('dev-recaptcha-token');
            await doPay();
            if(!document.getElementById('btnDoPay').disabled || document.getElementById('txtPrice').innerText!=='확인 불가')throw Error('Failed read did not block quote');
            if(payments()!==before)throw Error('Payment was called before pricing readiness');
            return {delayBlocked:true,loadedNightBoundary:true,failureBlocked:true,paymentsWhileUnready:0};
        } finally {
            loadConfig=originalLoadConfig;seasonalPricingLoadPromise=null;window.seasonalPricings=originalSeasons;closeModal('modalBook');
        }
    });
    await page.evaluate(async()=>{
        await startGoogleLogin();await startKakaoLogin();await startNaverLogin();
        const recaptcha=await (await fetch('/verify-recaptcha',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'dev-recaptcha-token'})})).json();
        if(!recaptcha.development)throw new Error('Not a local Pages Function');
        sendSmsToAdmin('가상회원','000-0000-0000','2030-11-04','2코트 10시','개발결제','1000');
        new Notification('개발 알림',{body:'발송하지 않음'});
    });
    await page.click('#dev-refund');
    // Exercise unchanged payment + saveBook against synthetic Emulator documents only.
    await page.evaluate(async()=>{
        const date='2030-11-04';
        for(const time of [10,11])await db.collection('reservations').doc(buildSlotLockId(currentCenter,date,2,time)).delete();
        document.getElementById('hiddenDate').value=date;
        selected=[{c:2,t:10},{c:2,t:11}];
        await openBook();
        document.getElementById('chkAutomationPolicy').checked=true;
        onRecaptchaSuccess('dev-recaptcha-token');
        if (window.__TRANSFER_ONLY_TEST__) {
            if (useCardPay !== false || currentPayMethod !== 'TRANSFER' || document.getElementById('mthPay').style.display !== 'none') throw Error('Card-disabled setting was not applied');
            setPayMethod('PAY');
            if (currentPayMethod !== 'TRANSFER') throw Error('Disabled card selection was accepted');
            currentPayMethod='PAY';
            await doPay();
            if (currentPayMethod !== 'TRANSFER') throw Error('Tampered card method was not blocked');
            if (DEV_EVENTS.some(event=>event.kind==='payment-mock')) throw Error('Disabled card invoked PG mock');
        } else setPayMethod('PAY');
        await doPay();
    });
    let reservationSaved=false;
    for(let attempt=0;attempt<100&&!reservationSaved;attempt++) {
        reservationSaved=await page.evaluate(async()=>{
            const snapshots=await Promise.all([10,11].map(time=>db.collection('reservations').doc(buildSlotLockId(currentCenter,'2030-11-04',2,time)).get()));
            return snapshots.every(snap=>snap.exists && (window.__TRANSFER_ONLY_TEST__ ? snap.data().paymentUid==='TRANSFER' : snap.data().paymentUid?.startsWith('dev-payment-')));
        });
        if(!reservationSaved)await new Promise(resolve=>setTimeout(resolve,200));
    }
    assert.ok(reservationSaved,'Both synthetic slots must be saved; dialogs='+JSON.stringify(dialogs));
    const result=await page.evaluate(()=>({events:DEV_EVENTS,keys:Object.keys(localStorage),project:firebaseApp.options.projectId}));
    for(const kind of [...(transferOnly?[]:['payment-mock']),'refund-mock','sms-mock','notification-mock','oauth-mock'])assert.ok(result.events.some(x=>x.kind===kind),kind);
    let transferResult;
    if(transferOnly) {
        transferResult=await page.evaluate(async()=>{
            const rows=await Promise.all([10,11].map(async time=>(await db.collection('reservations').doc(buildSlotLockId(currentCenter,'2030-11-04',2,time)).get()).data()));
            if(rows.some(row=>!row))throw Error('Missing synthetic reservation: '+JSON.stringify({center:currentCenter,rows,all:(await db.collection('reservations').get()).docs.map(doc=>({id:doc.id,...doc.data()}))}));
            return {statuses:rows.map(row=>row.status),paymentUids:rows.map(row=>row.paymentUid),pgMockCalls:DEV_EVENTS.filter(event=>event.kind==='payment-mock').length,cardVisible:document.getElementById('mthPay').style.display!=='none',method:currentPayMethod};
        });
        assert.deepEqual(transferResult.statuses,['PENDING','PENDING']);assert.deepEqual(transferResult.paymentUids,['TRANSFER','TRANSFER']);assert.equal(transferResult.pgMockCalls,0);assert.equal(transferResult.cardVisible,false);
    }
    await page.evaluate(async()=>{const cache=await caches.open('old-development-fixture');await cache.put('/fixture',new Response('synthetic'));});
    await page.reload({waitUntil:'load'});
    await page.waitForFunction(()=>typeof currentUser!=='undefined' && currentUser?.name==='가상회원');
    await page.waitForFunction(()=>DEV_EVENTS.some(x=>x.kind==='emulators-ready'));
    if(transferOnly) {
        const policy=await page.evaluate(async()=>{
            document.getElementById('hiddenDate').value='2030-11-05';selected=[{c:3,t:10},{c:3,t:11}];
            await openBook();return {card:document.getElementById('mthPay').style.display,method:currentPayMethod,enabled:useCardPay};
        });
        assert.deepEqual(policy,{card:'none',method:'TRANSFER',enabled:false});
    }
    assert.deepEqual(await page.evaluate(()=>caches.keys()),[]);
    // Native browser transports are denied by CSP, independently of the fetch wrapper.
    const csp=await page.evaluate(async()=>{
        const blocked=[];
        document.addEventListener('securitypolicyviolation',e=>blocked.push(e.violatedDirective));
        await new Promise(resolve=>{const xhr=new XMLHttpRequest();xhr.onerror=resolve;xhr.open('POST','https://network-denied.invalid/message');xhr.send('SYNTHETIC');});
        try {navigator.sendBeacon('https://network-denied.invalid/beacon','SYNTHETIC');} catch {}
        try {new WebSocket('wss://network-denied.invalid/socket');} catch {}
        await new Promise(resolve=>setTimeout(resolve,100));
        return blocked;
    });
    assert.ok(csp.includes('connect-src'));
    // Unknown host document is supplied entirely in memory, with no DNS or remote access.
    const unknown=await browser.newContext();
    const unknownRequests=[];
    await unknown.route('**/*',async route=>{
        const url=new URL(route.request().url()); unknownRequests.push(url.pathname);
        if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:await fs.readFile('index.html','utf8')});
        if(url.pathname==='/js/environment.js')return route.fulfill({contentType:'text/javascript',body:await fs.readFile('js/environment.js','utf8')});
        return route.abort();
    });
    const blockedPage=await unknown.newPage();
    await blockedPage.goto('http://unapproved-host.invalid/',{waitUntil:'load'});
    assert.match(await blockedPage.locator('body').textContent(),/실행 중단/);
    assert.equal(await blockedPage.evaluate(()=>typeof firebase),'undefined');
    await unknown.close();
    // Simulate unreachable Emulator after connection settings: never allow fallback.
    const offline=await browser.newContext({serviceWorkers:'block'});
    await offline.route('**/*',route=>{
        const url=route.request().url();
        if(new URL(url).origin==='http://127.0.0.1:4173')return route.continue();
        if(!allowed.has(new URL(url).origin))violations.push(url);
        return route.abort();
    });
    const stopped=await offline.newPage();stopped.on('dialog',d=>d.accept());
    await stopped.goto('http://127.0.0.1:4173/',{waitUntil:'load'});
    await stopped.waitForSelector('#dev-stopped',{timeout:15000});
    assert.match(await stopped.locator('#dev-stopped').textContent(),/fallback/);
    await offline.close();
    assert.deepEqual(violations,[],'External browser request attempted');
    assert.deepEqual(errors,[],'Page JavaScript errors');
    await fs.mkdir('dev/artifacts',{recursive:true});
    await fs.writeFile('dev/artifacts/'+(transferOnly?'transfer-browser-report.json':usePages?'pages-browser-report.json':'browser-report.json'),JSON.stringify({passed:true,runtime:usePages?'Cloudflare workerd':'Node harness',requests,violations,errors,sdk,pricingReadiness,transferResult,events:result.events,offlineStopped:true,csp,unknownRequests,cacheCleared:true,unprefixedAdminIgnored:true},null,2));
    console.log('PASS: synthetic Auth / Firestore / Storage / booking / mocks / session restore / offline stop; external requests: 0');
} finally {await browser?.close();await closeServer();}
