// A fully memory-routed origin fixture. No socket/DNS request to the production host is permitted.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { root } from './tools.mjs';
process.env.PLAYWRIGHT_BROWSERS_PATH=path.join(root,'dev/artifacts/browsers');
const {chromium}=await import('playwright');
const baseline=execFileSync('git',['show','3b5bb59:js/config.js'],{encoding:'utf8',cwd:root});
const candidate=await fs.readFile(path.join(root,'js/config.js'),'utf8');
const environment=await fs.readFile(path.join(root,'js/environment.js'),'utf8');
const connection=await fs.readFile(path.join(root,'js/firebase-environment.js'),'utf8');
const origin='https://tenniskj-app.pages.dev';
const uid='synthetic-session-user', email='session@example.invalid';
const now=Math.floor(Date.now()/1000);
const b64=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
const idToken=b64({alg:'RS256',typ:'JWT'})+'.'+b64({iss:'https://securetoken.google.com/tenniskj',aud:'tenniskj',sub:uid,user_id:uid,iat:now,exp:now+3600,auth_time:now,email,email_verified:false,firebase:{identities:{email:[email]},sign_in_provider:'password'}})+'.SYNTHETIC_SIGNATURE';
const fulfilled=[],denied=[];
function html(modern) {
    const scripts=['app','auth','firestore','storage'].map(name=>`<script src="/fixture-sdk/firebase-${name}-compat.js"></script>`).join('');
    return '<!doctype html><meta charset="utf-8">'+scripts+'<script>window.beforeNotification=Notification;window.beforeFetch=fetch;</script><script>'+environment+'</script><script>'+connection+'</script><script>'+(modern?candidate:baseline)+`</script><script>
        window.firebaseApp=firebase.initializeApp(firebaseConfig${modern?", '[DEFAULT]'":''});
        ${modern?'connectDevelopmentEmulators(firebaseApp);':''}
        window.auth=firebaseApp.auth();
        window.restored=new Promise(resolve=>auth.onAuthStateChanged(user=>resolve(user?user.uid:null)));
    </script>`;
}
const browser=await chromium.launch({headless:true});
try {
    const context=await browser.newContext({serviceWorkers:'block'});
    await context.route('**/*',async route=>{
        const req=route.request(),url=new URL(req.url());
        fulfilled.push({url:req.url(),method:req.method()});
        // Every request is fulfilled or aborted here, including all SDK endpoints; never route.continue().
        if(url.origin===origin && ['/baseline','/candidate'].includes(url.pathname))return route.fulfill({contentType:'text/html',body:html(url.pathname==='/candidate')});
        if(url.origin===origin && /^\/fixture-sdk\/firebase-(app|auth|firestore|storage)-compat\.js$/.test(url.pathname))return route.fulfill({contentType:'text/javascript',body:await fs.readFile(path.join(root,'node_modules/firebase',path.basename(url.pathname)))});
        if(url.origin==='https://identitytoolkit.googleapis.com' && url.pathname.endsWith('accounts:signInWithPassword'))return route.fulfill({contentType:'application/json',body:JSON.stringify({localId:uid,email,idToken,refreshToken:'SYNTHETIC_REFRESH_TOKEN',expiresIn:'3600',registered:true})});
        if(url.origin==='https://identitytoolkit.googleapis.com' && url.pathname.endsWith('accounts:lookup'))return route.fulfill({contentType:'application/json',body:JSON.stringify({users:[{localId:uid,email,emailVerified:false,createdAt:String(Date.now()),lastLoginAt:String(Date.now()),providerUserInfo:[{providerId:'password',email,federatedId:email}]}]})});
        denied.push(req.url());return route.abort();
    });
    const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(origin+'/baseline');
    await page.evaluate(async({email})=>{await auth.signInWithEmailAndPassword(email,'SYNTHETIC_PASSWORD');localStorage.setItem('isAdm','true');},{email});
    assert.equal(await page.evaluate(()=>auth.currentUser.uid),uid);
    const originalConfig=await page.evaluate(()=>firebaseApp.options);
    await page.goto(origin+'/candidate');
    const actual=await page.evaluate(async()=>({uid:await restored,appName:firebaseApp.name,config:firebaseApp.options,
        rawAdmin:localStorage.getItem('isAdm'),notificationPreserved:Notification===beforeNotification,fetchPreserved:fetch===beforeFetch,
        devEvents:typeof DEV_EVENTS,mode:APP_ENV.mode,appNames:firebase.apps.map(app=>app.name)}));
    assert.equal(actual.uid,uid,'Must restore baseline SDK session without migration');
    assert.equal(actual.appName,'[DEFAULT]');assert.deepEqual(actual.appNames,['[DEFAULT]']);
    assert.deepEqual(actual.config,originalConfig);assert.equal(actual.rawAdmin,'true');
    assert.equal(actual.notificationPreserved,true);assert.equal(actual.fetchPreserved,true);assert.equal(actual.devEvents,'undefined');assert.equal(actual.mode,'production');
    assert.deepEqual(denied,[]);assert.deepEqual(errors,[]);
    await fs.writeFile(path.join(root,'dev/artifacts/production-browser-report.json'),JSON.stringify({passed:true,sessionRestored:true,configurationUnchanged:true,developmentMocksAbsent:true,fulfilled,denied,externalNetwork:0},null,2));
    console.log('PASS: baseline Firebase SDK session restored by candidate; default app/config/raw storage preserved; production mocks absent; all requests memory-only');
} finally {await browser.close();}
