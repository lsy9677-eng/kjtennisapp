import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { createPagesRuntime } from './pages-runtime.mjs';
const privateKey=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'pem',type:'pkcs8'});
const bindings={RECAPTCHA_SECRET:'synthetic-only',NAVER_CLIENT_ID:'synthetic-client',NAVER_CLIENT_SECRET:'synthetic-secret',
    NAVER_REDIRECT_URI:'https://tenniskj-app.pages.dev/naver-auth?action=callback',NAVER_STATE_SECRET:'synthetic-state',
    FIREBASE_PROJECT_ID:'demo-kjtennis-local',FIREBASE_CLIENT_EMAIL:'fixture@example.invalid',FIREBASE_PRIVATE_KEY:privateKey,
    KAKAO_REST_API_KEY:'synthetic-client',KAKAO_REDIRECT_URI:'https://tenniskj-app.pages.dev/kakao-auth?action=callback'};
async function dispatchBuffered(mf,url,options) {
    const response=await mf.dispatchFetch(url,options);
    // Fully consume workerd's proxy stream before disposing the runtime.
    const body=await response.arrayBuffer();
    return new Response([204,205,304].includes(response.status)?null:body,{status:response.status,headers:response.headers});
}
const runtime=await createPagesRuntime({bindings,outboundService:async request=>{
    // No pass-through: even production URL strings are evaluated entirely inside local workerd.
    if(request.url==='https://www.google.com/recaptcha/api/siteverify') {
        assert.match(await request.text(),/secret=synthetic-only/);
        return Response.json({success:true});
    }
    if(request.url==='https://kapi.kakao.com/v2/user/me')return Response.json({id:'fixture-kakao',properties:{nickname:'가상회원'},kakao_account:{email:'fixture@example.invalid',name:'가상회원',phone_number:'+82 00-0000-0000'}});
    throw new Error('Unexpected outbound request in fixture: '+request.url);
}});
try {
    const dispatch=(url,options)=>dispatchBuffered(runtime.mf,url,options);
    const checks=[];
    for(const [asset,type] of [['/','text/html'],['/js/environment.js','javascript'],['/css/app.bundle.css','text/css'],['/vendor/firebase-app-compat.js','javascript'],['/.well-known/assetlinks.json','application/json']]) {
        const response=await dispatch('http://127.0.0.1:4173'+asset);
        assert.equal(response.status,200,asset+' '+(response.status===200?'':await response.text()));assert.ok(response.headers.get('content-type')?.includes(type),asset);
        checks.push({asset,status:response.status,type:response.headers.get('content-type')});
    }
    const root=await dispatch('http://127.0.0.1:4173/');assert.match(root.headers.get('content-security-policy'),/connect-src/);
    for(const pathname of ['/naver-auth?action=start','/naver-auth?action=callback&code=fixture','/kakao-auth?action=start','/kakao-auth?action=callback&code=fixture','/kakao-auth?action=token','/verify-recaptcha']) {
        const res=await dispatch('http://127.0.0.1:4173'+pathname,{method:'POST',body:'{}',headers:{'Content-Type':'application/json'}});
        // Naver only exports GET; check method routing separately below.
        if(!pathname.startsWith('/naver-auth')){assert.equal(res.status,200);assert.equal((await res.json()).development,true);}
        const get=await dispatch('http://127.0.0.1:4173'+pathname);
        if(pathname!=='/verify-recaptcha'){assert.equal(get.status,200);assert.equal((await get.json()).development,true);}
    }
    const options=await dispatch('http://127.0.0.1:4173/verify-recaptcha',{method:'OPTIONS'});assert.equal(options.status,200);
    assert.equal(runtime.outbound.length,0,'Local handlers must never fetch externally');
    for(const host of ['http://unapproved.invalid','https://preview.tenniskj-app.pages.dev','http://localhost:9999']) {
        const res=await dispatch(host+'/kakao-auth?action=start');assert.equal(res.status,403);
    }
    // Exact production origin is a URL string passed into local dispatch, not a network destination.
    const prod='https://tenniskj-app.pages.dev';
    const productionCaptcha=await dispatch(prod+'/verify-recaptcha',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'synthetic-token'})});
    assert.deepEqual(await productionCaptcha.json(),{success:true});
    for(const [pathname,provider] of [['/naver-auth?action=start','https://nid.naver.com/'],['/kakao-auth?action=start','https://kauth.kakao.com/']]) {
        const res=await dispatch(prod+pathname,{redirect:'manual'});assert.equal(res.status,302);
        assert.ok(res.headers.get('location').startsWith(provider));
    }
    const kakao=await dispatch(prod+'/kakao-auth?action=token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({accessToken:'synthetic-token'})});
    const token=await kakao.json();assert.equal(kakao.status,200,JSON.stringify(token));assert.equal(token.development,undefined);assert.ok(token.customToken.split('.').length===3);
    assert.equal(runtime.outbound.length,2); // Both handled in memory, no external network.
    await fs.writeFile('dev/artifacts/pages-report.json',JSON.stringify({passed:true,checks,developmentOutbound:0,productionFixtureOutbound:runtime.outbound,externalNetwork:0,runtime:'Wrangler Pages bundle + Cloudflare workerd',productionCredentials:'none'},null,2));
    console.log('PASS: real local workerd static assets/headers/Functions/production branch fixtures; external network: 0');
} finally {await runtime.mf.dispose();}
// Production staging must preserve headers and exclude local tools/fixtures/vendor assets.
const production=await createPagesRuntime({development:false});
try {
    const response=await dispatchBuffered(production.mf,'https://tenniskj-app.pages.dev/');
    assert.equal(response.status,200);assert.equal(response.headers.has('content-security-policy'),false);
    assert.equal(await fs.readFile(production.built.dest+'/_headers','utf8'),await fs.readFile('_headers','utf8'));
    for(const relative of ['dev','tests','node_modules','package.json','.dev.vars','vendor'])
        await assert.rejects(fs.access(production.built.dest+'/'+relative));
    assert.deepEqual(production.outbound,[]);
    const report=JSON.parse(await fs.readFile('dev/artifacts/pages-report.json','utf8'));
    Object.assign(report,{productionStaticStagePassed:true,productionHeadersUnchanged:true,localToolFilesExcluded:true});
    await fs.writeFile('dev/artifacts/pages-report.json',JSON.stringify(report,null,2));
    console.log('PASS: production static stage/headers unchanged; development tools/fixtures excluded');
} finally {await production.mf.dispose();}
