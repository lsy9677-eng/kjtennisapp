// Local source review at an intercepted origin. No request is sent to the live app or Firebase.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';
const root=fileURLToPath(new URL('../',import.meta.url));
const output=path.join(root,'dev/artifacts/design-preview');await fs.mkdir(output,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true});
const results=[],blocked=[],errors=[];
try {
const context=await browser.newContext({serviceWorkers:'block'});
await context.route('**/*',async route=>{
 const req=route.request(),u=new URL(req.url());
 if(req.method()!=='GET'){blocked.push(u.origin);return route.abort();}
 if(u.hostname==='tenniskj-app.pages.dev'){
 const name=u.pathname==='/'?'index.html':u.pathname.slice(1);
 if(!/^(assets\/(neungdong|dongbu|oldtown)-map\.svg|index\.html|js\/[a-z-]+\.js|css\/app\.bundle\.css|manifest\.json|abc-(192|512)\.png|court_map\.jpg)$/.test(name))return route.fulfill({status:404,body:''});
 const contentType=name.endsWith('.svg')?'image/svg+xml':name.endsWith('.js')?'application/javascript':name.endsWith('.css')?'text/css':name.endsWith('.html')?'text/html':name.endsWith('.json')?'application/json':name.endsWith('.png')?'image/png':'image/jpeg';
 return route.fulfill({body:await fs.readFile(path.join(root,name)),contentType});
 }
 const sdk=u.pathname.match(/firebase-(app|auth|firestore|storage)-compat\.js$/);
 if(sdk)return route.fulfill({body:await fs.readFile(path.join(root,'node_modules/firebase/firebase-'+sdk[1]+'-compat.js')),contentType:'application/javascript'});
 if(u.hostname==='cdn.jsdelivr.net'&&u.pathname.endsWith('/chart.js'))return route.fulfill({body:await fs.readFile(path.join(root,'node_modules/chart.js/dist/chart.umd.js')),contentType:'application/javascript'});
 if(/\.js$/.test(u.pathname)||u.hostname.includes('recaptcha'))return route.fulfill({body:'',contentType:'application/javascript'});
 blocked.push(u.origin);return route.abort();
});
const page=await context.newPage();page.on('dialog',d=>{console.log('DIALOG',d.message());return d.dismiss();});page.on('pageerror',e=>errors.push(e.message));
await page.goto('https://tenniskj-app.pages.dev/',{waitUntil:'domcontentloaded'});
await page.waitForFunction(()=>typeof updateAdminUI==='function'&&typeof changeCenter==='function');
await page.evaluate(()=>{
 // Use in-memory data only. Existing production request transports are blocked above.
 loadDB=async()=>{drawGrid();};loadAllRes=()=>{};loadSeasonalPricings=async()=>[];
 currentUser=null;isAdmin=false;isCenterOpen=false;centerVisibility=null;
 const date=new Date();date.setDate(date.getDate()+1);document.getElementById('hiddenDate').value=formatDateStrLocal(date);
 updateAdminUI();drawCalendar();drawGrid();updateBookingContext();
 const demo=(c,t,cls,text)=>{const el=document.getElementById('c-'+c+'-'+t);if(el){el.classList.add(cls);el.innerHTML='<div class="orb '+cls+'-orb">'+text+'</div>';}};
 demo(1,10,'booked','예약');demo(2,11,'pending','대기');demo(3,12,'fixed','정기');
 document.getElementById('gridArea').scrollLeft=0;
});
assert.deepEqual(await page.locator('#centerSel option').evaluateAll(es=>es.map(e=>e.value)),['국제']);
for(const [name,width,height] of [['mobile',390,844],['small-mobile',360,780],['tablet',820,1180],['desktop',1440,1000]]){
 await page.setViewportSize({width,height});
 await page.evaluate(()=>{
  const demo=(c,t,cls,text)=>{const el=document.getElementById('c-'+c+'-'+t);if(el){el.classList.add(cls);el.innerHTML='<div class="orb '+cls+'-orb">'+text+'</div>';}};
  demo(1,10,'booked','예약');demo(2,11,'pending','대기');demo(3,12,'fixed','정기');
  document.getElementById('gridArea').scrollLeft=0;
 });await page.screenshot({path:path.join(output,name+'.png'),fullPage:true});
 const state=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,courts:document.querySelectorAll('.head-court').length}));assert.equal(state.scroll,state.width);results.push({name,...state});
}
await page.setViewportSize({width:390,height:844});
assert.equal(await page.locator('#calendarWrap').isVisible(),true);
await page.click('#btnCalendarFold');assert.equal(await page.locator('#calendarWrap').evaluate(e=>e.classList.contains('folded')),true);
await page.click('#btnCalendarFold');assert.equal(await page.locator('#calendarWrap').evaluate(e=>e.classList.contains('folded')),false);
await page.evaluate(()=>{isAdmin=true;hasDeveloperAccess=()=>true;updateAdminUI();});
assert.equal(await page.locator('#centerSel option').count(),4);
for(const [id,count] of [['능동',8],['원도심',4],['동부',7]]){
 await page.evaluate(()=>{selected=[{c:8,t:10}];document.getElementById('btnMainBook').disabled=false;});
 const previousDate=await page.locator('#hiddenDate').inputValue();
 await page.selectOption('#centerSel',id);
 assert.equal(await page.locator('.head-court').count(),count);
 assert.equal(await page.locator('.chk-bulk-court').count(),count);
 assert.equal(await page.locator('#hiddenDate').inputValue(),previousDate);
 assert.equal(await page.evaluate(()=>selected.length),0);
 assert.equal(await page.locator('#btnMainBook').isDisabled(),true);
 assert.equal(await page.locator('#bookingAdminPreview').evaluate(el=>el.hidden),false);
 assert.match(await page.locator('#centerSel option:checked').textContent(),/비공개/);
 await page.evaluate(()=>showMap(1));await page.waitForFunction(()=>document.getElementById('mapImg').complete&&document.getElementById('mapImg').naturalWidth>0);assert.equal(await page.locator('#mapEmpty').isVisible(),false);assert.equal(await page.locator('#highlightBox').isVisible(),id==='능동');await page.evaluate(()=>closeModal('modalMap'));
 results.push({venue:id,courts:count,selectionReset:true,datePreserved:true});
}
await page.evaluate(()=>{centerVisibility=normalizeCenterVisibility({'능동':true});centerPublicationApprovals={'능동':true};isAdmin=false;updateAdminUI();});
assert.deepEqual(await page.locator('#centerSel option').evaluateAll(es=>es.map(e=>e.value)),['국제','능동']);
assert.equal(await page.evaluate(()=>currentCenter),'국제');
await page.selectOption('#centerSel','능동');assert.equal(await page.locator('.head-court').count(),8);
await page.evaluate(()=>{centerVisibility=normalizeCenterVisibility({});updateAdminUI();});
assert.equal(await page.evaluate(()=>currentCenter),'국제');assert.equal(await page.locator('#centerSel option').count(),1);
// Save only one chosen venue to an in-memory settings document; no Firebase write.
const saved=await page.evaluate(async()=>{
 isAdmin=true;renderCenterVisibilitySettings();
 document.querySelector('[data-center-visibility="동부"]').checked=true;syncCenterVisibilityMaster();
 const captured=[];db.collection=()=>({doc:()=>({set:async data=>captured.push(data)})});
 loadConfig=async()=>{};window.confirm=()=>true;window.prompt=()=> '동부 공개';await saveSet();return captured[0];
});
assert.deepEqual(saved.centerVisibility,{'국제':true,'능동':false,'동부':true,'원도심':false});assert.deepEqual(saved.centerPublicationApprovals,saved.centerVisibility);assert.equal(saved.isCenterOpen,false);
await page.evaluate(()=>{renderCenterVisibilitySettings();openModal('modalSet');});
await page.waitForTimeout(350);
await page.screenshot({path:path.join(output,'venue-settings.png'),fullPage:true});
assert.deepEqual(errors.filter(message=>message!=='Failed to fetch'),[]);
console.log(JSON.stringify({results,savedVisibility:saved.centerVisibility,blockedRequests:blocked.length,pageErrors:errors},null,2));
await fs.writeFile(path.join(output,'verification.json'),JSON.stringify({results,savedVisibility:saved.centerVisibility,blockedRequests:blocked.length,pageErrors:errors},null,2));
}finally{await browser.close()}
