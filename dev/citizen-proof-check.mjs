// All assets are fulfilled from disk. Synthetic uploads/profile updates never reach a network.
import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {root} from './tools.mjs';
const html=await fs.readFile(path.join(root,'index.html'),'utf8');
const auth=await fs.readFile(path.join(root,'js/auth.js'),'utf8');
const css=await fs.readFile(path.join(root,'css/app.bundle.css'),'utf8');
const settings=html.slice(html.indexOf('<div class="modal-mask" id="modalUserSettings">'),html.indexOf('<!-- ▲▲▲',html.indexOf('<div class="modal-mask" id="modalUserSettings">')));
const bottom=html.slice(html.indexOf('<div aria-label="주요 메뉴" id="mobileBottomNav">'),html.indexOf('<script>',html.indexOf('<div aria-label="주요 메뉴" id="mobileBottomNav">')));
const compressor=html.slice(html.indexOf('    function compressImage('),html.indexOf('   /* [수정] 회원가입 함수',html.indexOf('    function compressImage(')));
const openSettings=html.slice(html.indexOf('function openSettings()'),html.indexOf('/* step5-auth-extracted: openUserSettings',html.indexOf('function openSettings()')));
const logout=auth.slice(auth.indexOf('    function doLogout()'),auth.indexOf('function openUserSettings()'));
const pageBody='<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>'+css+'</style><body>'+settings+bottom+'<script>window.openModal=id=>document.getElementById(id).style.display="flex";window.closeModal=id=>document.getElementById(id).style.display="none";window.syncBookingAccessUI=()=>{};window.setMobileNavActive=()=>{};window.chkAdmin=()=>{};window.isAdmin=false;window.currentUser={uid:"synthetic",name:"가상회원",phone:"01000000000",address:"가상 주소",proofUrl:"old"};window.__events=[];window.__alerts=[];window.__fail=false;window.confirm=()=>true;window.alert=x=>__alerts.push(x);window.auth={currentUser:{uid:"synthetic"},signOut:async()=>{__events.push("logout");}};window.storage={ref:()=>({child:()=>({put:async(blob,meta)=>{if(__fail)throw new Error("synthetic upload failure");if(blob.type!=="image/jpeg"||meta.contentType!=="image/jpeg")throw Error("Wrong JPEG");__events.push("upload");},getDownloadURL:async()=>"synthetic-url"})})};window.db={collection:()=>({doc:()=>({update:async data=>{__events.push("profile");window.__saved=data;}})})};window.deleteProofByUrl=async()=>__events.push("delete-old");window.appendCitizenAudit=async()=>__events.push("audit");</script><script>'+compressor+openSettings+logout+auth.slice(auth.indexOf('function citizenProofError'))+auth.slice(auth.indexOf('function openUserSettings()'),auth.indexOf('function citizenProofError'))+'</script></body></html>';
const browser=await chromium.launch({channel:'chrome',headless:true});
const output=path.join(root,'dev/artifacts/citizen-proof');await fs.mkdir(output,{recursive:true});
let externalRequestsSent=0;const results=[];
try {
 for(const width of [320,390,1440]){
  const context=await browser.newContext({viewport:{width,height:844},isMobile:width<500,hasTouch:width<500,serviceWorkers:'block'});
  await context.route('**/*',route=>{const req=route.request();if(req.url()==='https://fixture.invalid/')return route.fulfill({contentType:'text/html',body:pageBody});return route.abort();});
  const page=await context.newPage();await page.goto('https://fixture.invalid/');
  await page.locator('#mobileBottomNav [data-nav=settings]').click();
  await page.locator('#userSettingsProof').scrollIntoViewIfNeeded();
  const chooserPromise=page.waitForEvent('filechooser');await page.locator('#userSettingsProof').click();const chooser=await chooserPromise;
  await chooser.setFiles({name:'synthetic.png',mimeType:'image/png',buffer:Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jvWQAAAAASUVORK5CYII=','base64')});
  assert.match(await page.locator('#citizenProofUploadStatus').textContent(),/synthetic.png/);
  await page.evaluate(()=>__fail=true);await page.locator('#btnSaveUserSettings').click();await page.waitForFunction(()=>!saveUserSettingsInfo.pending);
  assert.match(await page.locator('#citizenProofUploadStatus').textContent(),/저장하지 못/);assert.equal(await page.locator('#userSettingsProof').evaluate(el=>el.files.length),1);
  await page.evaluate(()=>__fail=false);await page.locator('#btnSaveUserSettings').click();await page.waitForFunction(()=>!saveUserSettingsInfo.pending);
  assert.match(await page.locator('#citizenProofUploadStatus').textContent(),/신청 완료/);assert.equal(await page.evaluate(()=>__saved.verifStatus),'PENDING');assert.deepEqual(await page.evaluate(()=>__events),['upload','profile','delete-old','audit']);
  await page.locator('#btnUserSettingsLogout').scrollIntoViewIfNeeded();assert.equal(await page.locator('#btnUserSettingsLogout').evaluate(el=>{const r=el.getBoundingClientRect();return r.width>40&&r.height>=44&&el.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));}),true);
  await page.screenshot({path:path.join(output,'settings-'+width+'.png')});
  // Cancel invokes the real handler but preserves the session. Confirm then invokes signOut once.
  await page.evaluate(()=>window.confirm=()=>false);await page.locator('#btnUserSettingsLogout').click();assert.equal(await page.evaluate(()=>__events.includes('logout')),false);
  await page.evaluate(()=>{auth.signOut=()=>{__events.push('logout');return new Promise(()=>{});};window.confirm=()=>true;});await page.locator('#btnUserSettingsLogout').click();assert.equal(await page.evaluate(()=>__events.filter(x=>x==='logout').length),1);
  results.push({width,nativePicker:true,uploadFailureRetry:true,jpegConversion:true,pendingSaved:true,logoutReachable:true});await context.close();
 }
 await fs.writeFile(path.join(output,'result.json'),JSON.stringify({passed:true,engine:'Chromium with responsive touch viewports; not physical Safari',results,externalRequestsSent},null,2));console.log(JSON.stringify({passed:true,results,externalRequestsSent}));
} finally {await browser.close();}

