import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
const simulatedSamsung=process.argv.includes('--samsung-simulated');
const forceDark=process.argv.includes('--force-dark');
const output='dev/artifacts/dark-mode'+(simulatedSamsung?'-samsung-simulated':'')+(forceDark?'-force-dark':'');
const browser=await chromium.launch({channel:'chrome',headless:true,args:forceDark?['--enable-features=WebContentsForceDark']:[]});
const results=[],errors=[];
try{
 const context=await browser.newContext({colorScheme:'dark',serviceWorkers:'block',timezoneId:'Asia/Seoul',...(simulatedSamsung?{userAgent:'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36',isMobile:true,hasTouch:true}:{})});
 await context.route('**/*',r=>['4173','8080','9099','9199'].includes(new URL(r.request().url()).port)&&new URL(r.request().url()).hostname==='127.0.0.1'?r.continue():r.abort());
 const page=await context.newPage();page.on('dialog',d=>d.dismiss());page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:4173/');await page.waitForFunction(()=>window.DEV_EVENTS?.some(e=>e.kind==='emulators-ready'));await page.waitForTimeout(500);
 assert.equal(await page.evaluate(()=>document.body.classList.contains('dark-mode')),false,'system dark must not enable app dark');
 assert.equal(await page.evaluate(()=>localStorage.getItem('theme')),null,'default must not become a saved override');
 await mkdir(output,{recursive:true});await page.setViewportSize({width:390,height:844});await page.screenshot({path:output+'/default-light.png'});
 assert.ok(await page.evaluate(()=>{const s=document.documentElement.style.colorScheme;return s.includes('light')&&s.includes('only');}));
 await page.emulateMedia({colorScheme:'light'});await page.waitForTimeout(60);assert.equal(await page.evaluate(()=>document.body.classList.contains('dark-mode')),false);
 await page.emulateMedia({colorScheme:'dark'});await page.waitForTimeout(60);assert.equal(await page.evaluate(()=>document.body.classList.contains('dark-mode')),false,'OS changes must not override default light');
 await page.evaluate(()=>toggleDarkMode(true));await page.emulateMedia({colorScheme:'light'});assert.equal(await page.evaluate(()=>document.body.classList.contains('dark-mode')),true);
 await page.reload();await page.waitForFunction(()=>document.querySelectorAll('.head-court').length===8);assert.equal(await page.evaluate(()=>document.body.classList.contains('dark-mode')),true);
 await page.waitForFunction(()=>window.DEV_EVENTS?.some(e=>e.kind==='emulators-ready'));await page.waitForTimeout(1000);
 await mkdir(output,{recursive:true});
 for(const width of [360,390,1440,1920]){
  await page.setViewportSize({width,height:width<400?844:900});
  await page.evaluate(()=>{
   document.getElementById('gridArea').scrollLeft=0;
   for(const [c,kind,label] of [[1,'booked','일반'],[2,'fixed','정기'],[3,'pending','대기']]){
    const cell=document.querySelector('.data-cell[data-c="'+c+'"]')||document.getElementById('c-'+c+'-6');
    cell.classList.remove('past');cell.innerHTML='<div class="orb '+kind+'-orb">'+label+'</div>';
   }
  });
  await page.waitForTimeout(100);
  const samples=await page.evaluate(()=>{
   const rgb=value=>{const n=value.match(/[\d.]+/g)?.map(Number)||[0,0,0];return [...n.slice(0,3),n[3]??1];};
   const luminance=rgb=>{const a=rgb.slice(0,3).map(v=>{const n=v/255;return n<=.04045?n/12.92:((n+.055)/1.055)**2.4;});return a[0]*.2126+a[1]*.7152+a[2]*.0722;};
   return ['#wbText','#wbTemp','.desktop-quick-title','#myReservationCard>div:first-child','#mobileBookingBar .sel-info','#mobileBookingBar .footer-mini-btn','#schTable .booked-orb','#schTable .fixed-orb','#schTable .pending-orb','#schTable .head-time','#calBody .cal-date.today.selected .cal-date-num'].map(selector=>{
    const el=document.querySelector(selector);if(!el)return {selector,missing:true};if(!el.getClientRects().length)return {selector,hidden:true};
    const style=getComputedStyle(el),color=rgb(style.color);let background=[0,0,0,0];
    for(let node=el;node;node=node.parentElement){const c=rgb(getComputedStyle(node).backgroundColor);if(c[3]===1){background=c;break;}}
    const a=luminance(color),b=luminance(background);return {selector,color:style.color,background:background.slice(0,3),contrast:(Math.max(a,b)+.05)/(Math.min(a,b)+.05)};
   });
  });
  for(const sample of samples){assert.ok(!sample.missing,sample.selector);if(!sample.hidden)assert.ok(sample.contrast>=4.5,JSON.stringify(sample));}
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:output+'/home-'+width+'.png'});results.push({width,samples});
 }
 await page.locator('#dev-admin-login').click();await page.waitForFunction(()=>isAdmin&&currentUser?.name==='테스트관리자');
 for(const [name,open,close] of [['settings',()=>openConf(),'modalSet'],['notice',()=>openNoticePopupAdmin(),'modalNoticePopupAdmin']]){
  await page.evaluate(open);await page.waitForTimeout(350);await page.screenshot({path:output+'/'+name+'.png'});await page.evaluate(id=>closeModal(id),close);
 }
 await page.evaluate(()=>{isAdmin=false;currentUser={name:'가상회원',email:'fixture@example.invalid',isCitizen:true};openUserSettings();});await page.waitForTimeout(300);await page.screenshot({path:output+'/member-settings.png'});
 await page.evaluate(()=>{closeModal('modalUserSettings');goTab('board');openWrite();});await page.waitForTimeout(300);await page.screenshot({path:output+'/board-write.png'});
 await page.evaluate(()=>{closeModal('modalWrite');toggleDarkMode(false);});await page.emulateMedia({colorScheme:'dark'});await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>document.body.classList.contains('dark-mode')),false,'saved light override wins over system');
 assert.deepEqual(errors,[]);await writeFile(output+'/result.json',JSON.stringify({passed:true,results,defaultLightIgnoresSystem:true,manualOverride:true,sessionRestore:true,pageErrors:errors,samsungPhysicalDeviceTested:false,samsungUserAgentSimulated:simulatedSamsung,chromiumForceDark:forceDark},null,2));
 console.log('PASS: default light ignores system, manual overrides, reload and main text contrast >=4.5 at four widths; modal screenshots captured; Samsung physical device not tested');
}finally{await browser.close();}
