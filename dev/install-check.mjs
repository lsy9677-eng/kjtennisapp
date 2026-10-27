import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
const browser=await chromium.launch({channel:'chrome',headless:true});
const results=[];
const android='Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';
const ios='Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
async function open(ua,{standalone=false,dark=false}={}){
 const context=await browser.newContext({userAgent:ua,viewport:{width:390,height:844},isMobile:true,hasTouch:true,colorScheme:'light',serviceWorkers:'block'});
 await context.route('**/*',r=>['4173','8080','9099','9199'].includes(new URL(r.request().url()).port)&&new URL(r.request().url()).hostname==='127.0.0.1'?r.continue():r.abort());
 await context.addInitScript(({standalone,dark})=>{localStorage.setItem('appBannerDismissed','true');if(standalone)Object.defineProperty(navigator,'standalone',{value:true});if(dark)localStorage.setItem('theme','dark');},{standalone,dark});
 const page=await context.newPage();page.on('pageerror',error=>{throw error;});
 await page.goto('http://127.0.0.1:4173/');await page.waitForFunction(()=>typeof requestAppInstall==='function'&&document.querySelectorAll('.head-court').length===8);await page.waitForTimeout(500);
 if(dark)await page.evaluate(()=>toggleDarkMode(true));
 return {context,page};
}
try{
 await mkdir('dev/artifacts/home-install',{recursive:true});
 for(const [name,ua] of [['ios-safari',ios],['android-chrome',android],['samsung',android.replace('Chrome/130','SamsungBrowser/28.0 Chrome/130')]]){
  const {context,page}=await open(ua);assert.equal(await page.locator('#appInstallBanner').isVisible(),true,'old banner dismissal must not hide new install flow');
  for(const width of [360,390]){await page.setViewportSize({width,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);const fits=await page.evaluate(()=>{const grid=document.getElementById('gridArea').getBoundingClientRect();return [...document.querySelectorAll('.head-court')].at(-1).getBoundingClientRect().bottom<=grid.bottom+1;});assert.ok(fits);}
  await page.locator('#btnHomeInstall').click();
  await page.waitForTimeout(250);
  const text=await page.locator('#modalAppInstall').innerText();assert.match(text,/홈 화면/);
  if(name==='ios-safari'){assert.match(text,/Safari/);assert.match(text,/공유/);assert.equal(await page.locator('#installStoreLink').isVisible(),false);}
  else assert.equal(await page.locator('#installStoreLink').isVisible(),true);
  if(name==='samsung')assert.match(text,/현재 페이지 추가/);
  await page.screenshot({path:'dev/artifacts/home-install/'+name+'.png'});
  await page.keyboard.press('Escape');assert.equal(await page.locator('#modalAppInstall').isVisible(),false);
  assert.equal(await page.evaluate(()=>document.activeElement?.id),'btnHomeInstall');
  await page.locator('.install-banner-close').click();assert.equal(await page.locator('#appInstallBanner').isVisible(),false);
  await page.reload();await page.waitForFunction(()=>typeof requestAppInstall==='function');assert.equal(await page.locator('#appInstallBanner').isVisible(),false);
  await page.evaluate(()=>requestAppInstall());assert.equal(await page.locator('#modalAppInstall').isVisible(),true,'settings entry stays available after dismissal');
  results.push({name,manualGuide:true,oldDismissalIgnored:true,sevenDayDismissal:true,courtsVisible:true});await context.close();
 }
 for(const outcome of ['accepted','dismissed']){
  const {context,page}=await open(android);
  await page.evaluate(outcome=>{const event=new Event('beforeinstallprompt',{cancelable:true});window.__installCalls=0;event.prompt=()=>{window.__installCalls++;return Promise.resolve();};event.userChoice=Promise.resolve({outcome});window.dispatchEvent(event);window.__prevented=event.defaultPrevented;},outcome);
  assert.equal(await page.evaluate(()=>__installCalls),0);assert.equal(await page.evaluate(()=>__prevented),true);
  await page.locator('#btnHomeInstall').click();await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>__installCalls),1);assert.equal(await page.locator('#appInstallBanner').isVisible(),false);
  await page.evaluate(()=>requestAppInstall());assert.equal(await page.evaluate(()=>__installCalls),1,'prompt cannot be reused');
  await page.evaluate(()=>window.dispatchEvent(new Event('appinstalled')));assert.equal(await page.locator('#appInstallBanner').isVisible(),false);assert.equal(await page.locator('#appInstallSettings').getAttribute('hidden'),'');
  results.push({nativePromptMock:outcome,userGestureRequired:true,singleUse:true,appInstalledHidesPromotion:true});await context.close();
 }
 const standalone=await open(ios,{standalone:true});assert.equal(await standalone.page.locator('#appInstallBanner').isVisible(),false);assert.equal(await standalone.page.locator('#appInstallSettings').getAttribute('hidden'),'');await standalone.context.close();
 const dark=await open(ios,{dark:true});await dark.page.locator('#btnHomeInstall').click();await dark.page.screenshot({path:'dev/artifacts/home-install/ios-dark.png'});assert.equal(await dark.page.locator('#modalAppInstall .install-guide').evaluate(el=>getComputedStyle(el).backgroundColor),'rgb(23, 35, 56)');await dark.context.close();
 await writeFile('dev/artifacts/home-install/result.json',JSON.stringify({passed:true,results,standaloneHidden:true,darkGuide:true,nativeInstallCompletedOnPhysicalDevices:false},null,2));
 console.log(JSON.stringify({passed:true,results,standaloneHidden:true,darkGuide:true,physicalDevicesTested:false}));
}finally{await browser.close();}
