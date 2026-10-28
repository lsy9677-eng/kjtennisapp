// Every request is fulfilled from local files or blocked. No live app/API request.
import {chromium} from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {root} from './tools.mjs';
const browser=await chromium.launch({channel:'chrome',headless:true});
const output=path.join(root,'dev/artifacts/calendar-header');await fs.mkdir(output,{recursive:true});
const results=[];
try {
 const context=await browser.newContext({serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const req=route.request(),u=new URL(req.url());
  if(req.method()!=='GET')return route.abort();
  if(u.origin==='https://tenniskj-app.pages.dev'){
   const name=u.pathname==='/'?'index.html':u.pathname.slice(1);
   if(!/^(index\.html|js\/[a-z-]+\.js|css\/app\.bundle\.css|manifest\.json|abc-(192|512)\.png|court_map\.jpg)$/.test(name))return route.fulfill({status:404,body:''});
   const contentType=name.endsWith('.html')?'text/html':name.endsWith('.js')?'application/javascript':name.endsWith('.css')?'text/css':name.endsWith('.json')?'application/json':name.endsWith('.png')?'image/png':'image/jpeg';
   return route.fulfill({body:await fs.readFile(path.join(root,name)),contentType});
  }
  const sdk=u.pathname.match(/firebase-(app|auth|firestore|storage)-compat\.js$/);
  if(sdk)return route.fulfill({body:await fs.readFile(path.join(root,'node_modules/firebase/firebase-'+sdk[1]+'-compat.js')),contentType:'application/javascript'});
  if(req.resourceType()==='script')return route.fulfill({body:'',contentType:'application/javascript'});
  return route.abort();
 });
 const page=await context.newPage();page.on('dialog',d=>d.dismiss());
 await page.goto('https://tenniskj-app.pages.dev/',{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>typeof updateAdminUI==='function'&&typeof mvMonth==='function');
 await page.evaluate(()=>{loadDB=async()=>{};loadAllRes=()=>{};currentUser=null;});
 for(const admin of [false,true])for(const width of [320,360,390,820,1100,1440,1920]){
  await page.setViewportSize({width,height:900});
  await page.evaluate(admin=>{isAdmin=admin;updateAdminUI();viewDate=new Date(2030,0,1);drawCalendar();},admin);
  if(admin)await page.locator('#btnBatchExec').evaluate(el=>{el.style.display='inline-block';});
  for(const label of ['이전 달','다음 달']){
   const fits=await page.getByRole('button',{name:label,exact:true}).evaluate(el=>{
    const r=el.getBoundingClientRect(),p=document.getElementById('calendarWrap').getBoundingClientRect();
    return r.width>=24&&r.left>=p.left&&r.right<=p.right&&r.top>=p.top&&r.bottom<=p.bottom&&el.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));
   });assert.equal(fits,true,`${label}: width=${width} admin=${admin}`);
  }
  await page.getByRole('button',{name:'다음 달',exact:true}).click();assert.equal(await page.evaluate(()=>viewDate.getMonth()),1);
  await page.getByRole('button',{name:'이전 달',exact:true}).click();assert.equal(await page.evaluate(()=>viewDate.getMonth()),0);
  assert.equal(await page.locator('#calTitle').evaluate(el=>el.scrollWidth<=el.clientWidth),true,'Month title must not wrap/clip');
  assert.equal(await page.locator('#calBody').evaluate(el=>el.clientHeight>80),true,'Calendar remains scrollable');
  results.push({admin,width,previousAndNextClickable:true});
  console.log('PASS: calendar navigation',JSON.stringify({admin,width}));
  if(admin&&[360,1920].includes(width))await page.screenshot({path:path.join(output,'admin-'+width+'.png')});
 }
 await page.locator('#btnCalendarFold').click();
 assert.equal(await page.locator('#calendarWrap').evaluate(el=>el.classList.contains('folded')),true);
 await page.locator('#btnCalendarFold').click();
 assert.equal(await page.locator('#calendarWrap').evaluate(el=>el.classList.contains('folded')),false);
 await fs.writeFile(path.join(output,'result.json'),JSON.stringify({passed:true,results,externalRequestsSent:0},null,2));
 console.log(JSON.stringify({passed:true,cases:results.length,externalRequestsSent:0}));
}finally{await browser.close();}
