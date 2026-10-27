import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
function context(){const c={APP_ENV:{isDevelopment:false}};c.window=c;vm.createContext(c);vm.runInContext(fs.readFileSync(new URL('../js/config.js',import.meta.url),'utf8'),c);return c;}
test('legacy public flags cannot expose any additional venue without new approval',()=>{
 const c=context();c.centerVisibility=c.normalizeCenterVisibility({'能力':true,'능동':true,'동부':true,'원도심':true});c.isCenterOpen=true;
 for(const id of ['능동','동부','원도심'])assert.equal(c.isPublicCenter(id),false);
 assert.equal(c.isPublicCenter('국제'),true);
 c.centerPublicationApprovals={'능동':'true','동부':1};for(const id of ['능동','동부','원도심'])assert.equal(c.isPublicCenter(id),false);
 c.centerPublicationApprovals={'동부':true};assert.equal(c.isPublicCenter('동부'),true);assert.equal(c.isPublicCenter('능동'),false);
});
test('public launch requires affirmative confirmation and exact names for all selected venues',()=>{
 const c=context(),next={'국제':true,'능동':true,'동부':true};let prompts=0;
 c.alert=()=>{};c.confirm=()=>false;c.prompt=()=>{prompts++;return '능동, 동부 공개';};assert.equal(c.confirmCenterPublication(next),false);assert.equal(prompts,0);
 c.confirm=()=>true;c.prompt=()=>null;assert.equal(c.confirmCenterPublication(next),false);
 c.prompt=()=> '능동 공개';assert.equal(c.confirmCenterPublication(next),false);
 c.prompt=()=> '능동, 동부 공개';assert.equal(c.confirmCenterPublication(next),true);
});
test('canceled launch exits settings save before all database writes and side effects',async()=>{
 for(const answer of [null,'wrong']){
  const c=context();let writes=0;const button={innerText:'저장하기',disabled:false};
  c.readCenterVisibilitySettings=()=>({'국제':true,'능동':true});c.confirm=()=>true;c.prompt=()=>answer;c.alert=()=>{};
  c.document={getElementById:()=>button};c.db={collection:()=>{writes++;throw Error('Must not write');}};
  vm.runInContext(fs.readFileSync(new URL('../js/admin-settings.js',import.meta.url),'utf8'),c);await c.saveSet();
  assert.equal(writes,0);assert.equal(button.disabled,false);assert.equal(button.innerText,'저장하기');
 }
});
test('closing or retaining an already-approved venue needs no publication prompt',()=>{
 const c=context();c.centerVisibility={'능동':true};c.centerPublicationApprovals={'능동':true};c.confirm=()=>{throw Error('Unexpected prompt');};
 assert.equal(c.confirmCenterPublication({'국제':true,'능동':true}),true);assert.equal(c.confirmCenterPublication({'국제':true,'능동':false}),true);
});
