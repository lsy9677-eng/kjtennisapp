import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const config=fs.readFileSync(new URL('../js/config.js',import.meta.url),'utf8');
function context(){const c={APP_ENV:{isDevelopment:false}};c.window=c;vm.createContext(c);vm.runInContext(config,c);return c;}
test('venue metadata has international 8, Neungdong 8, old town 4 and Dongbu 7 courts',()=>{
 const c=context();for(const [id,count] of [['국제',8],['능동',8],['원도심',4],['동부',7]])assert.equal(c.CENTERS[id].courts,count);
});
test('new venues are hidden from members and ordinary administrators',()=>{
 const c=context();for(const id of ['능동','원도심','동부']){assert.equal(c.canSelectCenter(id,false),false);assert.equal(c.canSelectCenter(id,true),false);}assert.equal(c.isPublicCenter('국제'),true);assert.equal(c.canSelectCenter('unknown',true),false);
});
test('a legacy all-open flag cannot accidentally launch newly prepared venues',()=>{
 const c=context();c.isCenterOpen=true;assert.equal(c.isPublicCenter('국제'),true);for(const id of ['능동','동부','원도심'])assert.equal(c.isPublicCenter(id),false);
});
test('partial rollout opens only the chosen venue even if legacy all-open flag is true',()=>{
 const c=context();c.isCenterOpen=true;c.centerPublicationApprovals={'능동':true};c.centerVisibility=c.normalizeCenterVisibility({'능동':true});assert.equal(c.isPublicCenter('능동'),true);assert.equal(c.isPublicCenter('동부'),false);assert.equal(c.isPublicCenter('원도심'),false);assert.equal(c.isPublicCenter('국제'),true);
});
test('international stays public and malformed per-venue values cannot enable another venue',()=>{
 const c=context();c.centerVisibility=c.normalizeCenterVisibility({'국제':false,'능동':'true','동부':1,'원도심':false});assert.equal(c.isPublicCenter('국제'),true);for(const id of ['능동','동부','원도심'])assert.equal(c.isPublicCenter(id),false);
});
test('a saved closed map can override the old all-open flag and does not mutate its source',()=>{
 const c=context(),input={'능동':false,'동부':false,'원도심':false};c.isCenterOpen=true;c.centerVisibility=c.normalizeCenterVisibility(input);for(const id of Object.keys(input))assert.equal(c.isPublicCenter(id),false);assert.deepEqual(input,{'능동':false,'동부':false,'원도심':false});
});
test('venue diagrams keep unconfirmed court numbers unset and use separate assets',()=>{
 const c=context();assert.equal(c.CENTERS['국제'].img,'court_map.jpg');assert.equal(Object.keys(c.CENTERS['능동'].pos).length,8);for(const id of ['동부','원도심'])assert.equal(Object.keys(c.CENTERS[id].pos).length,0);for(const id of ['능동','동부','원도심']){assert.notEqual(c.CENTERS[id].img,'court_map.jpg');assert.ok(fs.existsSync(new URL('../'+c.CENTERS[id].img,import.meta.url)));}
});
