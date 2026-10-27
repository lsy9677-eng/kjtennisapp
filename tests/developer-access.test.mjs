import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
function context(){const c={APP_ENV:{isDevelopment:false}};c.window=c;vm.createContext(c);vm.runInContext(fs.readFileSync(new URL('../js/config.js',import.meta.url),'utf8'),c);return c;}
test('a profile email or stored administrator flag cannot unlock developer tools',()=>{
 const c=context();c.currentUser={email:'canyone2@korea.com',isAdmin:true};c.isAdmin=true;
 assert.equal(c.isDeveloperAccount(),false);assert.equal(c.hasDeveloperAccess(),false);assert.equal(c.canSelectCenter('능동',true),false);
 c.auth={currentUser:{email:'admin@example.invalid',uid:'admin'}};assert.equal(c.isDeveloperAccount(),false);
 c.auth.currentUser={email:'canyone2@korea.com',uid:'owner'};assert.equal(c.isDeveloperAccount(),true);assert.equal(c.hasDeveloperAccess(),false);assert.equal(c.canSelectCenter('능동',true),false);
});
test('locked settings ignore injected visibility inputs',()=>{
 const c=context();c.document={querySelectorAll(){throw Error('Locked settings must not read editable inputs');}};
 assert.deepEqual(JSON.parse(JSON.stringify(c.readCenterVisibilitySettings())),{'국제':true,'능동':false,'동부':false,'원도심':false});
});
test('ordinary administrator saves do not overwrite developer publication fields',async()=>{
 const c=context();let saved;
 const values={btnSaveSet:{},setUseCard:{checked:false},admPhone:{value:''},setAdminName:{value:''},setBank:{value:''},setAcc:{value:''},setOpenCenter:{checked:true},setPw:{value:''}};
 c.document={getElementById:id=>values[id],querySelectorAll:()=>[]};c.db={collection:()=>({doc:()=>({set:async data=>saved=data})})};c.alert=()=>{};c.loadConfig=()=>{};c.closeModal=()=>{};
 vm.runInContext(fs.readFileSync(new URL('../js/admin-settings.js',import.meta.url),'utf8'),c);await c.saveSet();
 assert.ok(saved);for(const field of ['centerVisibility','centerPublicationApprovals','isCenterOpen'])assert.equal(Object.hasOwn(saved,field),false);
});
