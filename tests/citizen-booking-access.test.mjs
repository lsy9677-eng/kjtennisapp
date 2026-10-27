import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
function fixture(){const nodes={citizenBookingStatus:{},btnRefreshCitizenStatus:{}};const cells=Array.from({length:15},(_,offset)=>{const d=new Date();d.setDate(d.getDate()+offset);const id='cal-day-'+[d.getFullYear(),String(d.getMonth()+1).padStart(2,'0'),String(d.getDate()).padStart(2,'0')].join('-');return {id,disabled:true,classList:{toggle(_,value){cells[offset].disabled=value;}}};});const c={APP_ENV:{isDevelopment:false},currentUser:null,isAdmin:false,document:{addEventListener(){},getElementById:id=>nodes[id],querySelectorAll:()=>cells},setTimeout,clearTimeout};c.window=c;vm.createContext(c);vm.runInContext(fs.readFileSync(new URL('../js/config.js',import.meta.url),'utf8'),c);return {c,cells,nodes};}
test('citizen approval and revocation immediately update all rendered date permissions',()=>{
 const {c,cells}=fixture();c.syncBookingAccessUI();assert.equal(cells[6].disabled,false);assert.equal(cells[7].disabled,true);
 c.currentUser={isCitizen:true,verifStatus:'APPROVED'};c.syncBookingAccessUI();for(let i=0;i<14;i++)assert.equal(cells[i].disabled,false);assert.equal(cells[14].disabled,true);
 c.currentUser={isCitizen:false,verifStatus:'REJECTED'};c.syncBookingAccessUI();assert.equal(cells[7].disabled,true);
});
test('approved text alone cannot silently grant citizenship privileges',()=>{
 const {c,nodes}=fixture();c.currentUser={isCitizen:false,verifStatus:'APPROVED'};c.syncBookingAccessUI();assert.equal(c.getMemberBookingDays(),7);assert.match(nodes.citizenBookingStatus.textContent,/확인 필요/);
});
test('explicit status refresh reads only the signed-in user from server and makes no writes',async()=>{
 const {c,nodes}=fixture();c.currentUser={uid:'own',isCitizen:false};c.auth={currentUser:{uid:'own'}};let calls=0;
 c.db={collection:name=>{assert.equal(name,'users');return {doc:uid=>{assert.equal(uid,'own');return {get:async options=>{assert.equal(options.source,'server');calls++;return {exists:true,data:()=>({isCitizen:true,verifStatus:'APPROVED'})};}};}};}};c.updateBookingContext=()=>{};
 await c.refreshMyCitizenBookingStatus();assert.equal(calls,1);assert.equal(c.currentUser.isCitizen,true);assert.match(nodes.citizenBookingStatus.textContent,/14일/);
});
test('failed status lookup keeps existing confirmed privileges and reports the read failure',async()=>{
 const {c,nodes}=fixture();c.currentUser={uid:'own',isCitizen:true};c.auth={currentUser:{uid:'own'}};c.db={collection:()=>({doc:()=>({get:async()=>{throw Error('offline');}})})};await c.refreshMyCitizenBookingStatus();assert.equal(c.currentUser.isCitizen,true);assert.match(nodes.citizenBookingStatus.textContent,/확인하지 못/);assert.equal(nodes.btnRefreshCitizenStatus.disabled,false);
});
