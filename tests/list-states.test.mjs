import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';
const source=fs.readFileSync(new URL('../js/my-reservations.js',import.meta.url),'utf8');
function fixture(read=async()=>({docs:[]})){
 const element=()=>({style:{},dataset:{},innerHTML:'',setAttribute(k,v){this[k]=v;}});
 const elements={myResList:element(),batchCancelArea:element(),myStatsBox:element()},states=[];
 const c={currentUser:{uid:'mine',name:'Member',phone:'010-0000-0000'},console:{error(){}},document:{getElementById:id=>elements[id]},
 db:{collection:name=>{assert.equal(name,'reservations');return {where:(field,op,value)=>({get:()=>read(field,value)})};}},
 renderListState:(container,state)=>{states.push(state);container.state=state;},closeModal(){},goTab(){}};
 c.window=c;vm.createContext(c);vm.runInContext(source,c);return {c,elements,states};
}
const doc=(id,data)=>({id,data:()=>data});
test('a reservation query failure is rejected instead of being interpreted as an empty list',async()=>{
 const {c}=fixture(async()=>{throw Error('offline');});await assert.rejects(c._getMyReservationDocs(),/offline/);
});
test('one failed member lookup cannot silently produce a partial personal reservation list',async()=>{
 const owned=doc('owned',{uid:'mine'});const {c}=fixture(async field=>{if(field==='ownerId')throw Error('partial failure');return {docs:[owned]};});await assert.rejects(c._getMyReservationDocs(),/partial failure/);
});
test('successful personal lookups still deduplicate owned results and exclude other members',async()=>{
 const owned=doc('owned',{uid:'mine'}),other=doc('other',{uid:'other',phone:'different',name:'Other'});const {c}=fixture(async()=>({docs:[owned,other]}));assert.deepEqual(Array.from(await c._getMyReservationDocs(),d=>d.id),['owned']);
});
test('an empty list offers a next action and hides cancellation controls',async()=>{
 const {c,elements,states}=fixture();await c.loadMyResData(true);assert.equal(states.at(-1).kind,'empty');assert.equal(states.at(-1).actionLabel,'예약하러 가기');assert.equal(elements.batchCancelArea.style.display,'none');
});
test('canceled-only results are shown as empty rather than a blank list',async()=>{
 const {c,states}=fixture();c._getMyReservationDocs=async()=>[doc('canceled',{status:'CANCELED',date:'2099-01-01'})];await c.loadMyResData(true);assert.equal(states.at(-1).kind,'empty');
});
test('a failed list can retry without exposing raw exception details',async()=>{
 const {c,states}=fixture();let failed=true;c._getMyReservationDocs=async()=>{if(failed)throw Error('private synthetic error');return [];};await c.loadMyResData(true);assert.equal(states.at(-1).kind,'error');assert.ok(!states.at(-1).detail.includes('private'));failed=false;await states.at(-1).action();assert.equal(states.at(-1).kind,'empty');
});
test('late results from an older tab cannot replace the latest tab state',async()=>{
 const {c,states}=fixture();let resolve,reads=0;c._getMyReservationDocs=()=>++reads===1?new Promise(r=>resolve=r):Promise.resolve([]);const old=c.loadMyResData(true);await c.loadMyResData(false);const latest=states.at(-1);resolve([doc('old',{date:'2099-01-01',status:'BOOKED'})]);await old;assert.equal(states.at(-1),latest);assert.equal(latest.title,'지난 이용 내역이 없어요');
});

const boardSource=fs.readFileSync(new URL('../js/board.js',import.meta.url),'utf8');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
function commentsFixture(read){
 const states=[],list={dataset:{},setAttribute(){},replaceChildren(){}};
 const c={currPostId:'first',console:{error(){}},document:{getElementById:()=>list},renderListState:(_list,state)=>states.push(state),db:{collection:()=>({doc:id=>({collection:()=>({orderBy:()=>({get:()=>read(id)})})})})}};
 c.window=c;vm.createContext(c);vm.runInContext(boardSource,c);return {c,states,list};
}
test('a comment read failure offers retry and can recover to an empty state',async()=>{
 let fail=true;const {c,states}=commentsFixture(async()=>{if(fail)throw Error('synthetic failure');return {empty:true};});c.loadComments();await settle();assert.equal(states.at(-1).kind,'error');fail=false;states.at(-1).action();await settle();assert.equal(states.at(-1).kind,'empty');
});
test('a late comment response from a different post cannot overwrite the current post',async()=>{
 let release;const {c,states}=commentsFixture(id=>id==='first'?new Promise(r=>release=r):Promise.resolve({empty:true}));c.loadComments();c.currPostId='second';c.loadComments();await settle();const latest=states.at(-1);release({empty:true});await settle();assert.equal(states.at(-1),latest);
});
test('an earlier comment request on the same post cannot replace a newer request',async()=>{
 let release,calls=0;const {c,states}=commentsFixture(()=>++calls===1?new Promise(r=>release=r):Promise.resolve({empty:true}));c.loadComments();c.loadComments();await settle();const latest=states.at(-1);release({empty:true});await settle();assert.equal(states.at(-1),latest);
});
