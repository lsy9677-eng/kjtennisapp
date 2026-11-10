import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source = file => fs.readFileSync(new URL('../'+file, import.meta.url), 'utf8');
const deferred = () => { let resolve, reject; const promise = new Promise((a,b)=>{resolve=a;reject=b;}); return {promise,resolve,reject}; };
function memberFixture() {
    let reads=0, gate=deferred();
    const c={currentUser:{uid:'demo-one',phone:'01000000000',name:'Demo'},db:{collection:()=>({where:()=>({get:()=>{reads++;return gate.promise;}})})}};
    vm.createContext(c);vm.runInContext(source('js/my-reservations.js'),c);
    return {c,get reads(){return reads;},get gate(){return gate;},reset(){gate=deferred();}};
}
test('concurrent personal lists share all four legacy lookups; subsequent reads remain fresh',async()=>{
    const f=memberFixture(); const a=f.c._getMyReservationDocs(), b=f.c._getMyReservationDocs();
    assert.equal(f.reads,4); f.gate.resolve({docs:[{id:'synthetic',data:()=>({uid:'demo-one'})}]});
    assert.equal((await a).length,1);assert.equal((await b).length,1);
    f.reset();const next=f.c._getMyReservationDocs();assert.equal(f.reads,8);f.gate.resolve({docs:[]});assert.equal((await next).length,0);
});
test('personal read failures release the request and allow retry',async()=>{
    const f=memberFixture(), a=f.c._getMyReservationDocs(), b=f.c._getMyReservationDocs();
    f.gate.reject(Error('synthetic failure'));await assert.rejects(a);await assert.rejects(b);
    f.reset();const next=f.c._getMyReservationDocs();f.gate.resolve({docs:[]});await next;assert.equal(f.reads,8);
});
test('switching member while a read is pending never returns previous member data',async()=>{
    const f=memberFixture(), a=f.c._getMyReservationDocs();f.c.currentUser={uid:'demo-two'};
    f.gate.resolve({docs:[{id:'private',data:()=>({uid:'demo-one'})}]});assert.equal((await a).length,0);
});
test('invalidated personal request cannot return an old reservation list',async()=>{
    const f=memberFixture(),a=f.c._getMyReservationDocs(),old=f.gate;
    f.c._getMyReservationDocs.pending.clear();f.reset();const b=f.c._getMyReservationDocs();assert.equal(f.reads,8);
    f.gate.resolve({docs:[]});await b;old.resolve({docs:[{id:'stale',data:()=>({uid:'demo-one'})}]});assert.equal((await a).length,0);
});
function calendarFixture() {
    let reads=0,gate=deferred(),marks=0;
    const query={where(){return this;},get(){reads++;return gate.promise;}};
    const c={currentUser:{uid:'demo-one',phone:'01000000000'},currentCenter:'demo-center',isAdmin:false,viewDate:new Date(2026,10,1),_myReservedDatesCache:{},MY_RESERVED_DATES_TTL:900000,formatDateStrLocal:()=> '2027-02-28',db:{collection:()=>query},document:{getElementById:()=>({classList:{add(){marks++;}}})}};
    vm.createContext(c);vm.runInContext(source('js/calendar.js'),c);
    vm.runInContext(source('js/reservation-data.js').match(/function _invalidateMyReservedDatesCache[\s\S]*?\n    }/)[0],c);
    return {c,get reads(){return reads;},get gate(){return gate;},get marks(){return marks;},reset(){gate=deferred();}};
}
const snap={forEach:fn=>fn({data:()=>({date:'2026-11-11',status:'PENDING'})})};
test('calendar shares pending reads and keeps the existing successful cache',async()=>{
    const f=calendarFixture(),a=f.c.markMyReservedDates(),b=f.c.markMyReservedDates();assert.equal(f.reads,1);
    f.gate.resolve(snap);await Promise.all([a,b]);f.c.markMyReservedDates();assert.equal(f.reads,1);
});
test('calendar failures can retry and previous members cannot mark the current calendar',async()=>{
    const f=calendarFixture(),a=f.c.markMyReservedDates();f.gate.reject(Error('offline'));await a;
    f.reset();const b=f.c.markMyReservedDates();assert.equal(f.reads,2);f.c.currentUser={uid:'demo-two',phone:'different'};f.gate.resolve(snap);await b;assert.equal(f.marks,0);
});
test('invalidation discards pending calendar results, so old data cannot refill the cache',async()=>{
    const f=calendarFixture(),a=f.c.markMyReservedDates(),oldGate=f.gate;f.c._invalidateMyReservedDatesCache('demo-center','01000000000');
    f.reset();const b=f.c.markMyReservedDates();assert.equal(f.reads,2);f.gate.resolve(snap);await b;
    const cached=Object.values(f.c._myReservedDatesCache)[0];
    oldGate.resolve({forEach:()=>{throw Error('invalidated result must not be applied');}});await a;
    assert.equal(Object.values(f.c._myReservedDatesCache)[0],cached);
    assert.equal(Object.keys(f.c._myReservedDatesCache).length,1);
});
test('admin monitor defaults to bounded samples, offers the old range, and shares concurrent loads',async()=>{
    const html=source('index.html');const code=html.slice(html.indexOf('async function loadMacroMonitor('),html.indexOf('async function performMacroMonitorLoad('));
    const gate=deferred(),calls=[];const c={isAdmin:true,performMacroMonitorLoad:limit=>{calls.push(limit);return gate.promise;}};
    vm.createContext(c);vm.runInContext(code,c);const a=c.loadMacroMonitor(),b=c.loadMacroMonitor();assert.deepEqual(calls,[300]);gate.resolve();await Promise.all([a,b]);await c.loadMacroMonitor(1500);assert.deepEqual(calls,[300,1500]);c.isAdmin=false;await c.loadMacroMonitor();assert.equal(calls.length,2);
    assert.match(html,/onclick="loadMacroMonitor\(1500\)"/);assert.match(html,/7일 전체 활동을 보장하지/);
    assert.equal((html.match(/\.limit\(limit\)\.get\(\)/g)||[]).length,2);
});
