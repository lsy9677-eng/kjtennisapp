import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../js/booking-core.js',import.meta.url),'utf8');
const limited=()=>Object.assign(new Error('Server responded with status 429'),{code:'unknown'});
function fixture({failBefore=0,loseCommit=false,monitorFailure=false,existing}={}) {
    const rows=new Map(existing||[]),writes=[],logs=[],alerts=[],waits=[];
    let attempts=0;
    const nodes=Object.fromEntries(['hiddenDate','txtPrice','bkName','bkPhone','btnDoPay'].map(id=>[id,{value:'2030-11-04',innerText:'1000',style:{}}]));
    const c={Date,Math,Map,Number,String,Array,console:{warn(){},error(){}},
        isAdmin:false,currentCenter:'국제',currentUser:{name:'가상회원',phone:'000',uid:'synthetic-user'},auth:{currentUser:{uid:'synthetic-user'}},selected:[{c:2,t:10},{c:2,t:11}],
        document:{getElementById:id=>nodes[id]||null},navigator:{userAgent:'synthetic'},
        firebase:{firestore:{FieldValue:{serverTimestamp:()=>0}}},
        setTimeout(fn,ms){waits.push(ms);if(ms>=1000)queueMicrotask(fn);return 1;},
        alert:message=>alerts.push(message),confirm:()=>false,formatCourtTimeSummary:()=>'',createBookingRequestId:()=> 'request-one',getMacroClientId:()=> 'synthetic-client',
        buildSlotLockId:(...parts)=>parts.join('_'),logBookingAttempt:async meta=>logs.push(meta),checkBookingGuards:async()=>{},validateDailyReservationLimits:async()=>{},
        hasRecurringConflict:async()=>false,addRecurringOccupiedSlotsToMap:async()=>{},validateRequestedSlotPattern:()=>{},maybeAutoBlockUser:async()=>{if(monitorFailure)throw limited();},
        showSuccessAnimation(){},closeModal(){},_invalidateReservationsCache(){},_invalidateMyReservedDatesCache(){},scheduleLoadDB(){},drawCalendar(){},refreshTodayMyReservationCard(){},sendSmsToAdmin(){},
        db:{collection:()=>({doc:id=>({id}),where(){return this;},get:async()=>({forEach(){}})}),runTransaction:async operation=>{
            attempts++;if(attempts<=failBefore)throw limited();
            const pending=[];
            await operation({get:async ref=>({exists:rows.has(ref.id),data:()=>rows.get(ref.id)}),set:(ref,data)=>pending.push([ref.id,data])});
            for(const [id,data] of pending){rows.set(id,data);writes.push(id);}
            if(loseCommit&&pending.length) {loseCommit=false;throw limited();}
        }} };
    c.window=c;vm.createContext(c);vm.runInContext(source,c);
    c.isBookingPriceReady=()=>true;c.updateBookingSubmitAvailability=()=>{nodes.btnDoPay.disabled=c.bookingSaveInProgress||c.bookingPaymentInProgress;};
    return {c,rows,writes,logs,alerts,waits,nodes,attempts:()=>attempts};
}
test('member HTTP 429 before save retries with backoff and saves both pending slots once',async()=>{
    const f=fixture({failBefore:2});await f.c.saveBook('TRANSFER');
    assert.equal(f.attempts(),3);assert.equal(f.rows.size,2);assert.equal(f.writes.length,2);
    assert.ok(f.waits.includes(1000)||f.waits.some(n=>n>=1000&&n<1300));assert.ok(f.waits.some(n=>n>=2500&&n<2800));
    assert.equal(f.logs.filter(log=>log.result==='TRY').length,1);assert.equal(f.logs.filter(log=>log.result==='SUCCESS').length,1);
    for(const row of f.rows.values()){assert.equal(row.status,'PENDING');assert.equal(row.paymentUid,'TRANSFER');}
    assert.equal(f.nodes.btnDoPay.disabled,false);
});
test('lost commit response: retry recognizes only the same request without duplicate writes',async()=>{
    const f=fixture({loseCommit:true});await f.c.saveBook('TRANSFER');assert.equal(f.attempts(),2);assert.equal(f.writes.length,2);assert.equal(f.rows.size,2);assert.deepEqual(f.alerts,[]);
});
test('occupied slot belonging to another request is never overwritten after retry',async()=>{
    const id='국제_2030-11-04_2_10',other={status:'BOOKED',requestId:'other',uid:'another-user'};
    const f=fixture({failBefore:1,existing:[[id,other]]});await f.c.saveBook('TRANSFER');
    assert.equal(f.attempts(),2);assert.equal(f.writes.length,0);assert.equal(f.rows.get(id),other);assert.match(f.alerts[0],/선점/);
});
test('persistent 429 stops after three attempts, restores button and gives an actionable message',async()=>{
    const f=fixture({failBefore:9});await f.c.saveBook('TRANSFER');assert.equal(f.attempts(),3);assert.equal(f.writes.length,0);assert.match(f.alerts[0],/내 예약/);assert.doesNotMatch(f.alerts[0],/Server responded/);assert.equal(f.nodes.btnDoPay.disabled,false);
});
test('post-commit monitoring 429 cannot turn a saved member reservation into failure',async()=>{
    const f=fixture({monitorFailure:true});await f.c.saveBook('TRANSFER');assert.equal(f.rows.size,2);assert.equal(f.logs.filter(log=>log.result==='FAIL').length,0);assert.deepEqual(f.alerts,[]);
});
test('concurrent save submits only one request and captures its original center',async()=>{
    const f=fixture({failBefore:1});const first=f.c.saveBook('TRANSFER');f.c.currentCenter='다른 구장';await f.c.saveBook('TRANSFER');await first;
    assert.equal(f.logs.filter(log=>log.result==='TRY').length,1);assert.equal(f.writes.length,2);assert.ok([...f.rows.keys()].every(id=>id.startsWith('국제_')));
});
test('permission/validation errors and explicit daily quota failures are not automatically retried',async()=>{
    for(const error of [Object.assign(new Error('denied'),{code:'permission-denied'}),new Error('선점'),Object.assign(new Error('Daily quota exceeded'),{code:'resource-exhausted'})]){
        const f=fixture();let calls=0;f.c.db.runTransaction=async()=>{calls++;throw error;};await f.c.saveBook('TRANSFER');assert.equal(calls,1);assert.equal(f.writes.length,0);
    }
});
test('administrator saves retain BOOKED status',async()=>{
    const f=fixture();f.c.isAdmin=true;f.c.adminDefaultName='가상관리자';await f.c.saveBook('ADMIN');assert.equal(f.rows.size,2);for(const row of f.rows.values())assert.equal(row.status,'BOOKED');
});
