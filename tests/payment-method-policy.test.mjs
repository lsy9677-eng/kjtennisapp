import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../js/booking-core.js',import.meta.url),'utf8');
function fixture(enabled) {
    const calls={pg:0,verify:0,saved:[]};
    const node=()=>({style:{},classList:{toggle(){}},innerText:'1000',value:'2030-11-04'});
    const nodes=Object.fromEntries(['mthPay','mthTransfer','transferInfo','txtPrice','hiddenDate','btnDoPay'].map(id=>[id,node()]));
    const c={useCardPay:enabled,currentPayMethod:'PAY',isAdmin:false,currentUser:{name:'가상',phone:'000'},selected:[{c:1,t:10}],bankName:'가상은행',bankAccount:'DEV-ONLY',
        document:{getElementById:id=>nodes[id]||null},isAutomationPolicyEnabled:()=>false,confirm:()=>true,alert(){},
        fetch:async()=>{calls.verify++;return {json:async()=>({success:true})};},IMP:{request_pay(options,callback){calls.pg++;callback({success:true,imp_uid:'dev-only'});}}};
    c.window=c;vm.createContext(c);vm.runInContext(source,c);
    c.isBookingPriceReady=()=>true;c.saveBook=uid=>calls.saved.push(uid);vm.runInContext('_recaptchaToken="synthetic"',c);
    return {c,nodes,calls};
}
test('card disabled: PAY selection becomes transfer and transfer saves without a PG call',async()=>{
    const {c,calls}=fixture(false);c.setPayMethod('PAY');assert.equal(c.currentPayMethod,'TRANSFER');
    await c.doPay();assert.deepEqual(calls.saved,['TRANSFER']);assert.equal(calls.pg,0);assert.equal(calls.verify,1);
});
test('card disabled: tampered method is blocked before verification, PG or reservation save',async()=>{
    const {c,nodes,calls}=fixture(false);c.currentPayMethod='PAY';await c.doPay();
    assert.deepEqual(calls,{pg:0,verify:0,saved:[]});assert.equal(c.currentPayMethod,'TRANSFER');assert.equal(nodes.mthPay.style.display,'none');
});
test('settings refresh from card enabled to disabled hides card and restores transfer selection',()=>{
    const {c,nodes}=fixture(true);c.setPayMethod('PAY');c.useCardPay=false;c.syncBookingPaymentAvailability();
    assert.equal(nodes.mthPay.style.display,'none');assert.equal(c.currentPayMethod,'TRANSFER');
});
test('explicitly enabled synthetic card setting retains the original PG callback path',async()=>{
    const {c,nodes,calls}=fixture(true);c.setPayMethod('PAY');c.syncBookingPaymentAvailability();
    assert.equal(nodes.mthPay.style.display,'block');assert.equal(c.currentPayMethod,'PAY');await c.doPay();
    assert.equal(calls.pg,1);assert.deepEqual(calls.saved,['dev-only']);
});

test('card enabled: explicit transfer selection survives settings sync and uses existing transfer verification/save',async()=>{
    const {c,nodes,calls}=fixture(true);c.setPayMethod('TRANSFER');c.syncBookingPaymentAvailability();
    assert.equal(nodes.mthPay.style.display,'block');assert.equal(c.currentPayMethod,'TRANSFER');
    await c.doPay();assert.deepEqual(calls,{pg:0,verify:1,saved:['TRANSFER']});
});

test('card disabled: transfer verification failure still prevents reservation save',async()=>{
    const {c,calls}=fixture(false);c.setPayMethod('TRANSFER');c.fetch=async()=>{calls.verify++;return {json:async()=>({success:false})};};
    await c.doPay();assert.deepEqual(calls,{pg:0,verify:1,saved:[]});
});
