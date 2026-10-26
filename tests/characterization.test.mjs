// These tests characterize current paths and latent defects, not confirmed live billing errors.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const read = file => fs.readFileSync(new URL('../js/'+file+'.js', import.meta.url),'utf8');
function sandbox() {
    const context = { prices:[[1000,2000],[3000,4000],[5000,6000],[7000,8000]], HOLIDAYS:{},
        currentUser:{isCitizen:false}, Date, Math, Number, Map, Set,
        document:{addEventListener(){}}, addEventListener(){} };
    context.window=context; vm.createContext(context);
    vm.runInContext(read('booking-helpers'),context);
    vm.runInContext(read('my-reservations'),context);
    return context;
}
test('REGRESSION: unequal synthetic tariffs select weekday day/night matrix rows', async () => {
    const c=sandbox();
    assert.equal(await c.isWeekendOrHoliday('2026-11-02'),false);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',10,false),2000);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',20,false),4000);
});
test('CURRENT PATH: seasonal night boundary applies; booking amount remains matrix based', () => {
    const c=sandbox(); c.seasonalPricings=[{start:'2026-01-01',end:'2026-12-31',nightStart:18,dayPrice:111,nightPrice:222}];
    assert.equal(c.getConfiguredPriceInfo('2026-11-02',18).nightPrice,222);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',18,false),4000);
});
test('CURRENT DEFECT: refund changes when current citizenship or current tariff changes', () => {
    const c=sandbox();
    const first=c.calcRefund('2030-11-04',10).amount;
    c.currentUser.isCitizen=true;
    assert.notEqual(c.calcRefund('2030-11-04',10).amount,first);
    c.prices[0][0]=999;
    assert.equal(c.calcRefund('2030-11-04',10).amount,999);
});
test('CURRENT DEFECT: two nontransactional daily checks each allow three new slots despite combined overflow', async () => {
    const c=sandbox(); c.isAdmin=false;
    c.db={collection:()=>({where(){return this;},get:async()=>({forEach(fn){[7,8,9].forEach(time=>fn({data:()=>({court:1,time})}));}})})};
    await Promise.all([c.validateDailyReservationLimits({phone:'000',date:'2026-11-02',slots:[10,11,12].map(time=>({court:2,time}))}),
        c.validateDailyReservationLimits({phone:'000',date:'2026-11-02',slots:[13,14,15].map(time=>({court:2,time}))})]);
    // Both independently pass the existing check. Desired combined outcome is tracked separately.
});
test('CURRENT DEFECT: successful card callback invokes save only after payment, with no compensation on save rejection', async () => {
    const calls=[];
    const c={ isAdmin:false,useCardPay:true,currentUser:{name:'Synthetic',phone:'000'},currentPayMethod:'PAY',selected:[{c:1,t:10}],
        isAutomationPolicyEnabled:()=>false,alert:()=>{},fetch:async()=>({json:async()=>({success:true})}),
        document:{getElementById:id=>({innerText:'1000',value:'2030-11-04'})},
        IMP:{request_pay:(options,callback)=>{calls.push('payment-success');callback({success:true,imp_uid:'dev-paid'});}},
        calls, Date, Math };
    c.window=c;vm.createContext(c);vm.runInContext(read('booking-core'),c);
    c.isBookingPriceReady=()=>true; // Isolate the unchanged post-readiness payment orchestration.
    vm.runInContext('_recaptchaToken="dev"; saveBook = function(uid) { calls.push("save-rejected:"+uid); };',c);
    await c.doPay();
    assert.deepEqual(calls,['payment-success','save-rejected:dev-paid']);
});
