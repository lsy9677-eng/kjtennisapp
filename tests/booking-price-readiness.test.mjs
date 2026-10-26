import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const read=file=>fs.readFileSync(new URL('../'+file,import.meta.url),'utf8');
const html=read('index.html');
const loader=html.slice(html.indexOf('var seasonalPricingLoadPromise'),html.indexOf('function renderSeasonalList()'));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const season={start:'2026-11-01',end:'2026-11-30',nightStart:18,dayPrice:111,nightPrice:222};
const config={exists:true,data:()=>({prices:[1000,1000,3000,3000,5000,5000,7000,7000]})};
function fixture({globalRead=async()=>config,seasonRead=async()=>({exists:true,data:()=>({list:[season]})}),admin=false}={}) {
    const calls={season:0,external:0,alerts:[],confirm:0};
    const elements={hiddenDate:{value:'2026-11-02'},isLocal:{checked:false},txtPrice:{innerText:'9,999'},
        btnDoPay:{style:{},disabled:false},bookingPriceStatus:{textContent:''},chkAutomationPolicy:{checked:true}};
    elements.txtPrice.parentElement={set innerHTML(value){this.html=value;elements.txtPrice.innerText=/<span id="txtPrice"[^>]*>([^<]+)/.exec(value)?.[1]||'';}};
    const c={isAdmin:admin,currentUser:{name:'가상회원',phone:'000'},currentCenter:'국제',selected:[{c:1,t:18}],
        currentPayMethod:'PAY',prices:[[1000,1000],[3000,3000],[5000,5000],[7000,7000]],nightStartHour:19,seasonalPricings:[],HOLIDAYS:{},
        document:{getElementById:id=>elements[id]||null,addEventListener(){}},addEventListener(){},
        isAutomationPolicyEnabled:()=>true,renderSeasonalList(){},loadConfig:globalRead,
        db:{collection:name=>{assert.equal(name,'settings');return {doc:id=>{assert.equal(id,'seasonalPricing');return {get:options=>{assert.equal(options.source,'server');calls.season++;return seasonRead();}};}};}},
        fetch:async()=>{calls.external++;return {json:async()=>({success:true})};},IMP:{request_pay(){calls.external++;}},
        alert:message=>calls.alerts.push(message),confirm:()=>{calls.confirm++;return true;},console:{error(){}},
        Date,Number,Math,JSON};
    c.window=c;vm.createContext(c);vm.runInContext(read('js/booking-helpers.js'),c);vm.runInContext(read('js/booking-core.js'),c);vm.runInContext(loader,c);
    c.onRecaptchaSuccess('synthetic-only');return {c,elements,calls};
}
test('global then seasonal delay: no amount or payment until both reads complete, even after consent/captcha',async()=>{
    const global=deferred(),seasonal=deferred();
    const {c,elements,calls}=fixture({globalRead:()=>global.promise,seasonRead:()=>seasonal.promise});
    const loading=c.refreshBookingPrice();
    assert.equal(elements.btnDoPay.disabled,true);assert.equal(elements.txtPrice.innerText,'확인 중');assert.equal(calls.season,0);
    await c.doPay();assert.equal(calls.external,0);
    global.resolve(config);await tick();assert.equal(calls.season,1);
    c.onRecaptchaSuccess('synthetic');c.calcPay();await c.doPay();
    assert.equal(elements.btnDoPay.disabled,true);assert.equal(elements.txtPrice.innerText,'확인 중');assert.equal(calls.external,0);
    seasonal.resolve({exists:true,data:()=>({list:[season]})});
    assert.equal(await loading,true);assert.equal(elements.txtPrice.innerText,'3,000');assert.equal(elements.btnDoPay.disabled,false);
    assert.match(elements.txtPrice.parentElement.html,/평일야간/);
});
test('season server failure preserves no payable quote even with old seasons; retry can recover',async()=>{
    let fail=true;
    const {c,elements,calls}=fixture({seasonRead:async()=>{if(fail)throw Error('synthetic offline');return {exists:true,data:()=>({list:[season]})};}});
    c.seasonalPricings=[{...season,nightStart:17}];
    assert.equal(await c.refreshBookingPrice(),false);assert.equal(elements.txtPrice.innerText,'확인 불가');
    assert.equal(elements.btnDoPay.disabled,true);assert.match(elements.bookingPriceStatus.textContent,/다시 시도/);
    c.onRecaptchaSuccess('synthetic');c.calcPay();await c.doPay();assert.equal(calls.external,0);assert.equal(elements.btnDoPay.disabled,true);
    fail=false;assert.equal(await c.refreshBookingPrice(),true);assert.equal(elements.txtPrice.innerText,'3,000');assert.equal(elements.btnDoPay.disabled,false);
});
test('global load failure/missing tariff blocks card, transfer and administrator bypass',async()=>{
    for(const globalRead of [async()=>{throw Error('synthetic global failure');},async()=>({exists:false}),async()=>({exists:true,data:()=>({})})]) {
        for(const admin of [false,true]) {
            const {c,elements,calls}=fixture({globalRead,admin});
            assert.equal(await c.refreshBookingPrice(),false);
            c.currentPayMethod='TRANSFER';await c.doPay();c.currentPayMethod='PAY';await c.doPay();
            assert.equal(calls.external,0);assert.equal(calls.confirm,0);assert.equal(calls.season,0);assert.equal(elements.btnDoPay.disabled,true);
        }
    }
});
test('valid missing season document or empty list permits global cutoff; malformed list blocks payment',async()=>{
    for(const doc of [{exists:false},{exists:true,data:()=>({list:[]})}]) {
        const {c,elements}=fixture({seasonRead:async()=>doc});
        assert.equal(await c.refreshBookingPrice(),true);assert.equal(elements.txtPrice.innerText,'1,000');assert.equal(elements.btnDoPay.disabled,false);
    }
    const {c,elements,calls}=fixture({seasonRead:async()=>({exists:true,data:()=>({list:{invalid:true}})})});
    assert.equal(await c.refreshBookingPrice(),false);await c.doPay();assert.equal(calls.external,0);assert.equal(elements.btnDoPay.disabled,true);
});
test('concurrent seasonal reads share one server request and return the same list',async()=>{
    const pending=deferred();const {c,calls}=fixture({seasonRead:()=>pending.promise});
    const one=c.loadSeasonalPricings(),two=c.loadSeasonalPricings();await tick();assert.equal(calls.season,1);
    pending.resolve({exists:true,data:()=>({list:[season]})});assert.equal(await one,await two);
});
test('newer failed quote cannot be replaced by a late successful older request',async()=>{
    const pending=deferred();const {c,elements}=fixture();let n=0;
    c.loadConfig=()=>++n===1?pending.promise:Promise.reject(Error('newer failure'));
    const old=c.refreshBookingPrice();assert.equal(await c.refreshBookingPrice(),false);
    pending.resolve(config);assert.equal(await old,false);assert.equal(elements.btnDoPay.disabled,true);assert.equal(elements.txtPrice.innerText,'확인 불가');
});
test('changed reservation selection during load or after quote cannot initiate payment',async()=>{
    const pending=deferred();const {c,elements,calls}=fixture({seasonRead:()=>pending.promise});
    const loading=c.refreshBookingPrice();await tick();c.elements=elements;elements.hiddenDate.value='2026-12-01';
    pending.resolve({exists:true,data:()=>({list:[season]})});assert.equal(await loading,false);await c.doPay();assert.equal(calls.external,0);
    c.loadSeasonalPricings=async()=>[];assert.equal(await c.refreshBookingPrice(),true);
    elements.hiddenDate.value='2026-12-02';await c.doPay();assert.equal(calls.external,0);assert.equal(elements.btnDoPay.disabled,true);
});
test('ready pricing still requires consent and captcha for members; administrator still waits for pricing',async()=>{
    const {c,elements}=fixture();elements.chkAutomationPolicy.checked=false;
    assert.equal(await c.refreshBookingPrice(),true);assert.equal(elements.btnDoPay.disabled,true);
    elements.chkAutomationPolicy.checked=true;c.updateBookingSubmitAvailability();assert.equal(elements.btnDoPay.disabled,false);
    c.onRecaptchaExpired();assert.equal(elements.btnDoPay.disabled,true);
    const pending=deferred();const a=fixture({admin:true,seasonRead:()=>pending.promise});
    const loading=a.c.refreshBookingPrice();assert.equal(a.elements.btnDoPay.disabled,true);
    pending.resolve({exists:true,data:()=>({list:[season]})});await loading;assert.equal(a.elements.btnDoPay.disabled,false);
});
