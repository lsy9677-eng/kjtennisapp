// Read-only source execution with synthetic settings and in-memory I/O. No Firebase/app startup.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const read=file=>fs.readFileSync(new URL('../'+file,import.meta.url),'utf8');
const html=read('index.html');
function between(source,start,end){const a=source.indexOf(start),b=source.indexOf(end,a);assert.ok(a>=0&&b>a);return source.slice(a,b);}
function sandbox() {
    const elements={isLocal:{checked:false},hiddenDate:{value:'2026-11-02'},txtPrice:{parentElement:{innerHTML:''}}};
    const c={prices:[[1000,1000],[3000,3000],[1000,1000],[3000,3000]],HOLIDAYS:{},selected:[],
        document:{addEventListener(){},getElementById:id=>elements[id]||null},addEventListener(){},
        safeSetInputValue(){},safeSetChecked(){},updateAdminUI(){},renderSeasonalList(){},
        currentUser:{isCitizen:false},console,seasonalPricingLoadPromise:null};
    c.window=c;vm.createContext(c);vm.runInContext(read('js/booking-helpers.js'),c);
    c.elements=elements;return c;
}
function season(start,end,nightStart,dayPrice=111,nightPrice=222){return {start,end,nightStart,dayPrice,nightPrice};}
test('equal weekday/weekend tariffs: amounts stay equal and Monday breakdown says weekday',()=>{
    const c=sandbox();
    for(const date of ['2026-11-02','2026-11-07']) {
        assert.equal(c.getMatrixPriceBySlot(date,10,false),1000);
        assert.equal(c.getMatrixPriceBySlot(date,20,false),3000);
    }
    c.selected=[{c:1,t:10}];c.calcPay();
    const output=c.elements.txtPrice.parentElement.innerHTML;
    assert.match(output,/1,000/);assert.match(output,/평일주간/);assert.doesNotMatch(output,/주말주간/);
});
test('unequal virtual tariffs: weekday/weekend amounts and breakdown match their own rows',()=>{
    const c=sandbox();c.prices=[[1000,1000],[3000,3000],[5000,5000],[7000,7000]];
    for(const [date,day,night,label] of [['2026-11-02',1000,3000,'평일'],['2026-11-07',5000,7000,'주말']]) {
        assert.equal(c.getMatrixPriceBySlot(date,10,false),day);
        assert.equal(c.getMatrixPriceBySlot(date,20,false),night);
        c.elements.hiddenDate.value=date;c.selected=[{c:1,t:10},{c:1,t:20}];c.calcPay();
        assert.match(c.elements.txtPrice.parentElement.innerHTML,new RegExp(label+'주간'));
        assert.match(c.elements.txtPrice.parentElement.innerHTML,new RegExp(label+'야간'));
    }
    c.HOLIDAYS['2026-11-02']='가상 공휴일';assert.equal(c.getMatrixPriceBySlot('2026-11-02',10,false),5000);
});
test('existing administrator table save duplicates each row into legacy citizen/noncitizen columns',async()=>{
    const c=sandbox();let saved;
    const values={btnSaveSet:{},setUseCard:{checked:true},admPhone:{value:'000'},setAdminName:{value:'가상'},setBank:{value:'가상은행'},setAcc:{value:'DEV'},setOpenCenter:{checked:true},setPw:{value:''}};
    c.document.getElementById=id=>values[id]||null;
    c.document.querySelectorAll=()=>[1000,3000,5000,7000].map(value=>({value:value.toLocaleString('en-US')}));
    c.db={collection:name=>{assert.equal(name,'settings');return {doc:id=>{assert.equal(id,'global');return {set:async data=>{saved=data;}};}};}};
    c.alert=()=>{};c.closeModal=()=>{};c.loadConfig=()=>{};
    vm.runInContext(read('js/admin-settings.js'),c);await c.saveSet();
    assert.deepEqual(Array.from(saved.prices),[1000,1000,3000,3000,5000,5000,7000,7000]);
});
test('global settings restore all four tariff rows and existing night threshold',()=>{
    const c=sandbox();c.loadSeasonalPricings=()=>{};
    vm.runInContext(between(html,'    function applyGlobalConfigDoc(doc) {','function loadConfig('),c);
    c.applyGlobalConfigDoc({exists:true,data:()=>({prices:[1000,1000,3000,3000,5000,5000,7000,7000],nightStartHour:18})});
    assert.equal(c.prices[0][0],1000);assert.equal(c.prices[2][0],5000);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',17,false),1000);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',18,false),3000);
});
test('seasonal night threshold overrides global and start hour is included; tariff amounts remain matrix based',()=>{
    const c=sandbox();c.nightStartHour=19;c.seasonalPricings=[season('2026-11-01','2026-11-30',18)];
    assert.equal(c.getConfiguredPriceInfo('2026-11-02',17).isNight,false);
    assert.equal(c.getConfiguredPriceInfo('2026-11-02',18).isNight,true);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',18,false),3000);
    assert.equal(c.getConfiguredPriceInfo('2026-12-01',18).isNight,false);
});
test('season boundaries include both dates; adjacent and explicit cross-year ranges match selected date',()=>{
    const c=sandbox();c.seasonalPricings=[season('2026-11-01','2026-11-30',17),season('2026-12-01','2027-02-28',18)];
    assert.equal(c.getConfiguredPriceInfo('2026-10-31',17).nightStart,19);
    assert.equal(c.getConfiguredPriceInfo('2026-11-01',17).nightStart,17);
    assert.equal(c.getConfiguredPriceInfo('2026-11-30',17).nightStart,17);
    assert.equal(c.getConfiguredPriceInfo('2026-12-01',17).nightStart,18);
    assert.equal(c.getConfiguredPriceInfo('2027-01-01',17).nightStart,18);
    assert.equal(c.getConfiguredPriceInfo('2027-03-01',17).nightStart,19);
});
test('midnight is hour zero of selected date, not continuation of previous night; threshold zero means all day night',()=>{
    const c=sandbox();c.seasonalPricings=[season('2026-11-01','2026-11-30',18),season('2026-12-01','2026-12-31',19)];
    assert.equal(c.getConfiguredPriceInfo('2026-11-30',23).isNight,true);
    assert.equal(c.getConfiguredPriceInfo('2026-12-01',0).isNight,false);
    assert.equal(c.getConfiguredPriceInfo('2026-12-01',0).nightStart,19);
    c.seasonalPricings=[season('2026-12-01','2026-12-31',0)];
    assert.equal(c.getConfiguredPriceInfo('2026-12-01',0).isNight,true);
    assert.equal(c.getConfiguredPriceInfo('2026-12-01',6).isNight,true);
});
test('overlapping ranges use first saved rule, gaps use global and reverse ranges never match',()=>{
    const c=sandbox();const a=season('2026-11-01','2026-12-01',17),b=season('2026-12-01','2026-12-31',18);
    c.seasonalPricings=[a,b];assert.equal(c.getConfiguredPriceInfo('2026-12-01',17).nightStart,17);
    c.seasonalPricings=[b,a];assert.equal(c.getConfiguredPriceInfo('2026-12-01',17).nightStart,18);
    c.seasonalPricings=[season('2026-12-31','2026-12-01',17)];
    assert.equal(c.getConfiguredPriceInfo('2026-12-15',18).nightStart,19);
});
test('split-pay amount path uses seasonal scalar amount separately from booking matrix',async()=>{
    const c=sandbox();c.seasonalPricings=[season('2026-11-01','2026-11-30',18)];
    assert.equal((await c.getPriceForDate('2026-11-02',18)).price,222);
    assert.equal(c.getMatrixPriceBySlot('2026-11-02',18,false),3000);
});
test('base config loader can resolve first; booking readiness separately awaits the seasonal fetch',async()=>{
    const c=sandbox();let release,calculated=0;
    c._configCache=null;c._configCacheTs=0;c._configCachePromise=null;c.CONFIG_TTL=1800000;
    c.seasonalPricings=[];c.calcPay=()=>{calculated++;};
    const pending=new Promise(resolve=>{release=resolve;});
    c.db={collection:()=>({doc:id=>({get:()=>id==='global'?Promise.resolve({exists:true,data:()=>({nightStartHour:19})}):pending})})};
    vm.runInContext(between(html,'async function loadSeasonalPricings() {','function renderSeasonalList()'),c);
    vm.runInContext(between(html,'    function applyGlobalConfigDoc(doc) {','// ▼▼▼ [신규] 요금 설정 관련 함수'),c);
    await c.loadConfig();
    assert.equal(c.getConfiguredPriceInfo('2026-11-02',18).isNight,false);
    release({exists:true,data:()=>({list:[season('2026-11-01','2026-11-30',18)]})});
    await pending;await new Promise(resolve=>setImmediate(resolve));
    assert.equal(c.getConfiguredPriceInfo('2026-11-02',18).isNight,true);
    assert.equal(calculated,0);
});
