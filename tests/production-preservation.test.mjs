import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {execFileSync} from 'node:child_process';
const source=file=>fs.readFileSync(new URL('../'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');
const original=file=>execFileSync('git',['show','3b5bb59:'+file],{encoding:'utf8'}).replace(/\r\n/g,'\n');
test('reservation policies, stored fields and payment-provider body remain unchanged around 429 recovery',()=>{
    assert.equal(source('js/reservation-data.js'),original('js/reservation-data.js'));
    const core=source('js/booking-core.js'),base=original('js/booking-core.js');
    const between=(text,start,end)=>text.slice(text.indexOf(start),text.indexOf(end,text.indexOf(start)));
    const normalizeCenter=text=>text.replace(/\bbookingCenter\b/g,'currentCenter');
    assert.equal(normalizeCenter(between(core,'        await validateDailyReservationLimits(attemptMeta);','        await runBookingTransactionWithRetry(')),between(base,'        await validateDailyReservationLimits(attemptMeta);','        await db.runTransaction('));
    assert.equal(normalizeCenter(between(core,'            // 2단계: 충돌 체크','        await logBookingAttempt({ ...attemptMeta, result: \'SUCCESS\'')),between(base,'            // 2단계: 충돌 체크','        await logBookingAttempt({ ...attemptMeta, result: \'SUCCESS\''));
    assert.equal(between(core,'        if(isAdmin && confirm','/* STEP 17 - reservation save').replace(/await saveBook\("(ADMIN|TRANSFER)"\)/g,'saveBook("$1")'),between(base,'        if(isAdmin && confirm','/* STEP 17 - reservation save'));
});
test('refund, cancellation and sharing logic remain unchanged outside list read/presentation changes',()=>{
    const stripped=source('js/my-reservations.js').replace(/if \(APP_ENV\.isDevelopment\) devEffect\('sms-mock', [^\n]+?\); else /g,'');
    const withoutListReadAndRendering = value => value
        .replace(/async function _getMyReservationDocs\(\) \{[\s\S]*?(?=function openMyResList\()/,'')
        .replace(/async function loadMyResData\(isUpcoming\) \{[\s\S]*?(?=async function openDutchPayModal\()/,'');
    assert.equal(withoutListReadAndRendering(stripped),withoutListReadAndRendering(original('js/my-reservations.js')));
    const helpers=source('js/booking-helpers.js');
    for(const fn of ['getSeasonalPricingMatch','getConfiguredPriceInfo','getMatrixPriceBySlot','getPriceForDate','calcPrice']){
        const start='function '+fn+'(';
        const segment=s=>{const a=s.indexOf(start);const b=s.indexOf('\n}',a)+2;return s.slice(a,b);};
        assert.equal(segment(helpers),segment(original('js/booking-helpers.js')),fn);
    }
});
test('production Firebase connector never touches emulator, persistence or SDK auth methods',()=>{
    const c={APP_ENV:{isDevelopment:false}};c.window=c;vm.createContext(c);vm.runInContext(source('js/firebase-environment.js'),c);
    c.connectDevelopmentEmulators(new Proxy({},{get(){throw new Error('Production SDK must be untouched');}}));
    assert.equal(c.devLogin,undefined);
});
test('production Firebase options match baseline and only development options use demo project',()=>{
    function evaluate(s,dev){const c={APP_ENV:{isDevelopment:dev,firebaseConfig:{projectId:'demo-kjtennis-local'}}};c.window=c;vm.createContext(c);vm.runInContext(s,c);return JSON.parse(JSON.stringify(c.firebaseConfig));}
    assert.deepEqual(evaluate(source('js/config.js'),false),evaluate(original('js/config.js'),false));
    assert.equal(evaluate(source('js/config.js'),true).projectId,'demo-kjtennis-local');
});
test('repository runtime tools contain no sibling application paths',()=>{
    for(const file of ['dev/tools.mjs','dev/run-emulators.mjs','dev/browser-check.mjs'])assert.doesNotMatch(source(file),/kimhaemach|openmachsystem|\.\.\/\.\.\//);
});
