import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {execFileSync} from 'node:child_process';
const source=file=>fs.readFileSync(new URL('../'+file,import.meta.url),'utf8').replace(/\r\n/g,'\n');
const original=file=>execFileSync('git',['show','3b5bb59:'+file],{encoding:'utf8'}).replace(/\r\n/g,'\n');
test('booking save/payment and reservation query implementation remain exactly unchanged',()=>{
    for(const file of ['js/booking-core.js','js/reservation-data.js'])assert.equal(source(file),original(file));
});
test('refund calculation is unchanged; only local SMS IO guards were added to its module',()=>{
    const stripped=source('js/my-reservations.js').replace(/if \(APP_ENV\.isDevelopment\) devEffect\('sms-mock', [^\n]+?\); else /g,'');
    assert.equal(stripped,original('js/my-reservations.js'));
    assert.equal(source('js/booking-helpers.js').replace("if (APP_ENV.isDevelopment) devEffect('sms-mock', smsLink); else ",''),original('js/booking-helpers.js'));
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
