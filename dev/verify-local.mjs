import { spawn } from 'node:child_process';
import { startEmulators } from './run-emulators.mjs';
const instance=await startEmulators();
function run(file) {
    return new Promise((resolve,reject)=>{
        const child=spawn(process.execPath,[file,...(file==='dev/browser-check.mjs'&&process.argv.includes('--pages')?['--pages']:[])],{stdio:'inherit',windowsHide:true});
        child.once('error',reject);
        child.once('exit',code=>code===0?resolve():reject(new Error(file+' exited '+code)));
    });
}
try {await run('dev/seed.mjs');await run('dev/browser-check.mjs');}
finally {await instance.stop();}
