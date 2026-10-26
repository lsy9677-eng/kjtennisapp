import { spawn } from 'node:child_process';
import { startEmulators } from './run-emulators.mjs';
const instance=await startEmulators();
function run(file) {
    return new Promise((resolve,reject)=>{
        const flags=file==='dev/browser-check.mjs'
            ? ['--pages','--transfer-only'].filter(flag=>process.argv.includes(flag))
            : file==='dev/seed.mjs'&&!process.argv.includes('--transfer-only')?['--card-enabled']:[];
        const child=spawn(process.execPath,[file,...flags],{stdio:'inherit',windowsHide:true});
        child.once('error',reject);
        child.once('exit',code=>code===0?resolve():reject(new Error(file+' exited '+code)));
    });
}
try {await run('dev/seed.mjs');await run('dev/browser-check.mjs');}
finally {await instance.stop();}
