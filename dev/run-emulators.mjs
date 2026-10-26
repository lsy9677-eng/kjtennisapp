import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { resolveTool, findJava, emulatorCache, root } from './tools.mjs';
import net from 'node:net';
async function freePort(port) {
    await new Promise((resolve,reject)=>{const server=net.createServer();server.once('error',()=>reject(new Error('Port already in use; refusing to touch another process: '+port)));server.listen(port,'127.0.0.1',()=>server.close(resolve));});
}
export async function startEmulators() {
    for (const port of [9099,8080,9199,4407,4507,9157]) await freePort(port);
    const java=findJava(), cli=resolveTool('node_modules/firebase-tools/lib/bin/firebase.js');
    const artifacts=path.join(root,'dev/artifacts'); fs.mkdirSync(artifacts,{recursive:true});
    const env={...process.env, CI:'true', FIREBASE_CLI_DISABLE_UPDATE_CHECK:'true', FIREBASE_EMULATORS_PATH:emulatorCache(),
        XDG_CONFIG_HOME:path.join(artifacts,'config'), JAVA_HOME:path.dirname(path.dirname(java)),
        PATH:path.dirname(java)+path.delimiter+process.env.PATH, TEMP:artifacts,TMP:artifacts,TMPDIR:artifacts };
    for(const key of Object.keys(env)) if(/SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|^DEBUG$|^FIREBASE_DEBUG$|^FIREBASE_PROJECT_ID$|^FIREBASE_CLIENT_EMAIL$/i.test(key)) delete env[key];
    const log=fs.openSync(path.join(artifacts,'emulators.log'),'w');
    const child=spawn(process.execPath,['dev/emulator-process.cjs',cli,'emulators:start','--project','demo-kjtennis-local','--config','dev/firebase.json','--only','auth,firestore,storage'],{cwd:root,env,windowsHide:true,stdio:['ignore',log,log,'ipc']});
    fs.closeSync(log);
    const stop=async()=>{
        if(child.exitCode!==null)return;
        const ended=new Promise(resolve=>child.once('exit',resolve));
        if(child.connected)child.send('shutdown');
        const timer=setTimeout(()=>{if(child.exitCode===null)spawnSync('taskkill',['/PID',String(child.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'});},10000);
        await ended;clearTimeout(timer);
    };
    try {
        for(let i=0;i<90;i++) {
            if(child.exitCode!==null)throw new Error('Emulator exited. Read dev/artifacts/emulators.log');
            try {
                const locator=await (await fetch('http://127.0.0.1:4407/',{signal:AbortSignal.timeout(500)})).json();
                if(locator.pid!==child.pid)throw new Error('Hub belongs to another process');
                await Promise.all([9099,8080,9199].map(port=>fetch('http://127.0.0.1:'+port+'/',{signal:AbortSignal.timeout(500)})));
                console.log('Repository JDK: '+java+'\nRepository CLI: '+cli+'\nReady: demo-kjtennis-local only');
                return {child,stop};
            }catch{}
            await new Promise(resolve=>setTimeout(resolve,500));
        }
        throw new Error('Emulator readiness timeout');
    } catch(err){await stop();throw err;}
}
if(process.argv[1]===path.join(root,'dev/run-emulators.mjs')) {
    const instance=await startEmulators();
    process.on('SIGINT',()=>instance.stop());process.on('SIGTERM',()=>instance.stop());
    instance.child.on('exit',code=>{process.exitCode=code||0;});
}
