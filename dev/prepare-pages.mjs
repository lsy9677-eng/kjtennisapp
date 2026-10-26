import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { root, resolveTool } from './tools.mjs';
import { localCSP } from './server.mjs';
import { copyPublicAssets } from './pages-assets.mjs';
export function isolatedToolEnvironment() {
    const artifacts=path.join(root,'dev/artifacts');
    // Never inherit service credentials, Node preload hooks or user Wrangler/Firebase configuration.
    const env={...process.env};
    for(const key of Object.keys(env))if(/SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|^DEBUG$|^NODE_OPTIONS$|^FIREBASE_|^CLOUDFLARE_|^CF_/i.test(key))delete env[key];
    return {...env,WRANGLER_SEND_METRICS:'false',WRANGLER_LOG_PATH:path.join(artifacts,'wrangler.log'),
        XDG_CONFIG_HOME:path.join(artifacts,'wrangler-config'),
        PATH:path.join(artifacts,'vclibs')+path.delimiter+env.PATH,
        NODE_OPTIONS:'--require='+JSON.stringify(path.join(root,'dev/offline-network.cjs'))};
}
export async function preparePages(development=true) {
    const dest=path.join(root,'dev/artifacts',development?'pages-development':'pages-production');
    if (path.dirname(dest)!==path.join(root,'dev/artifacts') || !['pages-development','pages-production'].includes(path.basename(dest))) throw new Error('Invalid local stage');
    await fs.rm(dest,{recursive:true,force:true});
    await fs.mkdir(dest,{recursive:true});
    // Allow list excludes node_modules, dev/, tests/, package files and credential files.
    await copyPublicAssets(dest);
    if(development) {
        await fs.mkdir(path.join(dest,'vendor'),{recursive:true});
        for(const name of ['app','auth','firestore','storage'])await fs.copyFile(resolveTool('node_modules/firebase/firebase-'+name+'-compat.js'),path.join(dest,'vendor/firebase-'+name+'-compat.js'));
        await fs.copyFile(resolveTool('node_modules/chart.js/dist/chart.umd.js'),path.join(dest,'vendor/chart.umd.js'));
        await fs.copyFile(resolveTool('node_modules/html2canvas/dist/html2canvas.min.js'),path.join(dest,'vendor/html2canvas.min.js'));
        const headers=await fs.readFile(path.join(dest,'_headers'),'utf8');
        await fs.writeFile(path.join(dest,'_headers'),headers.replace('/*','/*\n  Content-Security-Policy: '+localCSP+'\n  Cache-Control: no-store'));
    }
    const worker=path.join(root,'dev/artifacts/pages-worker');
    await fs.mkdir(worker,{recursive:true});
    await new Promise((resolve,reject)=>{
        const child=spawn(process.execPath,[resolveTool('node_modules/wrangler/bin/wrangler.js'),'pages','functions','build','functions','--outdir',worker,'--output-routes-path',path.join(worker,'routes.json'),'--compatibility-date','2026-10-26'],{cwd:root,env:isolatedToolEnvironment(),stdio:'inherit',windowsHide:true});
        child.once('error',reject);child.once('exit',code=>code===0?resolve():reject(new Error('Wrangler build failed: '+code)));
    });
    return {dest,worker:path.join(worker,'index.js')};
}
if(process.argv[1]===fileURLToPath(import.meta.url))console.log(await preparePages());
