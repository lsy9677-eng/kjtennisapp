// Explicit installation command only. Runtime commands never download tools or read sibling apps.
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { root } from './tools.mjs';
const base=path.join(root,'dev/artifacts');
await fs.mkdir(base,{recursive:true});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function download(url, target, checksum) {
    try {
        const existing=await fs.readFile(target);
        if(!checksum || sha(existing)===checksum) {console.log('Verified existing: '+path.basename(target));return;}
        throw new Error('Existing file checksum mismatch; refusing overwrite: '+target);
    } catch(err) {if(err.code!=='ENOENT')throw err;}
    const response=await fetch(url,{signal:AbortSignal.timeout(180000)});
    if(!response.ok)throw new Error('Tool download failed: '+response.status+' '+url);
    const bytes=Buffer.from(await response.arrayBuffer());
    if(checksum && sha(bytes)!==checksum)throw new Error('Download checksum mismatch: '+url);
    await fs.mkdir(path.dirname(target),{recursive:true});
    await fs.writeFile(target,bytes,{flag:'wx'});
    console.log('Downloaded: '+path.basename(target));
}
function extract(archive,dest) {
    const result=spawnSync('powershell.exe',['-NoProfile','-Command','Expand-Archive -LiteralPath $env:KJ_TOOL_ARCHIVE -DestinationPath $env:KJ_TOOL_DEST'],{
        env:{...process.env,KJ_TOOL_ARCHIVE:archive,KJ_TOOL_DEST:dest},stdio:'inherit',windowsHide:true});
    if(result.status!==0)throw new Error('Tool extraction failed');
}
if(process.platform!=='win32'||process.arch!=='x64')throw new Error('Documented setup supports Windows x64 only.');
const lock=JSON.parse(await fs.readFile(path.join(root,'dev/tool-downloads.json'),'utf8'));
const javaDir=path.join(base,'java');
try {await fs.access(path.join(javaDir,lock.java.directory,'bin/java.exe'));console.log('Repository JDK exists');}
catch {const archive=path.join(base,'jdk21.zip');await download(lock.java.url,archive,lock.java.sha256);extract(archive,javaDir);}
const info=JSON.parse(await fs.readFile(path.join(root,'node_modules/firebase-tools/lib/emulator/downloadableEmulatorInfo.json'),'utf8'));
for(const key of ['firestore','storage']) {
    const item=info[key];
    if(!item.remoteUrl.startsWith('https://storage.googleapis.com/firebase-preview-drop/emulator/'))throw new Error('Unexpected emulator download origin');
    await download(item.remoteUrl,path.join(base,'emulators',item.downloadPathRelativeToCacheDir),item.expectedChecksumSHA256);
}
const vcDir=path.join(base,'vclibs');
try {await fs.access(path.join(vcDir,'VCRUNTIME140.dll'));console.log('Repository Windows DLLs exist');}
catch {const archive=path.join(base,'vclibs.zip');await download(lock.vclibs.url,archive,lock.vclibs.sha256);extract(archive,vcDir);}
// Playwright browser binaries are isolated to this repository, not the shared user browser cache.
const result=spawnSync(process.execPath,[path.join(root,'node_modules/playwright/cli.js'),'install','chromium'],{
    env:{...process.env,PLAYWRIGHT_BROWSERS_PATH:path.join(base,'browsers')},stdio:'inherit',windowsHide:true});
if(result.status!==0)throw new Error('Chromium installation failed');
console.log('Standalone local tools ready. No Firebase login or production credentials required.');
