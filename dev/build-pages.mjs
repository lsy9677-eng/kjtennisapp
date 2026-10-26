import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { root, resolveTool } from './tools.mjs';
import { isolatedToolEnvironment } from './prepare-pages.mjs';
import { publicAssets, copyPublicAssets } from './pages-assets.mjs';

export async function buildPagesRelease() {
    const config=JSON.parse(await fs.readFile(path.join(root,'dev/pages-release-config.json'),'utf8'));
    if(config.projectName!=='tenniskj-app'||config.outputDirectory!=='dist')throw new Error('Unexpected release target');
    const output=path.resolve(root,config.outputDirectory);
    if(output!==path.join(root,'dist'))throw new Error('Release output escaped workspace');
    const artifacts=path.join(root,'dev/artifacts');await fs.mkdir(artifacts,{recursive:true});
    const temporary=await fs.mkdtemp(path.join(artifacts,'release-'));
    const stage=path.join(temporary,'public'),worker=path.join(temporary,'worker');
    await fs.mkdir(stage);await fs.mkdir(worker);await copyPublicAssets(stage);
    await new Promise((resolve,reject)=>{
        const child=spawn(process.execPath,[resolveTool('node_modules/wrangler/bin/wrangler.js'),'pages','functions','build','functions',
            '--outdir',worker,'--output-routes-path',path.join(worker,'routes.json'),'--compatibility-date',config.compatibilityDate],
            {cwd:root,env:isolatedToolEnvironment(),stdio:'inherit',windowsHide:true});
        child.once('error',reject);child.once('exit',code=>code===0?resolve():reject(new Error('Local Pages build failed: '+code)));
    });
    await fs.copyFile(path.join(worker,'index.js'),path.join(stage,'_worker.js'));
    await fs.copyFile(path.join(worker,'routes.json'),path.join(stage,'_routes.json'));
    const files=await listFiles(stage);
    const allowed=new Set([...publicAssets,'_worker.js','_routes.json']);
    if(files.length!==allowed.size||files.some(file=>!allowed.has(file)))throw new Error('Unexpected release file');
    // Validate the absolute output before replacing stale assets. Build failure leaves previous output intact.
    try { if((await fs.lstat(output)).isSymbolicLink()) throw new Error('Release output must not be a symlink/junction'); }
    catch(error) { if(error.code!=='ENOENT') throw error; }
    await fs.rm(output,{recursive:true,force:true});
    await fs.rename(stage,output);
    return {output,files,compatibilityDate:config.compatibilityDate,projectName:config.projectName};
}
export async function listFiles(directory) {
    const result=[];
    async function visit(current,prefix='') {
        for(const item of await fs.readdir(current,{withFileTypes:true})) {
            const relative=prefix+item.name;
            if(item.isDirectory())await visit(path.join(current,item.name),relative+'/');
            else if(item.isFile())result.push(relative);
            else throw new Error('Non-regular release asset: '+relative);
        }
    }
    await visit(directory);return result.sort();
}
if(process.argv[1]===fileURLToPath(import.meta.url))console.log(JSON.stringify(await buildPagesRelease(),null,2));
