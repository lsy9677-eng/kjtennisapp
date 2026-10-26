import path from 'node:path';
import { root } from './tools.mjs';
import { isolatedToolEnvironment, preparePages } from './prepare-pages.mjs';
export async function createPagesRuntime({port=0,development=true,bindings={},outboundService}={}) {
    process.env.PATH=isolatedToolEnvironment().PATH;
    const {Miniflare,convertV4MiniflareOptions}=await import('miniflare');
    const built=await preparePages(development);
    const outbound=[];
    const options=convertV4MiniflareOptions({host:'127.0.0.1',port,name:'kj-pages-local',modules:true,scriptPath:built.worker,compatibilityDate:'2026-10-26',
        bindings,assets:{directory:built.dest,binding:'ASSETS',run_worker_first:true},
        outboundService:async request=>{
            outbound.push({url:request.url,method:request.method});
            if(outboundService)return outboundService(request);
            return new Response('LOCAL_RUNTIME_EXTERNAL_REQUEST_BLOCKED',{status:502});
        }});
    options.telemetry={enabled:false};
    options.workers[0].config.assets.hasUserWorker=true;
    options.resourcePersistencePath=path.join(root,'dev/artifacts/miniflare');
    options.cf=false;
    const mf=new Miniflare(options);
    try {await mf.ready;return {mf,outbound,built};}
    catch(error){await mf.dispose();throw error;}
}
