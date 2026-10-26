// Shared by local CLI subprocesses. No Cloudflare/Firebase API, telemetry or credential network access.
function assertLocal(input, options) {
    const host=typeof input==='string'?new URL(input).hostname:input instanceof URL?input.hostname:input?.hostname||input?.host||options?.hostname||options?.host||'localhost';
    if(!['127.0.0.1','localhost','::1','[::1]'].includes(host)&&!/^127\.0\.0\.1:\d+$/.test(host))throw new Error('OFFLINE_CLI_EXTERNAL_REQUEST_BLOCKED: '+host);
}
for(const protocol of ['node:http','node:https']) {
    const api=require(protocol);
    for(const method of ['request','get']) {const original=api[method];api[method]=function(...args){assertLocal(args[0],args[1]);return original.apply(this,args);};}
}
const originalFetch=global.fetch;
global.fetch=(input,options)=>{assertLocal(input?.url||input);return originalFetch(input,options);};
