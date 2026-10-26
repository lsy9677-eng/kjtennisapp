// Offline CLI preloader. Restrict HTTP(S) before loading the reused firebase-tools installation.
function assertLocal(input, options) {
    const host = typeof input === 'string' ? new URL(input).hostname : input instanceof URL ? input.hostname
        : input?.hostname || input?.host || options?.hostname || options?.host || 'localhost';
    if (!['127.0.0.1','localhost','::1','[::1]'].includes(String(host).replace(/:\d+$/, ''))) throw new Error('OFFLINE_CLI_EXTERNAL_REQUEST_BLOCKED: ' + host);
}
for (const protocol of ['node:http','node:https']) {
    const api=require(protocol);
    for(const method of ['request','get']) {
        const original=api[method];
        api[method]=function(...args){assertLocal(args[0],args[1]);return original.apply(this,args);};
    }
}
const originalFetch=global.fetch;
global.fetch=(input,options)=>{assertLocal(typeof input==='object' && input.url ? input.url : input);return originalFetch(input,options);};
process.on('message', msg => { if(msg==='shutdown') process.emit('SIGINT'); });
const cli=process.argv[2];
process.argv=[process.execPath,cli,...process.argv.slice(3)];
require(cli);
