import { createPagesRuntime } from './pages-runtime.mjs';
const runtime=await createPagesRuntime({port:4173});
console.log('Cloudflare workerd locally: http://127.0.0.1:4173. External Worker requests blocked.');
process.on('SIGINT',()=>runtime.mf.dispose());process.on('SIGTERM',()=>runtime.mf.dispose());
