import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
export const root = fileURLToPath(new URL('../', import.meta.url));
export function resolveTool(relative) {
    const found = path.resolve(root, relative);
    if (!found.startsWith(root) || !fs.existsSync(found)) throw new Error('Missing repository tool: ' + relative + '. Run npm ci and npm run setup:tools.');
    return found;
}
export function findJava() {
    for (const base of [path.join(root, 'dev/artifacts/java')]) {
        if (!fs.existsSync(base)) continue;
        for (const item of fs.readdirSync(base)) {
            const bin = path.join(base,item,'bin','java.exe');
            if (fs.existsSync(bin)) return bin;
        }
    }
    throw new Error('Local JDK unavailable; no automatic installation.');
}
export function emulatorCache() {
    const dest = path.join(root, 'dev/artifacts/emulators'); fs.mkdirSync(dest, {recursive:true});
    for (const name of ['cloud-firestore-emulator-v1.22.0.jar','cloud-storage-rules-runtime-v1.1.3.jar']) {
        const target=path.join(dest,name);
        if (!fs.existsSync(target)) throw new Error('Missing Emulator binary; run npm run setup:tools: ' + name);
    }
    return dest;
}
