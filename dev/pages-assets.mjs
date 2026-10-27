import fs from 'node:fs/promises';
import path from 'node:path';
import { root } from './tools.mjs';

// Public runtime files only. Never recursively copy a source directory into a release.
export const publicAssets = [
    'index.html', 'css/app.bundle.css', 'manifest.json', 'sw.js', 'reset-cache.html',
    'assets/neungdong-map.svg', 'assets/dongbu-map.svg', 'assets/oldtown-map.svg',
    'court_map.jpg', 'abc-192.png', 'abc-512.png', '.well-known/assetlinks.json', '_headers',
    ...['app-install','config','environment','firebase-environment','sdk-loader','utils','policy-settings',
        'reservation-data','auth','calendar','reservation-ui','booking-helpers','booking-core',
        'recovery-center','admin-actions','admin-settings','member-manager','my-reservations','board','notice-popup']
        .map(name => 'js/' + name + '.js')
];
export async function copyPublicAssets(destination) {
    for (const file of publicAssets) {
        const source=path.join(root,file);
        if (!(await fs.lstat(source)).isFile()) throw new Error('Public asset must be a regular file: '+file);
        await fs.mkdir(path.dirname(path.join(destination,file)),{recursive:true});
        await fs.copyFile(source,path.join(destination,file));
    }
}
