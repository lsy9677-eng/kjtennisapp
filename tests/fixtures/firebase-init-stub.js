/* Synthetic browser SDK boundary for the full production-mode HTML initialization check. */
(function () {
    const controls = window.__INIT_FIXTURE = { globalFailure: new URL(location.href).searchParams.has('fixture-global-failure'), seasonFailure: false, reads: [], writes: 0, payments: 0 };
    const empty = { exists: false, empty: true, size: 0, docs: [], forEach() {}, data: () => ({}) };
    function query(collection, id) {
        return {
            doc: next => query(collection, next), where() { return this; }, orderBy() { return this; }, limit() { return this; }, startAfter() { return this; },
            async get() {
                controls.reads.push(collection + '/' + (id || '*'));
                if (collection === 'settings' && id === 'global') {
                    if (controls.globalFailure) throw new Error('synthetic global read failure');
                    return { exists: true, data: () => ({ prices: [1000,1000,3000,3000,1000,1000,3000,3000], nightStartHour: 19, useCardPay: true }) };
                }
                if (collection === 'settings' && id === 'seasonalPricing') {
                    if (controls.seasonFailure) throw new Error('synthetic seasonal read failure');
                    return { exists: true, data: () => ({ list: [{ start: '2030-11-01', end: '2030-11-30', nightStart: 18, dayPrice: 111, nightPrice: 222 }] }) };
                }
                return empty;
            },
            onSnapshot(callback) { queueMicrotask(() => callback(empty)); return () => {}; },
            async set() { controls.writes++; throw new Error('INIT_WRITE_FORBIDDEN'); },
            async update() { controls.writes++; throw new Error('INIT_WRITE_FORBIDDEN'); },
            async add() { controls.writes++; throw new Error('INIT_WRITE_FORBIDDEN'); },
            async delete() { controls.writes++; throw new Error('INIT_WRITE_FORBIDDEN'); }
        };
    }
    const db = { collection: name => query(name) };
    const auth = { currentUser: null, onAuthStateChanged(callback) { queueMicrotask(() => callback(null)); return () => {}; }, getRedirectResult: async () => ({ user: null }) };
    const app = { name: '[DEFAULT]', firestore: () => db, auth: () => auth, storage: () => ({}) };
    window.firebase = { apps: [], initializeApp(options, name = '[DEFAULT]') { app.options = options; app.name = name; this.apps.push(app); return app; },
        firestore: Object.assign(() => db, { FieldValue: { serverTimestamp: () => 'SYNTHETIC_TIMESTAMP' } }), auth: () => auth };
    window.IMP = { init() {}, request_pay() { controls.payments++; } };
    window.Kakao = { isInitialized: () => true, init() {} };
    window.grecaptcha = { reset() {} };
}());
