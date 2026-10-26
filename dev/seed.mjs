// Synthetic fixtures only. No configurable destination and no production SDK/credentials.
const project = 'demo-kjtennis-local';
const firestore = `http://127.0.0.1:8080/v1/projects/${project}/databases/(default)/documents`;
async function request(url, options) {
    const target = new URL(url);
    if (!['http://127.0.0.1:8080', 'http://127.0.0.1:9099', 'http://127.0.0.1:9199'].includes(target.origin)) throw new Error('Non-emulator target');
    const response = await fetch(target, options);
    const body = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(body));
    return body;
}
function value(input) {
    if (input === null) return { nullValue: null };
    if (Array.isArray(input)) return { arrayValue: { values: input.map(value) } };
    if (typeof input === 'object') return { mapValue: { fields: Object.fromEntries(Object.entries(input).map(([k,v]) => [k,value(v)])) } };
    return { [typeof input === 'boolean' ? 'booleanValue' : typeof input === 'number' ? 'integerValue' : 'stringValue']: input };
}
async function document(collection, id, data) {
    return request(`${firestore}/${collection}/${encodeURIComponent(id)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value(data).mapValue) });
}
const email = 'member@example.invalid', password = 'LocalOnly123!';
let account;
try {
    account = await request('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=demo-local-api-key', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, returnSecureToken: true }) });
} catch (err) {
    if (!err.message.includes('EMAIL_EXISTS')) throw err;
    account = await request('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=demo-local-api-key', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, returnSecureToken: true }) });
}
await document('users', account.localId, { email, name: '가상회원', phone: '000-0000-0000', isCitizen: false, verifStatus: 'NONE', isAdmin: false, fixture: true });
await document('settings', 'global', { prices: [1000,2000,3000,4000,5000,6000,7000,8000], adminPhone: '000-0000-0000', bankName: '가상은행', bankAccount: 'DEV-ONLY-NOT-AN-ACCOUNT', useCardPay: process.argv.includes('--card-enabled'), isCenterOpen: true, dayStartHour: 7, nightStartHour: 19 });
await document('settings', 'app_version', { ver: 7 });
await document('settings', 'seasonalPricing', { list: [{ start: '2026-01-01', end: '2030-12-31', nightStart: 19, dayPrice: 111, nightPrice: 222 }] });
await document('settings', 'automation_policy', { loginNoticeEnabled: false, bookingConsentEnabled: true });
const date = '2026-11-02';
await document('reservations', `국제_${date}_1_10`, { center: '국제', date, court: 1, time: 10, status: 'BOOKED', uid: account.localId, name: '가상회원', phone: '000-0000-0000', fixture: true });
await request(`http://127.0.0.1:9199/v0/b/${project}.appspot.com/o?uploadType=media&name=fixtures%2Fexample.txt`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'SYNTHETIC LOCAL FIXTURE' });
console.log('Seeded synthetic Auth / Firestore / Storage fixtures in ' + project);
