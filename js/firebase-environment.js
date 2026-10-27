/* Called immediately after initializeApp, before any auth listener, read or write. */
function connectDevelopmentEmulators(app) {
    if (!APP_ENV.isDevelopment) return;
    if (navigator.serviceWorker?.controller) throw new Error('기존 로컬 서비스 워커가 실행 중입니다. 탭을 닫고 다시 여세요.');
    if (app.options.projectId !== APP_ENV.projectId || !app.options.projectId.startsWith('demo-')) throw new Error('개발 Firebase 프로젝트 차단');
    const auth = app.auth(), db = app.firestore(), storage = app.storage();
    auth.useEmulator('http://127.0.0.1:9099', { disableWarnings: true });
    db.useEmulator('127.0.0.1', 8080);
    storage.useEmulator('127.0.0.1', 9199);
    auth.setPersistence(firebase.auth.Auth.Persistence.SESSION);
    window.devLogin = async function (provider = 'local') {
        devEffect('oauth-mock', { provider });
        return auth.signInWithEmailAndPassword(provider === 'admin' ? 'admin@example.invalid' : 'member@example.invalid', 'LocalOnly123!');
    };
    // Redirect/hash payloads from real OAuth sessions must never be consumed locally.
    auth.getRedirectResult = async () => ({ user: null });
    auth.signInWithCustomToken = async () => { throw new Error('개발 환경: 외부 custom token 차단'); };
    auth.signInWithPopup = async () => window.devLogin('google');
    auth.signInWithRedirect = async () => window.devLogin('google');
    auth.sendPasswordResetEmail = async email => devEffect('password-reset-mock', { email });
}
