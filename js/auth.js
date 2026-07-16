/*
 * 국제 테니스장 예약 앱 - Step 5 Auth / Member
 * step5-auth-extracted
 *
 * 원칙:
 * - 예약 저장, 결제, 코트 배정, 관리자 통계 로직은 아직 index.dev.html에 둔다.
 * - 로그인/소셜로그인/회원가입/비밀번호 재설정/로그아웃/내 정보 수정만 분리한다.
 * - 기존 전역 함수명은 유지해 HTML onclick 및 기존 호출과 호환한다.
 */

    // ===============================
    // NAVER Social Login (Cloudflare Pages Functions)
    // ===============================
    /* step3-config-extracted: NAVER_AUTH_BASE is loaded from ./js/config.js */

/* step4-utils-extracted: normalizePhoneNumber moved to ./js/utils.js */


    const REAL_NAME_WARNING_TEXT = "회원가입은 반드시 본인 실명으로만 가능합니다.\n\n이름은 한글 2~6자만 입력할 수 있으며, 영문·숫자·특수문자는 사용할 수 없습니다.\n실명이 아니면 가입이 제한됩니다.";
    let joinRealNameWarningShown = false;

/* step4-utils-extracted: normalizeKoreanRealName moved to ./js/utils.js */

/* step4-utils-extracted: isValidKoreanRealName moved to ./js/utils.js */

/* step4-utils-extracted: sanitizeKoreanRealNameInput moved to ./js/utils.js */

    function showJoinRealNameWarning(force = false) {
        if (!force && joinRealNameWarningShown) return;
        joinRealNameWarningShown = true;
        alert(REAL_NAME_WARNING_TEXT);
    }

    function requireValidKoreanRealName(name) {
        const cleaned = normalizeKoreanRealName(name).slice(0, 6);
        if (!isValidKoreanRealName(cleaned)) {
            alert("이름은 본인 실명 기준 한글 2~6자만 입력 가능합니다.\n영문, 숫자, 공백, 특수문자는 사용할 수 없습니다.");
            return "";
        }
        return cleaned;
    }

    async function ensureNaverUserDocument(profile = {}) {
        if (!auth.currentUser) return;
        const ref = db.collection('users').doc(auth.currentUser.uid);
        const snap = await ref.get();
        const existing = snap.exists ? (snap.data() || {}) : {};

        let phone = normalizePhoneNumber(profile.phone || existing.phone || '');
        while (!phone) {
            const value = prompt('네이버 로그인은 완료되었습니다. 예약에 필요한 휴대폰번호를 입력해주세요.\n예: 010-1234-5678');
            if (value === null) throw new Error('휴대폰번호 입력이 취소되어 로그인을 완료할 수 없습니다.');
            phone = normalizePhoneNumber(value);
            if (!phone) alert('휴대폰번호를 다시 입력해주세요.');
        }

        let name = normalizeKoreanRealName(profile.name || existing.name || auth.currentUser.displayName || '');
        while (!isValidKoreanRealName(name)) {
            const value = prompt('회원가입은 반드시 본인 실명으로만 가능합니다.\n한글 실명 2~6자를 입력해주세요.\n영문·숫자·특수문자는 사용할 수 없습니다.');
            if (value === null) throw new Error('실명 입력이 취소되어 회원가입을 완료할 수 없습니다.');
            name = normalizeKoreanRealName(value);
            if (!isValidKoreanRealName(name)) alert('한글 실명 2~6자로 다시 입력해주세요.');
        }
        const email = (profile.email || existing.email || auth.currentUser.email || '').trim().toLowerCase();
        const address = existing.address || '';
        const birth = existing.birth || '';
        const joinedAt = existing.joinedAt || new Date();

        await ref.set({
            email: email,
            name: name,
            phone: phone,
            address: address,
            birth: birth,
            isCitizen: !!existing.isCitizen,
            verifStatus: existing.verifStatus || 'NONE',
            isAdmin: !!existing.isAdmin,
            joinedAt: joinedAt,
            provider: existing.provider || 'naver',
            providerUid: profile.providerUid || existing.providerUid || auth.currentUser.uid,
            socialType: 'naver',
            socialProviders: Object.assign({}, existing.socialProviders || {}, { naver: true })
        }, { merge: true });
    }


    async function ensureSocialUserDocument(profile = {}, provider = 'social') {
        if (!auth.currentUser) return;
        const providerLabel = provider === 'google' ? 'Google' : (provider === 'kakao' ? '카카오' : provider);
        const ref = db.collection('users').doc(auth.currentUser.uid);
        const snap = await ref.get();
        const existing = snap.exists ? (snap.data() || {}) : {};

        let phone = normalizePhoneNumber(profile.phone || profile.mobile || existing.phone || '');
        while (!phone) {
            const value = prompt(`${providerLabel} 로그인은 완료되었습니다. 예약에 필요한 휴대폰번호를 입력해주세요.\n예: 010-1234-5678`);
            if (value === null) throw new Error('휴대폰번호 입력이 취소되어 로그인을 완료할 수 없습니다.');
            phone = normalizePhoneNumber(value);
            if (!phone) alert('휴대폰번호를 다시 입력해주세요.');
        }

        let name = normalizeKoreanRealName(profile.name || existing.name || auth.currentUser.displayName || '');
        while (!isValidKoreanRealName(name)) {
            const value = prompt('회원가입은 반드시 본인 실명으로만 가능합니다.\n한글 실명 2~6자를 입력해주세요.\n영문·숫자·특수문자는 사용할 수 없습니다.');
            if (value === null) throw new Error('실명 입력이 취소되어 회원가입을 완료할 수 없습니다.');
            name = normalizeKoreanRealName(value);
            if (!isValidKoreanRealName(name)) alert('한글 실명 2~6자로 다시 입력해주세요.');
        }

        const email = (profile.email || existing.email || auth.currentUser.email || '').trim().toLowerCase();
        const address = existing.address || '';
        const birth = existing.birth || '';
        const joinedAt = existing.joinedAt || new Date();
        const providerUid = profile.providerUid || profile.uid || existing.providerUid || auth.currentUser.uid;
        const socialProviders = Object.assign({}, existing.socialProviders || {});
        socialProviders[provider] = true;

        await ref.set({
            email: email,
            name: name,
            phone: phone,
            address: address,
            birth: birth,
            isCitizen: !!existing.isCitizen,
            verifStatus: existing.verifStatus || 'NONE',
            isAdmin: !!existing.isAdmin,
            joinedAt: joinedAt,
            provider: existing.provider || provider,
            providerUid: providerUid,
            socialType: provider,
            socialProviders: socialProviders,
            agreedAt: existing.agreedAt || new Date()
        }, { merge: true });
    }

    async function startGoogleLogin(mode = 'login') {
        try {
            const provider = new firebase.auth.GoogleAuthProvider();
            provider.setCustomParameters({ prompt: 'select_account' });
            const result = await auth.signInWithPopup(provider);
            const user = result.user || auth.currentUser;
            await ensureSocialUserDocument({
                name: user ? user.displayName : '',
                email: user ? user.email : '',
                providerUid: user ? user.uid : ''
            }, 'google');
            closeModal('modalLogin');
            closeModal('modalJoin');
            alert(mode === 'join' ? 'Google 자동 회원가입이 완료되었습니다.' : 'Google 로그인이 완료되었습니다.');
        } catch (err) {
            console.error('Google 로그인 실패:', err);
            const msg = (err && err.message) ? err.message : String(err);
            if (String(err && err.code || '').includes('popup')) {
                try {
                    sessionStorage.setItem('pendingSocialMode', mode);
                    sessionStorage.setItem('pendingSocialProvider', 'google');
                    const provider = new firebase.auth.GoogleAuthProvider();
                    provider.setCustomParameters({ prompt: 'select_account' });
                    await auth.signInWithRedirect(provider);
                    return;
                } catch (redirectErr) {
                    alert('Google 로그인 처리 실패: ' + (redirectErr && redirectErr.message ? redirectErr.message : redirectErr));
                    return;
                }
            }
            alert('Google 로그인 처리 실패: ' + msg + '\n\nFirebase Authentication에서 Google 제공자가 사용 설정되어 있는지 확인해주세요.');
        }
    }

    async function completeFirebaseRedirectLogin() {
        try {
            const result = await auth.getRedirectResult();
            if (!result || !result.user) return;
            const provider = sessionStorage.getItem('pendingSocialProvider') || 'google';
            const mode = sessionStorage.getItem('pendingSocialMode') || 'login';
            sessionStorage.removeItem('pendingSocialProvider');
            sessionStorage.removeItem('pendingSocialMode');
            await ensureSocialUserDocument({
                name: result.user.displayName || '',
                email: result.user.email || '',
                providerUid: result.user.uid || ''
            }, provider);
            closeModal('modalLogin');
            closeModal('modalJoin');
            alert(mode === 'join' ? `${provider === 'kakao' ? '카카오' : 'Google'} 자동 회원가입이 완료되었습니다.` : `${provider === 'kakao' ? '카카오' : 'Google'} 로그인이 완료되었습니다.`);
        } catch (err) {
            if (err && err.code) console.warn('소셜 리다이렉트 로그인 확인 실패:', err);
        }
    }

    function startKakaoLogin(mode = 'login') {
        // Kakao JavaScript SDK v2에는 Kakao.Auth.login()이 없으므로
        // Cloudflare Pages Function(/kakao-auth) 리다이렉트 방식으로 처리합니다.
        const nextUrl = window.location.origin + window.location.pathname;
        const authUrl = `/kakao-auth?action=start&mode=${encodeURIComponent(mode)}&next=${encodeURIComponent(nextUrl)}`;
        window.location.href = authUrl;
    }

    function getKakaoHashPayload() {
        const raw = (location.hash || '').replace(/^#/, '');
        if (!raw) return null;
        const params = new URLSearchParams(raw);
        const error = params.get('kakaoError');
        if (error) return { error };
        if (!params.get('kakaoCustomToken')) return null;
        return {
            token: params.get('kakaoCustomToken') || '',
            providerUid: params.get('kakaoUid') || '',
            name: params.get('kakaoName') || '',
            email: params.get('kakaoEmail') || '',
            phone: params.get('kakaoMobile') || '',
            mode: params.get('kakaoMode') || 'login'
        };
    }

    async function completeKakaoLoginFromUrl() {
        const payload = getKakaoHashPayload();
        if (!payload) return;

        history.replaceState(null, '', location.pathname + location.search);

        if (payload.error) {
            alert('카카오 로그인 처리 실패: ' + payload.error);
            return;
        }

        try {
            await auth.signInWithCustomToken(payload.token);
            await ensureSocialUserDocument(payload, 'kakao');

            closeModal('modalLogin');
            closeModal('modalJoin');

            alert(payload.mode === 'join' ? '카카오 자동 회원가입이 완료되었습니다.' : '카카오 로그인이 완료되었습니다.');
        } catch (err) {
            console.error('카카오 로그인 완료 실패:', err);
            alert('카카오 로그인 처리 실패: ' + (err && err.message ? err.message : err));
        }
    }

    function getNaverHashPayload() {
        const raw = (location.hash || '').replace(/^#/, '');
        if (!raw) return null;
        const params = new URLSearchParams(raw);
        if (!params.get('naverCustomToken')) return null;
        return {
            token: params.get('naverCustomToken') || '',
            providerUid: params.get('naverUid') || '',
            name: decodeURIComponent(params.get('naverName') || ''),
            email: decodeURIComponent(params.get('naverEmail') || ''),
            phone: decodeURIComponent(params.get('naverMobile') || ''),
            mode: params.get('naverMode') || 'login'
        };
    }

    async function completeNaverLoginFromUrl() {
        const payload = getNaverHashPayload();
        if (!payload || !payload.token) return;

        history.replaceState(null, '', location.pathname + location.search);

        try {
            await auth.signInWithCustomToken(payload.token);
            await ensureNaverUserDocument(payload);

            closeModal('modalLogin');
            closeModal('modalJoin');

            alert(payload.mode === 'join' ? '네이버 자동 회원가입이 완료되었습니다.' : '네이버 로그인이 완료되었습니다.');
        } catch (err) {
            console.error('네이버 로그인 완료 실패:', err);
            alert('네이버 로그인 처리 실패: ' + (err && err.message ? err.message : err));
        }
    }

    function startNaverLogin(mode = 'login') {
        const nextUrl = window.location.origin + window.location.pathname;
        const authUrl = `${NAVER_AUTH_BASE}?action=start&mode=${encodeURIComponent(mode)}&next=${encodeURIComponent(nextUrl)}`;
        window.location.href = authUrl;
    }

    window.addEventListener('DOMContentLoaded', () => {
        completeNaverLoginFromUrl();
        completeKakaoLoginFromUrl();
        completeFirebaseRedirectLogin();
    });



// ===== v10 로그인 시 공정 예약 이용 고지 =====
async function showAutomationPolicyLoginNoticeOnce() {
    if (isAdmin || !currentUser) return;
    try { if (typeof loadAutomationPolicySettings === 'function') await loadAutomationPolicySettings(false); } catch (_) {}
    if (typeof isAutomationPolicyEnabled === 'function' && !isAutomationPolicyEnabled('loginNoticeEnabled')) return;
    const today = new Date().toISOString().slice(0,10);
    const key = 'automationPolicyNotice_' + today;
    try { if (localStorage.getItem(key) === 'shown') return; } catch (_) {}
    let modal = document.getElementById('modalAutomationPolicyNotice');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'modalAutomationPolicyNotice';
        modal.className = 'modal-mask';
        modal.innerHTML = `<div class="modal-win" style="max-width:430px;">
            <div class="modal-head">⚠️ 공정 예약 이용 안내</div>
            <div style="padding:14px;border:1px solid #fca5a5;background:#fff1f2;border-radius:12px;color:#7f1d1d;line-height:1.65;font-size:.9rem;">
                매크로, 자동화 프로그램, 비정상적 반복 요청 등 공정한 예약을 저해하는 행위는 금지됩니다.<br><br>
                객관적인 접속·예약 기록을 통해 위반 사실이 확인되면 운영규정에 따라 예약 취소, 일정 기간 이용 제한 또는 계정 차단 조치가 이루어질 수 있습니다.<br><br>
                시스템 장애 유발, 부정한 명령 입력 등 위법성이 확인되는 경우 관계기관 신고 및 법적 조치가 진행될 수 있습니다.
            </div>
            <button id="btnAutomationPolicyConfirm" class="btn-full bg-blue" style="margin-top:14px;">확인</button>
        </div>`;
        document.body.appendChild(modal);
        modal.querySelector('#btnAutomationPolicyConfirm').onclick = function(){
            try { localStorage.setItem(key, 'shown'); } catch (_) {}
            closeModal('modalAutomationPolicyNotice');
        };
    }
    setTimeout(() => openModal('modalAutomationPolicyNotice'), 180);
}

/* 로그인 상태 감지 초기화: main script에서 db/auth/currentUser 상태 변수를 만든 뒤 호출합니다. */
function initAuthStateListener() {
    /* [수정] 로그인 상태 변경 감지 */
    auth.onAuthStateChanged(user => {
        const btnSet = document.getElementById('btnSet');
        const btnMyRes = document.getElementById('btnMyRes');

        if (userDocUnsubscribe) {
            try { userDocUnsubscribe(); } catch (_) {}
            userDocUnsubscribe = null;
        }

        if(user) {
            // [로그인 상태] 사용자 문서를 실시간으로 구독하여 시민인증 승인값이 즉시 반영되도록 수정
            userDocUnsubscribe = db.collection("users").doc(user.uid).onSnapshot(doc => {
                if(!doc.exists) return;

                const prevCitizen = currentUser ? !!currentUser.isCitizen : false;
                const prevStatus = currentUser ? (currentUser.verifStatus || '') : '';

                currentUser = doc.data() || {};
                currentUser.uid = user.uid;
                isAdmin = !!currentUser.isAdmin || localStorage.getItem('isAdm') === 'true';
            
                document.getElementById('btnOut').style.display = 'inline-block';
                document.getElementById('btnLogin').style.display = 'none';
            
                if(isAdmin) {
                    // === 관리자일 때 ===
                    btnSet.style.display = 'inline-block';
                    if(btnMyRes) { btnMyRes.style.display = 'inline-block'; btnMyRes.innerText = '예약현황'; }
                } else {
                    // === 일반 회원일 때 ===
                    if (btnSet) {
                        btnSet.style.display = 'inline-block';
                        btnSet.style.visibility = 'visible';
                    }
                    if(btnMyRes) { btnMyRes.style.display = 'inline-block'; btnMyRes.innerText = '예약관리'; }
                
                    const enabled = localStorage.getItem('notificationEnabled') === 'true';
                    if (enabled) startNotificationScheduler();

                    const msgSpan = document.getElementById('welcomeMsg');
                    msgSpan.innerText = currentUser.name + " 님";
                    msgSpan.style.display = 'inline-block';

                    if(!!currentUser.isCitizen && currentUser.verifStatus === 'APPROVED' && currentUser.citizenNoticeShown !== true) {
                        setTimeout(async () => {
                            alert('김해시민 인증이 승인되었습니다. 일반 요금이 바로 반영됩니다.');
                            try {
                                await db.collection("users").doc(user.uid).update({
                                    citizenNoticeShown: true
                                });
                            } catch (err) {
                                console.warn('citizenNoticeShown 저장 실패:', err);
                            }
                            try { if (typeof calcPay === 'function') calcPay(); } catch (_) {}
                            try { if (typeof scheduleLoadDB === 'function') scheduleLoadDB(0); } catch (_) {}
                        }, 120);
                    } else if(prevStatus === 'PENDING' && currentUser.verifStatus === 'REJECTED') {
                        setTimeout(() => {
                            alert('김해시민 인증이 반려되었습니다. 설정에서 다시 신청해주세요.');
                        }, 120);
                    }
                }

                updateAdminUI();
                showAutomationPolicyLoginNoticeOnce();
                try {
                    if (_authRefreshTimer) clearTimeout(_authRefreshTimer);
                    _authRefreshTimer = setTimeout(() => {
                        if (typeof drawCalendar === 'function') drawCalendar();
                        if (typeof scheduleLoadDB === 'function') scheduleLoadDB(80);
                    }, 80);
                } catch (_) {}
            }, err => {
                console.error('사용자 정보 실시간 로딩 실패:', err);
            });
        } else {
            // [로그아웃 상태]
            currentUser = null;
        
            if(!localStorage.getItem('isAdm')) {
                 document.getElementById('welcomeMsg').style.display = 'none';
            }
        
            if(btnMyRes) btnMyRes.style.display = 'none';

            if(!localStorage.getItem('isAdm')) {
                isAdmin = false;
                document.getElementById('btnOut').style.display = 'none';
                document.getElementById('btnLogin').style.display = 'inline-block';
                btnSet.style.display = 'none';
            }
            updateAdminUI();
            try {
                if (_authRefreshTimer) clearTimeout(_authRefreshTimer);
                _authRefreshTimer = setTimeout(() => {
                    if (typeof drawCalendar === 'function') drawCalendar();
                    if (typeof scheduleLoadDB === 'function') scheduleLoadDB(80);
                }, 80);
            } catch (_) {}
        }
    });
}


/* 이메일 회원가입/로그인/비밀번호/로그아웃 */
    async function doJoin() {
        // 1. 필수 약관 동의 확인
        const t1 = document.getElementById('chkTerm1').checked;
        const t2 = document.getElementById('chkTerm2').checked;
        const t3 = document.getElementById('chkTerm3').checked;

        if(!t1 || !t2 || !t3) {
            alert("모든 필수 약관 및 개인정보 수집에 동의해야 가입할 수 있습니다.");
            return;
        }

        const email = document.getElementById('joinEmail').value.trim();
        const pw = document.getElementById('joinPw').value.trim();
        const joinNameEl = document.getElementById('joinName');
        sanitizeKoreanRealNameInput(joinNameEl);
        const name = joinNameEl.value.trim();
        const ph = document.getElementById('joinPh').value.trim();
        const birth = document.getElementById('joinBirth').value.trim();
        const addr = document.getElementById('joinAddr').value.trim();
        const fileInput = document.getElementById('joinProof');
        const file = fileInput.files[0];

        if(!email || !pw || !name || !ph || !birth || !addr) return alert("모든 필수 정보를 입력해주세요.");

        const validName = requireValidKoreanRealName(name);
        if(!validName) {
            document.getElementById('joinName').focus();
            return;
        }

        // [법적 주의] 시민 인증 사진 업로드 시 안내
        if(file && !confirm("증빙 서류(신분증 등) 업로드 시\n주민번호 뒷자리는 반드시 가려야 합니다.\n진행하시겠습니까?")) {
            return;
        }

        const btn = document.getElementById('btnJoin');
        btn.innerText = "처리중...";
        btn.disabled = true;

        try {
            const cred = await auth.createUserWithEmailAndPassword(email, pw);
            const uid = cred.user.uid;
            let proofUrl = "";

            if(file) {
                try {
                    const compressedFile = await compressImage(file, 800, 0.6); // 화질 약간 조정
                    const path = `proofs/${uid}_proof.jpg`;
                    const ref = storage.ref().child(path);
                    await ref.put(compressedFile);
                    proofUrl = await ref.getDownloadURL();
                } catch(imgErr) { console.error("이미지 실패:", imgErr); }
            }

            // DB 저장 시 동의 날짜 기록 (법적 분쟁 대비)
            await db.collection("users").doc(uid).set({
                email: email, name: validName, phone: ph, birth: birth, address: addr,
                proofUrl: proofUrl, proofUploadedAt: file ? new Date() : null,
                isCitizen: false, verifStatus: file ? "PENDING" : "NONE",
                isAdmin: false, 
                joinedAt: new Date(),
                agreedAt: new Date() // 약관 동의 시점 저장
            });

            await appendCitizenAudit(uid, 'JOIN', {
                name: validName,
                phone: ph,
                address: addr,
                hasProof: !!proofUrl
            });

            alert("회원가입 완료! 로그인해주세요.");
            closeModal('modalJoin');

            // 입력창 초기화
            document.getElementById('joinEmail').value="";
            document.getElementById('joinPw').value="";
            document.getElementById('joinName').value="";
            document.getElementById('joinPh').value="";
            document.getElementById('joinBirth').value="";
            document.getElementById('joinAddr').value="";
            fileInput.value="";
            // 체크박스 초기화
            document.getElementById('chkAll').checked = false;
            document.querySelectorAll('.term-item').forEach(el => el.checked = false);

        } catch(err) {
            console.error(err);
            let msg = "오류가 발생했습니다: " + err.message;
            switch(err.code) {
                case "auth/email-already-in-use": msg = "이미 사용 중인 이메일입니다."; break;
                case "auth/invalid-email": msg = "이메일 형식이 올바르지 않습니다."; break;
                case "auth/weak-password": msg = "비밀번호는 6자리 이상이어야 합니다."; break;
            }
            alert(msg);
        } finally {
            btn.innerText = "가입하기";
            btn.disabled = false;
        }
    }

    function toggleAllTerms() {
        const allChecked = document.getElementById('chkAll').checked;
        document.querySelectorAll('.term-item').forEach(el => el.checked = allChecked);
    }

function doUserLogin() {
    const email = document.getElementById('loginEmail').value;
    const pw = document.getElementById('loginPw').value;
    const btn = document.getElementById('btnLoginAction');
    btn.innerText = "로그인 중...";
    btn.disabled = true;

    auth.signInWithEmailAndPassword(email, pw).then(() => {
        closeModal('modalLogin');
        // 로그인 성공 시 버튼 텍스트 원복은 auth 상태 변화 감지에서 처리되거나, 팝업 닫히므로 생략 가능
    }).catch(err => {
        let msg = "로그인 실패: " + err.message;
        
        // [수정] 최신 Firebase 에러 코드(invalid-login-credentials) 추가
        if(err.code === 'auth/user-not-found' || err.code === 'auth/wrong-password' || err.code === 'auth/invalid-login-credentials') {
            msg = "이메일 또는 비밀번호가 잘못되었습니다.";
        } else if(err.code === 'auth/invalid-email') {
            msg = "이메일 형식이 올바르지 않습니다.";
        } else if(err.code === 'auth/too-many-requests') {
            msg = "로그인 시도가 너무 많아 잠시 차단되었습니다. 잠시 후 다시 시도해주세요.";
        }
        
        alert(msg);
    }).finally(() => {
        btn.innerText = "로그인";
        btn.disabled = false;
    });
}

function sendResetEmail() {
    const email = document.getElementById('resetEmail').value.trim();
    
    if (!email) {
        alert("이메일을 입력해주세요.");
        return;
    }

    const btn = document.getElementById('btnResetAction');
    btn.innerText = "전송 중...";
    btn.disabled = true;

    // Firebase Auth 내장 함수 사용
    auth.sendPasswordResetEmail(email)
        .then(() => {
            alert("재설정 메일을 보냈습니다!\n이메일함을 확인하고 링크를 클릭하여 비밀번호를 변경하세요.\n(스팸함도 확인해주세요)");
            closeModal('modalReset');
            document.getElementById('resetEmail').value = ""; // 입력창 초기화
        })
        .catch((error) => {
            let msg = "메일 발송 실패: " + error.message;
            if (error.code === 'auth/user-not-found') {
                msg = "가입되지 않은 이메일입니다.";
            } else if (error.code === 'auth/invalid-email') {
                msg = "이메일 형식이 올바르지 않습니다.";
            }
            alert(msg);
        })
        .finally(() => {
            btn.innerText = "재설정 메일 발송";
            btn.disabled = false;
        });
}


/* 내 정보/일반 회원 설정 */

    function doLogout() {
        if(confirm("로그아웃 하시겠습니까?")) {
            localStorage.removeItem('isAdm');
            isAdmin = false;
            auth.signOut().then(() => {
                alert("로그아웃 되었습니다.");
                location.reload();
            }).catch(() => { location.reload(); });
        }
    }


function openUserSettings() {
    console.log('openUserSettings 호출됨');
    
    if (!currentUser) return;
    
    // 내 정보 자동 입력
    document.getElementById('userSettingsName').value = currentUser.name || '';
    document.getElementById('userSettingsPhone').value = currentUser.phone || '';
    document.getElementById('userSettingsAddr').value = currentUser.address || '';
    document.getElementById('userSettingsNewPw').value = '';
    document.getElementById('userSettingsProof').value = '';
    
    // 토글 상태 동기화
    const darkToggle = document.getElementById('userDarkModeToggle');
    const notificationToggle = document.getElementById('userNotificationToggle');
    
    console.log('darkToggle:', darkToggle, 'notificationToggle:', notificationToggle);
    
    if (darkToggle) {
        darkToggle.checked = document.body.classList.contains('dark-mode');
    }
    
    if (notificationToggle) {
        notificationToggle.checked = localStorage.getItem('notificationEnabled') === 'true';
    }
    
    openModal('modalUserSettings');
}

async function saveUserSettingsInfo() {
    if (!currentUser) {
        alert("로그인 정보가 없습니다. 다시 로그인해주세요.");
        return;
    }
    
    const newPw = document.getElementById('userSettingsNewPw').value.trim();
    const newAddr = document.getElementById('userSettingsAddr').value.trim();
    const file = document.getElementById('userSettingsProof').files[0];
    
    try {
        // 비밀번호 변경
        if (newPw) {
            if (newPw.length < 6) throw new Error("비밀번호는 6자 이상이어야 합니다.");
            await auth.currentUser.updatePassword(newPw);
            alert("비밀번호가 변경되었습니다.");
        }
        
        let updateData = { address: newAddr };
        
        // 김해시민 인증 파일 업로드
        if (file) {
            const oldProofUrl = currentUser.proofUrl || "";
            const compressedFile = await compressImage(file, 600, 0.5);
            const path = `proofs/${currentUser.uid}_proof_${new Date().getTime()}.jpg`;
            const ref = storage.ref().child(path);
            
            await ref.put(compressedFile);
            const url = await ref.getDownloadURL();
            
            updateData.proofUrl = url;
            updateData.proofUploadedAt = new Date();
            updateData.proofDeletedAt = null;
            updateData.verifStatus = "PENDING";
            updateData.isCitizen = false; // 재심사 대기
            updateData.citizenNoticeShown = false;

            if (oldProofUrl && oldProofUrl !== url) {
                await deleteProofByUrl(oldProofUrl);
            }
            
            alert("김해시민 인증 서류가 업로드되었습니다. 관리자 승인을 기다려주세요.");
        }
        
        // Firestore 업데이트
        await db.collection("users").doc(currentUser.uid).update(updateData);
        
        // 현재 사용자 정보 갱신
        currentUser.address = newAddr;
        if (file) {
            currentUser.proofUrl = updateData.proofUrl;
            currentUser.proofUploadedAt = updateData.proofUploadedAt;
            currentUser.proofDeletedAt = null;
            currentUser.verifStatus = "PENDING";
            currentUser.isCitizen = false;
        }
        
        alert("정보가 저장되었습니다.");
        
        // 입력 필드 초기화
        document.getElementById('userSettingsNewPw').value = '';
        document.getElementById('userSettingsProof').value = '';
        
    } catch (error) {
        console.error("저장 오류:", error);
        alert("저장 중 오류가 발생했습니다: " + error.message);
    }
}

   function openMyInfo() {
        if(!currentUser) return;
        document.getElementById('myName').value = currentUser.name;
        document.getElementById('myPhone').value = currentUser.phone;
        document.getElementById('myAddr').value = currentUser.address;
        document.getElementById('myNewPw').value = ""; 
        document.getElementById('myProof').value = ""; 
        openModal('modalMyInfo');
    }


    async function saveMyInfo() {
        if(!currentUser) {
            alert("로그인 정보가 없습니다. 다시 로그인해주세요.");
            return;
        }

        const btn = document.getElementById('btnSaveInfo');
        btn.innerText = "저장중...";
        btn.disabled = true;

        const newPw = document.getElementById('myNewPw').value.trim();
        const newAddr = document.getElementById('myAddr').value.trim();
        const file = document.getElementById('myProof').files[0];

        try {
            if(newPw) {
                if(newPw.length < 6) throw new Error("비밀번호는 6자 이상이어야 합니다.");
                await auth.currentUser.updatePassword(newPw);
                alert("비밀번호가 변경되었습니다.");
            }

            let updateData = { address: newAddr };

            if(file) {
                const oldProofUrl = currentUser.proofUrl || "";
                const compressedFile = await compressImage(file, 600, 0.5);
                const path = `proofs/${currentUser.uid}_proof.jpg`;
                const ref = storage.ref().child(path);

                await ref.put(compressedFile);
                const url = await ref.getDownloadURL();

                updateData.proofUrl = url;
                updateData.proofUploadedAt = new Date();
                updateData.proofDeletedAt = null;
                updateData.verifStatus = "PENDING"; 
                updateData.isCitizen = false;
                updateData.citizenNoticeShown = false;

                if (oldProofUrl && oldProofUrl !== url) {
                    await deleteProofByUrl(oldProofUrl);
                }

                await appendCitizenAudit(currentUser.uid, 'REAPPLY', {
                    name: currentUser.name || '',
                    phone: currentUser.phone || '',
                    address: newAddr,
                    hasProof: true
                });
            }

            await db.collection("users").doc(currentUser.uid).update(updateData);

            currentUser.address = newAddr;
            if(updateData.proofUrl) {
                currentUser.proofUrl = updateData.proofUrl;
                currentUser.proofUploadedAt = updateData.proofUploadedAt;
                currentUser.proofDeletedAt = null;
                currentUser.verifStatus = "PENDING";
                currentUser.isCitizen = false;
            }

            alert("정보가 수정되었습니다.");
            closeModal('modalMyInfo');

        } catch(e) {
            console.error(e);
            alert("수정 실패: " + e.message);
            if(e.code === 'auth/requires-recent-login') {
                alert("보안을 위해 다시 로그인한 후 시도해주세요.");
                doLogout();
            }
        } finally {
            btn.innerText = "저장하기";
            btn.disabled = false;
        }
    }

