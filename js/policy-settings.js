/* 공정 예약 안내 노출 설정 - 매크로 감시 기능과 분리 */
(function () {
    const DEFAULTS = {
        loginNoticeEnabled: true,
        bookingConsentEnabled: true
    };
    let loaded = false;
    let loadingPromise = null;
    let settings = Object.assign({}, DEFAULTS);

    function applyLocalCache() {
        try {
            const raw = localStorage.getItem('automationPolicySettingsCache');
            if (!raw) return;
            const data = JSON.parse(raw);
            settings.loginNoticeEnabled = data.loginNoticeEnabled !== false;
            settings.bookingConsentEnabled = data.bookingConsentEnabled !== false;
        } catch (_) {}
    }

    function saveLocalCache() {
        try { localStorage.setItem('automationPolicySettingsCache', JSON.stringify(settings)); } catch (_) {}
    }

    applyLocalCache();

    window.getAutomationPolicySettings = function () {
        return Object.assign({}, settings);
    };

    window.isAutomationPolicyEnabled = function (key) {
        return settings[key] !== false;
    };

    window.loadAutomationPolicySettings = async function (force) {
        if (loaded && !force) return window.getAutomationPolicySettings();
        if (loadingPromise && !force) return loadingPromise;
        if (typeof db === 'undefined') return window.getAutomationPolicySettings();

        loadingPromise = db.collection('settings').doc('automation_policy').get()
            .then(function (snap) {
                if (snap.exists) {
                    const data = snap.data() || {};
                    settings.loginNoticeEnabled = data.loginNoticeEnabled !== false;
                    settings.bookingConsentEnabled = data.bookingConsentEnabled !== false;
                }
                loaded = true;
                saveLocalCache();
                return window.getAutomationPolicySettings();
            })
            .catch(function (err) {
                console.warn('공정 예약 안내 설정 불러오기 실패 - 기존값 유지:', err);
                return window.getAutomationPolicySettings();
            })
            .finally(function () { loadingPromise = null; });
        return loadingPromise;
    };

    window.saveAutomationPolicySetting = async function (key, enabled) {
        if (!window.isAdmin) throw new Error('관리자만 변경할 수 있습니다.');
        if (!Object.prototype.hasOwnProperty.call(DEFAULTS, key)) throw new Error('지원하지 않는 설정입니다.');
        if (typeof db === 'undefined') throw new Error('Firestore가 준비되지 않았습니다.');

        const patch = {};
        patch[key] = !!enabled;
        patch.updatedAt = firebase.firestore.FieldValue.serverTimestamp();
        patch.updatedBy = (auth.currentUser && auth.currentUser.uid) ? auth.currentUser.uid : 'admin';
        await db.collection('settings').doc('automation_policy').set(patch, { merge: true });
        settings[key] = !!enabled;
        loaded = true;
        saveLocalCache();

        if (key === 'bookingConsentEnabled' && typeof ensureAutomationPolicyBookingBox === 'function') {
            try { ensureAutomationPolicyBookingBox(); } catch (_) {}
            try { updateBookingSubmitAvailability(); } catch (_) {}
        }
        return window.getAutomationPolicySettings();
    };

    function switchHtml(key, title, desc) {
        const on = settings[key] !== false;
        return `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid #fed7aa;">
            <div><div style="font-weight:800;color:#7c2d12;font-size:.82rem;">${title}</div><div style="font-size:.68rem;color:#78716c;margin-top:2px;">${desc}</div></div>
            <button type="button" onclick="toggleAutomationPolicySetting('${key}')" style="min-width:58px;border:none;border-radius:999px;padding:7px 12px;cursor:pointer;font-weight:900;background:${on ? '#16a34a' : '#cbd5e1'};color:${on ? '#fff' : '#475569'};">${on ? 'ON' : 'OFF'}</button>
        </div>`;
    }

    window.renderAutomationPolicyControls = async function (container) {
        if (!container || !window.isAdmin) return;
        await window.loadAutomationPolicySettings(false);
        let panel = container.querySelector('#automationPolicyControlPanel');
        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'automationPolicyControlPanel';
            container.insertBefore(panel, container.firstChild);
        }
        panel.style.cssText = 'background:#fff;border:1px solid #fdba74;border-radius:10px;padding:10px 12px;margin-bottom:12px;';
        panel.innerHTML = `<div style="font-weight:900;color:#9a3412;margin-bottom:2px;">⚠️ 공정 예약 안내 노출</div>
            <div style="font-size:.68rem;color:#78716c;margin-bottom:5px;">안내만 켜고 끕니다. 매크로 감시·포렌식 기록은 계속 작동합니다.</div>
            ${switchHtml('loginNoticeEnabled', '로그인 안내 팝업', '일반 회원 로그인 후 하루 한 번 표시')}
            ${switchHtml('bookingConsentEnabled', '예약 단계 동의 확인', '예약창 안내문·체크박스·버튼 잠금을 함께 제어')}`;
    };

    window.toggleAutomationPolicySetting = async function (key) {
        if (!window.isAdmin) return alert('관리자만 변경할 수 있습니다.');
        const next = !(settings[key] !== false);
        try {
            await window.saveAutomationPolicySetting(key, next);
            const box = document.getElementById('macroMonitorBox');
            if (box) await window.renderAutomationPolicyControls(box);
        } catch (err) {
            console.error(err);
            alert('설정 저장 실패: ' + (err && err.message ? err.message : err));
        }
    };

    window.addEventListener('DOMContentLoaded', function () {
        setTimeout(function () { window.loadAutomationPolicySettings(false); }, 0);
    });
})();
