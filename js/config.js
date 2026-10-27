/*
 * 국제 테니스장 예약 앱 - Step 3 Config
 * 기능 로직은 index.dev.html에 그대로 두고, 변경 빈도가 높은 설정/상수만 분리했습니다.
 * 배포 전에는 dev/index.dev.html로 먼저 화면/예약 동작을 확인하세요.
 */

var firebaseConfig = window.firebaseConfig = {
      apiKey: "AIzaSyD_KKxj9MnV_CwvW2Kz5dTENQ15KftKrjE",
      authDomain: "tenniskj.firebaseapp.com",
      projectId: "tenniskj",
      storageBucket: "tenniskj.firebasestorage.app",
      messagingSenderId: "783970944210",
      appId: "1:783970944210:web:91d07da54028e6db5c990b"
    };

if (APP_ENV.isDevelopment) window.firebaseConfig = firebaseConfig = APP_ENV.firebaseConfig;

var PORTONE_ID = window.PORTONE_ID = "imp31773320";
    var adminPass = window.adminPass = "1234"; 
var currentCenter = window.currentCenter = "국제"; // 기본값
var adminDefaultName = window.adminDefaultName = "김테협"; // 설정에서 변경 가능한 관리자 예약 기본 이름
var isCenterOpen = window.isCenterOpen = false;
/* [수정] 지점별 이미지와 코트 위치 설정 */

var CENTERS = window.CENTERS = {
    "국제": { 
        name: "장유 국제테니스장", 
        courts: 8,
        img: "court_map.jpg", // 기존 이미지 파일명
        // 좌표 설정: { 코트번호: [위에서%, 왼쪽에서%, 너비%, 높이%] }
        pos: {
            1: [76, 52, 44, 21], // 1코트 위치
            2: [53, 52, 44, 21], 
            3: [76, 4, 44, 21],
            4: [53, 4, 44, 21],
            5: [26, 52, 44, 21],
            6: [3, 52, 44, 21],
            7: [26, 4, 44, 21],
            8: [3, 4, 44, 21]
        }
    },
    
    "능동": { 
        name: "능동 테니스장", 
        courts: 8,
        img: "assets/neungdong-map.svg",
        mapRotation: -42,
        pos: {"1":[18.125,51.666666666666664,10,18.125],"2":[29.125,41.888888888888886,10,18.125],"3":[40.125,32.111111111111114,10,18.125],"4":[51.125,22.333333333333332,10,18.125],"5":[41.25,72.22222222222223,10,18.125],"6":[52.25,62.44444444444444,10,18.125],"7":[63.25,52.666666666666664,10,18.125],"8":[74.25,42.888888888888886,10,18.125]}
    },
    
    "동부": { 
        name: "동부 테니스장", 
        courts: 7,
        img: "assets/dongbu-map.svg",
        pos: {
            // 아직 좌표를 모르니 비워둡니다 (빨간 박스 안 나옴)
        } 
    },
    
    "원도심": { 
        name: "원도심 테니스장",
        courts: 4, 
        img: "assets/oldtown-map.svg",
        pos: {
            // 좌표를 입력해야 빨간 박스가 뜹니다
        } 
    }
};

var HOLIDAYS = window.HOLIDAYS = {
    '2026-01-01': '신정',
    '2026-02-16': '설날', '2026-02-17': '설날', '2026-02-18': '설날',
    '2026-03-01': '삼일절', '2026-03-02': '대체공휴일',
    '2026-05-01': '근로자의 날',
    '2026-05-05': '어린이날',
    '2026-05-24': '부처님오신날', '2026-05-25': '대체공휴일',
    '2026-06-03': '전국동시지방선거',
    '2026-06-06': '현충일',
    '2026-07-17': '제헌절',
    '2026-08-15': '광복절', '2026-08-17': '대체공휴일',
    '2026-09-24': '추석 연휴', '2026-09-25': '추석', '2026-09-26': '추석 연휴', '2026-09-27': '추석 연휴',
    '2026-10-03': '개천절', '2026-10-05': '대체공휴일',
    '2026-10-09': '한글날',
    '2026-12-25': '성탄절'
};

var KAKAO_JS_KEY = window.KAKAO_JS_KEY || "b4e236cbf329d2176957d5b6ee0c22e9";
window.KAKAO_JS_KEY = KAKAO_JS_KEY;

var NAVER_AUTH_BASE = window.NAVER_AUTH_BASE || "/naver-auth";
window.NAVER_AUTH_BASE = NAVER_AUTH_BASE;

var CURRENT_APP_VERSION = window.CURRENT_APP_VERSION || 7;
window.CURRENT_APP_VERSION = CURRENT_APP_VERSION;

/* Multi-venue rollout: metadata exists independently from member visibility.
 * Existing all-open flags must not launch newly prepared venues.
 * Only entries explicitly saved in the per-venue map become public. */
var centerVisibility = null;
var centerPublicationApprovals = null;
function normalizeCenterVisibility(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const result = {};
    Object.keys(CENTERS).forEach(id => { result[id] = id === '국제' || value[id] === true; });
    return result;
}
function isPublicCenter(id) {
    if (!Object.prototype.hasOwnProperty.call(CENTERS, id)) return false;
    if (id === '국제') return true;
    return !!centerVisibility && centerVisibility[id] === true && !!centerPublicationApprovals && centerPublicationApprovals[id] === true;
}
function canSelectCenter(id, administrator) {
    return Object.prototype.hasOwnProperty.call(CENTERS, id) && (isPublicCenter(id) || (administrator === true && hasDeveloperAccess()));
}
function renderCenterVisibilitySettings() {
    const list = document.getElementById('centerVisibilityList');
    if (!list) return;
    renderDeveloperVenueControls();
    const visibleIds = hasDeveloperAccess() ? Object.keys(CENTERS) : ['국제'];
    list.replaceChildren(...visibleIds.map(id => {
        const row = document.createElement('label');
        row.className = 'center-visibility-row';
        const name = document.createElement('span');
        name.textContent = CENTERS[id].name;
        const count = document.createElement('small');
        count.textContent = CENTERS[id].courts + '면';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.dataset.centerVisibility = id;
        input.setAttribute('aria-label', CENTERS[id].name + ' 공개');
        input.checked = isPublicCenter(id);
        input.disabled = id === '국제';
        input.addEventListener('change', syncCenterVisibilityMaster);
        const status = document.createElement('span');
        status.className = 'center-visibility-state';
        row.append(name, count, status, input);
        return row;
    }));
    syncCenterVisibilityMaster();
}
function syncCenterVisibilityMaster() {
    const inputs = Array.from(document.querySelectorAll('[data-center-visibility]'));
    inputs.forEach(input => {
        input.previousElementSibling.textContent = input.disabled ? '항상 공개' : input.checked ? '공개' : '비공개';
        input.closest('label').classList.toggle('is-public', input.checked);
    });
    const additional = inputs.filter(input => !input.disabled);
    const master = document.getElementById('setOpenCenter');
    if (master) {
        master.checked = additional.length > 0 && additional.every(input => input.checked);
        master.indeterminate = additional.some(input => input.checked) && !master.checked;
    }
}
function setAllCenterVisibility(open) {
    if (!hasDeveloperAccess()) return;
    document.querySelectorAll('[data-center-visibility]').forEach(input => {
        if (!input.disabled) input.checked = open === true;
    });
    syncCenterVisibilityMaster();
}
function readCenterVisibilitySettings() {
    const result = {};
    Object.keys(CENTERS).forEach(id => { result[id] = isPublicCenter(id); });
    if (!hasDeveloperAccess()) return result;
    document.querySelectorAll('[data-center-visibility]').forEach(input => {
        if (Object.prototype.hasOwnProperty.call(CENTERS, input.dataset.centerVisibility)) result[input.dataset.centerVisibility] = input.checked;
    });
    result['국제'] = true;
    return result;
}

/* Booking screen presentation uses the existing date and center state. */
function updateBookingContext() {
    const center = CENTERS[currentCenter] || CENTERS['국제'];
    const table = document.getElementById('schTable');
    if (table) table.style.setProperty('--court-count', center.courts);
    const grid = document.getElementById('gridArea');
    if (grid) {
        grid.scrollTop = 0;
        grid.dataset.center = currentCenter;
        grid.dataset.surface = currentCenter === '국제' ? 'hard' : 'turf';
        grid.setAttribute('role', 'region');
        grid.setAttribute('aria-label', center.name + ' 코트 예약 현황');
        const centerWatermark = () => {
            const courtHeader = grid.querySelector('.head-court');
            const timeHeader = grid.querySelector('.head-time');
            const left = courtHeader ? courtHeader.getBoundingClientRect().width : 0;
            const top = timeHeader ? timeHeader.getBoundingClientRect().height : 0;
            const width = Math.max(0, grid.clientWidth - left);
            const height = Math.max(0, grid.clientHeight - top);
            const fontSize = Math.min(220, height * .62, (width - 24) / (currentCenter.length + .55));
            grid.style.setProperty('--watermark-center-x', (grid.scrollLeft + left + width / 2) + 'px');
            grid.style.setProperty('--watermark-center-y', (grid.scrollTop + top + height / 2) + 'px');
            grid.style.setProperty('--watermark-label-width', Math.max(0, width - 24) + 'px');
            grid.style.setProperty('--watermark-font-size', Math.max(32, fontSize) + 'px');
        };
        if (!grid._watermarkResizeObserver && typeof ResizeObserver !== 'undefined') {
            grid._watermarkResizeObserver = new ResizeObserver(centerWatermark);
            grid._watermarkResizeObserver.observe(grid);
            if (table) grid._watermarkResizeObserver.observe(table);
        }
        if (!grid._watermarkCenterBound) {
            grid.addEventListener('scroll', centerWatermark, { passive: true });
            grid._watermarkCenterBound = true;
        }
        centerWatermark();
    }
    const name = document.getElementById('bookingCenterName');
    if (name) name.textContent = center.name;
    const count = document.getElementById('bookingCourtCount');
    if (count) count.textContent = center.courts + '개 코트';
    const preview = document.getElementById('bookingAdminPreview');
    if (preview) preview.hidden = !(typeof isAdmin !== 'undefined' && isAdmin && !isPublicCenter(currentCenter));
    const value = document.getElementById('hiddenDate')?.value;
    const label = document.getElementById('bookingDateLabel');
    if (value && label) {
        const date = new Date(value + 'T12:00:00');
        label.textContent = new Intl.DateTimeFormat('ko-KR', {month:'long',day:'numeric',weekday:'long'}).format(date);
    }
    renderBookingWeek();
}
function renderBookingWeek() {
    const host = document.getElementById('bookingWeek');
    const value = document.getElementById('hiddenDate')?.value;
    if (!host || !value) return;
    const selectedDate = new Date(value + 'T12:00:00');
    const start = new Date(selectedDate);
    start.setDate(start.getDate() - start.getDay());
    const today = new Date(); today.setHours(0,0,0,0);
    const limit = typeof currentUser !== 'undefined' && currentUser?.isCitizen ? 13 : 6;
    host.replaceChildren(...Array.from({length:7}, (_,i) => {
        const date = new Date(start); date.setDate(start.getDate() + i);
        const key = date.getFullYear() + '-' + String(date.getMonth()+1).padStart(2,'0') + '-' + String(date.getDate()).padStart(2,'0');
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'booking-day' + (i===0?' sunday':'') + (i===6?' saturday':'');
        button.setAttribute('aria-pressed', String(key === value));
        button.setAttribute('aria-label', new Intl.DateTimeFormat('ko-KR',{month:'long',day:'numeric',weekday:'long'}).format(date));
        const day = document.createElement('span'); day.textContent = ['일','월','화','수','목','금','토'][i];
        const number = document.createElement('strong'); number.textContent = date.getDate();
        button.append(day,number);
        button.disabled = !(typeof isAdmin !== 'undefined' && isAdmin) && (date.getTime() - today.getTime()) / 86400000 > limit;
        button.addEventListener('click', () => pickDate(key));
        return button;
    }));
}
function toggleBookingCalendar() {
    const open = document.body.classList.toggle('booking-calendar-open');
    const button = document.getElementById('bookingCalendarToggle');
    button.setAttribute('aria-expanded', String(open));
    button.textContent = open ? '달력 닫기' : '날짜 변경';
    if (open) {
        const wrap = document.getElementById('calendarWrap');
        if (wrap.classList.contains('folded')) toggleCalendar();
    }
}
if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', () => {
    renderCenterVisibilitySettings();
    updateBookingContext();
    // Also covers startup code assigning today's value after the config listener.
    setTimeout(updateBookingContext, 0);
});

if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', () => {
    const tabs = ['tabMyUp', 'tabMyPast'].map(id => document.getElementById(id)).filter(Boolean);
    const sync = () => tabs.forEach(tab => tab.setAttribute('aria-selected', String(tab.style.borderBottomWidth === '3px')));
    tabs.forEach(tab => new MutationObserver(sync).observe(tab, { attributes: true, attributeFilter: ['style'] }));
    sync();
    document.querySelector('.account-tabs')?.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const next = tabs.find(tab => tab !== document.activeElement);
        if (next) { next.click(); next.focus(); }
    });
});

if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', () => {
    const status = document.getElementById('bookingPriceStatus');
    const retry = document.getElementById('bookingPriceRetry');
    const modal = document.getElementById('modalBook');
    if (!status || !retry || !modal) return;
    const sync = () => {
        const state = typeof bookingPriceState !== 'undefined' ? bookingPriceState.status : 'idle';
        modal.dataset.quoteState = state;retry.hidden = state !== 'error';
    };
    new MutationObserver(sync).observe(status, { childList: true, characterData: true, subtree: true });sync();
});

// Shared presentation for list loading, genuinely empty results and recoverable errors.
function renderListState(container, options) {
    const state = document.createElement('div');state.className = 'app-list-state app-list-state--' + options.kind + (options.append ? ' app-list-state--inline' : '');
    state.setAttribute('role', options.kind === 'error' ? 'alert' : 'status');
    const icon = document.createElement('span');icon.className = 'app-list-state-icon';icon.setAttribute('aria-hidden','true');
    if (options.kind !== 'loading') icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 13h5M8 17h3"/></svg>';
    const title = document.createElement('h3');title.textContent = options.title;
    const detail = document.createElement('p');detail.textContent = options.detail || '';
    state.append(icon,title,detail);
    if (options.action && options.actionLabel) {
        const button = document.createElement('button');button.type = 'button';button.textContent = options.actionLabel;
        button.addEventListener('click',options.action);state.append(button);
    }
    if (options.append) container.append(state);else container.replaceChildren(state);
    container.dataset.listState = options.kind;
    container.setAttribute('aria-busy',String(options.kind === 'loading'));
}

// A visibility checkbox alone must never launch an unannounced venue.
function confirmCenterPublication(nextVisibility) {
    const opening = Object.keys(CENTERS).filter(id => id !== '국제' && nextVisibility[id] === true && !isPublicCenter(id));
    if (!opening.length) return true;
    const names = opening.map(id => CENTERS[id].name).join(', ');
    if (!confirm('추가 구장 공개 확인 (1/2)\n\n'+names+'\n\n저장하면 일반 회원에게 구장이 표시되고 예약할 수 있습니다. 오픈 일정이 확정된 구장입니까?')) return false;
    const phrase = opening.join(', ') + ' 공개';
    const answer = prompt('추가 구장 공개 최종 확인 (2/2)\n\n공개 대상: '+names+'\n취소하면 설정은 저장되지 않습니다.\n\n아래 문구를 정확히 입력해 주세요.\n'+phrase);
    if (answer !== phrase) {
        if (answer !== null) alert('확인 문구가 일치하지 않아 공개 설정을 저장하지 않았습니다.');
        return false;
    }
    return true;
}

// Developer tools are locked on every new page/session. Never persist passwords or unlock state.
(function(){
    const email='canyone2@korea.com';
    let unlockedUid='', expires=0, timer;
    window.isDeveloperAccount=function(){
        const user=typeof auth!=='undefined'?auth.currentUser:null;
        return !!user && String(user.email||'').trim().toLowerCase()===email;
    };
    window.hasDeveloperAccess=function(){
        const user=typeof auth!=='undefined'?auth.currentUser:null;
        return isDeveloperAccount() && !!user.uid && unlockedUid===user.uid && Date.now()<expires;
    };
    window.lockDeveloperAccess=function(refresh=true){
        unlockedUid='';expires=0;clearTimeout(timer);
        if(refresh && typeof updateAdminUI==='function') updateAdminUI();
        if(document.getElementById('centerVisibilityList'))renderCenterVisibilitySettings();
    };
    window.syncDeveloperSession=function(user){
        if(!user || user.uid!==unlockedUid || String(user.email||'').toLowerCase()!==email)lockDeveloperAccess(false);
    };
    window.renderDeveloperVenueControls=function(){
        const unlocked=hasDeveloperAccess(), developer=isDeveloperAccount();
        const access=document.getElementById('developerVenueAccess');
        const controls=document.getElementById('developerVenueControls');
        const button=document.getElementById('btnDeveloperVenueUnlock');
        if(access)access.hidden=unlocked;
        if(controls)controls.hidden=!unlocked;
        if(button)button.hidden=!developer||unlocked;
        const lock=document.getElementById('btnDeveloperVenueLock');if(lock)lock.hidden=!unlocked;
        const help=document.getElementById('developerVenueHelp');
        if(help)help.textContent=developer?'개발자 계정의 로그인 비밀번호를 다시 확인하면 15분 동안 개발 메뉴를 사용할 수 있습니다.':'추가 구장 기능은 개발 중입니다. 공개 설정은 개발자만 사용할 수 있습니다.';
    };
    window.openDeveloperVenueUnlock=function(){
        if(!isDeveloperAccount())return alert('지정된 개발자 계정만 사용할 수 있습니다.');
        let modal=document.getElementById('modalDeveloperUnlock');
        if(!modal){
            modal=document.createElement('div');modal.id='modalDeveloperUnlock';modal.className='modal-mask';
            modal.innerHTML='<form class="modal-win developer-unlock-form" aria-labelledby="developerUnlockTitle"><button class="modal-close" type="button" aria-label="닫기">×</button><h2 id="developerUnlockTitle">개발자 확인</h2><p>로그인한 개발자 계정의 비밀번호를 입력해 주세요.</p><label for="developerUnlockPassword">로그인 비밀번호</label><input id="developerUnlockPassword" type="password" autocomplete="current-password" required/><p id="developerUnlockError" role="alert"></p><button type="submit" class="btn-full bg-blue">비밀번호 확인</button></form>';
            document.body.append(modal);
            modal.querySelector('.modal-close').onclick=()=>{modal.querySelector('input').value='';closeModal('modalDeveloperUnlock');};
            modal.querySelector('form').onsubmit=async event=>{
                event.preventDefault();
                const input=modal.querySelector('input'),button=modal.querySelector('[type=submit]'),error=document.getElementById('developerUnlockError');
                const password=input.value;input.value='';error.textContent='';button.disabled=true;button.textContent='확인 중…';
                try{
                    if(!isDeveloperAccount())throw Error('account-changed');
                    const user=auth.currentUser,uid=user.uid;
                    const credential=firebase.auth.EmailAuthProvider.credential(user.email,password);
                    await user.reauthenticateWithCredential(credential);
                    const result=await user.getIdTokenResult(true);
                    if(auth.currentUser?.uid!==uid || !isDeveloperAccount() || String(result.claims.email||'').toLowerCase()!==email)throw Error('account-changed');
                    unlockedUid=uid;expires=Date.now()+15*60*1000;
                    clearTimeout(timer);timer=setTimeout(()=>lockDeveloperAccess(),15*60*1000);
                    closeModal('modalDeveloperUnlock');updateAdminUI();renderCenterVisibilitySettings();
                }catch(_){error.textContent='비밀번호를 확인하지 못했습니다. 개발자 계정의 로그인 비밀번호로 다시 시도해 주세요.';}
                finally{button.disabled=false;button.textContent='비밀번호 확인';}
            };
        }
        document.getElementById('developerUnlockPassword').value='';document.getElementById('developerUnlockError').textContent='';
        openModal('modalDeveloperUnlock');setTimeout(()=>document.getElementById('developerUnlockPassword').focus(),80);
    };
})();
