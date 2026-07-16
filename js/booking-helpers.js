/*
 * STEP 9 - Booking/payment helper functions
 *
 * Extracted from index.dev.html without behavior changes.
 * Intentionally NOT moved in this step:
 * - doPay()
 * - saveBook()
 * - Firestore transaction write block
 * - PortOne payment request block
 */

function calcPay() {
        const isLocal = document.getElementById('isLocal').checked;
        const date = document.getElementById('hiddenDate').value;
        const isRed = isWeekendOrHoliday(date);
        let total = 0;
        let breakdown = []; // 금액 상세 내역

        selected.forEach(s => {
            const pricingInfo = getConfiguredPriceInfo(date, s.t);
            const isNight = pricingInfo.isNight;
            const price = getMatrixPriceBySlot(date, s.t, isLocal);
            total += price;

            let priceType = '';
            if (isRed && isNight) priceType = '주말야간';
            else if (isRed) priceType = '주말주간';
            else if (isNight) priceType = '평일야간';
            else priceType = '평일주간';

            breakdown.push({
                court: s.c,
                time: s.t,
                price: price,
                type: priceType
            });
        });

        let priceHTML = `<span id="txtPrice" style="color:var(--primary); font-size:1.6rem;">${total.toLocaleString()}</span>원`;

        if (isLocal) {
            priceHTML += `<div style="font-size:0.75rem; color:#059669; margin-top:4px;">✓ 일반 요금적용</div>`;
        }

        const priceGroups = {};
        breakdown.forEach(b => {
            if (!priceGroups[b.type]) {
                priceGroups[b.type] = { count: 0, price: b.price };
            }
            priceGroups[b.type].count++;
        });

        let detailHTML = '<div style="margin-top:8px; font-size:0.75rem; color:#64748b; border-top:1px dashed #e2e8f0; padding-top:8px;">';
        Object.entries(priceGroups).forEach(([type, info]) => {
            detailHTML += `<div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                <span>${type} ${info.count}시간</span>
                <span>${info.price.toLocaleString()}원 × ${info.count}</span>
            </div>`;
        });
        detailHTML += '</div>';

        document.getElementById('txtPrice').parentElement.innerHTML = `
            <span style="font-size:1rem; color:#64748b;">결제금액:</span> 
            ${priceHTML}
            ${detailHTML}
        `;
    }

async function validateDailyReservationLimits(meta) {
    if (isAdmin) return;
    const phone = String(meta.phone || '').trim();
    const date = meta.date;
    const newSlots = Array.isArray(meta.slots) ? meta.slots : [];
    if (!phone || !date || !newSlots.length) return;

    const snap = await db.collection('reservations')
        .where('phone', '==', phone)
        .where('date', '==', date)
        .where('status', 'in', ['PENDING', 'BOOKED', 'BLOCKED'])
        .get();

    const slotMap = new Map();
    snap.forEach(doc => {
        const d = doc.data() || {};
        if (d.court == null || d.time == null) return;
        const key = `${d.court}_${d.time}`;
        slotMap.set(key, { court: Number(d.court), time: Number(d.time) });
    });
    newSlots.forEach(s => {
        const key = `${s.court}_${s.time}`;
        slotMap.set(key, { court: Number(s.court), time: Number(s.time) });
    });

    const merged = Array.from(slotMap.values());
    if (merged.length > 6) {
        throw new Error('하루 예약은 전체 합산 최대 6시간까지만 가능합니다.');
    }

    const courts = [...new Set(merged.map(s => Number(s.court)))];
    if (courts.length > 2) {
        throw new Error('하루 예약은 최대 2개 코트까지만 가능합니다.');
    }

    const byCourt = {};
    merged.forEach(s => {
        const c = Number(s.court);
        byCourt[c] = (byCourt[c] || 0) + 1;
    });
    for (const [court, hours] of Object.entries(byCourt)) {
        if (hours > 3) {
            throw new Error(`${court}코트는 하루 최대 3시간까지만 예약 가능합니다.`);
        }
    }
}

function validateRequestedSlotPattern(slots, occupiedMap) {
    if (isAdmin) return;
    if (!Array.isArray(slots) || slots.length === 0) return;

    const OPEN_TIME = 7;
    const LAST_START_TIME = 21;
    const byCourt = {};

    slots.forEach(slot => {
        const court = Number(slot.c);
        const time = Number(slot.t);
        if (!Number.isFinite(court) || !Number.isFinite(time)) return;
        if (!byCourt[court]) byCourt[court] = [];
        byCourt[court].push(time);
    });

    for (const [court, timesRaw] of Object.entries(byCourt)) {
        const times = [...new Set(timesRaw)].sort((a, b) => a - b);
        let block = [times[0]];

        for (let i = 1; i < times.length; i++) {
            if (times[i] === times[i - 1] + 1) {
                block.push(times[i]);
            } else {
                checkRequestedBlock(court, block, occupiedMap, OPEN_TIME, LAST_START_TIME);
                block = [times[i]];
            }
        }

        if (block.length) {
            checkRequestedBlock(court, block, occupiedMap, OPEN_TIME, LAST_START_TIME);
        }
    }
}

function checkRequestedBlock(court, block, occupiedMap, openTime, lastStartTime) {
    if (!Array.isArray(block) || block.length === 0) return;
    if (block.length >= 2) return;

    const time = Number(block[0]);
    const prevKey = `${court}_${time - 1}`;
    const nextKey = `${court}_${time + 1}`;

    if (time === lastStartTime) return;

    const isPrevBlocked = (time - 1) < openTime || occupiedMap.has(prevKey);
    const isNextBlocked = (time + 1) > lastStartTime || occupiedMap.has(nextKey);

    if (isPrevBlocked && isNextBlocked) return;

    throw new Error('일반 회원 예약은 기본 2시간입니다. 다만 끼어 있는 1시간이나 마지막 1시간만 예외적으로 예약할 수 있습니다.');
}



// ===== v8 정밀 상호작용 증거 수집 =====
var macroInteractionBuffer = window.macroInteractionBuffer = window.macroInteractionBuffer || [];
var macroInteractionInstalled = window.macroInteractionInstalled || false;

function installMacroInteractionRecorder() {
    if (window.macroInteractionInstalled) return;
    window.macroInteractionInstalled = true;
    const record = function(ev) {
        try {
            const now = Date.now();
            const target = ev && ev.target;
            const cell = target && target.closest ? target.closest('.data-cell') : null;
            const bookBtn = target && target.closest ? target.closest('#btnMainBook, #btnBookAction, [onclick*="openBook"], [onclick*="doPay"]') : null;
            const relevant = !!cell || !!bookBtn || (ev && ev.type === 'keydown');
            if (!relevant) return;
            macroInteractionBuffer.push({
                atMs: now,
                type: String(ev.type || ''),
                trusted: ev.isTrusted === true,
                pointerType: String(ev.pointerType || ''),
                key: ev.type === 'keydown' ? String(ev.key || '') : '',
                target: cell ? String(cell.id || 'grid-cell') : (bookBtn ? String(bookBtn.id || 'book-action') : String((target && target.id) || ''))
            });
            const cutoff = now - 120000;
            while (macroInteractionBuffer.length && macroInteractionBuffer[0].atMs < cutoff) macroInteractionBuffer.shift();
            if (macroInteractionBuffer.length > 300) macroInteractionBuffer.splice(0, macroInteractionBuffer.length - 300);
        } catch (_) {}
    };
    ['pointerdown','click','keydown','touchstart'].forEach(type => {
        document.addEventListener(type, record, { capture: true, passive: true });
    });
}

function getBookingInteractionEvidence() {
    installMacroInteractionRecorder();
    const now = Date.now();
    const recent = macroInteractionBuffer.filter(x => now - Number(x.atMs || 0) <= 60000);
    const trusted = recent.filter(x => x.trusted);
    const gridTrusted = trusted.filter(x => String(x.target || '').startsWith('c-'));
    const last = recent.length ? recent[recent.length - 1] : null;
    const lastTrusted = trusted.length ? trusted[trusted.length - 1] : null;
    const gaps = [];
    for (let i = 1; i < gridTrusted.length; i++) gaps.push(gridTrusted[i].atMs - gridTrusted[i-1].atMs);
    return {
        interactionCount60s: recent.length,
        trustedInteractionCount60s: trusted.length,
        trustedGridInteractionCount60s: gridTrusted.length,
        untrustedInteractionCount60s: recent.length - trusted.length,
        lastInteractionAgoMs: last ? Math.max(0, now - last.atMs) : -1,
        lastTrustedInteractionAgoMs: lastTrusted ? Math.max(0, now - lastTrusted.atMs) : -1,
        lastPointerType: last ? String(last.pointerType || '') : '',
        gridIntervalMinMs: gaps.length ? Math.min.apply(null, gaps) : 0,
        gridIntervalMedianMs: gaps.length ? gaps.slice().sort((a,b)=>a-b)[Math.floor(gaps.length/2)] : 0
    };
}

installMacroInteractionRecorder();

// ===== v10 예약 오픈 전용 포렌식 모드 =====
var FORENSIC_OPEN_HOUR = 0;
var FORENSIC_OPEN_MINUTE = 0;
var FORENSIC_BEFORE_MS = 30 * 1000;
var FORENSIC_AFTER_MS = 90 * 1000;

function getForensicOpenState(nowMs) {
    const now = new Date(nowMs || Date.now());
    const todayOpen = new Date(now);
    todayOpen.setHours(FORENSIC_OPEN_HOUR, FORENSIC_OPEN_MINUTE, 0, 0);
    const prevOpen = todayOpen.getTime() <= now.getTime() ? todayOpen.getTime() : todayOpen.getTime() - 86400000;
    const nextOpen = prevOpen + 86400000;
    const prevDelta = now.getTime() - prevOpen;
    const nextDelta = now.getTime() - nextOpen;
    const delta = Math.abs(prevDelta) <= Math.abs(nextDelta) ? prevDelta : nextDelta;
    const active = delta >= -FORENSIC_BEFORE_MS && delta <= FORENSIC_AFTER_MS;
    return {
        active,
        openDeltaMs: delta,
        openEpochMs: now.getTime() - delta,
        forensicVersion: 'v10-open-forensic',
        windowBeforeMs: FORENSIC_BEFORE_MS,
        windowAfterMs: FORENSIC_AFTER_MS
    };
}

function getForensicEventSnapshot() {
    const state = getForensicOpenState(Date.now());
    if (!state.active) return { ...state, events: [] };
    const minMs = state.openEpochMs - FORENSIC_BEFORE_MS;
    const maxMs = state.openEpochMs + FORENSIC_AFTER_MS;
    const events = macroInteractionBuffer
        .filter(x => Number(x.atMs || 0) >= minMs && Number(x.atMs || 0) <= maxMs)
        .slice(-120)
        .map(x => ({
            d: Number(x.atMs || 0) - state.openEpochMs,
            t: String(x.type || '').slice(0,16),
            tr: x.trusted === true,
            p: String(x.pointerType || '').slice(0,12),
            k: String(x.key || '').slice(0,12),
            el: String(x.target || '').slice(0,48)
        }));
    return { ...state, events };
}

function getMacroClientId() {
    const key = 'tenniskj_macro_client_id';
    let value = '';
    try { value = localStorage.getItem(key) || ''; } catch (_) {}
    if (!value) {
        value = 'cli_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
        try { localStorage.setItem(key, value); } catch (_) {}
    }
    return value;
}

function createBookingRequestId(uid) {
    const safeUid = String(uid || 'guest').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 'guest';
    return 'req_' + safeUid + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
}

function getMacroSessionId() {
    const key = 'tenniskj_macro_session_id';
    let value = '';
    try { value = sessionStorage.getItem(key) || ''; } catch (_) {}
    if (!value) {
        value = 'ses_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
        try { sessionStorage.setItem(key, value); } catch (_) {}
    }
    return value;
}

function nextMacroClientSequence() {
    const key = 'tenniskj_macro_sequence';
    let seq = 0;
    try {
        seq = Number(sessionStorage.getItem(key) || '0') + 1;
        sessionStorage.setItem(key, String(seq));
    } catch (_) {
        seq = Date.now();
    }
    return seq;
}

async function logBookingAttempt(payload) {
    try {
        await db.collection('booking_attempt_logs').add({
            ...payload,
            clientId: payload.clientId || getMacroClientId(),
            sessionId: payload.sessionId || getMacroSessionId(),
            clientSequence: payload.clientSequence || nextMacroClientSequence(),
            clientAtMs: payload.clientAtMs || Date.now(),
            pagePath: location.pathname || '',
            pageVisibility: document.visibilityState || '',
            platform: navigator.platform || '',
            language: navigator.language || '',
            hardwareConcurrency: Number(navigator.hardwareConcurrency || 0),
            deviceMemory: Number(navigator.deviceMemory || 0),
            maxTouchPoints: Number(navigator.maxTouchPoints || 0),
            webdriver: navigator.webdriver === true,
            screenWidth: Number((window.screen && window.screen.width) || 0),
            screenHeight: Number((window.screen && window.screen.height) || 0),
            viewportWidth: Number(window.innerWidth || 0),
            viewportHeight: Number(window.innerHeight || 0),
            navigationStartMs: Number((performance && performance.timeOrigin) || 0),
            perfNowMs: Number((performance && performance.now && performance.now()) || 0),
            ...getBookingInteractionEvidence(),
            forensicOpen: getForensicEventSnapshot(),
            timeZone: (Intl && Intl.DateTimeFormat) ? Intl.DateTimeFormat().resolvedOptions().timeZone : '',
            createdAt: firebase.firestore.FieldValue.serverTimestamp()
        });
    } catch (e) {
        if (String(e && e.code || '').includes('permission-denied')) bookingGuardCollectionsReadable = false;
        console.warn('booking_attempt_logs 저장 실패:', e);
    }
}

async function getRecentAttemptLogs(uid, ms) {
    if (!bookingGuardCollectionsReadable) return [];
    try {
        const since = firebase.firestore.Timestamp.fromMillis(Date.now() - ms);
        const snap = await db.collection('booking_attempt_logs')
            .where('uid', '==', uid)
            .where('createdAt', '>=', since)
            .orderBy('createdAt', 'desc')
            .get();
        return snap.docs.map(d => ({ id: d.id, ...d.data() }));
    } catch (e) {
        if (String(e && e.code || '').includes('permission-denied')) bookingGuardCollectionsReadable = false;
        console.warn('최근 시도 로그 조회 실패:', e);
        return [];
    }
}

function calcMacroScore(logs) {
    let score = 0;
    const now = Date.now();
    logs.forEach(l => {
        const ts = l.createdAt && l.createdAt.toMillis ? l.createdAt.toMillis() : 0;
        const age = now - ts;
        if (age <= 10000) score += 8;
        else if (age <= 60000) score += 3;

        if (l.result === 'TRY') score += 1;
        if (l.result === 'FAIL') score += 8;
        if (l.result === 'FAIL_GUARD') score += 12;
        if (l.result === 'SUCCESS') score += 2;
        if (l.result === 'SUCCESS_BURST') score += 35;
        if (l.result === 'UNLOGGED_SUCCESS') score += 45;
        if (l.result === 'DIRECT_WRITE_SUSPECT') score += 55;

        const reason = String(l.reason || '');
        if (reason.includes('선점')) score += 10;
        if (reason.includes('너무 빠릅니다')) score += 12;
        if (reason.includes('과도한 반복')) score += 15;
        if (reason.includes('제한되었습니다')) score += 20;
    });
    return score;
}

async function isBlockedUser(uid) {
    if (!bookingGuardCollectionsReadable) return false;
    if (!uid || uid === 'guest') return false;
    try {
        const snap = await db.collection('blocked_users').doc(uid).get();
        if (!snap.exists) return false;
        const data = snap.data() || {};
        if (data.expiresAt && data.expiresAt.toMillis && data.expiresAt.toMillis() < Date.now()) return false;
        return true;
    } catch (e) {
        if (String(e && e.code || '').includes('permission-denied')) bookingGuardCollectionsReadable = false;
        console.warn('차단 여부 조회 실패:', e);
        return false;
    }
}

async function setUserCooldown(uid) {
    if (!bookingGuardCollectionsReadable) return;
    if (!uid || uid === 'guest') return;
    try {
        await db.collection('booking_guard').doc(uid).set({
            lastAttemptAt: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
    } catch (e) {
        if (String(e && e.code || '').includes('permission-denied')) bookingGuardCollectionsReadable = false;
        console.warn('쿨다운 저장 실패:', e);
    }
}

async function checkCooldown(uid) {
    if (!uid || uid === 'guest') return;
    try {
        const snap = await db.collection('booking_guard').doc(uid).get();
        if (!snap.exists) return;
        const data = snap.data() || {};
        const last = data.lastAttemptAt && data.lastAttemptAt.toMillis ? data.lastAttemptAt.toMillis() : 0;
        if (last && Date.now() - last < MACRO_LIMITS.COOLDOWN_MS) {
            throw new Error('요청이 너무 빠릅니다. 잠시 후 다시 시도해주세요.');
        }
    } catch (e) {
        const msg = String(e && e.message ? e.message : e);
        if (msg.includes('too fast') || msg.includes('요청이 너무 빠릅니다')) throw e;
        console.warn('쿨다운 조회 실패:', e);
    }
}

async function checkBookingGuards(meta) {
    const uid = meta.uid;
    try {
        if (await isBlockedUser(uid)) {
            throw new Error('이 계정은 예약이 제한되었습니다. 관리자에게 문의하세요.');
        }

        await checkCooldown(uid);

        const shortLogs = await getRecentAttemptLogs(uid, MACRO_LIMITS.SHORT_MS);
        const shortCount = shortLogs.filter(l => l.result !== 'SUCCESS').length;
        if (shortLogs.length >= MACRO_LIMITS.SHORT_MAX || shortCount >= MACRO_LIMITS.SHORT_MAX) {
            throw new Error('짧은 시간에 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.');
        }

        const midLogs = await getRecentAttemptLogs(uid, MACRO_LIMITS.MID_MS);
        if (midLogs.length >= MACRO_LIMITS.MID_MAX) {
            throw new Error('과도한 반복 시도로 인해 잠시 예약이 제한되었습니다.');
        }

        await setUserCooldown(uid);
    } catch (e) {
        const msg = String(e && e.message ? e.message : e);
        const isExpectedGuard = msg.includes('제한되었습니다') || msg.includes('시도가 너무 많') || msg.includes('요청이 너무 빠릅니다');
        if (isExpectedGuard) throw e;
        console.warn('매크로 가드 검사 중 권한/조회 오류 - 예약은 계속 진행:', e);
    }
}

async function maybeAutoBlockUser(uid) {
    if (!bookingGuardCollectionsReadable) return;
    if (!uid || uid === 'guest' || isAdmin) return;
    const logs = await getRecentAttemptLogs(uid, 10 * 60 * 1000);
    const score = calcMacroScore(logs);
    if (score < MACRO_LIMITS.AUTO_BLOCK_SCORE) return;

    await db.collection('blocked_users').doc(uid).set({
        uid,
        reason: 'AUTO_MACRO_BLOCK',
        score,
        blockedAt: firebase.firestore.FieldValue.serverTimestamp(),
        expiresAt: firebase.firestore.Timestamp.fromMillis(Date.now() + 24 * 60 * 60 * 1000)
    }, { merge: true });
}

function sendSmsToAdmin(name, phone, date, times, method, amount) {
        // 1. 보낼 메시지 내용 구성
        const msgBody = `[테니스장 예약알림]
예약자: ${name}
날짜: ${date}
예약: ${times}
금액: ${amount}원
결제: ${method}
확인 부탁드립니다.`;

        // 2. 아이폰(iOS)인지 안드로이드인지 확인
        const userAgent = navigator.userAgent.toLowerCase();
        const isIOS = /iphone|ipad|ipod/.test(userAgent);
        
        // 3. 운영체제에 맞는 구분자 선택 (아이폰은 &, 안드로이드는 ?)
        const separator = isIOS ? '&' : '?';
        
        // 4. 문자 링크 생성 (특수문자 깨짐 방지를 위해 encodeURIComponent 사용)
        const smsLink = `sms:${admPh}${separator}body=${encodeURIComponent(msgBody)}`;
        
        // 5. 문자 앱 실행
        location.href = smsLink;
    }

async function isWeekendOrHoliday(dateStr) {
    const dt = new Date(dateStr);
    return dt.getDay() === 0 || dt.getDay() === 6 || !!HOLIDAYS[dateStr];
}

function getSeasonalPricingMatch(dateStr) {
    if (!Array.isArray(window.seasonalPricings) || window.seasonalPricings.length === 0) return null;
    return window.seasonalPricings.find(item => dateStr >= item.start && dateStr <= item.end) || null;
}

function getConfiguredPriceInfo(dateStr, time) {
    const seasonal = getSeasonalPricingMatch(dateStr);
    const defaultNightStart = Number.isFinite(Number(window.nightStartHour)) ? Number(window.nightStartHour) : 19;
    const defaultDayPrice = Number.isFinite(Number(window.dayPrice)) ? Number(window.dayPrice) : 5000;
    const defaultNightPrice = Number.isFinite(Number(window.nightPrice)) ? Number(window.nightPrice) : 10000;

    const nightStart = seasonal && Number.isFinite(Number(seasonal.nightStart)) ? Number(seasonal.nightStart) : defaultNightStart;
    const dayPrice = seasonal && Number.isFinite(Number(seasonal.dayPrice)) ? Number(seasonal.dayPrice) : defaultDayPrice;
    const nightPrice = seasonal && Number.isFinite(Number(seasonal.nightPrice)) ? Number(seasonal.nightPrice) : defaultNightPrice;
    const isNight = Number(time) >= nightStart;

    return { nightStart, dayPrice, nightPrice, isNight, seasonal };
}

function getMatrixPriceBySlot(dateStr, time, isCitizen) {
    const isWeekend = isWeekendOrHoliday(dateStr);
    const pricingInfo = getConfiguredPriceInfo(dateStr, time);
    const idx = isWeekend ? (pricingInfo.isNight ? 3 : 2) : (pricingInfo.isNight ? 1 : 0);
    return (prices && prices[idx]) ? prices[idx][isCitizen ? 0 : 1] : 0;
}

async function getPriceForDate(dateStr, time) {
    if (!window.seasonalPricings || window.seasonalPricings.length === 0) {
        const doc = await db.collection('settings').doc('seasonalPricing').get();
        window.seasonalPricings = doc.exists ? (doc.data().list || []) : [];
    }

    const pricingInfo = getConfiguredPriceInfo(dateStr, time);
    return {
        price: pricingInfo.isNight ? pricingInfo.nightPrice : pricingInfo.dayPrice,
        isNight: pricingInfo.isNight,
        nightStart: pricingInfo.nightStart
    };
}

function calcPrice(dateStr, time, isCitizen) {
    return getMatrixPriceBySlot(dateStr, time, !!isCitizen);
}
