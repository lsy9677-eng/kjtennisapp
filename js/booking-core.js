/*
 * STEP 17 - Booking Core: booking modal + payment execution + reservation save
 *
 * Moved from dev/index.dev.html:
 * - setPayMethod(m)
 * - copyAcc()
 * - openBook()
 * - reCAPTCHA callbacks
 * - doPay()
 * - saveBook()
 *
 * STEP 17 note:
 * - saveBook(uid) has been moved here without changing its Firestore transaction body.
 * - The transaction read-before-write order is intentionally preserved.
 * - dev/index.dev.html now only keeps a marker comment for saveBook.
 */

function setPayMethod(m) {
    currentPayMethod = m;

    const payTab = document.getElementById('mthPay');
    const transferTab = document.getElementById('mthTransfer');
    const transferInfo = document.getElementById('transferInfo');

    if (payTab) payTab.classList.toggle('active', m === 'PAY');
    if (transferTab) transferTab.classList.toggle('active', m === 'TRANSFER');
    if (transferInfo) transferInfo.style.display = (m === 'TRANSFER') ? 'block' : 'none';
}

function copyAcc() {
    const accEl = document.getElementById('dispAcc');
    const accText = accEl ? accEl.innerText : '';

    if (!accText) {
        alert('복사할 계좌번호가 없습니다.');
        return;
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(accText).then(() => alert('복사됨')).catch(() => {
            fallbackCopyAccount(accText);
        });
        return;
    }

    fallbackCopyAccount(accText);
}

function fallbackCopyAccount(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();

    try {
        document.execCommand('copy');
        alert('복사됨');
    } catch (err) {
        alert('복사 실패: ' + text);
    } finally {
        document.body.removeChild(textarea);
    }
}


/* STEP 14 - booking modal opener moved from dev/index.dev.html */
/* ▼▼▼ [수정] 예약창 열기 (요일 선택 제한 해제: 월~일 전체 표시) ▼▼▼ */
/* [수정] 예약 팝업 열기 (관리자 전화번호 undefined 방지) */
function openBook() {
    if(!isAdmin && !currentUser) {
        alert("로그인이 필요합니다.");
        openModal('modalLogin');
        return;
    }
    if(!isAdmin && selected.length > 6) { alert("6시간 초과입니다."); return; }
    
    // 마지막 타임 경고
    const hasLastTime = selected.some(s => s.t === 21);
    if(hasLastTime) {
        alert("21시~22시 마지막 타임 예약자 분들은 22시 5분전 경기종료, 조명off 후 퇴장 하셔야 합니다.");
    }

    // 결제수단 UI 처리
    const btnCard = document.getElementById('mthPay');
    if (typeof useCardPay !== 'undefined' && useCardPay) {
        btnCard.style.display = 'block'; setPayMethod('PAY'); 
    } else {
        btnCard.style.display = 'none'; setPayMethod('TRANSFER');
    }
    
    const date = document.getElementById('hiddenDate').value;
    
    // ▼▼▼ [개선] 예약 상세 정보 표시 ▼▼▼
    // 선택한 예약을 코트별로 그룹화
    const groupedByCourt = {};
    selected.forEach(s => {
        if (!groupedByCourt[s.c]) {
            groupedByCourt[s.c] = [];
        }
        groupedByCourt[s.c].push(s.t);
    });
    
    // 예약 상세 내역 생성
    let detailHTML = `<div style="font-size:0.85rem; color:#1e293b; margin-bottom:8px;"><b>${date}</b></div>`;
    
    Object.keys(groupedByCourt).sort((a, b) => a - b).forEach(court => {
        const times = groupedByCourt[court].sort((a, b) => a - b);
        const timeStr = times.map(t => `${String(t).padStart(2,'0')}시`).join(', ');
        detailHTML += `<div style="background:#e0f2fe; padding:6px 10px; border-radius:6px; margin-bottom:4px; border-left:3px solid #0284c7;">
            <span style="font-weight:700; color:#0c4a6e;">${court}코트</span> 
            <span style="color:#0369a1;">→ ${timeStr}</span>
        </div>`;
    });
    
    detailHTML += `<div style="margin-top:8px; text-align:center; font-size:0.9rem; color:#475569;">
        총 <b style="color:#3b82f6; font-size:1.1rem;">${selected.length}</b>시간
    </div>`;
    
    document.getElementById('modalInfo').innerHTML = detailHTML;
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
    
    const savedWeather = localStorage.getItem('tenniskj_weather_v2');
    if (savedWeather) {
        const wData = JSON.parse(savedWeather).data;
        const idx = wData.daily.time.indexOf(date);
        if (idx !== -1) {
            const rain = wData.daily.precipitation_probability_max[idx];
            const wind = wData.daily.wind_speed_10m_max[idx];
            
            let warnMsg = "";
            if (rain >= 50) warnMsg = `☔ 이날은 <b>비 예보(${rain}%)</b>가 있습니다. 기상 상황을 확인해주세요.`;
            else if (wind >= 7) warnMsg = `🌬️ 이날은 <b>강풍(${wind}m/s)</b>이 예상됩니다.`;

            if (warnMsg) {
                document.getElementById('modalInfo').innerHTML += 
                `<div style="margin-top:8px; color:#b91c1c; font-size:0.85rem; background:#fee2e2; padding:6px; border-radius:4px;">${warnMsg}</div>`;
            }
        }
    }
    const inpName = document.getElementById('bkName');
    const inpPhone = document.getElementById('bkPhone');
    const boxLocal = document.getElementById('isLocal').parentElement; 
    const adminBtns = document.getElementById('adminBtns');
    const recurBox = document.getElementById('recurOptionBox');

    if(isAdmin) {
        inpName.value = adminDefaultName || "관리자"; // 설정값 기반 관리자 기본 예약자명
        inpName.readOnly = false;
        inpName.style.background = "#fff";
        
        // ▼▼▼ [수정] admPh 변수가 없으면 빈칸("")으로 처리하여 undefined 방지
        inpPhone.value = (typeof admPh !== 'undefined' && admPh) ? admPh : ""; 
        inpPhone.readOnly = false; // 관리자는 수정 가능하게 설정
        inpPhone.style.background = "#fff";
        
        boxLocal.style.display = 'none';
        adminBtns.style.display = 'block';
        recurBox.style.display = 'block';
        
        // 정기 대관 시작일 자동 세팅
        document.getElementById('recurStart').value = date;
        document.getElementById('recurEnd').value = "";
        
        const dayCheckContainer = document.getElementById('recurDayChecks');
        dayCheckContainer.innerHTML = "";
        
        const days = [
            {v:1, n:'월'}, {v:2, n:'화'}, {v:3, n:'수'}, {v:4, n:'목'}, {v:5, n:'금'},
            {v:6, n:'토'}, {v:0, n:'일'}
        ];
        
        const curDayNum = new Date(date).getDay();

        days.forEach(d => {
            const isChecked = (d.v === curDayNum) ? "checked" : "";
            dayCheckContainer.innerHTML += `
                <label style="font-size:0.85rem; display:flex; align-items:center; margin-right:8px; margin-bottom:4px;">
                    <input type="checkbox" class="chk-recur-day" value="${d.v}" ${isChecked} style="accent-color:var(--primary);"> ${d.n}
                </label>`;
        });

    } else {
        // 일반 사용자
        inpName.value = currentUser.name;
        inpName.readOnly = true;
        inpName.style.background = "#eee";
        inpPhone.value = currentUser.phone;
        inpPhone.readOnly = true; // [추가] 일반 유저는 수정 불가
        
        boxLocal.style.display = 'flex';
        adminBtns.style.display = 'none';
        recurBox.style.display = 'none';

        const chkLocal = document.getElementById('isLocal');
        if(currentUser.isCitizen) {
            chkLocal.checked = true;
            chkLocal.nextElementSibling.innerHTML = `일반 요금`;
        } else {
            chkLocal.checked = false;
            chkLocal.nextElementSibling.innerHTML = `일반 요금`;
        }
    }

    calcPay();

    // ▼▼▼ [매크로 방지] 모달 열 때마다 reCAPTCHA 초기화 ▼▼▼
    const btn = document.getElementById('btnDoPay');
    if (!isAdmin) {
        document.getElementById('recaptchaBox').style.display = 'flex';
        btn.style.opacity = '0.4';
        btn.style.pointerEvents = 'none';
        // reCAPTCHA 위젯 리셋 (모달 재오픈 시 체크 초기화)
        try {
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
        } catch(e) {}
    } else {
        // 관리자는 reCAPTCHA 없이 바로 결제 가능
        document.getElementById('recaptchaBox').style.display = 'none';
        btn.style.opacity = '1';
        btn.style.pointerEvents = 'auto';
    }
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

    openModal('modalBook');
}


/* STEP 15 - payment execution moved from dev/index.dev.html */
/* ========== [매크로 방지] Google reCAPTCHA v2 콜백 ========== */
    let _recaptchaToken = null;

    // reCAPTCHA 체크박스 완료 시 Google이 자동으로 호출
    window.onRecaptchaSuccess = function(token) {
        _recaptchaToken = token;
        const btn = document.getElementById('btnDoPay');
        btn.style.opacity = '1';
        btn.style.pointerEvents = 'auto';
    };

    // 토큰 만료 시 (2분 후 자동 만료) Google이 자동으로 호출
    window.onRecaptchaExpired = function() {
        _recaptchaToken = null;
        const btn = document.getElementById('btnDoPay');
        btn.style.opacity = '0.4';
        btn.style.pointerEvents = 'none';
    };
    /* ========== [매크로 방지] reCAPTCHA 콜백 끝 ========== */

    async function doPay() {
        if(isAdmin && confirm("관리자 권한으로 결제 없이 예약하시겠습니까?")) { saveBook("ADMIN"); return; }
        if(!currentUser && !isAdmin) return alert("로그인 정보가 없습니다.");

        // ▼▼▼ [매크로 방지] reCAPTCHA 미완료 시 차단 (2중 안전장치) ▼▼▼
        if (!isAdmin && !_recaptchaToken) {
            alert("'나는 로봇이 아닙니다' 확인을 먼저 해주세요.");
            return;
        }
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        const amt = parseInt(document.getElementById('txtPrice').innerText.replace(/,/g,''));
        
        // ▼▼▼ [개선] 예약 내역 요약 생성 ▼▼▼
        const date = document.getElementById('hiddenDate').value;
        const groupedByCourt = {};
        selected.forEach(s => {
            if (!groupedByCourt[s.c]) groupedByCourt[s.c] = [];
            groupedByCourt[s.c].push(s.t);
        });
        
        let summary = Object.keys(groupedByCourt).sort((a,b) => a-b).map(court => {
            const times = groupedByCourt[court].sort((a,b) => a-b);
            const timeStr = times.map(t => `${String(t).padStart(2,'0')}시`).join(', ');
            return `${court}코트 ${timeStr}`;
        }).join('\n');
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
        
        if(currentPayMethod === 'TRANSFER') {
            const confirmMsg = `📅 ${date}\n${summary}\n\n💰 ${amt.toLocaleString()}원\n\n${bankName} ${bankAccount}로 입금하시겠습니까?`;
            if(!confirm(confirmMsg)) return;

            // ▼▼▼ [매크로 방지] 서버 측 reCAPTCHA 검증 ▼▼▼
            if (!isAdmin) {
                try {
                    const vRes = await fetch('/verify-recaptcha', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: _recaptchaToken })
                    });
                    const vData = await vRes.json();
                    if (!vData.success) {
                        alert('본인 확인에 실패했습니다. 다시 시도해주세요.');
                        try { if (typeof grecaptcha !== 'undefined') grecaptcha.reset(); } catch(e) {}
                        _recaptchaToken = null;
                        document.getElementById('btnDoPay').style.opacity = '0.4';
                        document.getElementById('btnDoPay').style.pointerEvents = 'none';
                        return;
                    }
                } catch(e) {
                    console.warn('reCAPTCHA 서버 검증 실패, 진행 허용:', e);
                }
            }
            // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

            saveBook("TRANSFER");
            return;
        }

        // ▼▼▼ [매크로 방지] 카드결제도 서버 측 reCAPTCHA 검증 ▼▼▼
        if (!isAdmin) {
            try {
                const vRes = await fetch('/verify-recaptcha', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: _recaptchaToken })
                });
                const vData = await vRes.json();
                if (!vData.success) {
                    alert('본인 확인에 실패했습니다. 다시 시도해주세요.');
                    try { if (typeof grecaptcha !== 'undefined') grecaptcha.reset(); } catch(e) {}
                    _recaptchaToken = null;
                    document.getElementById('btnDoPay').style.opacity = '0.4';
                    document.getElementById('btnDoPay').style.pointerEvents = 'none';
                    return;
                }
            } catch(e) {
                console.warn('reCAPTCHA 서버 검증 실패, 진행 허용:', e);
            }
        }
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        const buyerName = currentUser ? currentUser.name : "관리자";
        const buyerTel = currentUser ? currentUser.phone : admPh;

        IMP.request_pay({
            pg: "kakaopay", 
            merchant_uid: "res_"+new Date().getTime(),
            name: `테니스장 ${selected.length}건`, 
            amount: amt,
            buyer_name: buyerName, 
            buyer_tel: buyerTel
        }, function(rsp) {
            if(rsp.success) saveBook(rsp.imp_uid);
            else alert("결제 실패: " + rsp.error_msg);
        });
    }



/* STEP 17 - reservation save moved from dev/index.dev.html */
/* [수정] 예약 저장 함수 (화면 입력값 우선 사용) */
async function saveBook(uid) {
    const date = document.getElementById('hiddenDate').value;
    const rawAdminName = isAdmin ? (document.getElementById("bkName").value || "").trim() : "";
    const bkName = isAdmin ? (rawAdminName || adminDefaultName || "관리자") : (currentUser ? currentUser.name : "회원");
    const bkPhone = isAdmin ? document.getElementById('bkPhone').value : (currentUser ? currentUser.phone : '');

    if(!bkPhone) {
        alert('전화번호가 입력되지 않았습니다.');
        return;
    }

    const initialStatus = isAdmin ? 'BOOKED' : 'PENDING';
    const payMethod = (uid === 'TRANSFER') ? '계좌이체' : (uid === 'ADMIN' ? '관리자등록' : '카드결제');
    const amt = document.getElementById('txtPrice').innerText;
    const slots = [...selected].map(s => ({ ...s })).sort((a,b) => (a.c - b.c) || (a.t - b.t));
    let timeStr = slots.map(s => `${s.t}시`).join(', ');
    let courtTimeStr = formatCourtTimeSummary(slots);
    const actorUid = (auth.currentUser && auth.currentUser.uid) ? auth.currentUser.uid : (currentUser && currentUser.uid ? currentUser.uid : 'guest');
    const requestStartedAtMs = Date.now();
    const requestId = createBookingRequestId(actorUid);
    const clientId = getMacroClientId();

    const attemptMeta = {
        uid: actorUid,
        requestId,
        clientId,
        requestStartedAtMs,
        name: bkName || '',
        phone: bkPhone || '',
        center: currentCenter,
        date,
        slots: slots.map(s => ({ court: s.c, time: s.t })),
        slotCount: slots.length,
        paymentMethod: payMethod,
        amountText: amt,
        userAgent: navigator.userAgent || '',
        actorRole: isAdmin ? 'ADMIN' : 'USER',
        appVersion: 'macro-v8',
        interactionEvidence: (typeof getBookingInteractionEvidence === 'function') ? getBookingInteractionEvidence() : {}
    };

    try {
        await logBookingAttempt({ ...attemptMeta, result: 'TRY' });

        try {
            await checkBookingGuards(attemptMeta);
        } catch (guardErr) {
            await logBookingAttempt({ ...attemptMeta, result: 'FAIL_GUARD', reason: guardErr && guardErr.message ? guardErr.message : 'GUARD_BLOCK' });
            if (!isAdmin) await maybeAutoBlockUser(actorUid);
            if (document.getElementById('macroMonitorBox') && document.getElementById('macroMonitorBox').style.display !== 'none') {
                loadMacroMonitor();
            }
            throw guardErr;
        }

        await validateDailyReservationLimits(attemptMeta);

        if (!isAdmin) {
            await new Promise(res => setTimeout(res, 1200 + Math.floor(Math.random() * 800)));
        }

        for (const slot of slots) {
            const recurConflict = await hasRecurringConflict(currentCenter, date, slot.c, slot.t);
            if (recurConflict) {
                await logBookingAttempt({ ...attemptMeta, result: 'FAIL', reason: `${slot.c}코트 ${slot.t}시 정기예약 겹침` });
                if (document.getElementById('macroMonitorBox') && document.getElementById('macroMonitorBox').style.display !== 'none') loadMacroMonitor();
                alert(`${slot.c}코트 ${slot.t}시는 정기 예약과 겹쳐 예약할 수 없습니다.`);
                scheduleLoadDB(0);
                return;
            }
        }

        const dayReservationSnap = await db.collection('reservations')
            .where('center', '==', currentCenter)
            .where('date', '==', date)
            .get();

        const occupiedMap = new Map();
        dayReservationSnap.forEach(doc => {
            const d = doc.data() || {};
            if (!['PENDING', 'BOOKED', 'BLOCKED'].includes(d.status)) return;
            if (d.court == null || d.time == null) return;
            occupiedMap.set(`${Number(d.court)}_${Number(d.time)}`, { id: doc.id, ...d });
        });

        // 정기예약(recurring)도 점유 슬롯에 포함해야 1시간 틈새 예외가 정확히 동작한다.
        // 예: 일요일 정기예약 사이에 낀 1시간은 reservations에는 없지만 실제로는 양옆이 막힌 상태다.
        await addRecurringOccupiedSlotsToMap(currentCenter, date, occupiedMap);

        for (const slot of slots) {
            const key = `${slot.c}_${slot.t}`;
            if (occupiedMap.has(key)) {
                await logBookingAttempt({ ...attemptMeta, result: 'FAIL', reason: `${slot.c}코트 ${slot.t}시 이미 예약됨` });
                if (document.getElementById('macroMonitorBox') && document.getElementById('macroMonitorBox').style.display !== 'none') loadMacroMonitor();
                alert(`${slot.c}코트 ${slot.t}:00 자리가 이미 예약되어 있습니다.`);
                scheduleLoadDB(0);
                return;
            }
        }

        validateRequestedSlotPattern(slots, occupiedMap);

        await db.runTransaction(async (transaction) => {
            // [수정] Firestore 트랜잭션 규칙: 모든 read를 먼저 완료한 뒤 write 수행
            // read와 write가 섞이면 "reads must be executed before all writes" 오류 발생

            // 1단계: 모든 슬롯 read 먼저
            const snapshots = [];
            for (const slot of slots) {
                const reservationId = buildSlotLockId(currentCenter, date, slot.c, slot.t);
                const resRef = db.collection('reservations').doc(reservationId);
                const resSnap = await transaction.get(resRef);
                snapshots.push({ slot, resRef, resSnap });
            }

            // 2단계: 충돌 체크 (read 결과만 사용, Firestore 접근 없음)
            for (const { slot, resSnap } of snapshots) {
                if (resSnap.exists) {
                    const existingData = resSnap.data() || {};
                    if (['PENDING', 'BOOKED', 'BLOCKED'].includes(existingData.status)) {
                        throw new Error(`${slot.c}코트 ${slot.t}:00 자리가 방금 다른 분의 예약으로 선점되었습니다.`);
                    }
                }
            }

            // 3단계: 모든 write를 마지막에 일괄 처리
            for (const { slot, resRef } of snapshots) {
                transaction.set(resRef, {
                    center: currentCenter,
                    date,
                    court: slot.c,
                    time: slot.t,
                    name: bkName,
                    phone: bkPhone,
                    status: initialStatus,
                    uid: actorUid,
                    paymentUid: uid,
                    requestId,
                    requestSlotCount: slots.length,
                    requestStartedAtMs,
                    clientId,
                    actorRole: isAdmin ? 'ADMIN' : 'USER',
                    source: 'WEB_APP_V8',
                    appVersion: 'macro-v8',
                    clientCommitAtMs: Date.now(),
                    at: firebase.firestore.FieldValue.serverTimestamp()
                }, { merge: true });
            }
        });

        await logBookingAttempt({ ...attemptMeta, result: 'SUCCESS', elapsedMs: Date.now() - requestStartedAtMs });
        if (!isAdmin) await maybeAutoBlockUser(actorUid);
        if (document.getElementById('macroMonitorBox') && document.getElementById('macroMonitorBox').style.display !== 'none') loadMacroMonitor();
        showSuccessAnimation();
        setTimeout(() => {
            alert(isAdmin ? '예약이 완료되었습니다.' : '가예약 신청되었습니다. 입금 확인 후 최종 승인됩니다.');
        }, 800);

        closeModal('modalBook');
        _invalidateReservationsCache(currentCenter, date); // 예약 완료 → 캐시 무효화
        _invalidateMyReservedDatesCache(currentCenter, bkPhone);
        scheduleLoadDB(0);
        drawCalendar();
        refreshTodayMyReservationCard(true);

        if(!isAdmin) {
            setTimeout(() => {
                if(confirm('가예약이 완료되었습니다.\n관리자에게 예약 내역 승인문자를 보내시겠습니까?')) {
                    sendSmsToAdmin(bkName, bkPhone, date, courtTimeStr, payMethod, amt);
                }
            }, 1000);
        }
    } catch(err) {
        try {
            await logBookingAttempt({ ...attemptMeta, result: 'FAIL', reason: err && err.message ? err.message : 'UNKNOWN' });
            if (!isAdmin) await maybeAutoBlockUser(actorUid);
            if (document.getElementById('macroMonitorBox') && document.getElementById('macroMonitorBox').style.display !== 'none') loadMacroMonitor();
        } catch(_) {}
        console.error(err);
        alert(err.message || '예약 처리 중 오류가 발생했습니다. 다시 시도해주세요.');
        scheduleLoadDB(0);
    }
}
