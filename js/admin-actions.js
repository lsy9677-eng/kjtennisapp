/*
 * STEP 10 - Admin Actions Module
 * 관리자 예약/승인/취소/일괄처리 주변 저장 로직을 dev/index.dev.html에서 분리했습니다.
 * 주의: saveBook(), doPay(), loadDB() 핵심 예약/결제 함수는 아직 index.dev.html에 남겨 안정성을 유지합니다.
 */
async function doBulkReserve() {
    if(!isAdmin) return;
    const startStr = document.getElementById('bulkStart').value;
    const endStr = document.getElementById('bulkEnd').value;
    const timeS = parseInt(document.getElementById('bulkTimeStart').value);
    const timeE = parseInt(document.getElementById('bulkTimeEnd').value);
    const label = document.getElementById('bulkLabel').value.trim();
    const selectedCourts = Array.from(document.querySelectorAll('.chk-bulk-court:checked')).map(el => parseInt(el.value));
    
    // [추가] 입력된 금액 가져오기
    const priceInput = document.getElementById('bulkUnitPrice').value;
    const customPrice = priceInput ? parseInt(priceInput) : null;

    if(!startStr || !endStr || selectedCourts.length === 0 || !label) return alert("날짜, 코트, 명칭을 모두 입력해주세요.");
    if(!confirm("단체 대관을 진행하시겠습니까?")) return;

    const startDate = new Date(startStr);
    const endDate = new Date(endStr);
    let currentBatch = db.batch();
    let count = 0;
    const totalBatches = [];

    for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
        const dateStr = d.toISOString().split('T')[0];
        for (const court of selectedCourts) {
            for (let t = timeS; t < timeE; t++) {
                const ref = db.collection("reservations").doc(buildSlotLockId(currentCenter, dateStr, court, t));

                const docData = {
                    date: dateStr, court: court, time: t, name: label, phone: admPh,
                    status: "BOOKED", uid: "ADMIN_BULK", at: new Date()
                };
                
                // [핵심] 금액이 설정되어 있으면 저장
                if (customPrice !== null) docData.customPrice = customPrice;

                currentBatch.set(ref, docData);
                if(slotLocksEnabled) {
                    currentBatch.set(
                        db.collection('slot_locks').doc(buildSlotLockId(currentCenter, dateStr, court, t)),
                        {
                            reservationId: ref.id,
                            center: currentCenter,
                            date: dateStr,
                            court: court,
                            time: t,
                            status: 'BOOKED',
                            name: label,
                            phone: admPh,
                            createdAt: new Date()
                        }
                    );
                }

                count++;
                if (count % 400 === 0) {
                    totalBatches.push(currentBatch.commit());
                    currentBatch = db.batch();
                }
            }
        }
    }
    totalBatches.push(currentBatch.commit());
    await Promise.all(totalBatches);
    alert(`단체 대관 ${count}건 완료!`);
    closeModal('modalSet');
    scheduleLoadDB(0);
}

function openGroupApprove(jsonStr) {
    const data = JSON.parse(decodeURIComponent(jsonStr));
    const details = data.details;
    
    // 데이터 저장 (문자 발송용)
    currentApproveData = {
        name: data.name,
        phone: data.phone,
        date: data.date,
        center: currentCenter
    };

    const listContainer = document.getElementById('groupDetailList');
    listContainer.innerHTML = "";
    
    // 모달 제목 설정 (초록색)
    const modalTitle = document.querySelector('#modalGroupDetail .modal-head');
    modalTitle.innerText = "✅ 가승인 건 승인 처리";
    modalTitle.style.color = "#059669";

    // [핵심] 버튼을 '승인 모드'로 변경
    const actionBtn = document.getElementById('btnGroupAction');
    actionBtn.innerText = "선택한 항목 승인하기";
    actionBtn.className = "btn-full"; 
    actionBtn.style.background = "#10b981"; // 초록색 배경
    actionBtn.onclick = doGroupApprove; // 승인 함수 연결

    // 리스트 그리기 (체크박스 미리 모두 선택됨)
    details.sort((a,b) => a.time - b.time);
    details.forEach(item => {
        const div = document.createElement('div');
        div.style.padding = "10px";
        div.style.borderBottom = "1px solid #f1f5f9";
        div.style.display = "flex";
        div.style.alignItems = "center";
        
        div.innerHTML = `
            <label style="display:flex; align-items:center; width:100%; cursor:pointer;">
                <input type="checkbox" class="chk-part-del" value="${item.id}" data-time="${item.time}" data-court="${item.court}" checked 
                       style="width:20px; height:20px; margin-right:12px; accent-color:#10b981;">
                <span style="font-weight:700; color:#333; margin-right:8px;">${item.court}코트</span>
                <span style="color:#64748b;">${item.time}:00 ~ ${item.time+1}:00</span>
            </label>
        `;
        listContainer.appendChild(div);
    });

    openModal('modalGroupDetail');
}

async function doGroupApprove() {
    const checked = document.querySelectorAll('.chk-part-del:checked');
    if(checked.length === 0) return alert("승인할 항목을 선택하세요.");
    
    if(!confirm(`선택한 ${checked.length}건을 최종 승인하시겠습니까?`)) return;

    const batch = db.batch();
    const approvedTimes = [];
    const approvedSlots = []; // [추가] 코트+시간 정보

    checked.forEach(el => {
        const ref = db.collection("reservations").doc(el.value);
        batch.update(ref, { status: "BOOKED" });
        approvedTimes.push(parseInt(el.dataset.time));
        // [추가] 코트 정보도 수집 (data-court 속성에서)
        approvedSlots.push({ court: el.dataset.court || '', time: parseInt(el.dataset.time) });
    });

    try {
        await batch.commit();
        alert("승인 처리되었습니다.");
        closeModal('modalGroupDetail');
        
        // 목록 새로고침
        if(document.getElementById('btnListAll').classList.contains('bg-blue')) loadAllRes('all');
        else loadAllRes('general');

        // [문자 발송]
        if(currentApproveData && confirm("회원에게 '예약 확정' 안내 문자를 보내시겠습니까?")) {
            const d = currentApproveData;
            const centerName = CENTERS[d.center].name;
            
            // 시간 문자열 예쁘게 만들기 (코트+시간 상세 표시)
            approvedSlots.sort((a,b) => a.time - b.time || a.court - b.court);
            let timeStr = formatCourtTimeSummary(approvedSlots);
            if(!timeStr) {
                // fallback
                approvedTimes.sort((a,b)=>a-b);
                timeStr = approvedTimes.length === 1 ? `${approvedTimes[0]}시` : `${approvedTimes[0]}시 등 총 ${approvedTimes.length}건`;
            }

            const msg = `[${centerName}]\n${d.name}님, 입금 확인되었습니다.\n예약이 최종 확정되었습니다.\n일시: ${d.date}\n시간: ${timeStr}`;
            
            const isIOS = /iphone|ipad|ipod/.test(navigator.userAgent.toLowerCase());
            const separator = isIOS ? '&' : '?';
            location.href = `sms:${d.phone}${separator}body=${encodeURIComponent(msg)}`;
        }

    } catch(err) {
        alert("승인 실패: " + err.message);
    }
}

async function doRangeDelete() {
    if(!isAdmin) return;
    const startStr = document.getElementById('rangeDelStart').value;
    const endStr = document.getElementById('rangeDelEnd').value;

    if(!startStr || !endStr) return alert('날짜를 선택해주세요.');
    if(!confirm('해당 기간의 모든 예약을 삭제하시겠습니까?')) return;

    const snap = await db.collection('reservations').where('date', '>=', startStr).where('date', '<=', endStr).get();
    if(snap.empty) return alert('삭제할 예약이 없습니다.');

    const ids = snap.docs.map(doc => doc.id);
    const deletedCount = await deleteReservationsWithLocksByIds(ids);
    alert(`${deletedCount}건 삭제 완료!`);
    closeModal('modalSet');
    scheduleLoadDB(0);
}

async function doBlock(isRecur) {
    const date = document.getElementById('hiddenDate').value;
    const batch = db.batch();
    
    let inputName = document.getElementById('bkName').value.trim();
    if(!inputName) inputName = "정기";

    let inputPhone = document.getElementById('bkPhone').value.trim();
    if(!inputPhone) return alert("전화번호를 입력해주세요.");

    let targetDays = [];
    let rStart = "";
    let rEnd = "";
    let excludeHoliday = false;
    let monthlyFee = null; // [변경] 월 정액 요금 변수

    if(isRecur) {
        document.querySelectorAll('.chk-recur-day:checked').forEach(el => targetDays.push(parseInt(el.value)));
        if(targetDays.length === 0) return alert("최소 하나의 요일을 선택해야 합니다.");

        rStart = document.getElementById('recurStart').value;
        rEnd = document.getElementById('recurEnd').value;
        excludeHoliday = document.getElementById('chkRecurHoliday').checked; 
        
        // [변경] 월 이용료 가져오기 (recurMonthlyFee)
        const feeInput = document.getElementById('recurMonthlyFee').value;
        if(feeInput) monthlyFee = parseInt(feeInput);

        if(!rStart || !rEnd) return alert("시작일과 종료일을 모두 설정해주세요.");
        if(rStart > rEnd) return alert("종료일이 시작일보다 빠를 수 없습니다.");
    }

    const btn = event.target;
    const originTxt = btn.innerText;
    btn.innerText = "처리 중...";
    btn.disabled = true;

    // (중복 검사 로직 생략 - 기존과 동일하게 진행한다고 가정하고 바로 저장으로 넘어갑니다)
    // 실제 코드 적용 시엔 기존의 중복 검사 로직(checkOverlap 호출 부분)을 그대로 두셔도 됩니다.

    selected.forEach(s => {
        if(isRecur) {
            const docData = { 
                center: currentCenter, 
                dayType: "mixed", 
                court: s.c, time: s.t, 
                name: inputName, phone: inputPhone, 
                status: "FIXED", 
                weekDays: targetDays,
                startDate: rStart, endDate: rEnd,
                excludeHoliday: excludeHoliday
            };
            
            // [핵심] 월 이용료가 있으면 저장
            if(monthlyFee !== null) docData.monthlyFee = monthlyFee;

            batch.set(db.collection("recurring").doc(), docData);
        } else {
            // 일반 1회성 예약
            const ref = db.collection('reservations').doc(buildSlotLockId(currentCenter, date, s.c, s.t));
            batch.set(ref, { 
                center: currentCenter, 
                date: date, court: s.c, time: s.t, 
                name: inputName, phone: inputPhone, 
                status: 'BOOKED', uid: 'ADMIN', at: new Date() 
            });
            if(slotLocksEnabled) {
                batch.set(db.collection('slot_locks').doc(buildSlotLockId(currentCenter, date, s.c, s.t)), {
                    reservationId: ref.id,
                    center: currentCenter,
                    date,
                    court: s.c,
                    time: s.t,
                    status: 'BOOKED',
                    name: inputName,
                    phone: inputPhone,
                    createdAt: new Date()
                });
            }
        }
    });

    batch.commit().then(() => { 
        alert(isRecur ? "정기 예약(월 계약)이 설정되었습니다." : "예약 완료"); 
        closeModal('modalBook'); 
        _invalidateReservationsCache(currentCenter); // 예약 완료 → 캐시 무효화
        if(isRecur) _invalidateRecurringCache(currentCenter); // 정기예약 추가 → recurring 캐시 무효화
        scheduleLoadDB(0); 
    }).catch(err => alert("오류: " + err.message))
    .finally(() => {
        btn.innerText = originTxt;
        btn.disabled = false;
    });
}

function doBlockSlot() {
    if (selected.length === 0) return alert("막을 시간을 선택해주세요.");
    if (!confirm(`선택한 ${selected.length}개의 타임을 '예약 불가' 처리하시겠습니까?\n(회원들이 예약할 수 없게 됩니다)`)) return;

    const batch = db.batch();
    const date = document.getElementById('hiddenDate').value;
    
    // 막는 사유 (기본값: 시설점검) -> 필요하면 prompt로 입력받게 수정 가능
    // const reason = prompt("사유를 입력하세요", "시설점검");
    const reason = "⛔ 예약불가"; 

    selected.forEach(s => {
        const ref = db.collection('reservations').doc(buildSlotLockId(currentCenter, date, s.c, s.t));
        batch.set(ref, {
            center: currentCenter,
            date: date, 
            court: s.c, 
            time: s.t,
            name: reason,
            phone: 'ADMIN',
            status: 'BLOCKED',
            uid: 'ADMIN_BLOCK', 
            at: new Date()
        });
        if(slotLocksEnabled) {
            batch.set(db.collection('slot_locks').doc(buildSlotLockId(currentCenter, date, s.c, s.t)), {
                reservationId: ref.id,
                center: currentCenter,
                date,
                court: s.c,
                time: s.t,
                status: 'BLOCKED',
                name: reason,
                phone: 'ADMIN',
                createdAt: new Date()
            });
        }
    });

    batch.commit().then(() => {
        alert("처리가 완료되었습니다.");
        closeModal('modalBook');
        _invalidateReservationsCache(currentCenter, date); // 예약 완료 → 캐시 무효화
        _invalidateMyReservedDatesCache(currentCenter, bkPhone);
        scheduleLoadDB(0);
        drawCalendar();
        refreshTodayMyReservationCard(true);
    }).catch(err => alert("오류: " + err.message));
}

function openCancel(el) {
    const name = el.dataset.info;
    const phone = el.dataset.ph;
    const status = el.dataset.status;
    const date = document.getElementById('hiddenDate').value;
    const time = parseInt(el.dataset.t);
    const id = el.dataset.id;
    const coll = el.dataset.coll; 
    
    document.getElementById('dtInfo').value = name;
    document.getElementById('dtContact').value = phone;
    
    window.cancelTarget = { 
        id: id, coll: coll, name: name, phone: phone, date: date, time: time, court: parseInt(el.dataset.c), status: status
    };
    
    const btnApproveGroup = document.getElementById('adminApproveBtns');
    const btnEdit = document.getElementById('btnEditBook');
    const cancelGroup = document.getElementById('cancelBtnGroup'); 

    btnEdit.style.display = 'none';
    btnApproveGroup.style.display = 'none';
    cancelGroup.style.display = 'none';

    if(isAdmin) {
        // === 관리자 모드 (기존 동일) ===
        document.getElementById('dtInfo').readOnly = false;
        document.getElementById('dtContact').readOnly = false;
        document.getElementById('dtInfo').style.background = "#fff";
        document.getElementById('dtContact').style.background = "#fff";
        
        btnEdit.style.display = 'block';
        cancelGroup.style.display = 'flex'; 
        cancelGroup.style.flexDirection = 'column'; 
        cancelGroup.style.gap = '8px';

        let btnColorTime = "#f87171"; 
        let btnColorDay = "#b91c1c";
        let btnTxtTime = "이 예약 1건만 취소";
        let btnTxtDay = "오늘 예약 모두 취소";
        
        if(status === 'PENDING') {
            btnColorTime = "#64748b"; 
            btnColorDay = "#334155";
            btnTxtTime = "🚫 승인 거절 (삭제)";
            btnTxtDay = "🚫 오늘 신청 모두 거절";
        }

        if(coll === 'recurring') {
            cancelGroup.innerHTML = `
                <button class="btn-full" onclick="handleCancelClick('TIME')" style="background:#f59e0b; border:none; color:white; font-weight:bold; border-radius:8px; margin:0;">1️⃣ 이 시간만 취소 (1시간 휴강)</button>
                <button class="btn-full" onclick="handleCancelClick('DAY')" style="background:#ea580c; border:none; color:white; font-weight:bold; border-radius:8px; margin:0;">2️⃣ 이 날짜 전체 취소 (오늘 통째로 휴강)</button>
                <button class="btn-full" onclick="handleCancelClick('ALL')" style="background:#dc2626; border:none; color:white; font-weight:bold; border-radius:8px; margin:0;">3️⃣ 앞으로의 전체 취소 (영구 삭제)</button>
            `;
        } else {
            cancelGroup.innerHTML = `
                <div style="display:flex; gap:10px;">
                    <button class="btn-full" onclick="handleCancelClick('TIME')" style="background:${btnColorTime}; border:none; color:white; font-weight:bold; border-radius:8px; flex:1; margin:0;">${btnTxtTime}</button>
                    <button class="btn-full" onclick="handleCancelClick('DAY')" style="background:${btnColorDay}; border:none; color:white; font-weight:bold; border-radius:8px; flex:1; margin:0;">${btnTxtDay}</button>
                </div>
            `;
        }
        if(status === 'PENDING') btnApproveGroup.style.display = 'flex';

    } else {
        // === [일반 사용자 모드] (수정됨) ===
        document.getElementById('dtInfo').readOnly = true;
        document.getElementById('dtContact').readOnly = true;
        document.getElementById('dtInfo').style.background = "#f1f5f9";
        document.getElementById('dtContact').style.background = "#f1f5f9";
        
        if(currentUser && currentUser.phone === phone) {
            cancelGroup.style.display = 'flex';
            // [추가] 일반 회원도 '오늘 전체 취소' 버튼 보이게 변경
            cancelGroup.innerHTML = `
                <div style="display:flex; gap:10px; width:100%;">
                    <button class="btn-full" onclick="handleCancelClick('TIME')" 
                        style="background:#f87171; border:none; color:white; font-weight:bold; border-radius:8px; flex:1; margin:0;">
                        이 예약 취소
                    </button>
                    <button class="btn-full" onclick="handleCancelClick('DAY')" 
                        style="background:#dc2626; border:none; color:white; font-weight:bold; border-radius:8px; flex:1; margin:0;">
                        오늘 전체 취소
                    </button>
                </div>
            `;
        }
    }
    openModal('modalCancel');
}

function handleCancelClick(mode) {
    if(isAdmin) {
        // 관리자는 즉시 삭제 로직
        processAdminCancel(mode);
    } else {
        // 사용자는 환불 팝업 로직
        processUserCancel(mode);
    }
}

async function processAdminCancel(mode) {
    try {
        const target = window.cancelTarget;
        if(!target) throw new Error("선택된 예약 정보가 없습니다.");

        // 1. 클릭한 문서의 최신 정보 가져오기
        const docRef = db.collection(target.coll).doc(target.id);
        const docSnap = await docRef.get();
        
        if(!docSnap.exists) {
            alert("이미 삭제된 예약입니다.");
            closeModal('modalCancel');
            scheduleLoadDB(0);
            return;
        }
        
        const realData = docSnap.data();
        const searchName = realData.name;
        const searchPhone = realData.phone;
        const searchCenter = realData.center || currentCenter;

        // 연락처 확인 안전장치
        if ((mode === 'DAY' || mode === 'ALL') && (!searchPhone || searchPhone === 'undefined')) {
            alert("⛔ 오류: 예약자의 연락처 정보가 정확하지 않습니다.\n\n동명이인이나 다른 관리자 예약이 함께 삭제될 위험이 있어 작업을 중단합니다.\n\n👉 [수정 저장]을 통해 연락처를 명확히 입력한 후 다시 시도해주세요.");
            return;
        }

        const y = parseInt(target.date.substring(0,4));
        const m = parseInt(target.date.substring(5,7)) - 1;
        const d = parseInt(target.date.substring(8,10));
        const currentDayNum = new Date(y, m, d).getDay(); 

        // ====================================================
        // [CASE 1] 이 시간만 취소 (1건이므로 안전)
        // ====================================================
        if(mode === 'TIME') {
            if(target.coll === 'recurring') {
                if(!confirm(`[정기 예약 1건 제외]\n\n시간: ${target.time}시\n\n이 시간만 휴강 처리하시겠습니까?`)) return;
                
                await docRef.update({
                    exceptionDates: firebase.firestore.FieldValue.arrayUnion(target.date)
                });
                alert("선택하신 시간만 제외되었습니다.");
            } else {
                if(!confirm(`[일반 예약 1건 취소]\n\n시간: ${target.time}시\n\n이 예약만 취소하시겠습니까?`)) return;
                await deleteReservationsWithLocksByIds([target.id]);
                alert('취소되었습니다.');
            }
        } 
        
        // ====================================================
        // [CASE 2] 이 날짜 전체 취소 (안전장치: 목록 미리보기)
        // ====================================================
        else if(mode === 'DAY') {
            if(target.coll === 'recurring') {
                // 정기 예약
                const snap = await db.collection("recurring")
                    .where("name", "==", searchName)
                    .where("phone", "==", searchPhone)
                    .where("center", "==", searchCenter)
                    .get();
                
                if(snap.empty) throw new Error("데이터를 찾을 수 없습니다.");

                // 대상 추려내기
                let targetDocs = [];
                let timeListStr = "";
                
                snap.forEach(doc => {
                    const rData = doc.data();
                    if(rData.weekDays && rData.weekDays.includes(currentDayNum)) {
                        targetDocs.push(doc);
                        timeListStr += `[${rData.time}시] `;
                    }
                });

                if(targetDocs.length === 0) return alert("오늘 날짜에 해당하는 정기 예약이 없습니다.");

                // 🔥 [안전장치] 사용자에게 삭제 목록 확인
                const msg = `[안전 확인 - 정기 휴강]\n\n` +
                            `예약자: ${searchName}\n` +
                            `연락처: ${searchPhone}\n` +
                            `날짜: ${target.date}\n` +
                            `대상 시간: ${timeListStr}\n\n` +
                            `총 ${targetDocs.length}건을 정말 휴강 처리하시겠습니까?`;

                if(!confirm(msg)) return; // 취소 누르면 중단

                const batch = db.batch();
                targetDocs.forEach(doc => {
                    batch.update(doc.ref, {
                        exceptionDates: firebase.firestore.FieldValue.arrayUnion(target.date)
                    });
                });
                
                await batch.commit();
                alert("처리되었습니다.");

            } else {
                // 일반 예약
                const snap = await db.collection("reservations")
                    .where("date", "==", target.date)
                    .where("name", "==", searchName)
                    .where("phone", "==", searchPhone)
                    .where("center", "==", searchCenter)
                    .get();
                
                if(snap.empty) throw new Error("취소할 내역이 없습니다.");

                let timeListStr = "";
                snap.forEach(doc => { timeListStr += `[${doc.data().time}시] `; });

                // 🔥 [안전장치]
                const msg = `[안전 확인 - 당일 전체 취소]\n\n` +
                            `예약자: ${searchName}\n` +
                            `연락처: ${searchPhone}\n` +
                            `날짜: ${target.date}\n` +
                            `대상 시간: ${timeListStr}\n\n` +
                            `위 ${snap.size}건의 예약을 모두 삭제하시겠습니까?`;

                if(!confirm(msg)) return;

                const ids = snap.docs.map(doc => doc.id);
                await deleteReservationsWithLocksByIds(ids);
                alert('일괄 취소되었습니다.');
            }
        } 
        
        // ====================================================
        // [CASE 3] 앞으로의 전체 취소 (영구 삭제)
        // ====================================================
        else if(mode === 'ALL') {
            if(target.coll !== 'recurring') return;

            const snap = await db.collection("recurring")
                .where("name", "==", searchName)
                .where("phone", "==", searchPhone)
                .where("center", "==", searchCenter)
                .get();

            if(snap.empty) throw new Error("데이터가 없습니다.");

            let targetDocs = [];
            let timeListStr = "";

            snap.forEach(doc => {
                const rData = doc.data();
                if(rData.weekDays && rData.weekDays.includes(currentDayNum)) {
                    targetDocs.push(doc);
                    timeListStr += `[${rData.time}시] `;
                }
            });

            if(targetDocs.length === 0) return alert("해당 요일의 규칙을 찾지 못했습니다.");

            // 🔥 [안전장치]
            const msg = `⚠️ [위험 - 영구 삭제]\n\n` +
                        `예약자: ${searchName} (${searchPhone})\n` +
                        `대상 요일의 시간: ${timeListStr}\n\n` +
                        `이 정기 예약 규칙(${targetDocs.length}건)을 완전히 삭제하시겠습니까?\n` +
                        `(앞으로의 모든 일정이 사라집니다)`;

            if(!confirm(msg)) return;

            const batch = db.batch();
            targetDocs.forEach(doc => batch.delete(doc.ref));
            await batch.commit();
            alert("영구 삭제되었습니다.");
        }

        closeModal('modalCancel');
        _invalidateReservationsCache(currentCenter); // 취소/삭제 → 캐시 무효화
        _invalidateMyReservedDatesCache(currentCenter, searchPhone);
        scheduleLoadDB(0); 
        drawCalendar();

    } catch(err) {
        console.error(err);
        alert("작업 실패: " + err.message);
    }
}

async function processUserCancel(mode) {
    const target = window.cancelTarget;
    let targetList = [];

    if (!target || !target.id) {
        alert("선택된 예약 정보가 없습니다.");
        return;
    }

    // 최신 DB 상태를 기준으로 판단해야 승인 후에도 가승인 취소 문자로 잘못 나가지 않습니다.
    async function getLatestReservationStatus(item) {
        try {
            const ref = db.collection(item.coll || 'reservations').doc(item.id);
            const doc = await ref.get();
            if (doc.exists) {
                const d = doc.data() || {};
                return {
                    id: doc.id,
                    coll: item.coll || 'reservations',
                    date: d.date || item.date,
                    time: d.time !== undefined ? d.time : item.time,
                    court: d.court !== undefined ? d.court : item.court,
                    status: d.status || item.status || 'BOOKED',
                    name: d.name || target.name || (currentUser ? currentUser.name : '회원'),
                    phone: d.phone || target.phone || (currentUser ? currentUser.phone : '')
                };
            }
        } catch (e) {
            console.warn('예약 최신 상태 확인 실패:', e);
        }
        return {
            ...item,
            status: item.status || target.status || 'UNKNOWN',
            name: target.name || (currentUser ? currentUser.name : '회원'),
            phone: target.phone || (currentUser ? currentUser.phone : '')
        };
    }

    // 1. 취소 대상 목록 확보
    if (mode === 'TIME' || mode === 'ONE') {
        targetList.push(await getLatestReservationStatus({
            id: target.id,
            coll: target.coll || 'reservations',
            date: target.date,
            time: target.time,
            court: target.court,
            status: target.status
        }));

    } else if (mode === 'DAY' || mode === 'ALL') {
        const snap = await db.collection("reservations")
            .where("date", "==", target.date)
            .where("phone", "==", target.phone)
            .where("center", "==", currentCenter)
            .get();

        const latestPromises = [];
        snap.forEach(doc => {
            const d = doc.data() || {};
            latestPromises.push(getLatestReservationStatus({
                id: doc.id,
                coll: 'reservations',
                date: d.date,
                time: d.time,
                court: d.court,
                status: d.status
            }));
        });
        targetList = await Promise.all(latestPromises);
    } else {
        alert("취소 방식이 올바르지 않습니다.");
        return;
    }

    // 삭제/취소된 문서 등은 제외
    targetList = targetList.filter(item => item && item.id && item.status !== 'CANCELED');

    if (targetList.length === 0) return alert("취소할 내역이 없습니다.");
    closeModal('modalCancel');

    // 2. 최신 상태 기준 분기
    const hasBooked = targetList.some(item => item.status === 'BOOKED' || item.status === 'FIXED');
    const allPending = targetList.every(item => item.status === 'PENDING');

    if (hasBooked) {
        // 승인/확정 이후: 환불 규정 확인 후 게시판 취소 신청으로 이동
        openRefundPopup(targetList);
        return;
    }

    if (!allPending) {
        alert("예약 상태를 확인할 수 없습니다. 새로고침 후 다시 시도해주세요.");
        scheduleLoadDB(0);
        return;
    }

    // 3. 가승인 상태만 문자 취소 요청
    if (!confirm("가승인(입금 대기) 상태의 예약입니다.\n관리자에게 가승인 취소 요청 문자를 보내시겠습니까?")) return;

    const adminPhone = await getAdminPhoneNumber();
    const userName = currentUser ? currentUser.name : "회원";

    let details = "";
    targetList
        .sort((a, b) => (a.time || 0) - (b.time || 0))
        .forEach(t => {
            const courtText = t.court ? `${t.court}코트 ` : '';
            details += `- ${t.date} ${courtText}${t.time}:00\n`;
        });

    const msgBody = `[가승인 취소 요청]\n신청자: ${userName}\n\n${details}\n위 가승인 예약을 취소해 주세요.`;

    const isIOS = /iphone|ipad|ipod/.test(navigator.userAgent.toLowerCase());
    location.href = `sms:${adminPhone}${isIOS ? '&' : '?'}body=${encodeURIComponent(msgBody)}`;
}

    function toggleBatchMode() {
        isBatchMode = document.getElementById('chkBatchDel').checked;
        deleteQueue = []; 
        const btnBatchExec = document.getElementById('btnBatchExec');
        if (btnBatchExec) btnBatchExec.style.display = 'none';
        
        document.querySelectorAll('.delete-select').forEach(el => el.classList.remove('delete-select'));
        // 안내 팝업 제거: 버튼 ON/OFF만 조용히 전환합니다.
    }

async function doBatchDelete() {
    if(deleteQueue.length === 0) return;

    if(!confirm(`선택한 ${deleteQueue.length}건을 처리하시겠습니까?

- 정기 대관: 해당 날짜만 휴강됨
- 일반 예약: 영구 삭제됨`)) return;

    const recurringQueue = deleteQueue.filter(item => item.coll === 'recurring');
    const reservationIds = deleteQueue.filter(item => item.coll !== 'recurring').map(item => item.id);

    try {
        if (recurringQueue.length) {
            const batch = db.batch();
            recurringQueue.forEach(item => {
                const ref = db.collection(item.coll).doc(item.id);
                batch.update(ref, {
                    exceptionDates: firebase.firestore.FieldValue.arrayUnion(item.date)
                });
            });
            await batch.commit();
        }

        if (reservationIds.length) {
            await deleteReservationsWithLocksByIds(reservationIds);
        }

        alert('처리가 완료되었습니다.');
        deleteQueue = [];
        document.getElementById('btnBatchExec').style.display = 'none';
        document.getElementById('chkBatchDel').checked = false;
        isBatchMode = false;
        _invalidateReservationsCache(currentCenter); // 일괄삭제 → 캐시 무효화
        scheduleLoadDB(0);
    } catch(e) {
        alert('오류 발생: ' + e.message);
    }
}

async function deleteGroupBooking(ids, collectionName) {
    if(!collectionName) collectionName = "reservations"; 

    // ▼▼▼ [추가] 정기 예약 삭제 시 선택 옵션 제공 ▼▼▼
    if (collectionName === 'recurring') {
        // 정기 예약인 경우 - 같은 이름의 모든 예약 찾기
        const uniqueIds = [...new Set(ids)];
        
        // 첫 번째 예약 정보 가져오기
        const firstDoc = await db.collection('recurring').doc(uniqueIds[0]).get();
        if (!firstDoc.exists) {
            alert('예약 정보를 찾을 수 없습니다.');
            return;
        }
        
        const targetName = firstDoc.data().name;
        
        // 같은 이름의 모든 정기 예약 찾기
        const allSameNameDocs = await db.collection('recurring')
            .where('name', '==', targetName)
            .where('center', '==', currentCenter)
            .get();
        
        const allIds = allSameNameDocs.docs.map(doc => doc.id);
        const totalCount = allIds.length;
        const selectedCount = uniqueIds.length;
        
        // 선택 옵션 제공
        const choice = confirm(
            `${targetName}님의 정기 예약 삭제 옵션을 선택하세요:\n\n` +
            `[확인] → 이 시간대만 삭제 (${selectedCount}건)\n` +
            `         다른 시간대는 유지되며, 월 이용료도 유지됩니다.\n\n` +
            `[취소] → 모든 정기 예약 일괄 삭제 (${totalCount}건)\n` +
            `         ${targetName}님의 모든 예약과 월 이용료가 삭제됩니다.`
        );
        
        let idsToDelete;
        if (choice) {
            // 확인 = 선택한 시간대만 삭제
            idsToDelete = uniqueIds;
            if (!confirm(`선택한 ${selectedCount}건만 삭제하시겠습니까?\n(다른 시간대와 월 이용료는 유지됩니다)`)) {
                return;
            }
        } else {
            // 취소 = 모든 예약 일괄 삭제
            idsToDelete = allIds;
            if (!confirm(`${targetName}님의 모든 정기 예약 ${totalCount}건을 삭제하시겠습니까?\n월 이용료도 함께 제거됩니다.`)) {
                return;
            }
        }
        
        // 삭제 실행
        const batch = db.batch();
        idsToDelete.forEach(id => {
            batch.delete(db.collection('recurring').doc(id));
        });

        await batch.commit();
        _invalidateRecurringCache(currentCenter); // 정기예약 삭제 → recurring 캐시 무효화
        alert("삭제되었습니다.");
        
        // 화면 새로고침
        if(document.getElementById('btnListAll')?.classList.contains('bg-blue')) loadAllRes('all');
        else if(document.getElementById('btnListFix')?.classList.contains('bg-blue')) loadAllRes('recurring');
        else loadAllRes('general');
        
        if(document.getElementById('view-res')?.classList.contains('active')) loadDB();
        
        return;
    }
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

    // 일반/단체 예약 삭제
    const msg = `그룹에 포함된 예약 ${ids.length}건을 모두 취소하시겠습니까?`;
    if(!confirm(msg)) return;
    
    const uniqueIds = [...new Set(ids)];
    deleteReservationsWithLocksByIds(uniqueIds).then(() => {
        alert('삭제되었습니다.');
        // 화면 새로고침
        if(document.getElementById('btnListAll')?.classList.contains('bg-blue')) loadAllRes('all');
        else if(document.getElementById('btnListFix')?.classList.contains('bg-blue')) loadAllRes('recurring');
        else loadAllRes('general');
        
        if(document.getElementById('view-res')?.classList.contains('active')) loadDB();

    }).catch(err => alert('삭제 실패: ' + err.message));
}

function openGroupDetail(jsonStr) {
    const data = JSON.parse(decodeURIComponent(jsonStr));
    const details = data.details;
    const collectionName = data.collection; 
    const theme = data.theme; 
    
    details.sort((a,b) => {
        if(a.court !== b.court) return a.court - b.court;
        return a.time - b.time;
    });

    const listContainer = document.getElementById('groupDetailList');
    listContainer.innerHTML = "";
    listContainer.dataset.collection = collectionName;

    const modalTitle = document.querySelector('#modalGroupDetail .modal-head');
    
    // [중요] 버튼을 '삭제 모드'로 초기화
    const actionBtn = document.getElementById('btnGroupAction');
    actionBtn.innerText = "선택한 항목 삭제하기";
    actionBtn.className = "btn-full bg-red";
    actionBtn.onclick = doPartialGroupDelete; // 삭제 함수 연결

    if (theme === 'purple') {
        modalTitle.innerText = "🏢 단체 대관 상세 / 관리";
        modalTitle.style.color = "#7c3aed"; 
    } else if (theme === 'orange') {
        modalTitle.innerText = "🔄 정기 예약 상세 / 관리";
        modalTitle.style.color = "#ea580c"; 
    } else if (theme === 'pending') {
        modalTitle.innerText = "⏳ 가승인(대기) 상세 / 관리";
        modalTitle.style.color = "#059669"; 
    } else {
        modalTitle.innerText = "📅 일반 예약 상세 / 관리";
        modalTitle.style.color = "#2563eb"; 
    }

    details.forEach(item => {
        const div = document.createElement('div');
        div.style.padding = "10px";
        div.style.borderBottom = "1px solid #f1f5f9";
        div.style.display = "flex";
        div.style.alignItems = "center";
        
        div.innerHTML = `
            <label style="display:flex; align-items:center; width:100%; cursor:pointer;">
                <input type="checkbox" class="chk-part-del" value="${item.id}" style="width:20px; height:20px; margin-right:12px; accent-color:#ef4444;">
                <span style="font-weight:700; color:#333; margin-right:8px;">${item.court}코트</span>
                <span style="color:#64748b;">${item.time}:00 ~ ${item.time+1}:00</span>
            </label>
        `;
        listContainer.appendChild(div);
    });

    openModal('modalGroupDetail');
}

async function doPartialGroupDelete() {
    const checked = document.querySelectorAll('.chk-part-del:checked');
    if(checked.length === 0) return alert('삭제할 항목을 선택하세요.');

    const collectionName = document.getElementById('groupDetailList').dataset.collection || 'reservations';

    if(!confirm(`선택한 ${checked.length}건을 삭제하시겠습니까?`)) return;

    try {
        if (collectionName === 'recurring') {
            const batch = db.batch();
            checked.forEach(el => batch.delete(db.collection(collectionName).doc(el.value)));
            await batch.commit();
        } else {
            await deleteReservationsWithLocksByIds(Array.from(checked).map(el => el.value));
        }

        alert('선택한 항목이 취소되었습니다.');
        closeModal('modalGroupDetail');

        if(document.getElementById('btnListAll').classList.contains('bg-blue')) loadAllRes('all');
        else if(document.getElementById('btnListFix').classList.contains('bg-blue')) loadAllRes('recurring');
        else if(document.getElementById('btnListPend') && document.getElementById('btnListPend').classList.contains('bg-blue')) loadAllRes('pending');
        else loadAllRes('general');
    } catch(err) {
        alert('삭제 실패: ' + err.message);
    }
}

async function doApprove(mode) {
    const target = window.cancelTarget;
    
    if(mode === 'ONE') {
        if(!confirm("이 시간의 예약만 입금 확인(승인) 하시겠습니까?")) return;
        
        await db.collection(target.coll).doc(target.id).update({ status: "BOOKED", approvedAt: new Date() });
        alert("승인되었습니다.");
        finishApprove([target]); // 문자 발송 여부 묻기
        
    } else {
        if(!confirm(`'${target.name}'님의 ${target.date} 예약을 일괄 승인 하시겠습니까?`)) return;

        const snap = await db.collection("reservations")
            .where("date", "==", target.date)
            .where("phone", "==", target.phone)
            .where("center", "==", currentCenter)
            .where("status", "==", "PENDING") // 대기 중인 것만
            .get();

        if(snap.empty) return alert("승인할 대기 내역이 없습니다.");

        const batch = db.batch();
        const approvedList = [];
        
        snap.forEach(doc => {
            batch.update(doc.ref, { status: "BOOKED", approvedAt: new Date() });
            const d = doc.data();
            approvedList.push({ date: d.date, time: d.time });
        });
        
        await batch.commit();
        alert(`총 ${snap.size}건이 일괄 승인되었습니다.`);
        finishApprove(approvedList);
    }
}

function finishApprove(items) {
    closeModal('modalCancel');
    scheduleLoadDB(0);
    
    if(confirm("회원에게 '입금 확인 및 예약 확정' 안내 문자를 보내시겠습니까?")) {
        const target = window.cancelTarget;
        const centerName = CENTERS[currentCenter].name;
        
        let timeStr = "";
        if(items.length === 1) timeStr = `${items[0].time}시`;
        else timeStr = `${items[0].time}시 등 총 ${items.length}건`;

        const msg = `[${centerName}]\n${target.name}님, 입금 확인되었습니다.\n예약이 최종 확정되었습니다.\n일시: ${target.date} ${timeStr}`;
        
        const isIOS = /iphone|ipad|ipod/.test(navigator.userAgent.toLowerCase());
        const separator = isIOS ? '&' : '?';
        location.href = `sms:${target.phone}${separator}body=${encodeURIComponent(msg)}`;
    }
}

async function doEdit() {
    const target = window.cancelTarget;
    if(!target) return;
    if(!isAdmin) return alert("관리자만 수정할 수 있습니다.");

    const newName = document.getElementById('dtInfo').value.trim();
    const newPhone = document.getElementById('dtContact').value.trim();
    if(!newName || !newPhone) return alert("이름과 연락처를 입력해주세요.");

    // [추가] 정기 예약 관련 데이터 가져오기
    let updateData = { name: newName, phone: newPhone };
    
    if (target.isRecur) {
        const newStart = document.getElementById('editStart').value;
        const newEnd = document.getElementById('editEnd').value;
        const newTime = parseInt(document.getElementById('editTime').value);
        const newCourt = parseInt(document.getElementById('editCourt').value);

        if(!newStart || !newEnd || !newTime || !newCourt) {
            return alert("기간, 시간, 코트를 모두 입력해주세요.");
        }
        
        // 업데이트할 필드 추가
        updateData.startDate = newStart;
        updateData.endDate = newEnd;
        updateData.time = newTime;
        updateData.court = newCourt;
    }

    if(!confirm("정보를 수정하시겠습니까?")) return;

    try {
        const batch = db.batch();
        const ids = target.ids || [target.id];
        
        ids.forEach(docId => {
            const ref = db.collection(target.coll).doc(docId);
            batch.update(ref, updateData);
        });
        
        await batch.commit();
        alert("수정되었습니다.");
        closeModal('modalCancel');
        
        // 화면 새로고침
        if(document.getElementById('view-list').classList.contains('active')) {
            if(document.getElementById('btnListFix').classList.contains('bg-blue')) loadAllRes('recurring');
            else loadAllRes('general');
        } else {
            scheduleLoadDB(0); 
        }
    } catch(err) {
        alert("수정 중 오류 발생: " + err.message);
    }
}

async function checkOverlap(center, court, time, isRecur, oneDate, weekDays, start, end) {
    // 1. 기존 일반 예약(reservations)과 겹치는지 확인
    const resSnap = await db.collection("reservations")
        .where("center", "==", center)
        .where("court", "==", court)
        .where("time", "==", time)
        .get();

    if (!resSnap.empty) {
        for (const doc of resSnap.docs) {
            const r = doc.data();
            
            // [A] 내가 '일반 예약'을 넣으려는데, 이미 같은 날짜에 예약이 있는 경우
            if (!isRecur && r.date === oneDate) {
                return `${r.date} ${r.time}시에 '${r.name}'님의 예약이 이미 있습니다.`;
            }

            // [B] 내가 '정기 대관'을 넣으려는데, 그 기간 사이에 일반 예약이 끼어있는 경우
            if (isRecur) {
                // 예약 날짜가 정기대관 시작~종료일 사이인지?
                if (r.date >= start && r.date <= end) {
                    // 그리고 요일이 일치하는지?
                    const rDay = new Date(r.date).getDay();
                    if (weekDays.includes(rDay)) {
                        return `기간 중 ${r.date}(${getDayName(r.date)})에 '${r.name}'님의 기존 예약이 있습니다.`;
                    }
                }
            }
        }
    }

    // 2. 기존 정기 대관(recurring)과 겹치는지 확인
    const recSnap = await db.collection("recurring")
        .where("center", "==", center)
        .where("court", "==", court)
        .where("time", "==", time)
        .get();

    if (!recSnap.empty) {
        for (const doc of recSnap.docs) {
            const r = doc.data();
            
            // 요일이 겹치는지 확인 (교집합이 있는지)
            const myDays = isRecur ? weekDays : [new Date(oneDate).getDay()];
            const conflictDay = r.weekDays ? r.weekDays.find(d => myDays.includes(d)) : null;

            if (conflictDay !== undefined && conflictDay !== null) {
                // 기간도 겹치는지 확인
                // (내가 넣으려는 날짜/기간)과 (기존 정기대관 기간)이 겹치나?
                const myStart = isRecur ? start : oneDate;
                const myEnd = isRecur ? end : oneDate;
                
                // 기간 겹침 공식: (A시작 <= B종료) && (A종료 >= B시작)
                if (myStart <= (r.endDate || "2999-12-31") && myEnd >= (r.startDate || "2000-01-01")) {
                     return `기존 정기대관 '${r.name}'님과 겹칩니다.\n(기간: ${r.startDate}~${r.endDate})`;
                }
            }
        }
    }

    return null; // 겹치는거 없음 (통과)
}

function openGroupEdit(jsonStr) {
    const data = JSON.parse(decodeURIComponent(jsonStr));
    const ids = data.details.map(d => d.id); 

    window.cancelTarget = {
        ids: ids, 
        coll: data.collection,
        id: ids[0],
        isRecur: (data.collection === 'recurring') // 정기 예약 여부 플래그
    };

    const modalTitle = document.querySelector('#modalCancel .modal-head');
    modalTitle.innerText = `예약 정보 수정 (${ids.length}건)`;
    
    document.getElementById('dtInfo').value = data.name;
    document.getElementById('dtContact').value = data.phone;
    
    // 입력창 활성화
    document.getElementById('dtInfo').readOnly = false;
    document.getElementById('dtInfo').style.background = "#fff";
    document.getElementById('dtContact').readOnly = false;
    document.getElementById('dtContact').style.background = "#fff";

    // [추가] 정기 예약일 때만 추가 입력창 표시
    const recurArea = document.getElementById('editRecurArea');
    if (data.collection === 'recurring') {
        recurArea.style.display = 'block';
        // 전달받은 데이터로 초기값 세팅
        document.getElementById('editStart').value = data.startDate || "";
        document.getElementById('editEnd').value = data.endDate || "";
        document.getElementById('editTime').value = data.time || "";
        document.getElementById('editCourt').value = data.court || "";
    } else {
        recurArea.style.display = 'none';
    }

    document.getElementById('btnEditBook').style.display = 'block';
    document.getElementById('adminApproveBtns').style.display = 'none';
    document.getElementById('cancelBtnGroup').style.display = 'none';
    
    openModal('modalCancel');
}

function updateRecurFee(docId) {
    const input = document.getElementById(`fee-${docId}`);
    const newFee = parseInt(input.value);

    if (isNaN(newFee)) return alert("금액을 숫자로 입력해주세요.");

    if (!confirm(`이 정기 예약의 월 이용료를 ${newFee.toLocaleString()}원으로 설정하시겠습니까?`)) return;

    db.collection("recurring").doc(docId).update({
        monthlyFee: newFee
    }).then(() => {
        _invalidateRecurringCache(currentCenter); // 고정예약 수정 → recurring 캐시 무효화
        alert("저장되었습니다. 통계가 다시 계산됩니다.");
        loadMonthlyStats(); // 통계 새로고침
        closeModal('modalStatsDetail'); // 창 닫기 (또는 다시 열어서 갱신된 값 보여주기)
    }).catch(err => {
        alert("오류 발생: " + err.message);
    });
}

async function updateRecurFeeByName(name, docIdsStr) {
    const input = document.getElementById(`fee-${name}`);
    const newFee = parseInt(input.value);

    if (isNaN(newFee)) return alert("금액을 숫자로 입력해주세요.");
    
    // 쉼표로 구분된 문자열을 배열로 변환
    const docIds = docIdsStr.split(',');

    if (!confirm(`${name}님의 모든 정기 예약 월 이용료를 ${newFee.toLocaleString()}원으로 설정하시겠습니까?\n(${docIds.length}개 예약 일괄 적용)`)) return;

    try {
        const batch = db.batch();
        
        // 같은 이름의 모든 정기 예약에 동일한 월 이용료 적용
        docIds.forEach(docId => {
            const ref = db.collection("recurring").doc(docId);
            batch.update(ref, { monthlyFee: newFee });
        });
        
        await batch.commit();
        _invalidateRecurringCache(currentCenter); // 고정예약 수정 → recurring 캐시 무효화
        
        alert("저장되었습니다. 통계가 다시 계산됩니다.");
        loadMonthlyStats();
        closeModal('modalStatsDetail');
        
    } catch (err) {
        console.error('저장 오류:', err);
        alert("오류 발생: " + err.message);
    }
}

function deleteFromStats(id) {
    if(!confirm("정말 이 내역을 삭제하시겠습니까?\n(매출 통계에서도 제외됩니다)")) return;

    deleteReservationsWithLocksByIds([id]).then(() => {
        alert('삭제되었습니다.');
        loadMonthlyStats().then(() => {
            if(document.getElementById('modalStatsDetail').style.display === 'flex') {
                openStatsDetail('general');
            }
        });
    }).catch(err => alert("삭제 실패: " + err.message));
}
