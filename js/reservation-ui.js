/*
 * 국제 테니스장 예약 앱 - Step 7 Reservation UI
 * 예약판/코트 그리드 화면 함수만 분리했습니다.
 * 예약 저장(saveBook), 결제(doPay), Firestore 쓰기 로직은 index.dev.html에 남겨두었습니다.
 */

function changeCenter() {
    currentCenter = document.getElementById('centerSel').value;
    
    // 1. 그리드 다시 그리기
    drawGrid(); 
    
    // 2. 데이터 다시 불러오기
    loadDB(); 
    
    // 3. 리스트 뷰 갱신
    if(document.getElementById('view-list').classList.contains('active')) {
        loadAllRes('general');
    }

    // ▼▼▼ [추가된 기능] 단체 대관 체크박스도 코트 수에 맞춰 다시 그리기 ▼▼▼
    const max = CENTERS[currentCenter].courts;
    const bulkBox = document.getElementById('bulkCourts');
    if(bulkBox) {
        let html = "";
        for(let i=1; i<=max; i++) {
            html += `<label style="font-size:0.8rem;"><input type="checkbox" value="${i}" class="chk-bulk-court"> ${i}코트</label>`;
        }
        bulkBox.innerHTML = html;
    }
}

function drawGrid() {
    const tbl = document.getElementById('schTable');
    let h = `<div class="corner">코트</div>`;
    
    for(let t=7; t<22; t++) {
        h += `<div class="cell head-time">${String(t).padStart(2,'0')}~${String(t+1).padStart(2,'0')}</div>`;
    }
    
    const maxCourts = CENTERS[currentCenter].courts; 

    for(let c=1; c <= maxCourts; c++) {
        h += `<div class="cell head-court" id="row-head-${c}" onclick="showMap(${c})" title="배치도 보기">${c}코트 <span style="font-size:0.7rem; margin-left:2px;">🔍</span></div>`;
        
        for(let t=7; t<22; t++) {
            h += `<div class="cell data-cell row-cell-${c}" id="c-${c}-${t}" data-c="${c}" data-t="${t}"></div>`;
        }
    }
    
    tbl.innerHTML = h;

    // [중요] 클릭 감지기를 여기서 중복 없이 한 번만 설정합니다.
    const gridArea = document.getElementById('gridArea');
    gridArea.removeEventListener('click', onCellClick);
    gridArea.addEventListener('click', onCellClick);
}

async function refreshTodayMyReservationCard(forceDateSync = false, preloadedReservations = null) {
    try {
        if (Array.isArray(forceDateSync) && preloadedReservations === null) {
            preloadedReservations = forceDateSync;
            forceDateSync = false;
        }

        if (!currentUser || isAdmin || !currentUser.phone) {
            const card = document.getElementById('myReservationCard');
            if (card) card.style.display = 'none';
            return;
        }

        const dateInput = document.getElementById('hiddenDate');
        let currentDate = dateInput ? dateInput.value : '';
        if (!currentDate || forceDateSync) {
            const now = new Date();
            currentDate = now.toISOString().split('T')[0];
            if (dateInput && !dateInput.value) dateInput.value = currentDate;
        }

        let items = [];
        if (Array.isArray(preloadedReservations)) {
            items = preloadedReservations
                .filter(d => String(d.date || '') === currentDate)
                .filter(d => String(d.center || '') === String(currentCenter))
                .filter(d => String(d.phone || '') === String(currentUser.phone))
                .filter(d => ['PENDING', 'BOOKED', 'BLOCKED'].includes(d.status))
                .map(d => ({ court: d.court, time: d.time, status: d.status, name: d.name || '예약' }));
        } else {
            const snap = await db.collection('reservations')
                .where('date', '==', currentDate)
                .where('center', '==', currentCenter)
                .where('phone', '==', currentUser.phone)
                .get();

            snap.forEach(doc => {
                const d = doc.data() || {};
                if (!['PENDING', 'BOOKED', 'BLOCKED'].includes(d.status)) return;
                items.push({ court: d.court, time: d.time, status: d.status, name: d.name || '예약' });
            });
        }

        const card = document.getElementById('myReservationCard');
        const listContainer = document.getElementById('myReservationList');
        if (!card || !listContainer) return;

        if (!items.length) {
            card.style.display = 'none';
            return;
        }

        items.sort((a, b) => (a.time - b.time) || (a.court - b.court));
        listContainer.innerHTML = items.map(res => {
            const timeStr = `${String(res.time).padStart(2,'0')}시`;
            return `<span onclick="scrollToReservation(${res.court}, ${res.time})" style="background: rgba(255,255,255,0.9); padding: 4px 10px; border-radius: 16px; font-size: 0.8rem; color: #92400e; cursor: pointer; border: 1px solid rgba(146,64,14,0.2);">${res.court}코트 ${timeStr}</span>`;
        }).join('');

        card.style.display = 'block';
    } catch (err) {
        console.error('오늘 내 예약 카드 로딩 실패:', err);
    }
}

function updateMyReservations() {
    // 관리자이거나 로그인 안 했으면 카드 숨김
    if (!currentUser || isAdmin) {
        document.getElementById('myReservationCard').style.display = 'none';
        return;
    }
    
    const currentDate = document.getElementById('hiddenDate').value;
    const myPhone = currentUser.phone;
    const maxCourts = CENTERS[currentCenter].courts;
    
    let myReservations = [];
    
    // 모든 셀을 순회하며 내 예약 찾기
    for (let t = 7; t < 22; t++) {
        for (let c = 1; c <= maxCourts; c++) {
            const cell = document.getElementById(`c-${c}-${t}`);
            if (!cell) continue;
            
            // 내 예약인지 확인
            if (cell.dataset.ph === myPhone) {
                const isBooked = cell.classList.contains('booked') || 
                               cell.classList.contains('fixed') || 
                               cell.classList.contains('pending');
                
                if (isBooked) {
                    myReservations.push({
                        court: c,
                        time: t,
                        name: cell.dataset.info || '예약',
                        status: cell.dataset.status
                    });
                    
                    // ▼▼▼ [개선] 내 예약 셀에 노란색 배경 + 테두리 ▼▼▼
                    cell.style.background = 'linear-gradient(135deg, #fef3c7 0%, #fde68a 100%)';
                    cell.style.boxShadow = '0 0 0 3px #fbbf24, 0 4px 12px rgba(251, 191, 36, 0.3)';
                    cell.style.transform = 'scale(1.02)';
                    cell.style.zIndex = '5';
                    
                    // orb 스타일도 변경
                    const orb = cell.querySelector('.orb');
                    if (orb) {
                        orb.style.background = '#fbbf24';
                        orb.style.color = '#78350f';
                        orb.style.fontWeight = '800';
                    }
                    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
                }
            }
        }
    }
    
    const card = document.getElementById('myReservationCard');
    const listContainer = document.getElementById('myReservationList');
    
    if (myReservations.length === 0) {
        card.style.display = 'none';
        return;
    }
    
    // 시간순 정렬
    myReservations.sort((a, b) => a.time - b.time || a.court - b.court);
    
    // UI 업데이트
    listContainer.innerHTML = myReservations.map(res => {
        const timeStr = `${String(res.time).padStart(2,'0')}시`;
        return `<span onclick="scrollToReservation(${res.court}, ${res.time})" style="background: rgba(255,255,255,0.9); padding: 4px 10px; border-radius: 16px; font-size: 0.8rem; color: #92400e; cursor: pointer; border: 1px solid rgba(146,64,14,0.2);">${res.court}코트 ${timeStr}</span>`;
    }).join('');
    
    card.style.display = 'block';
}

function scrollToReservation(court, time) {
    const cell = document.getElementById(`c-${court}-${time}`);
    if (cell) {
        cell.scrollIntoView({ behavior: 'smooth', block: 'center' });
        // 깜빡임 효과
        cell.style.animation = 'pulse 0.5s ease-in-out 2';
        setTimeout(() => {
            cell.style.animation = '';
        }, 1000);
    }
}

function scrollToMyFirstReservation() {
    if (!currentUser) return;
    
    const myPhone = currentUser.phone;
    const maxCourts = CENTERS[currentCenter].courts;
    
    // 시간순으로 첫 번째 예약 찾기
    for (let t = 7; t < 22; t++) {
        for (let c = 1; c <= maxCourts; c++) {
            const cell = document.getElementById(`c-${c}-${t}`);
            if (cell && cell.dataset.ph === myPhone) {
                scrollToReservation(c, t);
                return;
            }
        }
    }
}

function shareMyReservation(method) {
    if (!currentUser) {
        alert('로그인이 필요합니다.');
        return;
    }
    
    const currentDate = document.getElementById('hiddenDate').value;
    const myPhone = currentUser.phone;
    const maxCourts = CENTERS[currentCenter].courts;
    
    let myReservations = [];
    
    // 내 예약 정보 수집
    for (let t = 7; t < 22; t++) {
        for (let c = 1; c <= maxCourts; c++) {
            const cell = document.getElementById(`c-${c}-${t}`);
            if (!cell) continue;
            
            if (cell.dataset.ph === myPhone) {
                const isBooked = cell.classList.contains('booked') || 
                               cell.classList.contains('fixed') || 
                               cell.classList.contains('pending');
                
                if (isBooked) {
                    myReservations.push({ court: c, time: t });
                }
            }
        }
    }
    
    if (myReservations.length === 0) {
        alert('오늘 예약이 없습니다.');
        return;
    }
    
    // 시간순 정렬
    myReservations.sort((a, b) => a.time - b.time || a.court - b.court);
    
    // 예약 정보 텍스트 생성
    let reservationText = myReservations.map(res => {
        const timeStr = `${String(res.time).padStart(2,'0')}시`;
        return `${res.court}코트 ${timeStr}`;
    }).join(', ');
    
    const shareText = `🎾 테니스 코트 예약 완료!\n\n${currentDate}\n${reservationText}\n\n김해시테니스협회`;
    
    if (method === 'sms') {
        // 문자앱 직접 열기
        window.location.href = `sms:?body=${encodeURIComponent(shareText)}`;
    } else if (method === 'kakao') {
        // 카카오톡 직접 공유
        if (typeof Kakao === 'undefined' || !Kakao.isInitialized()) {
            alert('카카오 SDK 오류. 공유 시트로 전환합니다.');
            navigator.share && navigator.share({ title: '테니스 코트 예약', text: shareText });
            return;
        }
        try {
            Kakao.Share.sendDefault({
                objectType: 'text',
                text: shareText,
                link: { mobileWebUrl: window.location.origin, webUrl: window.location.origin }
            });
        } catch(err) {
            alert('카카오톡 공유 실패. 다시 시도해주세요.');
        }
    } else {
        // 공유 시트 (앱 선택)
        if (navigator.share) {
            navigator.share({ title: '테니스 코트 예약', text: shareText })
                .catch(err => { if (err.name !== 'AbortError') copyToClipboard(shareText); });
        } else {
            copyToClipboard(shareText);
        }
    }
}

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            alert('예약 정보가 복사되었습니다!\n카카오톡이나 문자로 붙여넣기 하세요.');
        }).catch(() => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        alert('예약 정보가 복사되었습니다!\n카카오톡이나 문자로 붙여넣기 하세요.');
    } catch (err) {
        alert('복사 실패. 예약 정보:\n\n' + text);
    }
    document.body.removeChild(textarea);
}

function onCellClick(e) {
    const el = e.target.closest('.data-cell');
    if(!el) return;
    
    const c = parseInt(el.dataset.c);
    const t = parseInt(el.dataset.t);

    // [1] 관리자 일괄 취소 모드
    if (typeof isBatchMode !== 'undefined' && isBatchMode) {
        if (el.classList.contains('booked') || el.classList.contains('fixed') || el.classList.contains('pending')) {
            const id = el.dataset.id;
            const coll = el.dataset.coll;
            
            // ▼▼▼ [핵심] 현재 보고 있는 날짜도 함께 저장 ▼▼▼
            const currentDate = document.getElementById('hiddenDate').value;
            
            // 이미 선택된 건지 확인 (ID와 날짜가 모두 같은지)
            const exists = deleteQueue.some(item => item.id === id && item.date === currentDate);
            
            if (exists) {
                // 선택 해제
                deleteQueue = deleteQueue.filter(item => !(item.id === id && item.date === currentDate));
                el.classList.remove('delete-select');
            } else {
                // 선택 추가 (날짜 포함)
                deleteQueue.push({ id: id, coll: coll, date: currentDate });
                el.classList.add('delete-select');
            }

            const btn = document.getElementById('btnBatchExec');
            if(btn) btn.style.display = deleteQueue.length > 0 ? 'block' : 'none';
        }
        return; 
    }

    // ... (이하 기존 로직 동일) ...
    // [2] 본인 예약 클릭, [3] 예약된 칸 방어, [4] 선택 해제, [5] 신규 선택 등...
    // 기존 코드 그대로 두시면 됩니다.
    
    // ▼▼▼ 아래는 기존 코드 유지용 (복사해서 덮어쓰실 때 참고하세요) ▼▼▼
    if(currentUser && el.dataset.ph === currentUser.phone && !isAdmin) {
        openCancel(el); return; 
    }
    if(el.classList.contains('booked') || el.classList.contains('fixed') || el.classList.contains('pending')) {
        if(isAdmin) openCancel(el);
        else alert("이미 예약된 시간입니다."); 
        return;
    }
    if(el.classList.contains('past')) return;

    const courtStats = {}; 
    selected.forEach(s => { if (!courtStats[s.c]) courtStats[s.c] = []; courtStats[s.c].push(s.t); });
    const isSelected = selected.some(s => s.c === c && s.t === t);
    
    if (isSelected) { removeSelect(c, t); validateSelection(); return; }

    if (!isAdmin && selected.length >= 6) { alert("전체 코트 합산 최대 6시간까지만 예약 가능합니다."); return; }
    const usedCourts = Object.keys(courtStats).map(Number);
    if (!isAdmin && !usedCourts.includes(c) && usedCourts.length >= 2) { alert("최대 2개의 코트만 동시에 예약할 수 있습니다."); return; }
    const myCourtHours = courtStats[c] ? courtStats[c].length : 0;
    if (!isAdmin && myCourtHours >= 3) { alert("1개 코트당 최대 3시간까지만 이용 가능합니다."); return; }

    const isAdjacent = courtStats[c] && (courtStats[c].includes(t-1) || courtStats[c].includes(t+1));
    if (isAdjacent) { addSelect(c, t); } 
    else {
        const isLastOneHourSlot = (t === 21);
        if (isLastOneHourSlot) {
            // 마지막 타임(21~22시)은 기본 2시간 규칙의 예외로 1시간 단독 예약을 허용
            addSelect(c, t);
            validateSelection();
            return;
        }

        if (!isAdmin && selected.length >= 5) { alert("잔여 시간이 부족합니다."); return; }
        const nextEl = document.getElementById(`c-${c}-${t+1}`);
        const isNextAvailable = nextEl && !nextEl.classList.contains('booked') && !nextEl.classList.contains('fixed') && !nextEl.classList.contains('pending') && !nextEl.classList.contains('blocked') && !nextEl.classList.contains('past');
        if (isNextAvailable) { addSelect(c, t); addSelect(c, t+1); } 
        else {
            const prevEl = document.getElementById(`c-${c}-${t-1}`);
            const isPrevAvailable = prevEl && !prevEl.classList.contains('booked') && !prevEl.classList.contains('fixed') && !prevEl.classList.contains('pending') && !prevEl.classList.contains('blocked') && !prevEl.classList.contains('past');
            if(isPrevAvailable) { addSelect(c, t-1); addSelect(c, t); } 
            else { addSelect(c, t); }
        }
    }
    validateSelection(); 
}

function addSelect(c, t) {
    if (selected.some(s => s.c === c && s.t === t)) return; // 중복 방지
    const el = document.getElementById(`c-${c}-${t}`);
    if (el) {
        // 지난 시간은 자동 선택에도 포함되면 안 됨
        if (el.classList.contains('past')) return;
        el.innerHTML = `<div class="orb select-orb">V</div>`;
        selected.push({c: c, t: t});
    }
}

function removeSelect(c, t) {
    selected = selected.filter(s => !(s.c === c && s.t === t));
    const el = document.getElementById(`c-${c}-${t}`);
    if (el) el.innerHTML = "";
}

function validateSelection() {
    const selCnt = document.getElementById('selCnt');
    const btn = document.getElementById('btnMainBook');
    
    selCnt.innerText = selected.length;

    if (selected.length === 0) {
        btn.disabled = true;
        return;
    }

    // [검증] 1시간짜리 '외톨이' 예약이 있는지 확인
    // (예: 10,11,12시를 잡았다가 가운데 11시를 취소해서 10시(1시간), 12시(1시간) 이렇게 남는 경우 방지)
    
    const courtStats = {};
    selected.forEach(s => {
        if (!courtStats[s.c]) courtStats[s.c] = [];
        courtStats[s.c].push(s.t);
    });

    let hasIsolated = false;
    for (const c in courtStats) {
        const times = courtStats[c].sort((a,b) => a-b);
        // 연속된 덩어리 크기 확인
        let currentBlockSize = 1;
        for (let i = 0; i < times.length; i++) {
            if (i < times.length - 1 && times[i+1] === times[i] + 1) {
                currentBlockSize++;
           } else {
                // 덩어리가 끝났을 때 크기가 2 미만(즉 1시간)이면 검사
                if (currentBlockSize < 2) {
                    // [수정] 1시간짜리라도, 양옆이 꽉 차서 어쩔 수 없는 '틈새'이거나
                    // 마지막 타임(21~22시)이면 예외적으로 허용
                    const t = times[i]; // 현재 검사 중인 1시간짜리 시간

                    if (t === 21) {
                        // 마지막 타임은 1시간 단독 예약 허용
                    } else {
                        const prevEl = document.getElementById(`c-${c}-${t-1}`);
                        const nextEl = document.getElementById(`c-${c}-${t+1}`);

                        // 앞, 뒤 칸이 없는지(영업시간 밖) 또는 예약되어 있는지 확인
                        const isPrevBlocked = !prevEl || prevEl.classList.contains('booked') || prevEl.classList.contains('fixed') || prevEl.classList.contains('pending') || prevEl.classList.contains('blocked');
                        const isNextBlocked = !nextEl || nextEl.classList.contains('booked') || nextEl.classList.contains('fixed') || nextEl.classList.contains('pending') || nextEl.classList.contains('blocked');

                        if (isPrevBlocked && isNextBlocked) {
                            // 틈새시장이므로 허용 (hasIsolated를 true로 만들지 않음 = 통과)
                        } else {
                            hasIsolated = true; // 여유가 있는데 1시간만 잡은거면 차단
                        }
                    }
                }
                currentBlockSize = 1; // 리셋
            }
        }
    }

    if (hasIsolated && !isAdmin) { // 관리자는 자유롭게 허용
        btn.disabled = true;
        // 사용자에게 이유를 알려주려면 아래 주석 해제
        // alert("최소 2시간 단위여야 합니다. 1시간만 남은 구간이 있습니다.");
    } else {
        btn.disabled = false;
    }
}

function autoScroll() {
        const h = new Date().getHours();
        if(h>7) document.getElementById('gridArea').scrollLeft = (h-7)*40;
    }

function paint(d, id, coll) {
    const el = document.getElementById(`c-${d.court}-${d.time}`);
    if(!el) return;

    if (coll === 'reservations') {
        el.classList.remove('fixed', 'pending', 'booked', 'blocked'); // blocked 클래스 제거 추가
        el.innerHTML = ""; 
    }

    // 스타일 결정
    let statusClass = "booked-orb"; 

    // ▼▼▼ [추가] 블락(BLOCKED) 상태 처리 ▼▼▼
    if (d.status === 'BLOCKED') {
        statusClass = "blocked-orb";
        el.classList.add('booked'); // 일반 유저 클릭 방지용으로 booked 클래스도 같이 줌
        el.classList.add('blocked'); // 스타일용 클래스
    } 
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
    else if(d.status === 'PENDING') {
        statusClass = "pending-orb";
        el.classList.add('pending');
    } else if(d.status === 'FIXED' || coll === 'recurring') {
        statusClass = "fixed-orb";
        el.classList.add('fixed');
    } else {
        el.classList.add('booked');
    }

    el.dataset.id = id; 
    el.dataset.coll = coll;
    el.dataset.info = d.name; 
    el.dataset.ph = d.phone;
    el.dataset.status = d.status; 
    
    let txt = d.name;
    // 관리자가 아니면 이름 마스킹 (단, 블락된 건 그대로 표시)
    if(!isAdmin && txt && d.status !== 'BLOCKED') txt = txt.substring(0,1) + "**";
    
    if(!txt) txt = (d.status === 'PENDING') ? "대기" : "확정";
    
    el.innerHTML = `<div class="orb ${statusClass}">${txt}</div>`;
}

function showMap(courtNum) {
    const centerData = CENTERS[currentCenter]; // 현재 지점 정보 가져오기
    
    // 1. 이미지 교체
    const imgEl = document.getElementById('mapImg');
    // 이미지가 설정되어 있으면 그 파일로, 없으면 기본안내 이미지(혹은 빈칸)
    imgEl.src = centerData.img ? centerData.img : ""; 
    imgEl.alt = centerData.name + " 배치도";

    // 2. 제목 설정
    document.getElementById('mapTitle').innerText = `[${currentCenter}] ${courtNum}코트 위치`;

    // 3. 빨간 박스 위치 잡기
    const box = document.getElementById('highlightBox');
    const posData = centerData.pos ? centerData.pos[courtNum] : null;

    if (posData) {
        // 좌표 데이터가 있으면 박스를 해당 위치로 이동
        box.style.display = 'flex';
        box.style.top = posData[0] + "%";    // 위에서부터 거리
        box.style.left = posData[1] + "%";   // 왼쪽에서부터 거리
        box.style.width = posData[2] + "%";  // 너비
        box.style.height = posData[3] + "%"; // 높이
        box.innerText = courtNum + "코트";
    } else {
        // 좌표가 없으면(아직 설정 안함) 박스 숨김
        box.style.display = 'none';
    }
    
    // 모달 열기
    openModal('modalMap');
}
