/*
 * 국제 테니스장 예약 앱 - Step 19 My Reservations / Dutch Pay / Match Logs
 * step19-my-reservations-extracted
 *
 * 분리 범위:
 * - 나의 예약 목록/취소 요청
 * - 환불 안내/취소 게시글 연결
 * - 더치페이 계산/공유
 * - 개인 경기 기록/승률 차트
 */

function openMyResList() {
    if(!currentUser) return alert("로그인이 필요합니다.");
    openModal('modalMyRes');
    switchMyResTab('upcoming'); // 기본적으로 예정된 예약부터 보여줌
}

function switchMyResTab(type) {
    const tabUp = document.getElementById('tabMyUp');
    const tabPast = document.getElementById('tabMyPast');
    
    if(type === 'upcoming') {
        tabUp.style.borderBottom = "3px solid #8b5cf6"; tabUp.style.color = "#8b5cf6";
        tabPast.style.borderBottom = "none"; tabPast.style.color = "#94a3b8";
        loadMyResData(true); // 미래 데이터 로드
    } else {
        tabPast.style.borderBottom = "3px solid #64748b"; tabPast.style.color = "#64748b";
        tabUp.style.borderBottom = "none"; tabUp.style.color = "#94a3b8";
        loadMyResData(false); // 과거 데이터 로드
    }
}

/* [수정] 환불 금액 계산 로직 (전일 취소 90% 환불 적용) */
function calcRefund(resDateStr, resTime) {
    // 1. 날짜 차이 계산
    const today = new Date();
    today.setHours(0,0,0,0);
    
    const target = new Date(resDateStr);
    target.setHours(0,0,0,0);
    
    const diffTime = target.getTime() - today.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    
    // 2. 이용 요금 가져오기
    const isCitizen = currentUser ? currentUser.isCitizen : false;
    const pricingInfo = getConfiguredPriceInfo(resDateStr, resTime);
    const isNight = pricingInfo.isNight;
    const originalPrice = getMatrixPriceBySlot(resDateStr, resTime, isCitizen);
    
    // 3. 환불율 결정 [수정됨]
    let rate = 0;
    if (diffDays >= 5) {
        rate = 100; // 5일 전까지: 100% 환불
    } else if (diffDays >= 1 && diffDays <= 4) { 
        rate = 90;  // 1일 전(전날) ~ 4일 전: 90% 환불 (기존 2일에서 1일로 변경)
    } else {
        rate = 0;   // 당일(0): 환불 불가
    }
    
    const refundAmount = Math.floor(originalPrice * (rate / 100));
    
    return { dDay: diffDays, rate: rate, amount: refundAmount };
}

/* [수정] 나의 예약 목록 (통계 표시 + 캘린더 저장 버튼 추가) */
function loadMyResData(isUpcoming) {
    const list = document.getElementById('myResList');
    const batchArea = document.getElementById('batchCancelArea');
    list.innerHTML = "<div style='text-align:center; padding:20px;'>불러오는 중...</div>";
    
    if(batchArea) batchArea.style.display = isUpcoming ? 'block' : 'none';

    // [신규] 통계 박스 생성 (목록 위에 삽입)
    let statsBox = document.getElementById('myStatsBox');
    if (!statsBox) {
        statsBox = document.createElement('div');
        statsBox.id = 'myStatsBox';
        statsBox.style.cssText = "background:linear-gradient(135deg, #3b82f6, #8b5cf6); color:white; padding:15px; border-radius:12px; margin-bottom:15px; display:none; box-shadow:0 4px 6px rgba(0,0,0,0.1);";
        list.parentElement.insertBefore(statsBox, list);
    }

    const todayStr = new Date().toISOString().split('T')[0];
    let query = db.collection("reservations").where("phone", "==", currentUser.phone);

    if(isUpcoming) {
        query = query.where("date", ">=", todayStr).orderBy("date", "asc").orderBy("time", "asc");
        statsBox.style.display = 'none'; // 예정 내역에선 통계 숨김 (취향따라 켜도 됨)
    } else {
        // 지난 내역은 많이 불러와서 통계 냄 (최근 100개)
        query = query.where("date", "<", todayStr).orderBy("date", "desc").orderBy("time", "desc").limit(100);
        statsBox.style.display = 'block';
    }

    query.get().then(snap => {
        list.innerHTML = "";
        
        // [통계 계산]
        let totalCount = 0;
        let totalPrice = 0; // *정확한 금액은 요금표 로직 필요하지만, 여기선 대략 횟수로만 카운트
        
        if(snap.empty) {
            list.innerHTML = `<div style="text-align:center; padding:40px 10px; color:#94a3b8;">${isUpcoming ? "예정된 예약이 없습니다." : "지난 예약 내역이 없습니다."}</div>`;
            if(!isUpcoming) statsBox.innerHTML = "<div>아직 이용 내역이 없습니다.</div>";
            return;
        }

        snap.forEach(doc => {
            const d = doc.data();
            if (d.status === "CANCELED") return;
            
            // 통계 집계 (지난 내역일 때만)
            if (!isUpcoming) {
                totalCount++;
            }

            let statusBadge = "", cardBg = "", cardBorder = "", timeColor = "";

            if (isUpcoming) {
                if (d.status === 'PENDING') {
                    statusBadge = `<span style="background:#10b981; color:white; font-size:0.7rem; padding:2px 6px; border-radius:4px;">⏳ 가승인 (입금대기)</span>`;
                    cardBg = "#ecfdf5"; cardBorder = "1px solid #34d399"; timeColor = "#059669";
                } else {
                    statusBadge = `<span style="background:#8b5cf6; color:white; font-size:0.7rem; padding:2px 6px; border-radius:4px;">✅ 예약 확정</span>`;
                    cardBg = "#f5f3ff"; cardBorder = "1px solid #d8b4fe"; timeColor = "#7c3aed";
                }
            } else {
                statusBadge = `<span style="background:#94a3b8; color:white; font-size:0.7rem; padding:2px 6px; border-radius:4px;">이용 완료</span>`;
                cardBg = "#f1f5f9"; cardBorder = "1px solid #cbd5e1"; timeColor = "#64748b";
            }

            const div = document.createElement('div');
            div.style.cssText = `background:${cardBg}; border:${cardBorder}; border-radius:12px; padding:15px; margin-bottom:10px; position:relative; cursor:pointer; transition: all 0.2s ease;`;
            
            // ▼▼▼ [추가] 호버 효과 ▼▼▼
            div.onmouseenter = () => {
                div.style.transform = 'translateY(-2px)';
                div.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)';
            };
            div.onmouseleave = () => {
                div.style.transform = 'translateY(0)';
                div.style.boxShadow = 'none';
            };
            
            // ▼▼▼ [추가] 카드 클릭 시 더치페이 모달 열기 ▼▼▼
            div.onclick = (e) => {
                // 체크박스나 버튼 클릭 시에는 모달 안 열림
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON' || e.target.closest('button')) {
                    return;
                }
                openDutchPayModal(d, doc.id);
            };

            let checkboxHtml = "";
            if(isUpcoming) {
                checkboxHtml = `<input type="checkbox" class="chk-my-res" value="${doc.id}" 
                                data-date="${d.date}" data-time="${d.time}" data-status="${d.status}"
                                onclick="event.stopPropagation()"
                                style="width:20px; height:20px; margin-right:10px; accent-color:#ef4444;">`;
            }

            // [핵심] 캘린더 저장 버튼 생성 (예정된 예약 중 확정된 건만)
            let calBtn = "";
            if (isUpcoming && d.status === 'BOOKED') {
                calBtn = `<button onclick="event.stopPropagation(); downloadCalendarFile('테니스 예약', '${d.date}', ${d.time}, ${d.court})" 
                          style="border:1px solid #8b5cf6; background:white; color:#8b5cf6; border-radius:4px; padding:4px 8px; font-size:0.75rem; cursor:pointer; display:flex; align-items:center; gap:4px; font-weight:bold;">
                          📅 달력 저장
                          </button>`;
            }

            div.innerHTML = `
                <div style="display:flex; align-items:center; margin-bottom:8px;">
                    ${checkboxHtml}
                    <div style="flex:1;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div style="font-weight:bold; color:#333;">${d.date} (${getDayName(d.date)})</div>
                            ${statusBadge}
                        </div>
                    </div>
                </div>
                <div style="font-size:0.9rem; color:#475569; margin-bottom:5px; padding-left:${isUpcoming?'30px':'0'}; display:flex; align-items:center; justify-content:space-between;">
                    <div style="display:flex; align-items:center;">
                        <span>📍 <b>[${d.center || '국제'}]</b> ${d.court}코트</span>
                        <button onclick="event.stopPropagation(); showMap(${d.court})" style="margin-left:8px; border:1px solid #cbd5e1; background:white; color:#64748b; border-radius:4px; padding:2px 6px; font-size:0.75rem; cursor:pointer;">
                            🗺️ 위치
                        </button>
                    </div>
                    ${calBtn}
                </div>
                <div style="font-size:0.95rem; font-weight:800; color:${timeColor}; padding-left:${isUpcoming?'30px':'0'};">
                    ⏰ ${d.time}:00 ~ ${d.time+1}:00
                </div>
                <div style="text-align:center; margin-top:10px; padding-top:10px; border-top:1px dashed #cbd5e1;">
                    <div style="font-size:0.75rem; color:#64748b;">💡 카드를 클릭하면 더치페이 계산 & 공유</div>
                </div>
                ${isUpcoming ? `<div style="text-align:right; margin-top:8px;">
                    <button onclick="event.stopPropagation(); cancelMyRes('${doc.id}', '${d.date}', ${d.time}, '${d.status}')" 
                    style="background:#fff; border:1px solid #ef4444; color:#ef4444; padding:6px 12px; border-radius:6px; cursor:pointer; font-size:0.85rem; font-weight:bold;">예약 취소</button>
                </div>` : ''}
            `;
            list.appendChild(div);
        });

        // [통계 업데이트]
        if(!isUpcoming) {
            statsBox.innerHTML = `
                <div style="font-size:0.9rem; margin-bottom:5px; opacity:0.9;">🎾 나의 테니스 라이프</div>
                <div style="font-size:1.4rem; font-weight:800;">
                    최근 <span style="color:#fde047;">${totalCount}회</span> 운동완료!
                </div>
                <div style="font-size:0.8rem; margin-top:5px; opacity:0.8;">꾸준한 운동은 건강의 지름길입니다 💪</div>
            `;
        }

    }).catch(err => list.innerHTML = "오류 발생: " + err.message);
}

async function openDutchPayModal(resData, resId) {
    try {
        console.log('더치페이 모달 열기 시작:', resData);
        
        currentDutchPayData = { ...resData, id: resId };
        
        // currentUser 확인
        if (!currentUser || !currentUser.phone) {
            alert('로그인 정보를 찾을 수 없습니다. 다시 로그인해주세요.');
            return;
        }
        
        // ▼▼▼ [수정] 인덱스 없이 작동하도록 쿼리 변경 ▼▼▼
        // 먼저 phone과 date로만 조회 (인덱스 불필요)
        const sameDateReservations = await db.collection('reservations')
            .where('phone', '==', currentUser.phone)
            .where('date', '==', resData.date)
            .get();
        
        console.log('같은 날짜 예약 개수 (필터 전):', sameDateReservations.docs.length);
        
        let totalPrice = 0;
        let timeSlots = [];
        
        // 각 예약의 요금 계산 (CANCELED 제외는 여기서 처리)
        for (const doc of sameDateReservations.docs) {
            const d = doc.data();
            
            // CANCELED 상태 제외
            if (d.status === 'CANCELED') {
                continue;
            }
            
            const priceInfo = await getReservationPrice(d.center || '국제', d.date, d.time, d.court);
            totalPrice += priceInfo.price;
            timeSlots.push({
                time: d.time,
                court: d.court,
                price: priceInfo.price,
                isNight: priceInfo.isNight
            });
        }
        
        console.log('총 금액:', totalPrice, '시간대:', timeSlots);
        
        // 시간순 정렬
        timeSlots.sort((a, b) => a.time - b.time);
        
        currentDutchPayData.totalPrice = totalPrice;
        currentDutchPayData.timeSlots = timeSlots;
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
    
    // 모달 정보 업데이트
    const infoBox = document.getElementById('dutchPayInfo');
    
    // 예약 시간대 목록 생성
    const timeListHTML = timeSlots.map(slot => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid #e2e8f0;">
            <div>
                <span style="font-weight:600; color:#1e293b;">${slot.time}:00~${slot.time+1}:00</span>
                <span style="font-size:0.8rem; color:#64748b; margin-left:6px;">${slot.court}코트</span>
            </div>
            <div>
                <span style="font-size:0.75rem; color:#64748b; margin-right:6px;">${slot.isNight ? '🌙' : '☀️'}</span>
                <span style="font-weight:700; color:#475569;">${slot.price.toLocaleString()}원</span>
            </div>
        </div>
    `).join('');
    
    infoBox.innerHTML = `
        <div style="text-align:center; margin-bottom:15px;">
            <div style="font-size:1.1rem; font-weight:800; color:#1e293b; margin-bottom:8px;">
                📅 ${resData.date} (${getDayName(resData.date)})
            </div>
            <div style="font-size:0.9rem; color:#64748b; margin-top:4px;">
                📍 <strong>${resData.center || '국제'}</strong>
            </div>
        </div>
        
        ${timeSlots.length > 1 ? `
            <div style="background:#f8fafc; padding:12px; border-radius:8px; margin-bottom:12px; border:1px solid #e2e8f0;">
                <div style="font-size:0.85rem; font-weight:600; color:#475569; margin-bottom:8px;">
                    📋 당일 예약 내역 (${timeSlots.length}시간)
                </div>
                ${timeListHTML}
            </div>
        ` : `
            <div style="background:#f8fafc; padding:12px; border-radius:8px; margin-bottom:12px; border:1px solid #e2e8f0;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span style="font-weight:600; color:#1e293b;">${timeSlots[0].time}:00~${timeSlots[0].time+1}:00</span>
                        <span style="font-size:0.8rem; color:#64748b; margin-left:6px;">${timeSlots[0].court}코트</span>
                    </div>
                    <span style="font-size:0.75rem; color:#64748b;">${timeSlots[0].isNight ? '🌙 야간' : '☀️ 주간'}</span>
                </div>
            </div>
        `}
        
        <div style="background:linear-gradient(135deg, ${timeSlots.some(s => s.isNight) ? '#1e293b' : '#fef3c7'}, ${timeSlots.some(s => s.isNight) ? '#475569' : '#fde68a'}); padding:15px; border-radius:12px; border:2px solid ${timeSlots.some(s => s.isNight) ? '#64748b' : '#fbbf24'};">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:${timeSlots.some(s => s.isNight) ? '#e2e8f0' : '#78350f'}; font-size:0.9rem; font-weight:600;">당일 총 금액</span>
                <span style="font-weight:900; color:${timeSlots.some(s => s.isNight) ? 'white' : '#92400e'}; font-size:1.3rem;">${totalPrice.toLocaleString()}원</span>
            </div>
        </div>
    `;
    
    // 초기값 설정
    document.getElementById('dutchPeople').value = 2;
    calculateDutchPay();
    
    console.log('모달 열기 완료');
    openModal('modalDutchPay');
    
    } catch(err) {
        console.error('더치페이 모달 오류:', err);
        alert('더치페이 계산 중 오류가 발생했습니다.\n' + err.message);
    }
}

async function getReservationPrice(center, dateStr, time, court) {
    // ▼▼▼ [수정] 계절별 요금 사용 ▼▼▼
    const priceInfo = await getPriceForDate(dateStr, time);
    
    return {
        price: priceInfo.price,
        isNight: priceInfo.isNight,
        timeLabel: priceInfo.isNight ? '🌙 야간 (라이트)' : '☀️ 주간',
        hourRange: priceInfo.isNight ? `${String(priceInfo.nightStart).padStart(2,'0')}:00 ~ 23:59` : `07:00 ~ ${String(Math.max(priceInfo.nightStart - 1, 7)).padStart(2,'0')}:59`
    };
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
}

function adjustPeople(delta) {
    const input = document.getElementById('dutchPeople');
    let current = parseInt(input.value) || 2;
    current += delta;
    
    if (current < 1) current = 1;
    if (current > 20) current = 20;
    
    input.value = current;
    calculateDutchPay();
}

function calculateDutchPay() {
    if (!currentDutchPayData) return;
    
    const people = parseInt(document.getElementById('dutchPeople').value) || 2;
    const totalPrice = currentDutchPayData.totalPrice; // 변경: price → totalPrice
    const perPerson = Math.ceil(totalPrice / people); // 올림
    
    document.getElementById('dutchTotalPrice').textContent = totalPrice.toLocaleString() + '원';
    document.getElementById('dutchPeopleDisplay').textContent = people + '명';
    document.getElementById('dutchPerPerson').textContent = perPerson.toLocaleString() + '원';
}

function shareDutchPay(method) {
    if (!currentDutchPayData) return;
    
    const d = currentDutchPayData;
    const people = parseInt(document.getElementById('dutchPeople').value) || 2;
    const totalPrice = d.totalPrice;
    const perPerson = Math.ceil(totalPrice / people);
    
    // 예약 시간대 목록 생성
    const timeList = d.timeSlots.map(slot => 
        `  ${slot.time}:00~${slot.time+1}:00 ${slot.court}코트 (${slot.isNight ? '🌙야간' : '☀️주간'} ${slot.price.toLocaleString()}원)`
    ).join('\n');
    
    // 공유 메시지 생성
    const message = `🎾 테니스 예약 정산

📅 ${d.date} (${getDayName(d.date)})
📍 ${d.center || '국제'}

${d.timeSlots.length > 1 ? `📋 예약 내역 (${d.timeSlots.length}시간)\n${timeList}\n` : `⏰ ${d.timeSlots[0].time}:00~${d.timeSlots[0].time+1}:00 ${d.timeSlots[0].court}코트\n`}
💰 총 비용: ${totalPrice.toLocaleString()}원
👥 인원: ${people}명
💸 1인당: ${perPerson.toLocaleString()}원

─────────────────
장유국제테니스장
`;

    if (method === 'sms') {
        // 문자앱 직접 열기
        const encoded = encodeURIComponent(message);
        window.location.href = `sms:?body=${encoded}`;
    } else if (method === 'kakao') {
        // 카카오톡 직접 공유
        if (typeof Kakao === 'undefined' || !Kakao.isInitialized()) {
            alert('카카오 SDK 오류. 공유 시트로 전환합니다.');
            navigator.share && navigator.share({ title: '테니스 예약 정산', text: message });
            return;
        }
        try {
            Kakao.Share.sendDefault({
                objectType: 'text',
                text: message,
                link: { mobileWebUrl: window.location.origin, webUrl: window.location.origin }
            });
        } catch(err) {
            console.error('카카오톡 공유 오류:', err);
            alert('카카오톡 공유 실패. 다시 시도해주세요.');
        }
    } else {
        // 공유 시트 열기 (카카오·문자·기타 앱 선택 가능)
        if (navigator.share) {
            navigator.share({ title: '테니스 예약 정산', text: message })
                .catch(err => { if (err.name !== 'AbortError') copyToClipboard(message); });
        } else {
            copyToClipboard(message);
        }
    }
}

function shareViaSMS(message) {
    if (navigator.share) {
        // Web Share API 사용 (모바일)
        navigator.share({
            title: '테니스 예약 정산',
            text: message
        }).catch(err => {
            // 실패 시 클립보드 복사
            copyToClipboard(message);
        });
    } else {
        // 클립보드 복사
        copyToClipboard(message);
    }
}

/* [수정] 관리자 번호 가져오기 (설정된 admPh 변수 사용) */
async function getAdminPhoneNumber() {
    // admPh는 loadConfig()에서 이미 불러와진 전역 변수입니다.
    if(typeof admPh !== 'undefined' && admPh && admPh !== "010-0000-0000") {
        return admPh;
    }
    // 만약 로드가 안 됐다면 DB에서 다시 확인
    try {
        const doc = await db.collection('settings').doc('global').get();
        if (doc.exists && doc.data().adminPhone) {
            return doc.data().adminPhone;
        }
    } catch(e) { console.error(e); }
    
    return "010-0000-0000"; // 최후의 수단
}

/* [수정] 나의 예약 일괄 취소 (상태별 분기 처리) */
async function getLatestMyReservationItem(item) {
    try {
        const ref = db.collection('reservations').doc(item.id);
        const doc = await ref.get();
        if (doc.exists) {
            const d = doc.data() || {};
            return {
                id: doc.id,
                date: d.date || item.date,
                time: d.time !== undefined ? Number(d.time) : Number(item.time),
                court: d.court !== undefined ? Number(d.court) : (item.court !== undefined ? Number(item.court) : null),
                status: d.status || item.status || 'UNKNOWN',
                name: d.name || (currentUser ? currentUser.name : '회원'),
                phone: d.phone || (currentUser ? currentUser.phone : '')
            };
        }
    } catch(e) {
        console.warn('내 예약 최신 상태 확인 실패:', e);
    }
    return {
        id: item.id,
        date: item.date,
        time: Number(item.time),
        court: item.court !== undefined ? Number(item.court) : null,
        status: item.status || 'UNKNOWN',
        name: currentUser ? currentUser.name : '회원',
        phone: currentUser ? currentUser.phone : ''
    };
}

function buildCancelDetailText(targets) {
    return (targets || [])
        .slice()
        .sort((a,b) => String(a.date || '').localeCompare(String(b.date || '')) || (Number(a.time || 0) - Number(b.time || 0)) || (Number(a.court || 0) - Number(b.court || 0)))
        .map(t => {
            const courtText = t.court ? `${t.court}코트 ` : '';
            return `- ${t.date} ${courtText}${t.time}:00`;
        })
        .join('\n');
}

/* [최종 수정] 나의 예약 일괄 취소: 버튼/캐시 상태가 아니라 DB 최신 status 기준으로 분기 */
async function cancelSelectedMyRes() {
    const checked = document.querySelectorAll('.chk-my-res:checked');
    if(checked.length === 0) return alert("취소할 내역을 선택해주세요.");

    let targets = Array.from(checked).map(el => ({
        id: el.value,
        date: el.dataset.date,
        time: parseInt(el.dataset.time),
        court: el.dataset.court ? parseInt(el.dataset.court) : null,
        status: el.dataset.status
    }));

    targets = await Promise.all(targets.map(getLatestMyReservationItem));
    targets = targets.filter(t => t && t.id && t.status !== 'CANCELED');

    if(targets.length === 0) return alert('취소할 내역이 없습니다.');

    const hasBooked = targets.some(t => t.status === 'BOOKED' || t.status === 'FIXED');
    const allPending = targets.every(t => t.status === 'PENDING');

    if (hasBooked) {
        openRefundPopup(targets);
        return;
    }

    if (!allPending) {
        alert('예약 상태를 확인할 수 없습니다. 새로고침 후 다시 시도해주세요.');
        if (typeof openMyResList === 'function') openMyResList();
        return;
    }

    if(!confirm(`선택한 ${targets.length}건은 가승인(입금 대기) 상태입니다.\n관리자에게 가승인 취소 요청 문자를 보내시겠습니까?`)) return;

    const adminPhone = await getAdminPhoneNumber();
    const userName = currentUser ? currentUser.name : "회원";
    const msgBody = `[가승인 일괄 취소 요청]\n신청자: ${userName}\n총 ${targets.length}건 취소 요청합니다.\n\n${buildCancelDetailText(targets)}\n\n위 가승인 예약을 취소해 주세요.`;
    const isIOS = /iphone|ipad|ipod/.test(navigator.userAgent.toLowerCase());
    location.href = `sms:${adminPhone}${isIOS ? '&' : '?'}body=${encodeURIComponent(msgBody)}`;
}

async function cancelMyRes(id, date, time, status, court) {
    const target = await getLatestMyReservationItem({ id, date, time, status, court });

    if (target.status === 'BOOKED' || target.status === 'FIXED') {
        openRefundPopup([target]);
        return;
    }

    if (target.status !== 'PENDING') {
        alert('예약 상태를 확인할 수 없습니다. 새로고침 후 다시 시도해주세요.');
        if (typeof openMyResList === 'function') openMyResList();
        return;
    }

    if(!confirm("가승인(입금 대기) 상태의 예약입니다.\n관리자에게 가승인 취소 요청 문자를 보내시겠습니까?")) return;

    const adminPhone = await getAdminPhoneNumber();
    const msgBody = `[가승인 취소 요청]\n\n신청자: ${currentUser ? currentUser.name : '회원'}\n${buildCancelDetailText([target])}\n\n위 가승인 예약을 취소해 주세요.`;
    const isIOS = /iphone|ipad|ipod/.test(navigator.userAgent.toLowerCase());
    location.href = `sms:${adminPhone}${isIOS ? '&' : '?'}body=${encodeURIComponent(msgBody)}`;
}

function openRefundPopup(targets) {
    tempCancelTargets = targets; // 전역 변수에 저장
    
    let totalAmt = 0;
    let minRate = 100; // 가장 낮은 환불율 추적
    
    // 계산 로직 수행
    tempCancelTargets.forEach(t => {
        const calc = calcRefund(t.date, t.time);
        t.refundAmt = calc.amount;
        t.refundRate = calc.rate;
        t.dDay = calc.dDay;
        
        totalAmt += calc.amount;
        if(calc.rate < minRate) minRate = calc.rate;
    });

    // 팝업 UI 업데이트
    const msgSpan = document.getElementById('rfMsg');
    
    if(targets.length === 1) {
        const t = targets[0];
        document.getElementById('rfDate').innerText = `${t.date} ${t.court ? t.court + '코트 ' : ''}${t.time}:00`;
        document.getElementById('rfDday').innerText = (t.dDay === 0) ? "당일" : `${t.dDay}일 전`;
    } else {
        document.getElementById('rfDate').innerText = `${targets[0].date} 등 총 ${targets.length}건`;
        document.getElementById('rfDday').innerText = "날짜별 상이";
    }
    
    document.getElementById('rfAmount').innerText = totalAmt.toLocaleString() + "원";

    // 안내 메시지
    if (minRate === 100) {
        msgSpan.innerText = "전액 환불 대상입니다.";
        msgSpan.style.color = "#16a34a";
    } else if (minRate === 0) {
        msgSpan.innerText = "환불 불가 내역이 포함되어 있습니다.";
        msgSpan.style.color = "#dc2626";
    } else {
        msgSpan.innerText = "위약금이 포함된 내역이 있습니다.";
        msgSpan.style.color = "#ea580c";
    }

    openModal('modalRefund');
}

function checkUpcomingPopup() {
    if(!currentUser) return;

    // 1. 한국 시간(KST) 기준으로 오늘 날짜 정확히 계산
    // (기존 코드는 시차 때문에 오전 9시 이전에 어제로 인식될 수 있음)
    const now = new Date();
    const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
    const kstGap = 9 * 60 * 60 * 1000;
    const todayStr = new Date(utc + kstGap).toISOString().split('T')[0];
    
    // 2. 검색 조건 강화 (색인을 확실히 타도록 orderBy 추가)
    db.collection("reservations")
      .where("phone", "==", currentUser.phone)
      .where("date", ">=", todayStr)
      .orderBy("date", "asc")  // [중요] 이 줄이 없으면 색인을 못 찾을 수 있음
      .limit(1)
      .get()
      .then(snap => {
          if(!snap.empty) {
              // 예약이 있으면 팝업 열기
              openMyResList();
          }
      })
      .catch(err => {
          // [중요] 만약 색인이 또 필요하다면 여기서 링크가 뜹니다!
          if(err.message.includes("index")) {
             // 에러 메시지 속에 있는 링크를 복사하기 쉽도록 띄움
             alert("자동 팝업을 위한 추가 색인이 필요합니다.\n확인을 누르고 콘솔(F12)의 링크를 클릭하거나,\n아래 메시지를 참고하세요.\n\n" + err.message);
          } else {
             console.log("팝업 체크 중 오류:", err);
          }
      });
}

/* [신규] 스마트폰 캘린더에 일정 저장하기 (.ics 파일 생성) */
function downloadCalendarFile(title, date, time, court) {
    // 1. 날짜 시간 포맷팅 (YYYYMMDDTHHMMSS)
    const startStr = date.replace(/-/g, '') + 'T' + String(time).padStart(2,'0') + '0000';
    const endStr = date.replace(/-/g, '') + 'T' + String(time + 1).padStart(2,'0') + '0000';
    
    // 2. ICS 파일 내용 생성
    const icsMsg = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//TennisKJ//CourtBooking//KO
BEGIN:VEVENT
UID:${Date.now()}@tenniskj
DTSTAMP:${startStr}Z
DTSTART:${startStr}
DTEND:${endStr}
SUMMARY:[테니스] ${title} (${court}코트)
DESCRIPTION:예약 코트: ${court}번\\n시간: ${time}시 ~ ${time+1}시\\n즐거운 운동 되세요!
LOCATION:장유국제테니스장
END:VEVENT
END:VCALENDAR`;

    // 3. 파일 다운로드 트리거
    const blob = new Blob([icsMsg], { type: 'text/calendar;charset=utf-8' });
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.setAttribute('download', `tennis_invite_${date}.ics`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function toggleScoreForm() {
    const form = document.getElementById('scoreForm');
    if(form.style.display === 'none') {
        form.style.display = 'block';
        document.getElementById('gmDate').value = new Date().toISOString().split('T')[0]; // 오늘 날짜 자동
    } else {
        form.style.display = 'none';
    }
}

function saveMatchLog() {
    if(!currentUser) return;
    
    const date = document.getElementById('gmDate').value;
    const opponent = document.getElementById('gmOpponent').value.trim();
    const myScore = document.getElementById('gmMyScore').value;
    const oppScore = document.getElementById('gmOppScore').value;
    const result = document.getElementById('gmResult').value; // WIN, LOSE, DRAW

    if(!date || !opponent) return alert("날짜와 상대방 이름을 입력해주세요.");

    db.collection("match_logs").add({
        uid: currentUser.uid,
        date: date,
        opponent: opponent,
        score: `${myScore} : ${oppScore}`,
        result: result,
        at: new Date()
    }).then(() => {
        alert("기록되었습니다 🎾");
        toggleScoreForm(); // 폼 닫기
        // 입력창 초기화
        document.getElementById('gmOpponent').value="";
        document.getElementById('gmMyScore').value="";
        document.getElementById('gmOppScore').value="";
        loadMatchLogs(); // 목록 새로고침
    }).catch(err => alert("저장 실패: " + err.message));
}

function loadMatchLogs() {
    if(!currentUser) return;
    const list = document.getElementById('scoreList');
    list.innerHTML = "<div style='text-align:center; padding:20px;'>불러오는 중...</div>";

    db.collection("match_logs")
      .where("uid", "==", currentUser.uid)
      .orderBy("date", "desc")
      .get()
      .then(snap => {
          list.innerHTML = "";
          
          let wins = 0, losses = 0, draws = 0;
          
          if(snap.empty) {
              list.innerHTML = "<div style='text-align:center; padding:30px; color:#cbd5e1;'>아직 경기 기록이 없습니다.<br>첫 승리를 기록해보세요! 🏆</div>";
          } else {
              snap.forEach(doc => {
                  const d = doc.data();
                  
                  // 통계 집계
                  if(d.result === 'WIN') wins++;
                  else if(d.result === 'LOSE') losses++;
                  else draws++;

                  // 리스트 아이템 생성
                  let badge = "", border = "";
                  if(d.result === 'WIN') { badge = "<span style='color:#16a34a; font-weight:bold;'>WIN</span>"; border="3px solid #bbf7d0"; }
                  else if(d.result === 'LOSE') { badge = "<span style='color:#dc2626; font-weight:bold;'>LOSS</span>"; border="3px solid #fecaca"; }
                  else { badge = "<span style='color:#64748b; font-weight:bold;'>DRAW</span>"; border="3px solid #e2e8f0"; }

                  const div = document.createElement('div');
                  div.style.cssText = `background:white; padding:12px; border-radius:10px; border-left:${border}; margin-bottom:8px; display:flex; align-items:center; justify-content:space-between; box-shadow:0 1px 2px rgba(0,0,0,0.05);`;
                  div.innerHTML = `
                      <div>
                          <div style="font-size:0.8rem; color:#94a3b8;">${d.date}</div>
                          <div style="font-weight:bold; color:#333; font-size:0.95rem;">vs ${d.opponent}</div>
                      </div>
                      <div style="text-align:right;">
                          <div style="font-size:1.1rem; font-weight:800; color:#333;">${d.score}</div>
                          <div style="font-size:0.8rem;">${badge}</div>
                      </div>
                      <button onclick="deleteMatchLog('${doc.id}')" style="margin-left:10px; border:none; background:none; color:#cbd5e1; cursor:pointer;">&times;</button>
                  `;
                  list.appendChild(div);
              });
          }

          // 통계 업데이트
          const total = wins + losses + draws;
          const rate = total > 0 ? Math.round((wins / total) * 100) : 0;
          
          document.getElementById('scoreTotal').innerText = total;
          document.getElementById('scoreRate').innerText = rate;

          // 차트 그리기 (도넛 차트)
          drawScoreChart(wins, losses, draws);

      }).catch(err => {
          // 인덱스 에러가 날 수 있으므로 안내
          if(err.message.includes("index")) {
             const url = err.message.match(/https:\/\/[^\s]+/)[0];
             list.innerHTML = `<div style="padding:10px; text-align:center;"><a href="${url}" target="_blank" style="color:blue; text-decoration:underline;">👉 여기를 눌러 색인을 추가해주세요 (관리자용)</a></div>`;
          }
      });
}

function deleteMatchLog(id) {
    if(confirm("기록을 삭제하시겠습니까?")) {
        db.collection("match_logs").doc(id).delete().then(() => loadMatchLogs());
    }
}

function drawScoreChart(w, l, d) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    if(scoreChart) scoreChart.destroy(); // 기존 차트 삭제

    // 데이터가 없으면 회색 원 표시
    const data = (w+l+d === 0) ? [1] : [w, l, d];
    const colors = (w+l+d === 0) ? ['#e2e8f0'] : ['#22c55e', '#ef4444', '#94a3b8']; // 승(녹색), 패(빨강), 무(회색)

    scoreChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['승', '패', '무'],
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 0,
                cutout: '70%'
            }]
        },
        options: {
            plugins: { legend: { display: false }, tooltip: { enabled: (w+l+d > 0) } },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}
