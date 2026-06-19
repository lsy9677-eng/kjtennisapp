/*
 * 국제 테니스장 예약 앱 - Step 18 Admin Settings / Statistics
 * step18-admin-settings-extracted
 *
 * 분리 범위:
 * - 관리자 설정 저장/설정창 열기
 * - 월간 매출 통계/CSV
 * - 시민인증 회원 관리
 * - 관리자 비밀번호 로그인
 *
 * 예약 저장(saveBook), 결제(doPay), 예약 조회(loadDB)는 다른 모듈에 유지합니다.
 */

/* step4-utils-extracted: getDateFromAny moved to ./js/utils.js */

    async function cleanupCitizenProofs() {
        if (!isAdmin) {
            alert('관리자만 실행할 수 있습니다.');
            return;
        }
        if (!confirm('승인완료/거절 상태이거나 30일 지난 시민 인증 사진을 정리하시겠습니까?')) return;

        const btn = document.getElementById('btnCitizenCleanup');
        const orgText = btn ? btn.innerText : '';
        if (btn) {
            btn.disabled = true;
            btn.innerText = '정리 중...';
        }

        try {
            const snap = await db.collection('users').get();
            const now = Date.now();
            const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
            let deletedCount = 0;
            let checkedCount = 0;

            for (const doc of snap.docs) {
                checkedCount++;
                const data = doc.data() || {};
                const proofUrl = data.proofUrl || '';
                if (!proofUrl) continue;

                const status = String(data.verifStatus || '').toUpperCase();
                const uploadedAt = getDateFromAny(data.proofUploadedAt) || getDateFromAny(data.joinedAt) || getDateFromAny(data.at);
                const ageMs = uploadedAt ? (now - uploadedAt.getTime()) : 0;
                const shouldDeleteByStatus = ['APPROVED', 'REJECTED', 'NONE'].includes(status);
                const shouldDeleteByAge = !!uploadedAt && ageMs >= THIRTY_DAYS;

                if (!shouldDeleteByStatus && !shouldDeleteByAge) continue;

                const deleted = await deleteProofByUrl(proofUrl);
                if (!deleted) continue;

                await doc.ref.set({
                    proofUrl: firebase.firestore.FieldValue.delete(),
                    proofUploadedAt: firebase.firestore.FieldValue.delete(),
                    proofDeletedAt: firebase.firestore.FieldValue.serverTimestamp(),
                    proofAutoDeletedAt: firebase.firestore.FieldValue.serverTimestamp()
                }, { merge: true });

                await appendCitizenAudit(doc.id, shouldDeleteByAge ? 'AUTO_DELETE_30D' : 'DELETE_PROOF', {
                    targetStatus: status || 'UNKNOWN',
                    deletedBy: 'admin_cleanup',
                    reason: shouldDeleteByAge ? 'older_than_30_days' : 'approved_or_rejected_cleanup'
                });
                deletedCount++;
            }

            alert(`사진 정리 완료
점검: ${checkedCount}명
삭제: ${deletedCount}건`);
        } catch (err) {
            console.error(err);
            alert('사진 정리 실패: ' + (err && err.message ? err.message : err));
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerText = orgText || '🧹 승인완료/거절 사진 정리';
            }
        }
    }

/* step8: renderPostItem moved to ./js/board.js */

async function saveSet() {
    const btn = document.getElementById('btnSaveSet');
    btn.innerText = "저장 중...";
    btn.disabled = true;

    try {
        let flat = []; 
        
        // [수정] 콤마 제거 후 저장 로직 변경
        document.querySelectorAll('.p-inp').forEach(inp => {
            // 콤마(,)를 제거하고 숫자로 변환
            const val = Number(inp.value.replace(/,/g, '')) || 0;
            
            // [중요] 기존 시스템 호환성을 위해 같은 값을 두 번(시민, 일반) 넣음
            flat.push(val); 
            flat.push(val); 
        });
        
        const useCard = document.getElementById('setUseCard').checked;

        const dataToSave = { 
            prices: flat, 
            adminPhone: document.getElementById('admPhone').value.trim(),
            adminDefaultName: (document.getElementById('setAdminName') ? document.getElementById('setAdminName').value.trim() : ''),
            bankName: document.getElementById('setBank').value.trim(),
            bankAccount: document.getElementById('setAcc').value.trim(),
            useCardPay: useCard,
isCenterOpen: document.getElementById('setOpenCenter').checked 
        };
        
        const newPass = document.getElementById('setPw').value.trim();
        if(newPass) { dataToSave.adminPass = newPass; adminPass = newPass; }
        adminDefaultName = dataToSave.adminDefaultName || '관리자';

        await db.collection("settings").doc("global").set(dataToSave, { merge: true });

        _configCache = null; _configCacheTs = 0;
        alert("설정이 저장되었습니다.");
        loadConfig(true); closeModal('modalSet');

    } catch(err) {
        alert("오류: " + err.message);
    } finally {
        btn.innerText = "저장하기";
        btn.disabled = false;
    }
}

async function loadMonthlyStats() {
    const box = document.getElementById('adminStatsBox');
    if(!box) return;
    
    let pickVal = document.getElementById('statsMonthPicker') ? document.getElementById('statsMonthPicker').value : null;
    let now = pickVal ? new Date(pickVal + "-01") : new Date();
    
    const y = now.getFullYear();
    const m = now.getMonth() + 1;
    const startStr = `${y}-${String(m).padStart(2,'0')}-01`;
    const lastDay = new Date(y, m, 0).getDate();
    const endStr = `${y}-${String(m).padStart(2,'0')}-${lastDay}`;

    // UI 그리기 (캔버스 추가됨)
    box.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
            <div style="font-weight:800; color:#166534; font-size:1.1rem; display:flex; align-items:center; gap:8px;">
                📊 ${m}월 매출 현황
                <input type="month" id="statsMonthPicker" value="${y}-${String(m).padStart(2,'0')}" onchange="loadMonthlyStats()" 
                       style="font-size:0.9rem; padding:4px; border:1px solid #bbf7d0; border-radius:6px; color:#166534;">
            </div>
            <button onclick="loadMonthlyStats()" class="btn-sm bg-blue" style="margin:0; height:28px;">새로고침</button>
        </div>
        
        <div style="background:white; padding:10px; border-radius:8px; border:1px solid #e2e8f0; margin-bottom:15px; height:200px;">
            <canvas id="revenueChart"></canvas>
        </div>

        <div id="statsContent" style="text-align:center; padding:10px; color:#64748b;">분석 중...</div>
    `;

    try {
        const [resSnap, recSnap] = await Promise.all([
            db.collection("reservations").where("date", ">=", startStr).where("date", "<=", endStr).get(),
            db.collection("recurring").where("center", "==", currentCenter).get()
        ]);

        monthlyStatsData = { general: [], bulk: [], activeRules: [] };
        
        let genCount = 0; let genRev = 0;
        let bulkCount = 0; let bulkRev = 0;
        
        // [신규] 일별 매출 저장용 배열 (1일~31일)
        let dailyRevenue = new Array(lastDay + 1).fill(0);

        // 1. 일반 예약 집계
        resSnap.forEach(doc => {
            const d = doc.data();
            if (d.status === 'BOOKED' || d.uid === 'ADMIN' || d.uid === 'ADMIN_BULK') {
                let price = (d.customPrice !== undefined) ? d.customPrice : calcPrice(d.date, d.time, false);
                const item = { id: doc.id, ...d, price: price }; 
                
                // 일별 합산
                const day = parseInt(d.date.split('-')[2]);
                dailyRevenue[day] += price;

                if (d.uid === 'ADMIN_BULK') {
                    monthlyStatsData.bulk.push(item);
                    bulkCount++;
                    bulkRev += price;
                } else {
                    monthlyStatsData.general.push(item);
                    genCount++;
                    genRev += price;
                }
            }
        });

        // ▼▼▼ [수정] 정기 예약 집계 - 이름별로 합치기 ▼▼▼
        const recurByName = {}; // {name: {phone, totalFee, count, items:[], dailyData:{}, hasMonthlyFee:bool}}
        
        recSnap.forEach(doc => {
            const r = doc.data();
            if(r.startDate > endStr || r.endDate < startStr) return; 

            let unitPriceForChart = 0; 
            let totalRecurPrice = 0;

            // 이번달 몇 번인지 계산
            let tempCount = 0;
            for(let d=1; d<=lastDay; d++) {
                const currDate = `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
                if(currDate < r.startDate || currDate > r.endDate) continue;
                if(r.exceptionDates && r.exceptionDates.includes(currDate)) continue;
                if(r.excludeHoliday && HOLIDAYS[currDate]) continue;
                const dayNum = new Date(currDate).getDay();
                if(r.weekDays && r.weekDays.includes(dayNum)) tempCount++;
            }

            if(tempCount > 0) {
                // 이름별로 그룹화
                const nameKey = r.name.trim();
                if (!recurByName[nameKey]) {
                    recurByName[nameKey] = {
                        name: r.name,
                        phone: r.phone,
                        totalFee: 0,
                        count: 0,
                        items: [],
                        dailyData: {}, // 날짜별 데이터 저장
                        hasMonthlyFee: false,
                        monthlyFeeValue: 0
                    };
                }
                
                // ▼▼▼ [핵심 수정] monthlyFee가 있으면 그 값만 사용 (건수 곱하지 않음!) ▼▼▼
                if (r.monthlyFee !== undefined && r.monthlyFee !== null && r.monthlyFee > 0) {
                    // 월 정액이 설정되어 있으면 그 값을 그대로 사용
                    if (!recurByName[nameKey].hasMonthlyFee) {
                        // 처음 발견한 monthlyFee만 사용
                        recurByName[nameKey].totalFee = r.monthlyFee;
                        recurByName[nameKey].hasMonthlyFee = true;
                        recurByName[nameKey].monthlyFeeValue = r.monthlyFee;
                        totalRecurPrice = r.monthlyFee;
                        unitPriceForChart = Math.floor(r.monthlyFee / tempCount);
                    } else {
                        // 이미 monthlyFee가 있으면 추가 안함 (같은 사람의 다른 예약)
                        totalRecurPrice = 0; // 중복 계산 방지
                        unitPriceForChart = 0;
                    }
                } else {
                    // monthlyFee가 없으면 자동 계산
                    const unitP = calcPrice(startStr, r.time, false);
                    totalRecurPrice = unitP * tempCount;
                    unitPriceForChart = unitP;
                    
                    // 자동계산은 더해줌 (여러 시간대 합산)
                    if (!recurByName[nameKey].hasMonthlyFee) {
                        recurByName[nameKey].totalFee += totalRecurPrice;
                    }
                }
                // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
                
                recurByName[nameKey].count += tempCount;
                recurByName[nameKey].items.push({
                    id: doc.id,
                    time: r.time,
                    days: r.weekDays,
                    monthlyFee: r.monthlyFee || 0,
                    calculated: totalRecurPrice
                });

                // 차트용 일별 데이터 저장 (totalRecurPrice가 0이 아닐 때만)
                if (totalRecurPrice > 0) {
                    for(let d=1; d<=lastDay; d++) {
                        const currDate = `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
                        if(currDate < r.startDate || currDate > r.endDate) continue;
                        if(r.exceptionDates && r.exceptionDates.includes(currDate)) continue;
                        if(r.excludeHoliday && HOLIDAYS[currDate]) continue;
                        const dayNum = new Date(currDate).getDay();
                        if(r.weekDays && r.weekDays.includes(dayNum)) {
                            if (!recurByName[nameKey].dailyData[d]) {
                                recurByName[nameKey].dailyData[d] = 0;
                            }
                            recurByName[nameKey].dailyData[d] += unitPriceForChart;
                        }
                    }
                }
            }
        });
        
        // 합쳐진 데이터를 activeRules에 저장하고 차트에 반영
        Object.values(recurByName).forEach(group => {
            bulkCount += group.count;
            bulkRev += group.totalFee;
            
            // 차트에 일별 데이터 반영
            for (let d in group.dailyData) {
                dailyRevenue[d] += group.dailyData[d];
            }
            
            monthlyStatsData.activeRules.push({
                name: group.name,
                phone: group.phone,
                totalFee: group.totalFee,
                count: group.count,
                items: group.items
            });
        });
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        // 3. 차트 그리기 호출
        renderStatsChart(dailyRevenue, m);

        // 4. 텍스트 요약 표시
        const content = document.getElementById('statsContent');
        content.innerHTML = `
            <div style="background:white; padding:10px; border-radius:8px; border:1px solid #bbf7d0; margin-bottom:8px;">
                <div style="font-size:0.85rem; font-weight:bold; color:#15803d; border-bottom:1px solid #f0fdf4; margin-bottom:5px;">
                    👤 일반 예약 합계
                </div>
                <div style="display:flex; justify-content:space-around;">
                    <div onclick="openStatsDetail('general')" style="cursor:pointer; text-align:center;">
                        <div style="font-size:0.75rem; color:#64748b;">건수</div>
                        <div style="font-weight:800; font-size:1.1rem; color:#166534; text-decoration:underline;">${genCount}건</div>
                    </div>
                    <div onclick="openStatsDetail('general')" style="cursor:pointer; text-align:center;">
                        <div style="font-size:0.75rem; color:#64748b;">매출</div>
                        <div style="font-weight:800; font-size:1.1rem; color:#166534; text-decoration:underline;">${genRev.toLocaleString()}원</div>
                    </div>
                </div>
            </div>

            <div style="background:#fff7ed; padding:10px; border-radius:8px; border:1px solid #fed7aa;">
                <div style="font-size:0.85rem; font-weight:bold; color:#ea580c; border-bottom:1px solid #ffedd5; margin-bottom:5px;">
                    🔄 정기/단체 합계
                </div>
                <div style="display:flex; justify-content:space-around;">
                    <div onclick="openStatsDetail('recur')" style="cursor:pointer; text-align:center;">
                        <div style="font-size:0.75rem; color:#64748b;">배정 건수</div>
                        <div style="font-weight:800; font-size:1.1rem; color:#c2410c; text-decoration:underline;">${bulkCount}건</div>
                    </div>
                    <div onclick="openStatsDetail('recur')" style="cursor:pointer; text-align:center;">
                        <div style="font-size:0.75rem; color:#64748b;">월 수익 합계</div>
                        <div style="font-weight:800; font-size:1.1rem; color:#c2410c; text-decoration:underline;">${bulkRev.toLocaleString()}원</div>
                    </div>
                </div>
                <div style="font-size:0.7rem; color:#f97316; text-align:center; margin-top:4px;">
                    * 금액을 클릭하여 <b>[월 이용료]</b>를 직접 수정하세요.
                </div>
            </div>
        `;

    } catch(e) {
        console.error(e);
        document.getElementById('statsContent').innerHTML = "로딩 실패";
    }
}

/* [수정] 상세 내역 열기 (일반 예약 수정/삭제 기능 추가) */
function openStatsDetail(type) {
    // 1. 정기/단체 관리 모드
    if (type === 'recur') {
        const rules = monthlyStatsData.activeRules || [];
        const title = "🔄 정기 예약 월 이용료 관리";
        
        document.getElementById('statsDetailTitle').innerText = title;
        const tbody = document.getElementById('statsDetailBody');
        tbody.innerHTML = "";

        if (rules.length === 0) {
            tbody.innerHTML = "<tr><td colspan='4' style='text-align:center; padding:20px;'>이번 달 정기 예약이 없습니다.</td></tr>";
        } else {
            const thead = document.querySelector('#modalStatsDetail thead tr');
            if(thead) thead.innerHTML = `
                <th style="padding:10px;">예약자 정보</th>
                <th style="padding:10px;">예약 내역</th>
                <th style="padding:10px; width:120px;">월 이용료(원)</th>
                <th style="padding:10px;">관리</th>
            `;

            rules.forEach(r => {
                const row = document.createElement('tr');
                row.style.borderBottom = "1px solid #f1f5f9";
                
                // 여러 시간대 표시 (items 배열 사용)
                const timeInfo = r.items.map(item => {
                    const daysStr = item.days.map(d => ['일','월','화','수','목','금','토'][d]).join(',');
                    return `${daysStr} ${item.time}시`;
                }).join('<br>');
                
                // 월 이용료: items 중 첫번째의 monthlyFee 사용 (모두 같은 값)
                const currentMonthlyFee = r.items[0].monthlyFee || 0;
                const inputStyle = (currentMonthlyFee === 0) ? "border:2px solid #fca5a5; background:#fff1f2;" : "border:1px solid #cbd5e1;";
                
                // docIds를 안전하게 저장
                const docIdsStr = r.items.map(i => i.id).join(',');

                row.innerHTML = `
                    <td style="padding:10px; font-weight:bold;">
                        ${r.name}<br>
                        <span style="font-size:0.75rem; color:#64748b; font-weight:normal;">${r.phone}</span>
                    </td>
                    <td style="padding:10px; font-size:0.85rem;">
                        ${timeInfo}<br>
                        <span style="font-size:0.7rem; color:#64748b;">총 ${r.count}건</span>
                    </td>
                    <td style="padding:10px;">
                        <input type="number" id="fee-${r.name}" value="${currentMonthlyFee || ''}" placeholder="${r.totalFee.toLocaleString()}"
                               style="width:100%; padding:6px; border-radius:4px; text-align:right; font-weight:bold; ${inputStyle}">
                        <div style="font-size:0.7rem; color:#94a3b8; text-align:right;">(자동계산: ${r.totalFee.toLocaleString()})</div>
                    </td>
                    <td style="padding:10px; text-align:center;">
                        <button onclick="updateRecurFeeByName('${r.name.replace(/'/g, "\\'")}', '${docIdsStr}')" class="btn-sm" style="background:#3b82f6; color:white; border:none;">저장</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }
        
        document.getElementById('statsDetailTotal').parentElement.style.display = 'none';
        openModal('modalStatsDetail');
        return;
    }

    // 2. 일반 예약 상세 (관리 버튼 추가됨)
    const list = monthlyStatsData.general;
    document.getElementById('statsDetailTitle').innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span>👤 일반 예약 상세</span>
            <button onclick="downloadStatsCsv('general')" style="background:#2563eb; color:white; border:none; padding:4px 10px; border-radius:4px; font-size:0.75rem;">📥 엑셀</button>
        </div>
    `;
    
    // [수정] 테이블 헤더에 '관리' 추가
    const thead = document.querySelector('#modalStatsDetail thead tr');
    if(thead) thead.innerHTML = `<th>날짜/시간</th><th>예약자</th><th>코트</th><th style="text-align:right;">금액</th><th style="text-align:center;">관리</th>`;

    const tbody = document.getElementById('statsDetailBody');
    tbody.innerHTML = "";
    
    if (list.length === 0) {
        tbody.innerHTML = "<tr><td colspan='5' style='text-align:center; padding:20px;'>내역이 없습니다.</td></tr>";
    } else {
        list.sort((a,b) => (a.date !== b.date) ? (a.date < b.date ? -1 : 1) : (a.time - b.time));
        let total = 0;
        
        list.forEach(item => {
            total += item.price;
            const row = document.createElement('tr');
            row.style.borderBottom = "1px solid #f1f5f9";
            
            // [수정] 수정(✏️)/삭제(🗑️) 버튼 추가
            row.innerHTML = `
                <td style="padding:8px;">${item.date.substring(5)}<br><span style="color:#64748b; font-size:0.8rem;">${item.time}:00</span></td>
                <td style="padding:8px; font-weight:bold;">${item.name}</td>
                <td style="padding:8px; text-align:center;">${item.court}</td>
                <td style="padding:8px; text-align:right;">${item.price.toLocaleString()}</td>
                <td style="padding:8px; text-align:center;">
                    <button onclick="openEditFromList('${item.id}', '${item.name}', '${item.phone}', 'reservations')" 
                            class="btn-sm" style="font-size:0.8rem; padding:4px 8px; background:#fff; border:1px solid #cbd5e1; color:#0284c7; margin-right:4px;">✏️</button>
                    <button onclick="deleteFromStats('${item.id}')" 
                            class="btn-sm" style="font-size:0.8rem; padding:4px 8px; background:#fff; border:1px solid #ef4444; color:#dc2626;">🗑️</button>
                </td>
            `;
            tbody.appendChild(row);
        });
        
        document.getElementById('statsDetailTotal').innerText = total.toLocaleString();
        document.getElementById('statsDetailTotal').parentElement.style.display = 'block';
    }
    openModal('modalStatsDetail');
}

/* [신규] 통계 내역 엑셀(CSV) 다운로드 */
function downloadStatsCsv(type) {
    const list = (type === 'general') ? monthlyStatsData.general : monthlyStatsData.bulk;
    
    if(list.length === 0) return alert("다운로드할 데이터가 없습니다.");

    // CSV 내용 생성 (한글 깨짐 방지 BOM 추가)
    let csvContent = "\uFEFF날짜,시간,예약자,연락처,센터,코트,금액\n";
    
    list.forEach(item => {
        // 데이터 정제 (콤마 제거 등)
        const date = item.date;
        const time = item.time + ":00";
        const name = item.name.replace(/,/g, ""); // 이름에 콤마 있으면 제거
        const phone = item.phone || "-";
        const center = item.center || currentCenter;
        const court = item.court;
        const price = item.price;

        csvContent += `${date},${time},${name},${phone},${center},${court},${price}\n`;
    });

    // 파일명 생성 (예: 2024-05_일반예약내역.csv)
    const now = new Date();
    const fileName = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}_${type === 'general' ? '일반예약' : '정기예약'}_내역.csv`;

    // 다운로드 링크 생성 및 클릭
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", fileName);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

/* [수정 완료] 관리자 비밀번호 로그인 성공 시 화면 즉시 갱신 */
function doLogin() {
    if(document.getElementById('pw').value === adminPass) { 
        isAdmin = true; 
        localStorage.setItem('isAdm', 'true'); 
        closeModal('modalAuth'); 
        
        // [기존 동작] 설정창 열기 (원치 않으시면 이 줄을 지우세요)
        openConf(); 

        // UI 버튼 상태 변경
        const btnOut = document.getElementById('btnOut');
        btnOut.style.display = 'inline-block';
        btnOut.innerText = "관리자로그아웃";
        document.getElementById('btnLogin').style.display = 'none';
        document.getElementById('btnSet').style.display = 'inline-block';
        
        updateAdminUI(); 

        // ▼▼▼ [핵심 추가] 로그인 즉시 화면 데이터를 관리자 모드로 다시 그림 ▼▼▼
        drawCalendar();  // 달력 날짜 제한(회색) 해제
        loadDB();        // 예약 현황 마스킹(**) 해제 및 관리자 버튼 표시
        
    } else {
        alert("비번 오류");
    }
}

/* step10-admin-actions-extracted: doBlockSlot moved to ./js/admin-actions.js */
function chkAdmin() { 
    // [수정됨] 관리자일 때만 설정창을 열고, 아니면 아무것도 하지 않음 (비밀번호 입력창 차단)
    if(isAdmin) openConf(); 
}

/* [수정] 설정창 열기 (월간 통계 영역 추가) */
function openConf() {
    const body = document.getElementById('tblBody'); 
    body.innerHTML = "";
    
    const thead = document.querySelector('.tbl-set thead');
    if(thead) thead.innerHTML = "<tr><th>구분</th><th>이용료(원)</th></tr>";

    const lbs = ["평일주간","평일야간","주말주간","주말야간"];
    for(let i=0; i<4; i++) {
        const p = prices[i] ? prices[i][0] : 0;
        body.innerHTML += `
            <tr>
                <td>${lbs[i]}</td>
                <td>
                    <input class="p-inp" type="text" value="${p.toLocaleString()}" 
                    oninput="this.value = this.value.replace(/[^0-9]/g, '').replace(/\\B(?=(\\d{3})+(?!\\d))/g, ',');" 
                    style="text-align:center;">
                </td>
            </tr>`;
    }
    
    // ▼▼▼ [추가] 다크모드 토글 상태 동기화 ▼▼▼
    const darkModeToggle = document.getElementById('setDarkMode');
    if (darkModeToggle) {
        darkModeToggle.checked = document.body.classList.contains('dark-mode');
    }
    // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
    
    // 버튼들 생성 (기존 로직 유지)
    if(!document.getElementById('btnMemMgr')) {
        const container = document.querySelector('#modalSet .modal-win');
        
        let btn = document.createElement('button'); 
        btn.id="btnMemMgr"; btn.className="btn-full bg-gray"; 
        btn.innerText="회원 승인 대기 관리"; btn.onclick=loadPendingMembers;
        btn.style.marginBottom = "8px"; 
        container.appendChild(btn);

        let btnCitizen = document.createElement('button');
        btnCitizen.id = "btnCitizenMgr"; btnCitizen.className = "btn-full";
        btnCitizen.style.background = "#0284c7"; 
        btnCitizen.innerText = "📍 김해시민 인증자 목록/관리"; 
        btnCitizen.onclick = loadCitizenMembers; 
        container.appendChild(btnCitizen);

        let btnCitizenCleanup = document.createElement('button');
        btnCitizenCleanup.id = "btnCitizenCleanup"; btnCitizenCleanup.className = "btn-full";
        btnCitizenCleanup.style.background = "#475569";
        btnCitizenCleanup.innerText = "🧹 승인완료/거절 사진 정리";
        btnCitizenCleanup.onclick = cleanupCitizenProofs;
        container.appendChild(btnCitizenCleanup);
    }
    
    const setAdminNameEl = document.getElementById('setAdminName');
    if (setAdminNameEl) setAdminNameEl.value = adminDefaultName || '관리자';
    document.getElementById('admPhone').value = admPh;
    document.getElementById('setBank').value = bankName || "";    
    document.getElementById('setAcc').value = bankAccount || ""; 
    document.getElementById('setPw').value = ""; 
    loadSeasonalPricings();

    // ▼▼▼ [수정] 월간 통계 대시보드 - 버튼으로 토글 ▼▼▼
    let statsBtn = document.getElementById('btnToggleStats');
    let statsDiv = document.getElementById('adminStatsBox');
    
    if (!statsBtn) {
        // 토글 버튼 생성
        statsBtn = document.createElement('button');
        statsBtn.id = 'btnToggleStats';
        statsBtn.className = 'btn-full';
        statsBtn.style.cssText = 'background:#10b981; margin-bottom:15px;';
        statsBtn.innerHTML = '📊 월간 매출 현황 보기';
        statsBtn.onclick = function() {
            const box = document.getElementById('adminStatsBox');
            if (box.style.display === 'none') {
                box.style.display = 'block';
                this.innerHTML = '📊 월간 매출 현황 숨기기';
                loadMonthlyStats();
            } else {
                box.style.display = 'none';
                this.innerHTML = '📊 월간 매출 현황 보기';
            }
        };
        
        // 통계 영역 생성
        statsDiv = document.createElement('div');
        statsDiv.id = 'adminStatsBox';
        statsDiv.style.cssText = "background:#f0fdf4; border:1px solid #bbf7d0; border-radius:12px; padding:15px; margin-bottom:15px; display:none;";
        
        const target = document.querySelector('#modalSet .modal-win .inp-row');
        target.parentNode.insertBefore(statsBtn, target);
        target.parentNode.insertBefore(statsDiv, target);
    }
    // ▼▼▼ [추가] 매크로 감시판 버튼/영역 ▼▼▼
    let macroBtn = document.getElementById('btnToggleMacroMonitor');
    let macroDiv = document.getElementById('macroMonitorBox');

    if (!macroBtn) {
        macroBtn = document.createElement('button');
        macroBtn.id = 'btnToggleMacroMonitor';
        macroBtn.className = 'btn-full';
        macroBtn.style.cssText = 'background:#ef4444; margin-bottom:15px;';
        macroBtn.innerHTML = '🛡 매크로 의심 감시판 열기';
        macroBtn.onclick = function() {
            const box = document.getElementById('macroMonitorBox');
            if (box.style.display === 'none') {
                box.style.display = 'block';
                this.innerHTML = '🛡 매크로 의심 감시판 닫기';
                loadMacroMonitor();
            } else {
                box.style.display = 'none';
                this.innerHTML = '🛡 매크로 의심 감시판 열기';
            }
        };

        macroDiv = document.createElement('div');
        macroDiv.id = 'macroMonitorBox';
        macroDiv.style.cssText = 'background:#fff7ed; border:1px solid #fdba74; border-radius:12px; padding:15px; margin-bottom:15px; display:none;';
        macroDiv.innerHTML = '<div style="color:#9a3412; font-weight:700; margin-bottom:8px;">불러오는 중...</div>';

        const target = document.querySelector('#modalSet .modal-win .inp-row');
        target.parentNode.insertBefore(macroBtn, target);
        target.parentNode.insertBefore(macroDiv, target);
    }
    // ▲▲▲ [추가 끝] ▲▲▲

    openModal('modalSet');
}

/* [수정] 승인 대기 회원 목록 불러오기 (사진 바로 보기 적용) */
function loadPendingMembers() {
    const list = document.getElementById('memberList'); 
    list.innerHTML = "<div style='text-align:center; padding:20px;'>로딩중...</div>"; 
    openModal('modalMembers');

    db.collection("users").where("verifStatus", "==", "PENDING").get().then(snap => {
        list.innerHTML = "";
        
        if(snap.empty) { 
            list.innerHTML = "<div style='text-align:center; padding:40px; color:#64748b;'>현재 승인 대기중인 회원이 없습니다.</div>"; 
            return; 
        }

        snap.forEach(doc => {
            const u = doc.data();
            
            // 사진이 있으면 이미지 태그로 보여주고, 없으면 경고 문구 표시
            let proofContent = "";
            if (u.proofUrl) {
                proofContent = `
                    <div style="margin:10px 0; border:1px solid #e2e8f0; border-radius:8px; overflow:hidden;">
                        <a href="${u.proofUrl}" target="_blank">
                            <img src="${u.proofUrl}" style="width:100%; display:block;" alt="증빙서류">
                        </a>
                        <div style="background:#f8fafc; padding:4px; font-size:0.75rem; color:#64748b; text-align:center;">
                            👆 이미지를 누르면 원본 크기로 열립니다
                        </div>
                    </div>`;
            } else {
                proofContent = `<div style="background:#fff1f2; color:#e11d48; padding:10px; border-radius:8px; font-size:0.85rem; font-weight:bold; margin:10px 0;">
                    ❌ 업로드된 증빙 사진이 없습니다.
                </div>`;
            }

            list.innerHTML += `
                <div style="padding:15px; border-bottom:8px solid #f1f5f9; background:white;">
                    <div style="display:flex; justify-content:space-between; align-items:start; margin-bottom:5px;">
                        <span style="font-size:1.1rem; font-weight:800; color:#1e293b;">${u.name}</span>
                        <span style="font-size:0.85rem; color:#64748b; background:#f1f5f9; padding:2px 6px; border-radius:4px;">${u.birth}</span>
                    </div>
                    
                    <div style="font-size:0.9rem; color:#334155; margin-bottom:2px;">📞 ${u.phone}</div>
                    <div style="font-size:0.9rem; color:#334155; font-weight:bold;">🏠 ${u.address}</div>

                    ${proofContent}

                    <div style="display:flex; gap:10px; margin-top:10px; flex-wrap:wrap;">
                        <button onclick="approveMember('${doc.id}', true)" class="btn-full" style="margin-top:0; background:#10b981; border:none; flex:1;">
                            ✅ 승인 (텍스트만 보관)
                        </button>
                        <button onclick="approveMember('${doc.id}', false)" class="btn-full" style="margin-top:0; background:#ef4444; border:none; flex:1;">
                            🚫 거절 (텍스트만 보관)
                        </button>
                        <button onclick="deleteCitizenProofOnly('${doc.id}')" class="btn-full" style="margin-top:0; background:#475569; border:none; flex:1;">
                            🗑 사진만 삭제
                        </button>
                    </div>
                </div>`;
        });
    }).catch(err => {
        list.innerHTML = "오류 발생: " + err.message;
    });
}

async function deleteCitizenProofOnly(uid) {
        if(!isAdmin) return;
        if(!confirm("이 회원의 시민인증 사진만 삭제하고 텍스트 이력만 남기시겠습니까?")) return;
        try {
            const ref = db.collection("users").doc(uid);
            const doc = await ref.get();
            if(!doc.exists) throw new Error("회원 정보를 찾을 수 없습니다.");
            const u = doc.data() || {};
            if (u.proofUrl) await deleteProofByUrl(u.proofUrl);
            await ref.update({
                proofUrl: "",
                proofDeletedAt: new Date()
            });
            await appendCitizenAudit(uid, 'PROOF_DELETED_ONLY', {
                name: u.name || '',
                phone: u.phone || '',
                address: u.address || ''
            });
            alert("사진만 삭제되었습니다. 텍스트 이력은 유지됩니다.");
            loadPendingMembers();
        } catch (err) {
            alert("사진 삭제 실패: " + err.message);
        }
    }

async function approveMember(uid, isApprove) {
        if(!confirm("처리하시겠습니까?\n사진은 삭제되고 텍스트 이력만 남습니다.")) return;
        try {
            const ref = db.collection("users").doc(uid);
            const doc = await ref.get();
            if(!doc.exists) throw new Error("회원 정보를 찾을 수 없습니다.");
            const u = doc.data() || {};

            if (u.proofUrl) await deleteProofByUrl(u.proofUrl);

            await ref.update({
                isCitizen: isApprove,
                verifStatus: isApprove ? "APPROVED" : "REJECTED",
                proofUrl: "",
                proofDeletedAt: new Date(),
                approvedAt: isApprove ? new Date() : firebase.firestore.FieldValue.delete(),
                rejectedAt: !isApprove ? new Date() : firebase.firestore.FieldValue.delete(),
                citizenNoticeShown: isApprove ? false : firebase.firestore.FieldValue.delete()
            });

            await appendCitizenAudit(uid, isApprove ? 'APPROVED' : 'REJECTED', {
                name: u.name || '',
                phone: u.phone || '',
                address: u.address || '',
                birth: u.birth || ''
            });

            alert("처리됨");
            loadPendingMembers();
        } catch (err) {
            alert("처리 실패: " + err.message);
        }
    }

function togglePriceSettings() {
    const box = document.getElementById('priceSettingsBox');
    const icon = document.getElementById('priceSettingsIcon');
    
    if (box.style.display === 'none') {
        box.style.display = 'block';
        icon.textContent = '▲';
    } else {
        box.style.display = 'none';
        icon.textContent = '▼';
    }
}

async function savePriceSettings() {
    const dayStart = parseInt(document.getElementById('settingDayStart').value);
    const nightStart = parseInt(document.getElementById('settingNightStart').value);
    const dayPrice = parseInt(document.getElementById('settingDayPrice').value);
    const nightPrice = parseInt(document.getElementById('settingNightPrice').value);
    
    // 유효성 검사
    if (isNaN(dayStart) || isNaN(nightStart) || isNaN(dayPrice) || isNaN(nightPrice)) {
        alert('모든 값을 올바르게 입력해주세요.');
        return;
    }
    
    if (dayStart >= nightStart) {
        alert('주간 시작 시간은 야간 시작 시간보다 빨라야 합니다.');
        return;
    }
    
    if (dayPrice < 0 || nightPrice < 0) {
        alert('요금은 0원 이상이어야 합니다.');
        return;
    }
    
    try {
        await db.collection('settings').doc('global').update({
            dayStartHour: dayStart,
            nightStartHour: nightStart,
            dayPrice: dayPrice,
            nightPrice: nightPrice
        });
        
        // 전역 변수 업데이트
        window.dayStartHour = dayStart;
        window.nightStartHour = nightStart;
        window.dayPrice = dayPrice;
        window.nightPrice = nightPrice;
        
        alert('✅ 요금 설정이 저장되었습니다!\n\n' +
              `☀️ 주간: ${dayStart}시~${nightStart-1}시 (${dayPrice.toLocaleString()}원)\n` +
              `🌙 야간: ${nightStart}시~23시 (${nightPrice.toLocaleString()}원)`);
        
        // 박스 닫기
        togglePriceSettings();
        
    } catch(err) {
        alert('저장 실패: ' + err.message);
    }
}

/* [추가] 인증된 김해시민 목록 불러오기 */
function loadCitizenMembers() {
    const list = document.getElementById('memberList'); 
    
    // 모달 제목 변경 (재사용)
    document.querySelector('#modalMembers .modal-head').innerText = "김해시민 인증 완료 회원";
    
    list.innerHTML = "<div style='text-align:center; padding:20px;'>불러오는 중...</div>";
    openModal('modalMembers');

    // isCitizen이 true인 사용자 조회
    db.collection("users")
      .where("isCitizen", "==", true)
      .orderBy("name", "asc") // 이름순 정렬 (필요시 색인 추가 필요할 수 있음)
      .get()
      .then(snap => {
          list.innerHTML = "";
          
          if(snap.empty) { 
              list.innerHTML = "<p style='text-align:center; padding:20px; color:#64748b;'>인증된 회원이 없습니다.</p>"; 
              return; 
          }

          list.innerHTML = `<div style="padding:10px; font-weight:bold; color:#0369a1; border-bottom:2px solid #e2e8f0;">
                                총 ${snap.size}명 인증됨
                            </div>`;

          snap.forEach(doc => {
              const u = doc.data();
              list.innerHTML += `
                  <div style="padding:15px 10px; border-bottom:1px solid #f1f5f9; display:flex; justify-content:space-between; align-items:center;">
                      <div>
                          <div style="font-weight:bold; font-size:1rem; margin-bottom:4px;">
                              ${u.name} 
                              <span style="font-size:0.8rem; color:#64748b; font-weight:normal;">(${u.birth})</span>
                          </div>
                          <div style="font-size:0.85rem; color:#475569;">📞 ${u.phone}</div>
                          <div style="font-size:0.85rem; color:#64748b;">🏠 ${u.address}</div>
                          <div style="font-size:0.78rem; color:#64748b; margin-top:4px;">증빙 사진은 삭제되고 텍스트 이력만 보관됩니다.</div>
                      </div>
                      <button onclick="revokeCitizen('${doc.id}', '${u.name}')" 
                          style="background:#fee2e2; color:#dc2626; border:1px solid #ef4444; padding:6px 10px; border-radius:6px; font-size:0.8rem; font-weight:bold; cursor:pointer; flex-shrink:0; margin-left:10px;">
                          인증 취소
                      </button>
                  </div>`;
          });
      })
      .catch(err => {
          // 인덱스 에러 처리 (이름 정렬 등에서 발생 가능)
          if(err.message.includes("index")) {
              handleIndexError(err, list);
          } else {
              list.innerHTML = "오류 발생: " + err.message;
          }
      });
}

/* [추가] 시민 인증 취소 (박탈) 기능 */
async function revokeCitizen(uid, name) {
    if(!confirm(`[${name}] 회원의 김해시민 인증을 취소하시겠습니까?\n\n- 취소 후 회원은 다시 일반 요금이 적용됩니다.\n- 회원이 다시 인증 신청을 할 수 있습니다.`)) return;

    try {
        const ref = db.collection("users").doc(uid);
        const doc = await ref.get();
        const u = doc.exists ? (doc.data() || {}) : {};
        if (u.proofUrl) await deleteProofByUrl(u.proofUrl);
        await ref.update({ 
            isCitizen: false, 
            verifStatus: "NONE",
            proofUrl: "",
            proofDeletedAt: new Date()
        });
        await appendCitizenAudit(uid, 'REVOKED', {
            name: name || u.name || '',
            phone: u.phone || '',
            address: u.address || ''
        });
        alert("인증이 취소되었습니다."); 
        loadCitizenMembers();
    } catch(err) {
        alert("취소 실패: " + err.message);
    }
}

/* [추가] QR 모달 열기 함수 */
function openQrModal() {
    document.getElementById('modalQr').style.display = 'flex';
}

/* [신규] 차트 그리기 함수 (Chart.js) */
function renderStatsChart(dailyData, month) {
    const ctx = document.getElementById('revenueChart').getContext('2d');
    
    // 기존 차트가 있으면 삭제 (안 그러면 겹쳐서 보임)
    if(myChart) myChart.destroy();

    // 데이터 가공 (0일 제외하고 1일부터 끝까지)
    const labels = [];
    const data = [];
    for(let i=1; i<dailyData.length; i++) {
        labels.push(i + '일');
        data.push(dailyData[i]);
    }

    myChart = new Chart(ctx, {
        type: 'line', // 꺾은선 그래프
        data: {
            labels: labels,
            datasets: [{
                label: `${month}월 일별 매출`,
                data: data,
                borderColor: '#3b82f6', // 파란색 선
                backgroundColor: 'rgba(59, 130, 246, 0.1)', // 채우기 색
                borderWidth: 2,
                tension: 0.3, // 부드러운 곡선
                pointRadius: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false } // 범례 숨김 (깔끔하게)
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { display: false }
                },
                x: {
                    grid: { display: false },
                    ticks: { maxTicksLimit: 10 } // 날짜가 너무 많으면 적당히 건너뜀
                }
            }
        }
    });
}
