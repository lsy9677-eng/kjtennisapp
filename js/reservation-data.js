/**
 * Step 11 reservation-data.js
 * 예약 조회/Firestore 읽기/캐시 무효화 전담 파일입니다.
 * 주의: saveBook(), doPay() 결제/저장 핵심 함수는 아직 index.dev.html에 남겨 안정성을 유지합니다.
 */

// 예약 조회/저장을 과도하게 중복 호출하지 않도록 보호
var loadDBInFlight = false;
var loadDBPending = false;
var loadDBTimer = null;

// ── Firestore 읽기 절약을 위한 캐시 ──
// recurring(고정예약): 센터별로 메모리에 보관, 30분 TTL
var _recurringCache = {};
var RECURRING_TTL = 60 * 60 * 1000; // 정기예약은 수동 새로고침 중심으로 1시간 캐시
// reservations(날짜별 예약): 날짜+센터 키로 캐시, 3분 TTL
var _reservationsCache = {};
var RESERVATIONS_TTL = 15 * 60 * 1000; // 예약현황은 자동 갱신 대신 새로고침 버튼으로 갱신
// 내 예약 달력 dot: 월별 캐시
var _myReservedDatesCache = {};
var MY_RESERVED_DATES_TTL = 15 * 60 * 1000; // 내 예약 dot 반복 읽기 절감

function _invalidateRecurringCache(center) {
        if (center) delete _recurringCache[center];
        else Object.keys(_recurringCache).forEach(k => delete _recurringCache[k]);
    }

function _invalidateReservationsCache(center, date) {
        const prefix = (center || currentCenter) + '_';
        if (date) delete _reservationsCache[prefix + date];
        else Object.keys(_reservationsCache).filter(k => k.startsWith(prefix)).forEach(k => delete _reservationsCache[k]);
    }

function _invalidateMyReservedDatesCache(center, phone, monthStart) {
        const prefix = `${center || currentCenter}_${phone || ''}_`;
        if (monthStart) delete _myReservedDatesCache[prefix + monthStart];
        else Object.keys(_myReservedDatesCache).filter(k => k.startsWith(prefix)).forEach(k => delete _myReservedDatesCache[k]);
    }

function scheduleLoadDB(delay = 0) {
        if (loadDBTimer) clearTimeout(loadDBTimer);
        loadDBTimer = setTimeout(() => loadDB(), delay);
    }

function manualRefreshReservations() {
        const btn = document.getElementById('btnRefreshReservations');
        const oldText = btn ? btn.innerText : '';
        if (btn) {
            btn.disabled = true;
            btn.innerText = '갱신중';
        }
        try {
            const date = document.getElementById('hiddenDate') ? document.getElementById('hiddenDate').value : '';
            _invalidateReservationsCache(currentCenter, date);
            if (currentUser && currentUser.phone) _invalidateMyReservedDatesCache(currentCenter, currentUser.phone);
            return loadDB().then(() => {
                try { refreshTodayMyReservationCard(true); } catch (_) {}
                try { drawCalendar(); } catch (_) {}
            }).finally(() => {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = oldText || '새로고침';
                }
            });
        } catch (e) {
            if (btn) {
                btn.disabled = false;
                btn.innerText = oldText || '새로고침';
            }
            alert('새로고침 실패: ' + (e && e.message ? e.message : e));
        }
    }

async function hasRecurringConflict(center, date, court, time) {
        const dayNum = new Date(date).getDay();
        const snap = await db.collection('recurring')
            .where('center', '==', center)
            .where('court', '==', court)
            .where('time', '==', time)
            .get();

        let conflict = false;
        snap.forEach(doc => {
            const d = doc.data();
            if (conflict) return;
            if (d.startDate && date < d.startDate) return;
            if (d.endDate && date > d.endDate) return;
            if (d.weekDays && !d.weekDays.includes(dayNum)) return;
            if (d.excludeHoliday === true && HOLIDAYS[date]) return;
            if (d.exceptionDates && d.exceptionDates.includes(date)) return;
            conflict = true;
        });
        return conflict;
    }

function recurringRuleMatchesDate(rule, dateStr) {
        const dayNum = new Date(dateStr).getDay();
        if (!rule) return false;
        if (rule.startDate && dateStr < rule.startDate) return false;
        if (rule.endDate && dateStr > rule.endDate) return false;
        if (Array.isArray(rule.weekDays) && !rule.weekDays.includes(dayNum)) return false;
        if (rule.excludeHoliday === true && HOLIDAYS[dateStr]) return false;
        if (Array.isArray(rule.exceptionDates) && rule.exceptionDates.includes(dateStr)) return false;
        return true;
    }

async function addRecurringOccupiedSlotsToMap(center, dateStr, occupiedMap) {
        // 화면에는 정기예약이 막힌 칸으로 보이지만, 기존 저장 검증은 reservations 컬렉션만 보고 있어
        // 정기예약 사이에 낀 1시간을 일반 1시간 예외로 인정하지 못하는 문제가 있었다.
        const snap = await db.collection('recurring')
            .where('center', '==', center)
            .get();

        snap.forEach(doc => {
            const r = doc.data() || {};
            if (!recurringRuleMatchesDate(r, dateStr)) return;
            if (r.court == null || r.time == null) return;
            const key = `${Number(r.court)}_${Number(r.time)}`;
            occupiedMap.set(key, {
                id: doc.id,
                center,
                date: dateStr,
                court: Number(r.court),
                time: Number(r.time),
                status: 'FIXED',
                source: 'recurring',
                name: r.name || '정기예약'
            });
        });
    }

async function loadDB() {
    if (loadDBInFlight) {
        loadDBPending = true;
        return;
    }
    loadDBInFlight = true;

    try {
        const date = document.getElementById('hiddenDate').value;

        document.querySelectorAll('.data-cell').forEach(e => {
            e.className = 'cell data-cell'; e.innerHTML = '';
            e.style.background = ''; e.style.boxShadow = ''; e.style.transform = ''; e.style.zIndex = '';
            delete e.dataset.id; delete e.dataset.coll; delete e.dataset.info; delete e.dataset.ph; delete e.dataset.status;
        });
        selected = [];
        document.getElementById('selCnt').innerText = "0";
        document.getElementById('btnMainBook').disabled = true;

        deleteQueue = [];
        document.querySelectorAll('.delete-select').forEach(el => el.classList.remove('delete-select'));
        document.getElementById('btnBatchExec').style.display = 'none';

        const selZero = new Date(date); selZero.setHours(0,0,0,0);
        const todayZero = new Date(); todayZero.setHours(0,0,0,0);
        const curH = new Date().getHours();
        document.querySelectorAll('.data-cell').forEach(el => {
            if(selZero < todayZero || (selZero.getTime()===todayZero.getTime() && parseInt(el.dataset.t) < curH)) el.classList.add('past');
        });

        const currentDayNum = new Date(date).getDay();

        // ── Firestore 읽기 캐시: recurring 30분, reservations 3분 TTL ──
        const recCacheKey = currentCenter;
        const resCacheKey = currentCenter + '_' + date;
        const recNeedsFetch = !_recurringCache[recCacheKey] || (Date.now() - _recurringCache[recCacheKey].ts > RECURRING_TTL);
        const resNeedsFetch = !_reservationsCache[resCacheKey] || (Date.now() - _reservationsCache[resCacheKey].ts > RESERVATIONS_TTL);

        const [resSnap, recSnap] = await Promise.all([
            resNeedsFetch ? db.collection("reservations").where("date","==",date).where("center","==",currentCenter).get() : Promise.resolve(null),
            recNeedsFetch ? db.collection("recurring").where("center","==",currentCenter).get() : Promise.resolve(null)
        ]);

        if (resSnap) {
            const docs = []; resSnap.forEach(d => docs.push({ id: d.id, data: d.data() }));
            _reservationsCache[resCacheKey] = { docs, ts: Date.now() };
        }
        if (recSnap) {
            const docs = []; recSnap.forEach(d => docs.push({ id: d.id, data: d.data() }));
            _recurringCache[recCacheKey] = { docs, ts: Date.now() };
        }

        const resDocs = (_reservationsCache[resCacheKey] || {}).docs || [];
        const recDocs = (_recurringCache[recCacheKey] || {}).docs || [];
        const res = { forEach: (fn) => resDocs.forEach(d => fn({ id: d.id, data: () => d.data })) };
        const rec = { forEach: (fn) => recDocs.forEach(d => fn({ id: d.id, data: () => d.data })) };

        rec.forEach(doc => {
            const d = doc.data();
            if(d.weekDays && !d.weekDays.includes(currentDayNum)) return;
            if(d.startDate && date < d.startDate) return;
            if(d.endDate && date > d.endDate) return;
            if(d.excludeHoliday === true && HOLIDAYS[date]) return;
            if(d.exceptionDates && d.exceptionDates.includes(date)) return;
            paint(d, doc.id, 'recurring');
        });

        const todayReservationRows = [];
        res.forEach(doc => {
            const data = doc.data() || {};
            todayReservationRows.push({ id: doc.id, ...data });
            paint(data, doc.id, 'reservations');
        });
        autoScroll();
        updateMyReservations();
        refreshTodayMyReservationCard(todayReservationRows);
    } catch (err) {
        console.error('예약 데이터 로딩 실패:', err);
    } finally {
        loadDBInFlight = false;
        if (loadDBPending) {
            loadDBPending = false;
            scheduleLoadDB(120);
        }
    }
}
