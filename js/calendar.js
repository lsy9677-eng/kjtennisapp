/*
 * 국제 테니스장 예약 앱 - Step 6 Calendar / Weather
 * step6-calendar-extracted
 *
 * 원칙:
 * - 달력, 날짜 선택, 날씨 표시/배너, 달력 접기 기능만 분리한다.
 * - 예약 저장, 결제, Firestore 쓰기, 관리자 기능은 아직 index.dev.html에 둔다.
 * - 기존 전역 함수명은 유지해 HTML onclick 및 기존 호출과 호환한다.
 */

/* [달력 패치] drawCalendar가 초기 실행될 때도 접근 가능하도록 전역 var로 먼저 선언 */
var calendarMonthsToRender = 4;

/* step4-utils-extracted: getDatePartsFromStr / formatDateStrLocal are loaded from ./js/utils.js */

function openNaverWeather() {
    const url = 'https://search.naver.com/search.naver?query=' + encodeURIComponent('장유2동 날씨');
    window.open(url, '_blank', 'noopener,noreferrer');
}

function toggleWeatherView() {
    const isChecked = document.getElementById('chkWeather').checked;
    const calBody = document.getElementById('calBody');
    
    if(isChecked) {
        calBody.classList.add('show-weather'); // CSS 클래스로 제어
    } else {
        calBody.classList.remove('show-weather');
    }
}

function getCalendarCellHtml(cellDate, baseMonth) {
    // 연속 월 스크롤에서는 각 월 섹션에 해당 월 날짜만 표시한다.
    // 이전/다음 달 날짜는 클릭 가능한 날짜로 만들지 않고 빈 칸으로 둔다.
    if (cellDate.getMonth() !== baseMonth) {
        return `<div class="cal-date empty"></div>`;
    }

    const dStr = formatDateStrLocal(cellDate);
    const week = cellDate.getDay();
    let cls = "cal-date";

    const curDate = document.getElementById('hiddenDate').value;
    const now = new Date();
    const todayStr = formatDateStrLocal(now);
    const hName = HOLIDAYS[dStr] || "";

    const targetZero = new Date(cellDate);
    targetZero.setHours(0,0,0,0);
    const todayZero = new Date();
    todayZero.setHours(0,0,0,0);
    const diffDays = (targetZero.getTime() - todayZero.getTime()) / 86400000;
    let limitDays = (currentUser && currentUser.isCitizen) ? 13 : 6;

    if(!isAdmin && diffDays > limitDays) cls += " disabled";
    if(dStr === curDate) cls += " selected";
    if(dStr === todayStr) cls += " today";
    if (hName) cls += " holiday";
    else if (week === 0) cls += " holiday-sunday";
    else if (week === 6) cls += " sat";

    return `
        <div id="cal-day-${dStr}" class="${cls}" onclick="pickDate('${dStr}')">
            <span class="cal-date-num">${cellDate.getDate()}</span>
            ${hName ? `<span class="holiday-name">${hName}</span>` : ''}
            <div class="cal-weather" id="w-${dStr}"></div>
        </div>`;
}

function renderOneCalendarMonth(year, month) {
    const monthStart = new Date(year, month, 1);
    const start = new Date(year, month, 1 - monthStart.getDay());
    const lastDate = new Date(year, month + 1, 0).getDate();
    const rows = Math.ceil((monthStart.getDay() + lastDate) / 7);
    const totalCells = Math.max(35, rows * 7);

    let html = `<section class="cal-month-section" data-y="${year}" data-m="${month}">`;
    html += `<div class="cal-month-title">${year}. ${month + 1}</div>`;
    html += `<div class="cal-month-grid">`;
    html += `<div class="cal-day" style="color:#ef4444">일</div><div class="cal-day">월</div><div class="cal-day">화</div><div class="cal-day">수</div><div class="cal-day">목</div><div class="cal-day">금</div><div class="cal-day" style="color:#3b82f6">토</div>`;

    for (let i = 0; i < totalCells; i++) {
        const cellDate = new Date(start);
        cellDate.setDate(start.getDate() + i);
        html += getCalendarCellHtml(cellDate, month);
    }

    html += `</div></section>`;
    return html;
}

function updateCalendarTitleFromScroll() {
    const wrap = document.getElementById('calendarWrap');
    const sections = Array.from(document.querySelectorAll('#calBody .cal-month-section'));
    if (!wrap || sections.length === 0) return;

    const wrapTop = wrap.getBoundingClientRect().top;
    let best = sections[0];
    let bestDist = Infinity;

    sections.forEach(sec => {
        const dist = Math.abs(sec.getBoundingClientRect().top - wrapTop);
        if (dist < bestDist) { bestDist = dist; best = sec; }
    });

    const y = Number(best.dataset.y);
    const m = Number(best.dataset.m);
    if (Number.isFinite(y) && Number.isFinite(m)) {
        document.getElementById('calTitle').innerText = `${y}. ${m + 1}`;
    }
}

function ensureMoreCalendarMonthsOnScroll() {
    const wrap = document.getElementById('calendarWrap');
    if (!wrap || wrap.classList.contains('folded')) return;
    if (wrap._calendarAppending) return;

    const remain = wrap.scrollHeight - (wrap.scrollTop + wrap.clientHeight);
    if (remain > 260) return;

    wrap._calendarAppending = true;
    calendarMonthsToRender += 2;
    drawCalendar(true);

    setTimeout(() => {
        if (wrap) wrap._calendarAppending = false;
    }, 120);
}

function setupCalendarScrollTitleUpdate() {
    const wrap = document.getElementById('calendarWrap');
    if (!wrap) return;
    if (wrap._calendarScrollHandler) wrap.removeEventListener('scroll', wrap._calendarScrollHandler);
    wrap._calendarScrollHandler = () => {
        if (wrap._calendarScrollTimer) clearTimeout(wrap._calendarScrollTimer);
        wrap._calendarScrollTimer = setTimeout(() => {
            updateCalendarTitleFromScroll();
            ensureMoreCalendarMonthsOnScroll();
        }, 40);
    };
    wrap.addEventListener('scroll', wrap._calendarScrollHandler);
}

function drawCalendar(preserveScroll = false) {
    if (!Number.isFinite(Number(calendarMonthsToRender)) || Number(calendarMonthsToRender) < 1) calendarMonthsToRender = 4;
    const wrap = document.getElementById('calendarWrap');
    const prevScrollTop = wrap ? wrap.scrollTop : 0;

    const y = viewDate.getFullYear();
    const m = viewDate.getMonth();
    document.getElementById('calTitle').innerText = `${y}. ${m+1}`;

    const cal = document.getElementById('calBody');
    cal.classList.add('continuous-calendar');

    let html = '';
    for (let offset = 0; offset < calendarMonthsToRender; offset++) {
        const monthDate = new Date(y, m + offset, 1);
        html += renderOneCalendarMonth(monthDate.getFullYear(), monthDate.getMonth());
    }
    cal.innerHTML = html;

    loadWeeklyWeather();
    toggleWeatherView();
    markMyReservedDates();
    setupCalendarScrollTitleUpdate();

    if (preserveScroll && wrap) {
        requestAnimationFrame(() => {
            wrap.scrollTop = prevScrollTop;
            updateCalendarTitleFromScroll();
        });
    } else {
        setTimeout(updateCalendarTitleFromScroll, 0);
    }
}

function ensureMoreCalendarMonthsForDate(dateStr) {
    const parts = getDatePartsFromStr(dateStr);
    if (!parts.y || !parts.m) return;

    const selectedMonthIndex = parts.y * 12 + (parts.m - 1);
    const baseMonthIndex = viewDate.getFullYear() * 12 + viewDate.getMonth();
    const offset = selectedMonthIndex - baseMonthIndex;

    // 마지막으로 표시된 달 또는 그 직전 달을 클릭하면 다음 2개월을 자동으로 추가한다.
    if (offset >= calendarMonthsToRender - 2) {
        calendarMonthsToRender += 2;
        drawCalendar(true);
    }
}

function mvMonth(n) {
        viewDate.setMonth(viewDate.getMonth() + n);
        calendarMonthsToRender = 4;
        drawCalendar();
    }

function markMyReservedDates(forceRefresh = false) {
    if (!currentUser || isAdmin || !currentUser.phone) return;
    const y = viewDate.getFullYear();
    const m = viewDate.getMonth();
    const startStr = `${y}-${String(m+1).padStart(2,'0')}-01`;
    const endDateObj = new Date(y, m + calendarMonthsToRender, 0);
    const endStr = formatDateStrLocal(endDateObj);
    const cacheKey = `${currentCenter}_${currentUser.phone}_${startStr}_${endStr}`;
    const cached = _myReservedDatesCache[cacheKey];

    const applyReservedDates = (dates) => {
        (dates || []).forEach(date => {
            const cell = document.getElementById(`cal-day-${date}`);
            if (cell) cell.classList.add('my-reserved');
        });
    };

    if (!forceRefresh && cached && (Date.now() - cached.ts < MY_RESERVED_DATES_TTL)) {
        applyReservedDates(cached.dates);
        return;
    }

    db.collection('reservations')
        .where('center', '==', currentCenter)
        .where('phone', '==', currentUser.phone)
        .where('date', '>=', startStr)
        .where('date', '<=', endStr)
        .get()
        .then(snap => {
            const dates = [];
            snap.forEach(doc => {
                const data = doc.data() || {};
                if (data.status === 'CANCELED') return;
                dates.push(data.date);
            });
            _myReservedDatesCache[cacheKey] = { dates: [...new Set(dates)], ts: Date.now() };
            applyReservedDates(_myReservedDatesCache[cacheKey].dates);
        })
        .catch(() => {});
}

/* =========================================
   [속도 개선] 날씨 캐싱 시스템 (저장 후 즉시 로딩)
   ========================================= */
let latestWeatherData = null;
let weatherLoadPromise = null;

function applySavedWeatherImmediately(cacheObj) {
    if (!cacheObj || !cacheObj.data) return false;
    latestWeatherData = cacheObj.data;
    applyWeatherToCalendar(cacheObj.data);
    const curDate = document.getElementById('hiddenDate').value;
    updateWeatherBanner(curDate, cacheObj.data);
    return true;
}

async function loadWeeklyWeather(forceRefresh = false) {
    const CACHE_KEY = 'tenniskj_weather_v2';
    const CACHE_TIME = 3 * 60 * 60 * 1000;

    const saved = localStorage.getItem(CACHE_KEY);
    let parsed = null;

    if (saved) {
        try {
            parsed = JSON.parse(saved);
            applySavedWeatherImmediately(parsed);

            const now = Date.now();
            if (!forceRefresh && parsed.timestamp && (now - parsed.timestamp < CACHE_TIME)) {
                return parsed.data;
            }
        } catch (e) {
            console.error("캐시 오류", e);
        }
    } else if (latestWeatherData && !forceRefresh) {
        applyWeatherToCalendar(latestWeatherData);
        const curDate = document.getElementById('hiddenDate').value;
        updateWeatherBanner(curDate, latestWeatherData);
        return latestWeatherData;
    }

    if (weatherLoadPromise && !forceRefresh) return weatherLoadPromise;

    const lat = 35.15;
    const lon = 128.80;
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&daily=weathercode,temperature_2m_max,temperature_2m_min,precipitation_probability_max,wind_speed_10m_max&timezone=auto&forecast_days=16&wind_speed_unit=ms`;

    weatherLoadPromise = fetch(url)
        .then(res => res.json())
        .then(data => {
            latestWeatherData = data;
            const cacheObj = { timestamp: Date.now(), data };
            localStorage.setItem(CACHE_KEY, JSON.stringify(cacheObj));
            applyWeatherToCalendar(data);
            const curDate = document.getElementById('hiddenDate').value;
            updateWeatherBanner(curDate, data);
            return data;
        })
        .catch(err => {
            console.error("날씨 로딩 실패:", err);
            if (parsed && parsed.data) return parsed.data;
            throw err;
        })
        .finally(() => {
            weatherLoadPromise = null;
        });

    return weatherLoadPromise;
}

function applyWeatherToCalendar(data) {
    if(!data || !data.daily) return;

    const days = data.daily.time; 
    const codes = data.daily.weathercode;
    const maxTemps = data.daily.temperature_2m_max;
    const minTemps = data.daily.temperature_2m_min;
    
    const today = new Date();
    today.setHours(0,0,0,0);
    
    const limitDay = new Date(today);
    limitDay.setDate(today.getDate() + 14); // 2주치 표시

    for(let i=0; i < days.length; i++) {
        const dateStr = days[i];
        
        // 날짜 셀 찾기
        const targetDiv = document.getElementById(`w-${dateStr}`);
        if(!targetDiv) continue; // 해당 날짜가 달력에 없으면 패스

        const code = codes[i];
        const maxT = Math.round(maxTemps[i]);
        const minT = Math.round(minTemps[i]);

        let icon = "☀️"; 
        if (code >= 1 && code <= 3) icon = "⛅";
        else if (code >= 45 && code <= 48) icon = "🌫️";
        else if (code >= 51 && code <= 67) icon = "🌧️";
        else if (code >= 71 && code <= 77) icon = "❄️";
        else if (code >= 80 && code <= 99) icon = "☔";

        targetDiv.innerHTML = `
            <span class="cal-weather-icon">${icon}</span>
            <span class="cal-weather-temp">${minT}°/${maxT}°</span>
        `;
    }
}

function toggleCalendar() {
    const wrap = document.getElementById('calendarWrap');
    const btn = document.getElementById('btnCalendarFold');
    const grid = document.getElementById('gridArea');
    if (!wrap) return;

    const folded = wrap.classList.toggle('folded');

    if (folded) {
        // 기존 CSS에 min-height:258px 같은 !important 보정이 남아 있어도
        // 접었을 때는 달력 영역을 실제로 34px만 차지하게 강제한다.
        wrap.style.setProperty('height', '34px', 'important');
        wrap.style.setProperty('min-height', '34px', 'important');
        wrap.style.setProperty('max-height', '34px', 'important');
        wrap.style.setProperty('flex', '0 0 34px', 'important');
        wrap.style.setProperty('overflow', 'hidden', 'important');
        if (grid) {
            grid.style.setProperty('flex', '1 1 auto', 'important');
            grid.style.setProperty('min-height', '0', 'important');
            grid.style.setProperty('overflow-y', 'auto', 'important');
        }
    } else {
        // 펼칠 때는 인라인 강제를 제거해서 기존 연속 달력 스크롤 설정으로 복귀
        ['height','min-height','max-height','flex','overflow'].forEach(p => wrap.style.removeProperty(p));
        if (grid) {
            grid.style.removeProperty('flex');
            grid.style.removeProperty('min-height');
            grid.style.removeProperty('overflow-y');
        }
    }

    if (btn) btn.innerText = folded ? '달력펼치기' : '달력접기';

    setTimeout(() => {
        try {
            if (typeof updateCalendarTitleFromScroll === 'function') updateCalendarTitleFromScroll();
            if (typeof autoScroll === 'function') autoScroll();
        } catch(e) {}
    }, 60);
}

function toggleCourtBoard() { toggleCalendar(); }

function updateWeatherBanner(dateStr, weatherData) {
    // 데이터가 없으면 저장소에서 가져옴
    if(!weatherData) {
        const saved = localStorage.getItem('tenniskj_weather_v2');
        if(saved) weatherData = JSON.parse(saved).data;
        else return;
    }

    const idx = weatherData.daily.time.indexOf(dateStr);
    const banner = document.getElementById('weatherBanner');
    
    // 해당 날짜 데이터가 없으면(너무 먼 미래) 숨김
    if(idx === -1) {
        banner.style.display = 'none';
        return;
    }

    banner.style.display = 'flex'; // 배너 보이기

    const code = weatherData.daily.weathercode[idx];
    const maxT = Math.round(weatherData.daily.temperature_2m_max[idx]);
    const minT = Math.round(weatherData.daily.temperature_2m_min[idx]);
    const rainProb = weatherData.daily.precipitation_probability_max[idx]; // 강수확률
    const windSpeed = weatherData.daily.wind_speed_10m_max[idx]; // 풍속(m/s)

    // 1. 아이콘 & 텍스트 설정
    let icon = "☀️", text = "맑음";
    if (code >= 1 && code <= 3) { icon = "⛅"; text = "구름 조금"; }
    else if (code >= 45 && code <= 48) { icon = "🌫️"; text = "흐림/안개"; }
    else if (code >= 51 && code <= 67) { icon = "🌧️"; text = "비 예보"; }
    else if (code >= 71 && code <= 77) { icon = "❄️"; text = "눈 예보"; }
    else if (code >= 80 && code <= 99) { icon = "☔"; text = "비/소나기"; }

    document.getElementById('wbIcon').innerText = icon;
    document.getElementById('wbText').innerText = text;
    document.getElementById('wbTemp').innerText = `${minT}° / ${maxT}°`;
    document.getElementById('wbWind').innerText = `${windSpeed}m/s`;
    document.getElementById('wbRain').innerText = `${rainProb}%`;

  // 2. 테니스 지수 판별 (판정 로직 교체)
const scoreBox = document.getElementById('wbScore');

// [수정된 로직] 강수확률이 낮아도 날씨 코드가 '비/눈'이면 경고 띄움
// 코드 51번 이상은 이슬비, 비, 눈, 소나기 등을 의미함
if (rainProb >= 40 || (code >= 51 && code <= 99)) {
    scoreBox.style.background = "#fee2e2"; scoreBox.style.color = "#991b1b";
    scoreBox.innerText = "☔ 우천/눈 대비하세요";
} else if (windSpeed >= 6) {
    scoreBox.style.background = "#ffedd5"; scoreBox.style.color = "#9a3412";
    scoreBox.innerText = "🌬️ 바람이 강해요";
} else if (maxT >= 30) {
    scoreBox.style.background = "#ffedd5"; scoreBox.style.color = "#9a3412";
    scoreBox.innerText = "☀️ 더위 조심하세요";
} else if (maxT <= 5) {
    scoreBox.style.background = "#f1f5f9"; scoreBox.style.color = "#475569";
    scoreBox.innerText = "🧣 따뜻하게 입으세요";
} else {
    scoreBox.style.background = "#dcfce7"; scoreBox.style.color = "#166534";
    scoreBox.innerText = "🎾 운동하기 딱 좋아요!";
}
}

function pickDate(s) { 
    const hidden = document.getElementById('hiddenDate');
    hidden.value = s;

    const parts = getDatePartsFromStr(s);
    if (parts.y && parts.m) {
        // 상단 표시는 선택한 날짜 기준으로 바꾸되, viewDate는 현재 연속 달력의 시작 월로 유지한다.
        // 이렇게 해야 클릭할 때 달력이 위로 튀지 않고, 아래 달들이 계속 이어진다.
        document.getElementById('calTitle').innerText = `${parts.y}. ${parts.m}`;
    }

    document.querySelectorAll('.cal-date.selected').forEach(el => el.classList.remove('selected'));
    const pickedCell = document.getElementById(`cal-day-${s}`);
    if (pickedCell) pickedCell.classList.add('selected');

    ensureMoreCalendarMonthsForDate(s);
    loadDB(); 
    updateWeatherBanner(s);
}

