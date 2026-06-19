/*
 * 국제 테니스장 예약 앱 - 공통 유틸 함수
 * step4-utils-extracted
 *
 * 원칙:
 * - 예약 저장, 결제, Firebase 쓰기 로직은 이 파일로 옮기지 않는다.
 * - 순수 포맷/검증/날짜/해시/ID 생성 함수만 둔다.
 * - 기존 전역 함수명은 유지해 HTML onclick/onblur 및 기존 JS 호출과 호환한다.
 */

function normalizePhoneNumber(input) {
        const digits = String(input || '').replace(/\D/g, '');
        if (!digits) return '';
        if (digits.length === 11) return digits.replace(/(\d{3})(\d{4})(\d{4})/, '$1-$2-$3');
        if (digits.length === 10) return digits.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
        return input;
    }

function normalizeKoreanRealName(value) {
        return String(value || '').replace(/[^가-힣]/g, '').trim();
    }

function isValidKoreanRealName(value) {
        return /^[가-힣]{2,6}$/.test(String(value || '').trim());
    }

function sanitizeKoreanRealNameInput(input) {
        if (!input) return;
        // 입력 중에는 절대 건드리지 않고, 포커스를 벗어났을 때만 정리합니다.
        // 모바일/삼성키보드/한글 조합 중 글자가 끊기는 문제를 막기 위한 방식입니다.
        const raw = String(input.value || '');
        const cleaned = raw.replace(/[^가-힣]/g, '').slice(0, 6);
        if (raw !== cleaned) input.value = cleaned;
    }

function getStoragePathFromUrl(url) {
        try {
            if (!url) return "";
            const clean = url.split('?')[0];
            const marker = '/o/';
            const idx = clean.indexOf(marker);
            if (idx === -1) return "";
            return decodeURIComponent(clean.substring(idx + marker.length));
        } catch (_) {
            return "";
        }
    }

function getDateFromAny(value) {
        try {
            if (!value) return null;
            if (value instanceof Date) return value;
            if (value.toDate && typeof value.toDate === 'function') return value.toDate();
            if (typeof value === 'string' || typeof value === 'number') {
                const d = new Date(value);
                return isNaN(d.getTime()) ? null : d;
            }
            return null;
        } catch (_) {
            return null;
        }
    }

function buildSlotLockId(center, date, court, time) {
        return [center || '국제', date, court, time].join('_');
    }

function safeSetInputValue(id, value) {
        const el = document.getElementById(id);
        if (el) el.value = value;
    }

function safeSetChecked(id, value) {
        const el = document.getElementById(id);
        if (el) el.checked = !!value;
    }

async function hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

function getDatePartsFromStr(dateStr) {
    const [yy, mm, dd] = String(dateStr || '').split('-').map(Number);
    return { y: yy, m: mm, d: dd };
}

function formatDateStrLocal(dateObj) {
    return `${dateObj.getFullYear()}-${String(dateObj.getMonth()+1).padStart(2,'0')}-${String(dateObj.getDate()).padStart(2,'0')}`;
}

function formatCourtTimeSummary(slots) {
        if (!Array.isArray(slots) || slots.length === 0) return '';

        const grouped = {};
        slots.forEach(s => {
            const court = Number(s.c ?? s.court);
            const time = Number(s.t ?? s.time);
            if (!Number.isFinite(court) || !Number.isFinite(time)) return;
            if (!grouped[court]) grouped[court] = [];
            grouped[court].push(time);
        });

        const formatCourtRanges = (times) => {
            const uniqueTimes = [...new Set(times)].sort((a, b) => a - b);
            if (!uniqueTimes.length) return '';

            const ranges = [];
            let start = uniqueTimes[0];
            let prev = uniqueTimes[0];

            for (let i = 1; i < uniqueTimes.length; i++) {
                const current = uniqueTimes[i];
                if (current === prev + 1) {
                    prev = current;
                    continue;
                }
                ranges.push([start, prev]);
                start = current;
                prev = current;
            }
            ranges.push([start, prev]);

            return ranges.map(([rangeStart, rangeEnd]) => {
                const hours = (rangeEnd - rangeStart) + 1;
                return `${rangeStart}~${rangeEnd + 1}시 ${hours}시간`;
            }).join(', ');
        };

        return Object.keys(grouped)
            .map(Number)
            .sort((a, b) => a - b)
            .map(court => `${court}코트 ${formatCourtRanges(grouped[court])}`)
            .join(', ');
    }

function toJsDateSafe(v) {
    try {
        if (!v) return null;
        if (v instanceof Date) return v;
        if (v.toDate) return v.toDate();
        if (typeof v === 'string') return new Date(v);
        return new Date(v);
    } catch(e) {
        return null;
    }
}

function formatDateTimeKR(v) {
    const d = toJsDateSafe(v);
    if (!d || isNaN(d.getTime())) return '-';
    const y = d.getFullYear();
    const m = String(d.getMonth()+1).padStart(2,'0');
    const day = String(d.getDate()).padStart(2,'0');
    const hh = String(d.getHours()).padStart(2,'0');
    const mm = String(d.getMinutes()).padStart(2,'0');
    return `${y}-${m}-${day} ${hh}:${mm}`;
}

function formatElapsedKR(v) {
    const d = toJsDateSafe(v);
    if (!d || isNaN(d.getTime())) return '-';
    let diff = Math.max(0, Date.now() - d.getTime());
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return '방금 전';
    if (mins < 60) return `${mins}분 경과`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}시간 ${mins % 60}분 경과`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}일 ${hours % 24}시간 경과`;
    const months = Math.floor(days / 30);
    return `${months}개월 ${days % 30}일 경과`;
}
