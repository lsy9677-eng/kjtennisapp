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
        img: "map_neungdong.jpg", // [준비필요] 능동 배치도 이미지 파일명
        pos: {
            // 예시: 일단 국제랑 똑같이 넣어둠 (나중에 수정 필요)
            1: [76, 52, 44, 21], 8: [3, 4, 44, 21] 
        }
    },
    
    "동부": { 
        name: "동부 테니스장", 
        courts: 7,
        img: "map_dongbu.jpg", // [준비필요] 동부 배치도 이미지
        pos: {
            // 아직 좌표를 모르니 비워둡니다 (빨간 박스 안 나옴)
        } 
    },
    
    "원도심": { 
        name: "원도심", 
        courts: 4, 
        img: "map_one.jpg", // [준비필요] 원도심 배치도 이미지
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
