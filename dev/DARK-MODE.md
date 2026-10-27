# 다크모드 점검

앱 화면은 body.dark-mode와 html data-theme을 함께 갱신하고 color-scheme을 활성 테마에 맞춰 지정합니다. 기기 설정과 무관하게 밝은 화면을 기본으로 사용합니다. 앱에서 다크를 직접 선택한 경우에만 theme=dark를 저장하여 다음 접속에도 복원합니다. 기기 다크 설정 변화는 앱 테마를 바꾸지 않습니다. 기본 및 명시적 라이트에서는 color-scheme: only light로 브라우저 자동 어둡게 처리 방지를 요청합니다.

남색 배경·패널·입력란·구분선과 전경색을 함께 정의했습니다. 정기 예약은 어두운 빨강에 밝은 붉은 글자, 일반 예약은 어두운 파랑에 밝은 파란 글자, 입금 대기는 갈색에 밝은 노란 글자로 구분합니다. 실제 기기·필터·색각에 따라 색의 인상은 달라질 수 있습니다.

점검 범위: 홈, 달력, 좌측 예약 허브, 선택 요약/하단 도구, 주요 메뉴, 회원/관리자 설정, 게시글 작성, 공지 편집 및 예약 관련 공통 패널. 주요 본문·카드·버튼 글자는 실제 계산 색상으로 4.5:1 이상 대비를 검사합니다. 비활성 요소와 이미지 안의 글자까지 모두 검사했다는 뜻은 아닙니다.

삼성인터넷: 브라우저의 강제 다크 변환은 버전·설정별로 CSS 테마와 다르게 동작할 수 있습니다. 활성 테마의 color-scheme과 기본 only light를 제공하지만 강제 변환을 완전히 차단한다고 보장하지 않습니다. 삼성 User-Agent와 Chromium 강제 다크의 모의 검사는 실제 Galaxy 삼성인터넷 검사와 다릅니다. 실제 기기에서 최종 확인이 필요합니다.

근거: https://developer.samsung.com/browser/blog/en/2020/12/15/dark-mode-in-samsung-internet

## 로컬 재검사

저장소의 로컬 Emulator 및 미리보기 서버가 실행 중일 때 npm run test:dark를 실행합니다. node dev/dark-mode-check.mjs --samsung-simulated --force-dark는 예시 삼성 User-Agent와 Chromium 강제 다크로 실행하는 스트레스 검사입니다. 어느 검사도 실제 삼성인터넷 엔진을 사용한 것은 아닙니다. 결과는 dev/artifacts/dark-mode*/에 저장됩니다.
