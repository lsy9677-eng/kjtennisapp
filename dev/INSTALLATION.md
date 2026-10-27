# 브라우저에서 홈 화면에 추가

상단 홈 화면 추가 버튼과 회원 설정의 홈 화면에서 이용하기 영역을 제공합니다. iPhone/iPad는 Safari 공유 메뉴의 홈 화면에 추가 절차를 안내합니다. iOS에서 자바스크립트로 설치를 완료하거나 공유 메뉴를 강제로 열 수 있다고 표시하지 않습니다. Android/데스크톱은 브라우저가 beforeinstallprompt를 제공한 경우에만 사용자 클릭에서 prompt를 호출하며, 미지원/미준비 상태에서는 브라우저 메뉴의 설치 절차를 안내합니다.

기존 Android 배너는 실제 설치 확인 없이 플레이스토어 링크를 표시하던 기능입니다. 새 기본 동작은 브라우저 설치이고 플레이스토어는 Android 안내의 보조 링크로 유지합니다. 설치 완료 이벤트와 standalone/TWA 실행 모드는 확인하지만, 일반 브라우저 탭에서 설치된 모든 앱을 탐지한다고 보장하지 않습니다. 배너 닫기는 7일간 기억하며 설정 메뉴에서는 다시 안내를 열 수 있습니다. 설치 승인 결과와 완료 이벤트도 구분합니다.

manifest id /는 기존 start_url ./가 이 출처에서 해석되는 /와 같아 앱 식별자를 유지합니다. prefer_related_applications=false로 브라우저 설치를 우선합니다. 이름·설명·테마색과 scope를 명시했습니다. 기존 서비스워커 정책은 바꾸지 않았고 캐시/오프라인 지원을 추가했다고 주장하지 않습니다. 설치해도 예약과 로그인에는 인터넷이 필요합니다.

검사 도구의 네이티브 설치 이벤트는 모의 이벤트입니다. 실제 iOS Safari 및 Android Chrome에서 홈 화면에 아이콘이 생기고 standalone으로 실행되는 최종 검사는 실제 기기에서 필요합니다. 설치 가능 이벤트는 브라우저의 참여도·설치 여부·정책에 따라 바로 발생하지 않을 수 있습니다.

참고: https://support.apple.com/guide/iphone/open-as-web-app-iphea86e5236/ios , https://web.dev/articles/install-criteria , https://web.dev/learn/pwa/installation-prompt
