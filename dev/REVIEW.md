# 개발 환경 분리 재검토 결과

아래는 개발 환경 분리 커밋 `660882e`의 검토 기록이다. 이후 별도 요금 수정과 최종 초기화/재시도 검사는 [PRICING-REVIEW.md](PRICING-REVIEW.md)에 기록했다.

## 수정한 환경 문제

| 항목 | 기존 부족 사항 | 수정·검증 |
| --- | --- | --- |
| 도구 독립성 | 다른 앱의 JDK·CLI·Playwright·JAR 탐색 | 탐색 제거. npm lock과 공식 URL/SHA-256에 근거한 저장소 내부 설치 절차 구현·실행 |
| Pages 검사 | Node handler 호출만으로 Cloudflare 검사를 대신함 | Wrangler 실제 Pages 번들을 workerd에서 실행. 정적 assets·MIME·헤더·Functions·Web Crypto 검증 |
| 운영 세션 | 설정 비교만 수행하고 기존 SDK 세션 복원 미확인 | Firebase 9.6.1로 기준 코드의 가상 세션을 만든 뒤 변경 코드로 복원. 전 요청 메모리 처리 |
| 운영 정적 출력 | 개발 도구가 검사용 정적 stage에 섞이지 않는지 미확인 | 파일 허용 목록 stage 추가. 운영 `_headers` 보존, 개발 vendor/seed/tools 제외 확인 |
| 검사 프로세스 종료 | workerd 검사에서 소비하지 않은 응답 스트림으로 종료 지연 | 응답을 모두 읽고 runtime을 dispose하도록 수정해 정상 종료 확인 |

`booking-core.js`와 `reservation-data.js`는 기준 커밋과 완전히 같다. `my-reservations.js`와 `booking-helpers.js`는 개발용 SMS I/O 가드를 제외하면 기준과 같다. 요금·환불 계산 변경은 없다.

## 검증의 의미

- 단위 검사 16개 통과. 이 중 5개는 기존 결함 재현이며 해결을 뜻하지 않는다. TODO 6개는 미구현 정상 기준이다.
- Pages/workerd: 정적 파일·헤더·라우팅·개발 대역·운영 분기·가상 키의 JWT 발급을 로컬 확인했다.
- 운영 모드 브라우저 대역: 기준 SDK 세션 복원, `[DEFAULT]`, Firebase 설정, 기존 저장 키, Notification/fetch 비변경을 확인했다. 모든 요청은 메모리 처리했다.
- demo Emulator와 workerd 브라우저: 로그인·예약 저장·Storage·세션·대역·차단·캐시 격리를 확인했다.
- `npm ci --ignore-scripts`로 재설치하고 저장소 자체 도구만 사용해 재검증했다. 다른 앱을 참조하지 않는다.

실제 Cloudflare 배포·운영 접근, 실제 결제·발송, 운영 Rules/인덱스/비밀키, 실기기, 다중 클라이언트 경합은 미검증이다. 로컬 workerd 확인과 배포된 엣지 확인을 구분한다. 운영의 정적 출력 디렉터리 설정도 확인하지 않았다.

실행 절차는 [README.md](README.md), 미수정 TODO 6개의 대응은 [KNOWN-ISSUES.md](KNOWN-ISSUES.md)에 기록했다.
