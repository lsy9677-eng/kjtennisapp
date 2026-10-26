# 독립 로컬 개발 환경

배포 출력 구성과 프로젝트별 자동 배포 중지 기록은 [DEPLOYMENT-PREPARATION.md](DEPLOYMENT-PREPARATION.md)를 참고한다. `npm.cmd run build:pages`, `npm.cmd run test:release`, `npm.cmd run test:transfer`를 제공한다. 기본 가상 seed는 카드 비활성화이며 기존 카드 회귀 검증만 명시적인 가상 카드 활성 설정을 사용한다.

운영 접속·데이터 변경·커밋·푸시·배포를 하지 않는다. 브랜치 `dev/local-emulator-isolation`, 비교 기준 `3b5bb59`. 환경 분리 이후 요청에 따라 평일 판정과 계절 설정 로드 대기/실패 차단만 수정했다. 요금표 값·예약 저장·더치페이·환불 산식·PG 요청 구조는 유지한다.

## 처음 설치 — Windows x64

Windows x64, Node.js 24 LTS(검증: 24.22.1), npm, Git, 기본 Windows PowerShell이 필요하다. npm/Git은 PATH에 있어야 한다. 소스 보존 검사는 기준 커밋 `3b5bb59`가 로컬 Git 이력에 있어야 한다. Firebase/Cloudflare 로그인·서비스 계정·운영 `.env`/`.dev.vars`는 필요하지 않다.

저장소 루트에서 아래 명령만 실행한다. 다른 앱 폴더나 전역 Firebase CLI·Playwright·JDK를 검색하지 않는다.

```powershell
npm.cmd ci --ignore-scripts --no-audit --no-fund --cache dev/artifacts/npm-cache
npm.cmd run setup:tools
npm.cmd test
npm.cmd run test:production
npm.cmd run test:pages
npm.cmd run test:pages:browser
```

첫 두 명령만 도구 다운로드를 수행한다. npm 패키지는 lock 파일로 고정한다. JDK 21과 workerd용 Windows VCLibs는 `dev/tool-downloads.json`의 공식 URL·SHA-256으로 검증하고 저장소 안에만 압축을 푼다. Emulator JAR는 고정된 firebase-tools의 메타데이터·SHA-256으로 검증한다. Chromium은 고정된 Playwright 버전의 브라우저를 저장소에 설치한다. 시스템 설치·환경 변수 영구 변경은 없다. 다운로드 파일을 재사용하며 체크섬 불일치 시 덮어쓰지 않고 중단한다.

도구는 무시 대상 `node_modules/`, `dev/artifacts/`에 설치된다. Wrangler의 임시 빌드 캐시 `.wrangler/`도 무시한다. Windows x64 외 OS는 미지원·미검증이다. 실행/검사 명령은 자동 다운로드를 하지 않으며 도구가 없으면 실패한다.

## 수동 실행

```powershell
# 터미널 1
npm.cmd run emulators
# 터미널 2
npm.cmd run seed
npm.cmd run dev:pages
```

주소는 `http://127.0.0.1:4173/` 또는 `http://localhost:4173/`. 두 출처의 세션은 서로 다르다. `npm.cmd run dev`는 Node 서버이며 Cloudflare 런타임 검사를 대신하지 않는다. 종료는 각 터미널의 Ctrl+C. 포트가 사용 중이면 기존 프로세스를 건드리지 않고 중단한다.

가상 회원: `member@example.invalid` / `LocalOnly123!`. 연락처 `000-0000-0000`, 은행·요금·예약은 가상 값뿐이다. 운영 데이터 import는 없다. Emulator 데이터는 종료 후 보존하지 않으므로 재시작 후 seed한다.

`test:pages:browser`는 Emulator·seed·4173의 workerd를 직접 시작하고 검사 후 종료한다. 수동 개발 프로세스를 종료한 상태에서 실행한다. `test:local`은 같은 검사를 Node 서버로 실행한다.

## 환경과 차단

| 용도 | 허용 대상 |
| --- | --- |
| 운영 모드 | 정확한 `https://tenniskj-app.pages.dev` 출처 |
| 개발 모드 | HTTP의 `127.0.0.1:4173`, `localhost:4173` |
| Auth / Firestore / Storage | `127.0.0.1:9099` / `8080` / `9199`, `demo-kjtennis-local` |
| Hub / 로그 / Firestore WS | `127.0.0.1:4407` / `4507` / `9157` |

미확인 호스트·다른 프로토콜/포트·자격 증명이 붙은 URL은 중단한다. 쿼리·저장 값으로 운영 모드를 켤 수 없다. SDK 최초 사용 전에 Emulator에 연결한다. 연결 실패 시 운영 fallback 없이 화면을 중단한다.

개발 앱 이름은 `kjtennis-development`, Auth persistence는 SESSION이다. 개발 Storage 키에 `kjdev:demo-kjtennis-local:` 접두사를 사용하고 개발 출처의 CacheStorage만 초기화한다. 기존 로컬 서비스 워커는 해제하고 제어 중이면 탭 재시작을 요구한다. 새 워커는 CSP로 차단한다. 운영 출처의 저장소·캐시·워커에는 접근하지 않는다.

로컬 HTTP CSP와 초기 스크립트 CSP로 외부 연결을 막는다. fetch는 추가 허용 목록 검사, XHR·Beacon·WebSocket은 CSP를 적용한다. 로컬 Worker의 outboundService는 외부 요청을 차단하며 원격 proxy/binding은 없다. CLI는 인증 환경 변수를 제거하고 별도 config/log 및 네트워크 차단 preload를 사용한다.

기본 가상 설정은 계좌이체 전용이다. 카드 회귀 검증에서는 `--card-enabled` 가상 설정과 `dev-payment-*` 성공 대역으로 기존 예약 저장을 Emulator에서 재현한다. SMS·알림·OAuth·reCAPTCHA·날씨는 대역을 사용하고 화면에 기록한다. 실제 PG 환불 구현이 원래 없으므로 환불은 별도 가상 기록 버튼만 제공한다. 취소/환불 업무를 구현한 것이 아니다.

운영 분기는 기존 SDK URL·Firebase 설정·기본 앱 `[DEFAULT]`·Auth persistence·로컬 저장 키·예약 스키마를 유지한다. 대역 설치 함수는 운영 모드에서 즉시 반환한다.

## Pages/Workers와 운영 세션 검사

Cloudflare 공식 [Pages 로컬 개발](https://developers.cloudflare.com/pages/functions/local-development/) 및 [파일 라우팅](https://developers.cloudflare.com/pages/functions/routing/) 방식에 따라 Wrangler로 실제 Functions 번들을 생성하고 Miniflare의 실제 workerd와 assets binding으로 실행한다. Node handler 직접 호출 검사와 구분한다.

`prepare-pages.mjs`는 허용한 정적 파일만 임시 stage에 복사한다. 개발 stage에만 vendor와 로컬 CSP를 추가한다. 운영 검사용 stage는 원래 `_headers`를 보존한다. 소스 `_headers`는 변경하지 않는다. stage에 dev 문서·seed·node_modules·자격 증명은 포함하지 않는다. 생성물은 로컬 검증용이며 업로드·배포하지 않는다.

Function은 개발 출처에서 env 접근 전 대역 응답, 미확인 출처에서 403을 반환한다. Worker 검사는 가상 env만 사용한다. 운영 URL 문자열도 **로컬 dispatch 인자**로만 사용한다. reCAPTCHA/Kakao 하위 요청은 메모리 대역으로 응답하고 전달하지 않는다. 로그인 시작 302는 검사만 하고 따라가지 않는다.

운영 세션 검사는 브라우저의 모든 요청을 메모리에서 충족하거나 차단한다. 기준 코드와 실제 Firebase SDK 9.6.1로 가상 세션을 만들고 변경 코드로 이동해 복원을 확인한다. 운영 계정·토큰·데이터를 사용하지 않는다.

## 통과 검사와 TODO

| 검사 | 실제 확인 범위 |
| --- | --- |
| `npm.cmd test` | 환경 분리 6개 + 원본 보존/도구 독립성 5개 + 기존 경로/회귀 5개 + 요금 설정 10개 + 요금 로드 대기/실패 8개 + 카드 정책 6개 = **40개 통과**, TODO **5개** |
| `test:pages` | Wrangler 컴파일, workerd 정적 파일/MIME/헤더/Functions, 개발·미확인·운영 분기, Web Crypto 가상 토큰 |
| `test:production` | 기준 SDK 세션 복원/설정 보존과 별도 가상 SDK 경계의 전체 HTML 초기화·초기 설정 실패·재시도·결제 버튼 복구. 모든 요청 메모리 처리, 데이터 쓰기/결제 0건 |
| `test:pages:browser` | demo 로그인·예약 저장·Storage·세션 복원·대역·외부 차단·불통 시 중단·캐시 격리를 workerd 경유로 확인 |

**남은 결함 재현의 통과는 결함 해결을 뜻하지 않는다.** 해결한 평일 판정은 회귀 검사로 전환했다. TODO 5개는 미구현 기준 또는 정책 검토 항목이며 통과 수에 포함하지 않는다. 최신 요금 운영 기준과 대응 관계는 [KNOWN-ISSUES.md](KNOWN-ISSUES.md), 계산 경로 조사는 [PRICING-REVIEW.md](PRICING-REVIEW.md)에 기록했다.

보고서는 `dev/artifacts/pages-report.json`, `pages-browser-report.json`, `production-browser-report.json`. 운영 URL 문자열은 메모리 대역 요청 기록이며 운영 접속 기록이 아니다.

실제 Cloudflare 배포·엣지 설정·운영 비밀키·인증 제공자 설정·운영 Rules/인덱스, 실제 PG/환불/발송, 실제 다중 클라이언트 경합, 모바일은 미검증이다. 로컬 workerd 통과는 배포된 운영의 정상 동작 보증이 아니다. 운영 확인은 이번 범위에서 금지되어 있다.
