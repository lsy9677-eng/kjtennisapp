# 배포 출력 준비 및 자동 배포 중지 기록

2026-10-27 KST. 배포·푸시·병합은 실행하지 않았다.

## Cloudflare 프로젝트별 변경

`tenniskj-app1`만 프로젝트 API로 변경했다. 운영 자동 배포는 `true` → `false`, Preview는 `all` → `none`이다. 기존 사이트를 삭제하거나 배포를 교체하지 않았다. 기존 canonical 배포는 `d44943f0-d6aa-413c-9739-acb5632a423a`로 유지됐다.

`tenniskj-app`은 변경하지 않았다. 운영 자동 배포 `true`, Preview `all`, canonical 배포 `eab4ad5e-b98d-4538-81ec-9e6db409a707`을 유지했다. 두 프로젝트 모두 연결 저장소는 `lsy9677-eng/kjtennisapp`, 운영 브랜치는 `main`이다. app1이 실제로 테스트 용도인지는 확정하지 않았다.

변경 전후 설정은 자격 증명과 환경 변수 값을 제외하여 아래 로컬 무시 경로에 기록했다.

- `dev/artifacts/cloudflare/autodeploy-before-2026-10-26T21-42-26-235Z.json`
- `dev/artifacts/cloudflare/autodeploy-after-2026-10-26T21-42-26-235Z.json`

## 출력 구성

기존 설치 절차는 [README.md](README.md)를 따른다. 저장소 자체의 Node 의존성만 사용한다.

```powershell
npm.cmd run build:pages
npm.cmd run test:release
npm.cmd run test:transfer
```

`build:pages`는 `dev/pages-assets.mjs`의 명시적인 공개 파일 29개와 컴파일된 `_worker.js`, `_routes.json`만 `dist/`에 생성한다. Functions는 Pages advanced mode Worker로 포함한다. 기존 파일을 재귀 복사하지 않으며 재빌드 시 오래된 출력 파일을 제거한다. 런타임에 필요한 환경 판별 JS는 포함하고 `dev/`, 테스트, 로컬 vendor, 설치물, 문서, 로그와 비밀 설정은 제외한다. 출력물과 검증 결과는 Git에서 무시한다.

향후 **별도 승인을 받은 배포 시** 적용할 빌드 설정 후보는 저장소 루트, 명령 `npm run build:pages`, 출력 `dist`이다. Node는 `.node-version`의 24.22.1, Worker 호환 날짜는 현재 운영과 같은 2026-03-13이다. 이 설정을 Cloudflare에 적용하지 않았다. 현재 원격 빌드 설정은 그대로이므로 현 상태로 푸시하면 이 출력 구성이 자동 적용된다고 가정하면 안 된다. 실제 Cloudflare Linux 빌드와 업로드는 미검증이다.

### 향후 Pages 빌드 입력값

| 항목 | 값 |
| --- | --- |
| 대상 | `tenniskj-app` / `lsy9677-eng/kjtennisapp` / 운영 브랜치 `main` |
| Framework preset | `None` |
| Root directory | 저장소 루트 (빈 값) |
| Build command | `npm ci --include=dev --ignore-scripts --no-audit --no-fund && npm run build:pages` |
| Build output directory | `dist` |
| Node | `.node-version`: `24.22.1` |
| Worker compatibility date | 기존 값 `2026-03-13` 유지 |

위 명령은 Linux 빌드 셸용이다. 먼저 lock 파일대로 개발 의존성까지 명시적으로 설치한 다음 빌드한다. Wrangler는 devDependencies에 있으므로 이를 제외하면 빌드할 수 없다. `setup:tools`는 로컬 Windows Emulator/브라우저 검증 전용이며 Pages 빌드에서 실행하지 않는다. 이 표의 원격 설정은 이번 검토에서 적용하지 않았다.

Functions 컴파일 명령은 로컬 설치된 Wrangler의 `pages functions build functions --outdir <임시 worker 폴더> --output-routes-path <임시 routes.json> --compatibility-date 2026-03-13`이다. 생성된 모듈을 `dist/_worker.js`, 라우팅 설정을 `dist/_routes.json`으로 복사한다. 경로는 `/kakao-auth`, `/naver-auth`, `/verify-recaptcha`이다. 나머지 정적 파일은 ASSETS로 제공한다. [공식 advanced mode 문서](https://developers.cloudflare.com/pages/functions/advanced-mode/)에 따라 출력 루트의 `_worker.js`를 사용하고 저장소 `functions/`를 별도로 중복 배포하지 않는다. 기존 운영 환경 변수/비밀 값과 바인딩은 유지하며 출력 파일에 넣지 않는다.

### 배포 이후 문제가 생길 때의 복구 절차 (이번에는 실행하지 않음)

1. Cloudflare의 **tenniskj-app** → Deployments → All deployments에서 기존 성공한 production 배포 `eab4ad5e-b98d-4538-81ec-9e6db409a707` (소스 `3b5bb599e3445aaa4fcc55f07aac486b310ae7e0`)을 선택한다.
2. 해당 배포의 메뉴에서 **Rollback to this deployment**를 선택하고 대상 프로젝트·배포를 확인한 뒤 승인한다. Preview는 복구 대상이 될 수 없다. [공식 복구 절차](https://developers.cloudflare.com/pages/configuration/rollbacks/).
3. 이 작업은 사이트/Worker 버전을 되돌리며 Firebase 데이터·결제 상태·Git 이력·프로젝트 빌드 설정을 되돌리지 않는다. 빌드 설정도 복구해야 한다면 사전 기록의 저장소 루트/빈 build command/빈 destination 값을 별도 승인 후 복원한다.
4. 자동 배포는 유지되므로 이후 운영 브랜치 푸시가 다시 새 버전을 배포할 수 있다. 원인 해결 전 후속 푸시·재배포를 하지 않는다. `tenniskj-app1`은 이 복구 절차에서 변경하지 않는다.

## 세 커밋의 최종 배포 범위

- `660882e`: demo Emulator, 개발 세션·캐시 분리, 외부 요청 대역/차단, 정확한 운영 출처 제한, Functions 분기와 로컬 검증 도구.
- `c3b1944`: 평일 판정 동기화, 계절 설정 로드 완료 전 결제 차단, 실패·재시도와 버튼 복구. 요금표 금액·계절 금액·환불·예약 동시성·PG 처리 구조는 유지.
- 이번 추가 커밋: 공개 파일 allowlist 기반 `dist` 빌드, 출력물 검증, 카드 설정 우회 차단과 가상 카드/계좌이체 회귀 검증, 문서. Cloudflare 자동 배포 설정 변경은 Git 커밋과 별개의 이전 원격 작업이며 이번에는 원격 설정을 변경하지 않는다.

## 가상 데이터 검증 및 한계

기본 seed는 `useCardPay: false`이다. 카드 경로 회귀 검증만 명시적인 `--card-enabled` 가상 설정을 사용한다. `test:transfer`는 저장소의 demo Emulator와 로컬 workerd에서 실행한다. 계좌이체 예약 완료의 의미는 두 시간 슬롯이 `PENDING`, `paymentUid: TRANSFER`로 저장되는 가예약 신청 완료다. 실제 송금·입금 확인·예약 승인은 하지 않는다.

클라이언트는 카드 비활성 설정을 읽은 뒤 카드 탭을 숨기고, 카드 선택을 계좌이체로 되돌리며, 변조된 선택도 PG 호출 전에 차단한다. 요금·예약 저장·환불 공식과 기존 PG 처리 본문은 유지한다. 이는 클라이언트 제어이며 서버 결제 검증을 추가한 것은 아니다. 실제 운영 Firestore의 카드 설정 값은 조회하거나 변경하지 않았다.

`test:release`는 정확한 파일 목록, 오래된 파일 제거, 실제 로컬 workerd의 정적 파일 및 Functions, 출력 HTML의 메모리 전용 운영 초기화·설정 재시도·버튼 복구를 검증한다. 운영 URL 문자열은 로컬 dispatch와 메모리 응답에만 사용한다. 실제 운영 Firebase·PG·발송 요청은 보내지 않는다. TODO 5개는 [KNOWN-ISSUES.md](KNOWN-ISSUES.md)의 미수정 결함/정책 항목이며 통과 테스트가 아니다.
