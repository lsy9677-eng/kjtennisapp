# dev/css

Step 2에서 `index.dev.html` 내부의 `<style>` 블록을 순서 그대로 `app.bundle.css`로 분리했습니다.

- `app.bundle.css`: 원본 `<style>` 24개를 원래 순서대로 합친 개발용 CSS 번들
- 이 단계에서는 CSS만 이동했고 JS/Firebase/예약 로직은 수정하지 않았습니다.
- 다음 단계에서 이 번들을 `base/layout/calendar/reservation/modal/dark` 등으로 세분화할 수 있습니다.
