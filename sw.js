// v10.2: 자동 업데이트/강제 새로고침을 사용하지 않는 안정화 서비스워커
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', () => {});
