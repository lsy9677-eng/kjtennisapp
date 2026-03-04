// sw.js
const CACHE_NAME = 'tennis-v4';
const urlsToCache = [
  './',
  './index.html',
  './abc-192.png',
  './abc-512.jpg',
  './manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});// sw.js
// [중요] 코드를 수정할 때마다 버전을 올려주세요 (v1 -> v2 -> v3)
const CACHE_NAME = 'tennis-v2'; // 버전을 v2로 변경했습니다.

const urlsToCache = [
  './',
  './index.html',
  './abc-192.png',
  './abc-512.jpg',
  './manifest.json'
];

self.addEventListener('install', event => {
  // 대기 없이 즉시 설치
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(), // 즉시 제어권 가져오기
      caches.keys().then(keyList => {
        return Promise.all(keyList.map(key => {
          // 현재 버전과 다른 옛날 캐시는 모두 삭제
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        }));
      })
    ])
  );
});

// [핵심 변경 사항] 네트워크 우선 전략 (Network First)
self.addEventListener('fetch', event => {
  // 구글 폰트, 파이어베이스 등 외부 요청은 건드리지 않음
  if (event.request.url.includes('http') && !event.request.url.includes(location.origin)) {
     return;
  }

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // 1. 네트워크 요청 성공 시: 최신 파일 돌려주고, 캐시도 최신으로 갱신
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        const responseToCache = response.clone();
        caches.open(CACHE_NAME)
          .then(cache => {
            cache.put(event.request, responseToCache);
          });
        return response;
      })
      .catch(() => {
        // 2. 네트워크 요청 실패(오프라인) 시: 캐시에 저장된 것 사용
        return caches.match(event.request);
      })
  );
});