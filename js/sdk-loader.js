/* Parser-blocking SDK loading preserves legacy script order without speculative external downloads. */
(function () {
    if (APP_ENV.mode === 'blocked') return;
    const dev = APP_ENV.isDevelopment;
    const sources = dev ? [
        '/vendor/firebase-app-compat.js', '/vendor/firebase-auth-compat.js',
        '/vendor/firebase-firestore-compat.js', '/vendor/firebase-storage-compat.js', '/vendor/chart.umd.js'
    ] : [
        'https://cdn.iamport.kr/v1/iamport.js',
        'https://www.gstatic.com/firebasejs/9.6.1/firebase-app-compat.js',
        'https://www.gstatic.com/firebasejs/9.6.1/firebase-auth-compat.js',
        'https://www.gstatic.com/firebasejs/9.6.1/firebase-firestore-compat.js',
        'https://www.gstatic.com/firebasejs/9.6.1/firebase-storage-compat.js',
        'https://t1.kakaocdn.net/kakao_js_sdk/2.7.0/kakao.min.js',
        'https://cdn.jsdelivr.net/npm/chart.js'
    ];
    for (const src of sources) document.write('<script src="' + src + '"><\/script>');
    if (!dev) document.write('<script async defer src="https://www.google.com/recaptcha/api.js"><\/script><link rel="stylesheet" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.8/dist/web/static/pretendard.css">');
}());
