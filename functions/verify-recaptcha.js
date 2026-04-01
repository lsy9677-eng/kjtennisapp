// Cloudflare Pages Function
// 파일 위치: /functions/verify-recaptcha.js
// 역할: 브라우저에서 받은 reCAPTCHA 토큰을 Google 서버에서 서버 검증

export async function onRequestPost(context) {
    try {
        const body = await context.request.json();
        const token = body.token;

        if (!token) {
            return new Response(JSON.stringify({ success: false, error: 'token_missing' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }

        // Google reCAPTCHA 서버 검증
        // 비밀 키는 Cloudflare Pages 환경변수 RECAPTCHA_SECRET 에 저장
        const secret = context.env.RECAPTCHA_SECRET;

        const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${secret}&response=${token}`
        });

        const result = await verifyRes.json();

        if (result.success) {
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        } else {
            return new Response(JSON.stringify({ success: false, codes: result['error-codes'] }), {
                status: 200,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
    } catch (e) {
        return new Response(JSON.stringify({ success: false, error: e.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

// CORS preflight 처리
export async function onRequestOptions() {
    return new Response(null, {
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        }
    });
}
