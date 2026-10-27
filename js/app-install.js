/* Browser installation enhancement only; no auth, reservation, SW or cache writes. */
(function(){
    if(typeof APP_ENV!=='undefined' && APP_ENV.mode==='blocked')return;
    const dismissKey='tenniskj_install_dismissed_at_v1';
    const standalone=window.matchMedia?window.matchMedia('(display-mode: standalone)'):null;
    const ua=navigator.userAgent||'';
    const ios=/iPhone|iPad|iPod/i.test(ua)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);
    const android=/Android/i.test(ua);
    const samsung=/SamsungBrowser/i.test(ua);
    const inApp=/KAKAOTALK|FBAN|FBAV|Instagram|NAVER\(inapp/i.test(ua)||(/; wv[);]/i.test(ua)&&android);
    let deferred=null,installedThisSession=false,acceptedThisSession=false,dismissedThisSession=false,prompting=false,lastFocus=null;
    const runningAsApp=()=>installedThisSession||navigator.standalone===true||!!standalone?.matches||document.referrer.startsWith('android-app://dev.pages.tenniskj_app.twa');
    const dismissed=()=>{if(dismissedThisSession)return true;try{const at=Number(localStorage.getItem(dismissKey));return at>0&&Date.now()-at<7*86400000;}catch(_){return false;}};
    function sync(){
        const banner=document.getElementById('appInstallBanner');
        if(banner)banner.hidden=runningAsApp()||acceptedThisSession||dismissed()||(!ios&&!android&&!deferred);
        ['appInstallSettings','appInstallAdminSettings'].forEach(id=>{const settings=document.getElementById(id);if(settings)settings.hidden=runningAsApp();});
        const button=document.getElementById('btnHomeInstall');if(button)button.disabled=prompting;
    }
    window.dismissAppBanner=function(){dismissedThisSession=true;try{localStorage.setItem(dismissKey,String(Date.now()));}catch(_){}const banner=document.getElementById('appInstallBanner');if(banner)banner.hidden=true;};
    function closeGuide(){
        const modal=document.getElementById('modalAppInstall');if(!modal)return;
        modal.hidden=true;modal.style.display='none';lastFocus?.focus?.();
    }
    function openGuide(){
        let modal=document.getElementById('modalAppInstall');
        if(!modal){
            modal=document.createElement('div');modal.id='modalAppInstall';modal.className='modal-mask';modal.hidden=true;modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.setAttribute('aria-labelledby','appInstallTitle');
            modal.innerHTML='<div class="modal-win install-guide"><button type="button" class="modal-close" aria-label="설치 안내 닫기">×</button><img src="abc-192.png" alt="김해시테니스협회 로고" width="56" height="56"/><h2 id="appInstallTitle">홈 화면에 추가</h2><p id="appInstallDescription"></p><ol id="appInstallSteps"></ol><p class="install-guide-note" id="appInstallNote"></p><a id="installStoreLink" href="https://play.google.com/store/apps/details?id=dev.pages.tenniskj_app.twa" target="_blank" rel="noopener noreferrer">플레이스토어 앱으로 설치하기 ↗</a><button type="button" class="install-guide-done">확인</button></div>';
            document.body.append(modal);
            modal.querySelector('.modal-close').onclick=closeGuide;modal.querySelector('.install-guide-done').onclick=closeGuide;
            modal.addEventListener('click',event=>{if(event.target===modal)closeGuide();});
            modal.addEventListener('keydown',event=>{
                if(event.key==='Escape'){event.preventDefault();closeGuide();}
                if(event.key==='Tab'){
                    const focusable=[...modal.querySelectorAll('button,a')].filter(el=>!el.hidden&&el.getClientRects().length);
                    const first=focusable[0],last=focusable.at(-1);
                    if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
                    else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
                }
            });
        }
        let title='홈 화면에 추가',description='홈 화면에 아이콘을 추가하면 앱처럼 바로 열 수 있어요.',steps,note='브라우저 버전에 따라 메뉴 이름이 조금 다를 수 있습니다.';
        if(runningAsApp()){
            title='앱 화면으로 사용 중입니다';description='지금은 홈 화면 또는 설치된 앱에서 실행 중입니다.';steps=['다음에도 홈 화면의 김해테니스 아이콘으로 접속해 주세요.'];note='추가 설치는 필요하지 않습니다.';
        }else if(ios){
            title='아이폰·아이패드 홈 화면에 추가';
            steps=['Safari의 공유 버튼(위로 향한 화살표)을 누르세요.','목록에서 ‘홈 화면에 추가’를 선택하세요.','‘웹 앱으로 열기’가 보이면 켠 뒤 ‘추가’를 누르세요.'];
            note='자동 설치창은 제공되지 않습니다. 홈 화면에 추가한 뒤 아이콘으로 열어 주세요.';
            if(!/Safari/i.test(ua)||/CriOS|FxiOS|EdgiOS/i.test(ua)||inApp)description='이 링크를 Safari로 연 뒤 아래 순서로 추가해 주세요.';
        }else if(inApp){
            title='기본 브라우저에서 열어 주세요';steps=['현재 앱의 메뉴에서 ‘다른 브라우저로 열기’를 선택하세요.','Chrome 또는 Safari에서 이 예약 페이지를 여세요.','브라우저 메뉴에서 ‘앱 설치’ 또는 ‘홈 화면에 추가’를 선택하세요.'];
        }else if(samsung){
            steps=['삼성인터넷의 메뉴를 여세요.','‘현재 페이지 추가’에서 ‘홈 화면’을 선택하세요.','이름을 확인하고 ‘추가’를 누르세요.'];
        }else if(android){
            steps=['Chrome의 메뉴(⋮)를 여세요.','‘앱 설치’ 또는 ‘홈 화면에 추가’를 선택하세요.','브라우저가 표시하는 ‘설치’ 또는 ‘추가’를 눌러 완료하세요.'];
        }else{
            steps=['주소 표시줄의 설치 아이콘 또는 브라우저 메뉴를 여세요.','‘앱 설치’ 또는 ‘페이지를 앱으로 설치’를 선택하세요.','설치를 확인하면 앱 목록에서 바로 열 수 있습니다.'];
        }
        document.getElementById('appInstallTitle').textContent=title;document.getElementById('appInstallDescription').textContent=description;document.getElementById('appInstallNote').textContent=note;
        document.getElementById('appInstallSteps').replaceChildren(...steps.map(text=>{const li=document.createElement('li');li.textContent=text;return li;}));
        document.getElementById('installStoreLink').hidden=!android||runningAsApp();
        lastFocus=document.activeElement;modal.hidden=false;modal.style.display='flex';modal.querySelector('.modal-close').focus();
    }
    window.requestAppInstall=async function(){
        if(prompting)return;
        if(ios||inApp||runningAsApp()||!deferred){openGuide();return;}
        const event=deferred;deferred=null;prompting=true;sync();
        try{
            await event.prompt();
            const choice=await event.userChoice;
            if(choice?.outcome==='accepted'){acceptedThisSession=true;const banner=document.getElementById('appInstallBanner');if(banner)banner.hidden=true;}
            else window.dismissAppBanner();
        }catch(_){openGuide();}
        finally{prompting=false;sync();}
    };
    window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();deferred=event;sync();});
    window.addEventListener('appinstalled',()=>{installedThisSession=true;deferred=null;closeGuide();sync();});
    if(standalone?.addEventListener)standalone.addEventListener('change',sync);else if(standalone?.addListener)standalone.addListener(sync);
    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',sync);else sync();
})();
