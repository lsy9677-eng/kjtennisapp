/*
 * 국제 테니스장 예약 앱 - Step 23 Notice Popup
 * 관리자 공지 팝업: 텍스트/이미지/기간/on-off
 * 저장 위치: Firestore settings/notice_popup, 이미지: Firebase Storage notice_popups/
 */
(function(){
  const NOTICE_DOC_PATH = ['settings', 'notice_popup'];
  const NOTICE_DISMISS_PREFIX = 'tenniskj_notice_popup_dismiss_';
  let noticePopupCheckedOnce = false;

  function todayStrLocal(){
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  }

  function escapeHtml(value){
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function safeFileName(name){
    return String(name || 'notice.jpg').replace(/[^a-zA-Z0-9._-]/g, '_').slice(-80);
  }

  function noticeVersionKey(data){
    const updatedAt = data && data.updatedAt;
    if(updatedAt && typeof updatedAt.toMillis === 'function') return String(updatedAt.toMillis());
    if(updatedAt && updatedAt.seconds) return String(updatedAt.seconds);
    return [data && data.title, data && data.text, data && data.imageUrl, data && data.startDate, data && data.endDate].join('|').replace(/\s+/g,'_').slice(0,120);
  }

  function getNoticeRef(){
    if(typeof db === 'undefined') throw new Error('Firestore가 아직 준비되지 않았습니다.');
    return db.collection(NOTICE_DOC_PATH[0]).doc(NOTICE_DOC_PATH[1]);
  }

  function isNoticeActive(data){
    if(!data || data.enabled !== true) return false;
    const today = todayStrLocal();
    const start = data.startDate || '';
    const end = data.endDate || '';
    if(start && today < start) return false;
    if(end && today > end) return false;
    if(!String(data.title || '').trim() && !String(data.text || '').trim() && !String(data.imageUrl || '').trim()) return false;
    return true;
  }

  function ensureUserNoticeModal(){
    if(document.getElementById('modalNoticePopup')) return;
    const modal = document.createElement('div');
    modal.id = 'modalNoticePopup';
    modal.className = 'modal-mask notice-popup-mask';
    modal.innerHTML = `
      <div class="modal-win notice-popup-win">
        <button type="button" class="notice-popup-close" onclick="closeNoticePopup()" aria-label="닫기">×</button>
        <div id="noticePopupBody"></div>
        <div class="notice-popup-actions">
          <button type="button" class="notice-popup-secondary" onclick="dismissNoticePopupToday()">오늘 하루 보지 않기</button>
          <button type="button" class="notice-popup-primary" onclick="closeNoticePopup()">확인</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  function renderNoticePopup(data){
    ensureUserNoticeModal();
    const body = document.getElementById('noticePopupBody');
    const title = String(data.title || '').trim();
    const text = String(data.text || '').trim();
    const imageUrl = String(data.imageUrl || '').trim();
    const linkUrl = String(data.linkUrl || '').trim();

    let html = '';
    if(title) html += `<div class="notice-popup-title">${escapeHtml(title)}</div>`;
    if(imageUrl){
      const img = `<img class="notice-popup-image" src="${escapeHtml(imageUrl)}" alt="공지 이미지">`;
      html += linkUrl ? `<a href="${escapeHtml(linkUrl)}" target="_blank" rel="noopener noreferrer">${img}</a>` : img;
    }
    if(text) html += `<div class="notice-popup-text">${escapeHtml(text).replace(/\n/g,'<br>')}</div>`;
    if(linkUrl) html += `<a class="notice-popup-link" href="${escapeHtml(linkUrl)}" target="_blank" rel="noopener noreferrer">자세히 보기</a>`;

    body.innerHTML = html || '<div class="notice-popup-text">공지 내용이 없습니다.</div>';
    window.__currentNoticePopupKey = noticeVersionKey(data);
    document.getElementById('modalNoticePopup').style.display = 'flex';
  }

  window.closeNoticePopup = function(){
    const modal = document.getElementById('modalNoticePopup');
    if(modal) modal.style.display = 'none';
  };

  window.dismissNoticePopupToday = function(){
    const key = window.__currentNoticePopupKey || 'default';
    try { localStorage.setItem(NOTICE_DISMISS_PREFIX + key, todayStrLocal()); } catch(_) {}
    window.closeNoticePopup();
  };

  async function checkNoticePopup(){
    if(noticePopupCheckedOnce) return;
    noticePopupCheckedOnce = true;
    try{
      const snap = await getNoticeRef().get();
      if(!snap.exists) return;
      const data = snap.data() || {};
      if(!isNoticeActive(data)) return;
      const key = noticeVersionKey(data);
      const dismissed = localStorage.getItem(NOTICE_DISMISS_PREFIX + key);
      if(dismissed === todayStrLocal()) return;
      renderNoticePopup(data);
    }catch(err){
      noticePopupCheckedOnce = false;
      console.warn('공지 팝업 확인 실패:', err);
    }
  }

  function ensureAdminModal(){
    if(document.getElementById('modalNoticePopupAdmin')) return;
    const modal = document.createElement('div');
    modal.id = 'modalNoticePopupAdmin';
    modal.className = 'modal-mask notice-popup-admin-mask';
    modal.innerHTML = `
      <div class="modal-win notice-popup-admin-win">
        <span class="modal-close" onclick="closeModal('modalNoticePopupAdmin')">&times;</span>
        <div class="modal-head">📢 공지 팝업 관리</div>
        <div class="notice-admin-card">
          <label class="notice-admin-toggle">
            <input type="checkbox" id="noticePopupEnabled">
            <span>팝업 사용</span>
          </label>
          <div class="notice-admin-help">설정한 기간에만 회원 화면에 자동으로 표시됩니다.</div>
        </div>
        <div class="inp-row"><label>제목</label><input type="text" id="noticePopupTitle" placeholder="예: 코트 이용 안내"></div>
        <div class="inp-row"><label>텍스트 내용</label><textarea id="noticePopupText" rows="5" placeholder="공지 내용을 입력하세요. 줄바꿈 가능"></textarea></div>
        <div class="inp-row"><label>링크 주소 선택 입력</label><input type="url" id="noticePopupLink" placeholder="https://... (선택)"></div>
        <div class="notice-admin-dates">
          <div class="inp-row"><label>시작일</label><input type="date" id="noticePopupStart"></div>
          <div class="inp-row"><label>종료일</label><input type="date" id="noticePopupEnd"></div>
        </div>
        <div class="notice-admin-card">
          <label style="font-weight:800; color:#334155; display:block; margin-bottom:8px;">이미지 공지</label>
          <input type="file" id="noticePopupImageFile" accept="image/*">
          <div id="noticePopupImagePreview" class="notice-admin-preview"></div>
          <button type="button" class="notice-admin-small danger" onclick="clearNoticePopupImage()">이미지 제거</button>
          <div class="notice-admin-help">새 이미지를 선택하면 저장 시 Firebase Storage에 업로드됩니다.</div>
        </div>
        <div class="notice-admin-actions">
          <button type="button" class="btn-full bg-gray" onclick="previewNoticePopupAdmin()">미리보기</button>
          <button type="button" class="btn-full" style="background:#ef4444;" onclick="disableNoticePopupQuick()">팝업 끄기</button>
          <button type="button" id="btnSaveNoticePopup" class="btn-full bg-blue" onclick="saveNoticePopupSettings()">저장하기</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  function setAdminPreview(imageUrl){
    const box = document.getElementById('noticePopupImagePreview');
    if(!box) return;
    if(imageUrl){
      box.innerHTML = `<img src="${escapeHtml(imageUrl)}" alt="공지 이미지 미리보기"><div class="notice-admin-help">현재 이미지가 설정되어 있습니다.</div>`;
    }else{
      box.innerHTML = '<div class="notice-admin-empty">등록된 이미지 없음</div>';
    }
  }

  let currentAdminNoticeData = {};
  let removeNoticeImageFlag = false;

  window.openNoticePopupAdmin = async function(){
    if(!isAdmin) return alert('관리자만 사용할 수 있습니다.');
    ensureAdminModal();
    removeNoticeImageFlag = false;
    document.getElementById('noticePopupImageFile').value = '';
    try{
      const snap = await getNoticeRef().get();
      currentAdminNoticeData = snap.exists ? (snap.data() || {}) : {};
      const today = todayStrLocal();
      document.getElementById('noticePopupEnabled').checked = currentAdminNoticeData.enabled === true;
      document.getElementById('noticePopupTitle').value = currentAdminNoticeData.title || '';
      document.getElementById('noticePopupText').value = currentAdminNoticeData.text || '';
      document.getElementById('noticePopupLink').value = currentAdminNoticeData.linkUrl || '';
      document.getElementById('noticePopupStart').value = currentAdminNoticeData.startDate || today;
      document.getElementById('noticePopupEnd').value = currentAdminNoticeData.endDate || today;
      setAdminPreview(currentAdminNoticeData.imageUrl || '');
    }catch(err){
      console.error(err);
      alert('공지 팝업 설정을 불러오지 못했습니다: ' + (err.message || err));
    }
    openModal('modalNoticePopupAdmin');
  };

  window.clearNoticePopupImage = function(){
    removeNoticeImageFlag = true;
    document.getElementById('noticePopupImageFile').value = '';
    setAdminPreview('');
  };

  window.previewNoticePopupAdmin = function(){
    ensureAdminModal();
    const file = document.getElementById('noticePopupImageFile').files[0];
    const data = {
      enabled: true,
      title: document.getElementById('noticePopupTitle').value,
      text: document.getElementById('noticePopupText').value,
      linkUrl: document.getElementById('noticePopupLink').value,
      imageUrl: removeNoticeImageFlag ? '' : (currentAdminNoticeData.imageUrl || ''),
      startDate: document.getElementById('noticePopupStart').value,
      endDate: document.getElementById('noticePopupEnd').value,
      updatedAt: new Date()
    };
    if(file){
      const reader = new FileReader();
      reader.onload = function(e){ data.imageUrl = e.target.result; renderNoticePopup(data); };
      reader.readAsDataURL(file);
    }else{
      renderNoticePopup(data);
    }
  };

  async function uploadNoticeImageIfNeeded(){
    const file = document.getElementById('noticePopupImageFile').files[0];
    if(!file) return null;
    if(!file.type || !file.type.startsWith('image/')) throw new Error('이미지 파일만 업로드할 수 있습니다.');
    const uploadFile = (typeof compressImage === 'function') ? await compressImage(file, 1200, 0.82) : file;
    const path = `notice_popups/${Date.now()}_${safeFileName(file.name)}`;
    const ref = storage.ref().child(path);
    await ref.put(uploadFile);
    const url = await ref.getDownloadURL();
    return { url, path };
  }

  async function deleteOldNoticeImageIfPossible(data){
    try{
      if(!data || !data.imagePath) return;
      await storage.ref().child(data.imagePath).delete();
    }catch(err){
      console.warn('기존 공지 이미지 삭제 실패:', err);
    }
  }

  window.saveNoticePopupSettings = async function(){
    if(!isAdmin) return alert('관리자만 저장할 수 있습니다.');
    const btn = document.getElementById('btnSaveNoticePopup');
    const oldText = btn ? btn.innerText : '';
    if(btn){ btn.disabled = true; btn.innerText = '저장 중...'; }
    try{
      const startDate = document.getElementById('noticePopupStart').value;
      const endDate = document.getElementById('noticePopupEnd').value;
      if(startDate && endDate && startDate > endDate) throw new Error('종료일이 시작일보다 빠를 수 없습니다.');

      const uploaded = await uploadNoticeImageIfNeeded();
      const data = {
        enabled: document.getElementById('noticePopupEnabled').checked,
        title: document.getElementById('noticePopupTitle').value.trim(),
        text: document.getElementById('noticePopupText').value.trim(),
        linkUrl: document.getElementById('noticePopupLink').value.trim(),
        startDate,
        endDate,
        updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
        updatedBy: (auth.currentUser && auth.currentUser.uid) ? auth.currentUser.uid : 'local-admin'
      };

      if(uploaded){
        data.imageUrl = uploaded.url;
        data.imagePath = uploaded.path;
        await deleteOldNoticeImageIfPossible(currentAdminNoticeData);
      }else if(removeNoticeImageFlag){
        data.imageUrl = '';
        data.imagePath = '';
        await deleteOldNoticeImageIfPossible(currentAdminNoticeData);
      }else{
        data.imageUrl = currentAdminNoticeData.imageUrl || '';
        data.imagePath = currentAdminNoticeData.imagePath || '';
      }

      if(!data.title && !data.text && !data.imageUrl) data.enabled = false;
      await getNoticeRef().set(data, { merge: true });
      currentAdminNoticeData = data;
      removeNoticeImageFlag = false;
      alert(data.enabled ? '공지 팝업이 저장되었습니다.' : '공지 팝업이 저장되었습니다. 내용이 없어 비활성화되었습니다.');
      closeModal('modalNoticePopupAdmin');
      try { localStorage.removeItem(NOTICE_DISMISS_PREFIX + 'default'); } catch(_) {}
    }catch(err){
      console.error(err);
      alert('공지 팝업 저장 실패: ' + (err.message || err));
    }finally{
      if(btn){ btn.disabled = false; btn.innerText = oldText || '저장하기'; }
    }
  };

  window.disableNoticePopupQuick = async function(){
    if(!isAdmin) return;
    if(!confirm('공지 팝업을 끄시겠습니까?')) return;
    try{
      await getNoticeRef().set({ enabled:false, updatedAt: firebase.firestore.FieldValue.serverTimestamp() }, { merge:true });
      document.getElementById('noticePopupEnabled').checked = false;
      alert('공지 팝업을 껐습니다.');
    }catch(err){
      alert('팝업 끄기 실패: ' + (err.message || err));
    }
  };

  function injectNoticePopupAdminButton(){
    if(!isAdmin) return;
    if(document.getElementById('btnNoticePopupAdmin')) return;
    const container = document.querySelector('#modalSet .modal-win');
    if(!container) return;
    const btn = document.createElement('button');
    btn.id = 'btnNoticePopupAdmin';
    btn.className = 'btn-full';
    btn.style.cssText = 'background:#7c3aed; margin-bottom:15px;';
    btn.innerHTML = '📢 공지 팝업 관리';
    btn.onclick = window.openNoticePopupAdmin;
    const target = document.getElementById('btnToggleStats') || container.querySelector('.inp-row');
    if(target && target.parentNode === container) container.insertBefore(btn, target);
    else container.appendChild(btn);
  }

  function patchOpenConf(){
    if(window.__noticePopupOpenConfPatched) return;
    if(typeof window.openConf !== 'function') return;
    const original = window.openConf;
    window.openConf = function(){
      const result = original.apply(this, arguments);
      setTimeout(injectNoticePopupAdminButton, 0);
      return result;
    };
    window.__noticePopupOpenConfPatched = true;
  }

  window.initNoticePopupFeature = function(){
    ensureUserNoticeModal();
    ensureAdminModal();
    patchOpenConf();
    setTimeout(checkNoticePopup, 550);
  };

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', window.initNoticePopupFeature);
  }else{
    window.initNoticePopupFeature();
  }
  window.addEventListener('load', function(){ setTimeout(checkNoticePopup, 900); });
})();
