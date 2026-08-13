/*
 * 국제 테니스장 예약 앱 - Step 23 Notice Popup
 * 관리자 공지 팝업: 텍스트/이미지/기간/on-off
 * 저장 위치: Firestore settings/notice_popup, 이미지: Firebase Storage notice_popups/
 */
(function(){
  const NOTICE_DOC_PATH = ['settings', 'notice_popup'];
  const NOTICE_DISMISS_PREFIX = 'tenniskj_notice_popup_dismiss_';
  const COURT_TIME_POPUP_DOC_PATH = ['settings', 'court_time_popups'];
  let noticePopupCheckedOnce = false;
  let courtTimePopupRules = [];
  let courtTimePopupLoadedAt = 0;
  const COURT_TIME_POPUP_TTL = 5 * 60 * 1000;

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

  function getCourtTimePopupRef(){
    if(typeof db === 'undefined') throw new Error('Firestore가 아직 준비되지 않았습니다.');
    return db.collection(COURT_TIME_POPUP_DOC_PATH[0]).doc(COURT_TIME_POPUP_DOC_PATH[1]);
  }

  function normalizeCourtTimeRule(rule){
    const r = rule || {};
    return {
      id: String(r.id || ''),
      enabled: r.enabled !== false,
      center: String(r.center || '국제'),
      courts: Array.isArray(r.courts) ? r.courts.map(Number).filter(Number.isFinite) : [],
      times: Array.isArray(r.times) ? r.times.map(Number).filter(Number.isFinite) : [],
      startDate: String(r.startDate || ''),
      endDate: String(r.endDate || ''),
      title: String(r.title || ''),
      text: String(r.text || '')
    };
  }

  async function loadCourtTimePopupRules(force){
    const now = Date.now();
    if(!force && courtTimePopupLoadedAt && (now - courtTimePopupLoadedAt < COURT_TIME_POPUP_TTL)) return courtTimePopupRules;
    try{
      const snap = await getCourtTimePopupRef().get();
      const data = snap.exists ? (snap.data() || {}) : {};
      courtTimePopupRules = Array.isArray(data.rules) ? data.rules.map(normalizeCourtTimeRule) : [];
      courtTimePopupLoadedAt = now;
    }catch(err){
      console.warn('코트(시간)별 팝업 설정 불러오기 실패:', err);
    }
    return courtTimePopupRules;
  }

  function findCourtTimePopupRule(ctx){
    const date = String(ctx.date || '');
    const center = String(ctx.center || '국제');
    const court = Number(ctx.court);
    const time = Number(ctx.time);
    return courtTimePopupRules.find(rule => {
      if(!rule.enabled) return false;
      if(rule.center && rule.center !== center) return false;
      if(rule.startDate && date < rule.startDate) return false;
      if(rule.endDate && date > rule.endDate) return false;
      if(rule.courts.length && !rule.courts.includes(court)) return false;
      if(rule.times.length && !rule.times.includes(time)) return false;
      return !!(rule.title.trim() || rule.text.trim());
    }) || null;
  }

  function ensureCourtTimeUserModal(){
    if(document.getElementById('modalCourtTimeNotice')) return;
    const modal = document.createElement('div');
    modal.id = 'modalCourtTimeNotice';
    modal.className = 'modal-mask';
    modal.innerHTML = `
      <div class="modal-win" style="max-width:420px;">
        <span class="modal-close" onclick="closeCourtTimePopupNotice()">&times;</span>
        <div class="modal-head" id="courtTimeNoticeTitle">🎾 코트 이용 안내</div>
        <div id="courtTimeNoticeMeta" style="background:#eff6ff; border:1px solid #bfdbfe; color:#1e40af; padding:9px 11px; border-radius:10px; font-size:.82rem; font-weight:800; margin-bottom:12px;"></div>
        <div id="courtTimeNoticeText" style="white-space:pre-wrap; line-height:1.65; color:#334155; font-size:.95rem; background:#f8fafc; border:1px solid #e2e8f0; padding:14px; border-radius:12px;"></div>
        <button type="button" class="btn-full bg-blue" style="margin-top:15px;" onclick="confirmCourtTimePopupNotice()">확인하고 선택</button>
      </div>`;
    document.body.appendChild(modal);
  }

  let pendingCourtTimeContinue = null;
  window.closeCourtTimePopupNotice = function(){
    const modal = document.getElementById('modalCourtTimeNotice');
    if(modal) modal.style.display = 'none';
    pendingCourtTimeContinue = null;
  };

  window.confirmCourtTimePopupNotice = function(){
    const cb = pendingCourtTimeContinue;
    pendingCourtTimeContinue = null;
    const modal = document.getElementById('modalCourtTimeNotice');
    if(modal) modal.style.display = 'none';
    if(typeof cb === 'function') setTimeout(cb, 0);
  };

  window.maybeShowCourtTimePopup = function(ctx, continueFn){
    const key = `${ctx.center || ''}|${ctx.date || ''}|${ctx.court}|${ctx.time}`;
    if(window.__courtTimePopupSkipOnce === key){
      window.__courtTimePopupSkipOnce = '';
      return false;
    }
    const rule = findCourtTimePopupRule(ctx || {});
    if(!rule) return false;
    ensureCourtTimeUserModal();
    const titleEl = document.getElementById('courtTimeNoticeTitle');
    const metaEl = document.getElementById('courtTimeNoticeMeta');
    const textEl = document.getElementById('courtTimeNoticeText');
    if(titleEl) titleEl.textContent = rule.title.trim() || '🎾 코트 이용 안내';
    if(metaEl) metaEl.textContent = `${ctx.date} · ${ctx.court}코트 · ${String(ctx.time).padStart(2,'0')}:00~${String(Number(ctx.time)+1).padStart(2,'0')}:00`;
    if(textEl) textEl.textContent = rule.text.trim() || '해당 코트 이용 안내를 확인해 주세요.';
    pendingCourtTimeContinue = function(){
      window.__courtTimePopupSkipOnce = key;
      if(typeof continueFn === 'function') continueFn();
    };
    const modal = document.getElementById('modalCourtTimeNotice');
    if(modal) modal.style.display = 'flex';
    return true;
  };

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

  function renderNoticePopup(data, options = {}){
    ensureUserNoticeModal();
    const modal = document.getElementById('modalNoticePopup');
    if(modal){
      modal.classList.toggle('notice-popup-preview-mask', options.preview === true);
    }
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
    if(modal) modal.style.display = 'flex';
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
        <button type="button" class="btn-full" style="background:#0f766e; margin-top:8px;" onclick="openCourtTimePopupAdmin()">🎾 코트(시간)별 팝업 설정</button>
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
      reader.onload = function(e){ data.imageUrl = e.target.result; renderNoticePopup(data, { preview: true }); };
      reader.readAsDataURL(file);
    }else{
      renderNoticePopup(data, { preview: true });
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

  let editingCourtTimeRuleId = '';

  function ensureCourtTimeAdminModal(){
    if(document.getElementById('modalCourtTimePopupAdmin')) return;
    const modal = document.createElement('div');
    modal.id = 'modalCourtTimePopupAdmin';
    modal.className = 'modal-mask';
    modal.innerHTML = `
      <div class="modal-win" style="max-width:520px; max-height:90vh; overflow-y:auto;">
        <span class="modal-close" onclick="closeModal('modalCourtTimePopupAdmin')">&times;</span>
        <div class="modal-head">🎾 코트(시간)별 팝업 설정</div>
        <div style="background:#ecfeff; border:1px solid #a5f3fc; padding:11px; border-radius:10px; color:#155e75; font-size:.82rem; line-height:1.5; margin-bottom:14px;">설정한 기간·코트·시간의 빈 예약칸을 회원이 직접 클릭할 때만 안내 팝업이 표시됩니다.</div>
        <div class="inp-row"><label>적용 지점</label><select id="courtTimePopupCenter" style="width:100%; padding:12px; border:1px solid #cbd5e1; border-radius:10px;"></select></div>
        <div class="notice-admin-card"><label style="font-weight:800; display:block; margin-bottom:8px;">적용 코트</label><div id="courtTimePopupCourts" style="display:flex; flex-wrap:wrap; gap:8px;"></div></div>
        <div class="notice-admin-card"><label style="font-weight:800; display:block; margin-bottom:8px;">적용 시간</label><div id="courtTimePopupTimes" style="display:grid; grid-template-columns:repeat(4,1fr); gap:6px;"></div></div>
        <div class="notice-admin-dates">
          <div class="inp-row"><label>시작일</label><input type="date" id="courtTimePopupStart"></div>
          <div class="inp-row"><label>종료일</label><input type="date" id="courtTimePopupEnd"></div>
        </div>
        <div class="inp-row"><label>팝업 제목</label><input type="text" id="courtTimePopupTitle" placeholder="예: 대회 준비로 이용 제한 안내"></div>
        <div class="inp-row"><label>팝업 내용</label><textarea id="courtTimePopupText" rows="5" placeholder="해당 코트/시간을 클릭했을 때 보여줄 내용을 입력하세요."></textarea></div>
        <label style="display:flex; align-items:center; gap:8px; font-size:.9rem; font-weight:800; margin:6px 0 12px;"><input type="checkbox" id="courtTimePopupEnabled" checked style="width:19px; height:19px;"> 사용</label>
        <div style="display:flex; gap:8px;">
          <button type="button" class="btn-full bg-gray" onclick="resetCourtTimePopupForm()" style="margin-top:0;">새 설정</button>
          <button type="button" class="btn-full bg-blue" id="btnSaveCourtTimePopup" onclick="saveCourtTimePopupRule()" style="margin-top:0;">추가 저장</button>
        </div>
        <div style="border-top:1px solid #e2e8f0; margin:18px 0 12px;"></div>
        <div style="font-weight:900; margin-bottom:8px; color:#334155;">등록된 설정</div>
        <div id="courtTimePopupRuleList"></div>
      </div>`;
    document.body.appendChild(modal);
  }

  function buildCourtTimeAdminChoices(center){
    const courtBox = document.getElementById('courtTimePopupCourts');
    const timeBox = document.getElementById('courtTimePopupTimes');
    const centerSel = document.getElementById('courtTimePopupCenter');
    if(centerSel){
      const centers = (typeof CENTERS === 'object' && CENTERS) ? Object.keys(CENTERS) : ['국제'];
      centerSel.innerHTML = centers.map(k => `<option value="${escapeHtml(k)}">${escapeHtml((CENTERS[k] && CENTERS[k].name) || k)}</option>`).join('');
      centerSel.value = centers.includes(center) ? center : centers[0];
    }
    const selectedCenter = centerSel ? centerSel.value : (center || '국제');
    const maxCourts = (typeof CENTERS === 'object' && CENTERS[selectedCenter] && CENTERS[selectedCenter].courts) ? Number(CENTERS[selectedCenter].courts) : 8;
    if(courtBox) courtBox.innerHTML = Array.from({length:maxCourts}, (_,i) => `<label style="display:flex; align-items:center; gap:4px; border:1px solid #cbd5e1; border-radius:8px; padding:6px 9px; background:#fff;"><input type="checkbox" class="court-time-popup-court" value="${i+1}">${i+1}코트</label>`).join('');
    if(timeBox) timeBox.innerHTML = Array.from({length:16}, (_,i) => i+6).map(t => `<label style="display:flex; align-items:center; gap:4px; border:1px solid #cbd5e1; border-radius:7px; padding:6px; font-size:.78rem; background:#fff;"><input type="checkbox" class="court-time-popup-time" value="${t}">${String(t).padStart(2,'0')}~${String(t+1).padStart(2,'0')}</label>`).join('');
    if(centerSel && !centerSel.__courtTimeBound){
      centerSel.addEventListener('change', function(){ buildCourtTimeAdminChoices(this.value); });
      centerSel.__courtTimeBound = true;
    }
  }

  function renderCourtTimeRuleList(){
    const box = document.getElementById('courtTimePopupRuleList');
    if(!box) return;
    if(!courtTimePopupRules.length){ box.innerHTML = '<div style="padding:15px; text-align:center; color:#94a3b8; background:#f8fafc; border-radius:10px;">등록된 설정이 없습니다.</div>'; return; }
    box.innerHTML = courtTimePopupRules.map(rule => {
      const courts = rule.courts.length ? rule.courts.join(', ') + '코트' : '전체 코트';
      const times = rule.times.length ? rule.times.map(t => `${String(t).padStart(2,'0')}~${String(t+1).padStart(2,'0')}`).join(', ') : '전체 시간';
      const period = `${rule.startDate || '제한없음'} ~ ${rule.endDate || '제한없음'}`;
      return `<div style="border:1px solid #e2e8f0; border-radius:11px; padding:11px; margin-bottom:8px; background:${rule.enabled ? '#fff' : '#f8fafc'}; opacity:${rule.enabled ? '1' : '.65'};">
        <div style="display:flex; justify-content:space-between; gap:8px; align-items:flex-start;"><div><b>${escapeHtml(rule.title || '제목 없음')}</b><div style="font-size:.75rem; color:#64748b; margin-top:4px;">${escapeHtml(rule.center)} · ${escapeHtml(courts)}<br>${escapeHtml(times)}<br>${escapeHtml(period)}</div></div><span style="font-size:.72rem; font-weight:900; color:${rule.enabled ? '#059669' : '#94a3b8'};">${rule.enabled ? 'ON' : 'OFF'}</span></div>
        <div style="display:flex; gap:6px; margin-top:9px;"><button type="button" class="notice-admin-small" onclick="editCourtTimePopupRule('${escapeHtml(rule.id)}')">수정</button><button type="button" class="notice-admin-small danger" onclick="deleteCourtTimePopupRule('${escapeHtml(rule.id)}')">삭제</button></div>
      </div>`;
    }).join('');
  }

  window.resetCourtTimePopupForm = function(){
    editingCourtTimeRuleId = '';
    const today = todayStrLocal();
    buildCourtTimeAdminChoices((typeof currentCenter !== 'undefined' && currentCenter) ? currentCenter : '국제');
    document.getElementById('courtTimePopupStart').value = today;
    document.getElementById('courtTimePopupEnd').value = today;
    document.getElementById('courtTimePopupTitle').value = '';
    document.getElementById('courtTimePopupText').value = '';
    document.getElementById('courtTimePopupEnabled').checked = true;
    const btn = document.getElementById('btnSaveCourtTimePopup'); if(btn) btn.innerText = '추가 저장';
  };

  window.openCourtTimePopupAdmin = async function(){
    if(!isAdmin) return alert('관리자만 사용할 수 있습니다.');
    ensureCourtTimeAdminModal();
    await loadCourtTimePopupRules(true);
    window.resetCourtTimePopupForm();
    renderCourtTimeRuleList();
    closeModal('modalNoticePopupAdmin');
    openModal('modalCourtTimePopupAdmin');
  };

  window.editCourtTimePopupRule = function(id){
    const rule = courtTimePopupRules.find(r => r.id === id); if(!rule) return;
    editingCourtTimeRuleId = id;
    buildCourtTimeAdminChoices(rule.center || '국제');
    document.getElementById('courtTimePopupCenter').value = rule.center || '국제';
    buildCourtTimeAdminChoices(rule.center || '국제');
    document.querySelectorAll('.court-time-popup-court').forEach(el => el.checked = rule.courts.includes(Number(el.value)));
    document.querySelectorAll('.court-time-popup-time').forEach(el => el.checked = rule.times.includes(Number(el.value)));
    document.getElementById('courtTimePopupStart').value = rule.startDate || '';
    document.getElementById('courtTimePopupEnd').value = rule.endDate || '';
    document.getElementById('courtTimePopupTitle').value = rule.title || '';
    document.getElementById('courtTimePopupText').value = rule.text || '';
    document.getElementById('courtTimePopupEnabled').checked = rule.enabled !== false;
    const btn = document.getElementById('btnSaveCourtTimePopup'); if(btn) btn.innerText = '수정 저장';
    const modal = document.getElementById('modalCourtTimePopupAdmin'); if(modal) modal.scrollTop = 0;
  };

  window.saveCourtTimePopupRule = async function(){
    if(!isAdmin) return;
    const courts = Array.from(document.querySelectorAll('.court-time-popup-court:checked')).map(el => Number(el.value));
    const times = Array.from(document.querySelectorAll('.court-time-popup-time:checked')).map(el => Number(el.value));
    const startDate = document.getElementById('courtTimePopupStart').value;
    const endDate = document.getElementById('courtTimePopupEnd').value;
    const title = document.getElementById('courtTimePopupTitle').value.trim();
    const text = document.getElementById('courtTimePopupText').value.trim();
    if(!courts.length) return alert('적용할 코트를 1개 이상 선택해주세요.');
    if(!times.length) return alert('적용할 시간을 1개 이상 선택해주세요.');
    if(startDate && endDate && startDate > endDate) return alert('종료일이 시작일보다 빠를 수 없습니다.');
    if(!title && !text) return alert('팝업 제목 또는 내용을 입력해주세요.');
    const id = editingCourtTimeRuleId || `ctp_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;
    const rule = normalizeCourtTimeRule({ id, enabled:document.getElementById('courtTimePopupEnabled').checked, center:document.getElementById('courtTimePopupCenter').value || '국제', courts, times, startDate, endDate, title, text });
    const idx = courtTimePopupRules.findIndex(r => r.id === id);
    if(idx >= 0) courtTimePopupRules[idx] = rule; else courtTimePopupRules.push(rule);
    const btn = document.getElementById('btnSaveCourtTimePopup'); const old = btn ? btn.innerText : '';
    try{
      if(btn){ btn.disabled = true; btn.innerText = '저장 중...'; }
      await getCourtTimePopupRef().set({ rules:courtTimePopupRules, updatedAt:firebase.firestore.FieldValue.serverTimestamp(), updatedBy:(auth.currentUser && auth.currentUser.uid) ? auth.currentUser.uid : 'local-admin' }, { merge:true });
      courtTimePopupLoadedAt = Date.now();
      editingCourtTimeRuleId = '';
      renderCourtTimeRuleList();
      window.resetCourtTimePopupForm();
      alert('코트(시간)별 팝업 설정이 저장되었습니다.');
    }catch(err){ console.error(err); alert('저장 실패: ' + (err.message || err)); }
    finally{ if(btn){ btn.disabled = false; btn.innerText = old || '추가 저장'; } }
  };

  window.deleteCourtTimePopupRule = async function(id){
    if(!isAdmin) return;
    const rule = courtTimePopupRules.find(r => r.id === id);
    if(!rule || !confirm(`“${rule.title || '이 설정'}”을 삭제하시겠습니까?`)) return;
    const next = courtTimePopupRules.filter(r => r.id !== id);
    try{
      await getCourtTimePopupRef().set({ rules:next, updatedAt:firebase.firestore.FieldValue.serverTimestamp(), updatedBy:(auth.currentUser && auth.currentUser.uid) ? auth.currentUser.uid : 'local-admin' }, { merge:true });
      courtTimePopupRules = next; courtTimePopupLoadedAt = Date.now();
      if(editingCourtTimeRuleId === id) window.resetCourtTimePopupForm();
      renderCourtTimeRuleList();
    }catch(err){ alert('삭제 실패: ' + (err.message || err)); }
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
    ensureCourtTimeUserModal();
    ensureCourtTimeAdminModal();
    loadCourtTimePopupRules(false);
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
