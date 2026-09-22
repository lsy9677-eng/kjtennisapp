/* 국제 테니스장 예약 앱 - 관리자 회원 정보 관리 v1 (2026-09-22)
 * Firestore users 문서의 name / phone / email 만 수정합니다.
 * Firebase Authentication 로그인 이메일, 시민인증, 관리자권한, UID는 변경하지 않습니다.
 */
(function(){
  'use strict';
  let memberRows = [];
  let selectedMemberId = '';

  function esc(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
  function adminOk(){ try { return typeof isAdmin !== 'undefined' && isAdmin === true; } catch(_e){ return false; } }
  function modal(){ return document.getElementById('modalMemberManager'); }

  function ensureModal(){
    if(modal()) return;
    const el=document.createElement('div');
    el.id='modalMemberManager'; el.className='modal-mask';
    el.innerHTML=`<div class="modal-win" style="max-width:720px; max-height:88vh; overflow:auto;">
      <span class="modal-close" onclick="closeMemberManager()">×</span>
      <div class="modal-head">👤 회원 정보 관리</div>
      <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:10px 12px;margin-bottom:12px;font-size:.76rem;color:#9a3412;line-height:1.5;">
        이름·전화번호·Firestore 회원정보 이메일만 수정합니다. <b>로그인에 사용하는 Firebase Authentication 이메일은 변경되지 않습니다.</b>
      </div>
      <div style="display:flex;gap:7px;margin-bottom:10px;">
        <input id="memberManagerSearch" type="search" placeholder="이름 · 전화번호 · 이메일 검색" style="flex:1;padding:11px;border:1px solid #cbd5e1;border-radius:8px;" oninput="filterMemberManager()">
        <button type="button" class="btn-sm bg-blue" onclick="loadMemberManager()" style="min-width:76px;">새로고침</button>
      </div>
      <div id="memberManagerCount" style="font-size:.75rem;color:#64748b;margin-bottom:7px;"></div>
      <div id="memberManagerList" style="border:1px solid #e2e8f0;border-radius:10px;max-height:270px;overflow:auto;margin-bottom:14px;"></div>
      <div id="memberManagerEditor" style="display:none;background:#f8fafc;border:1px solid #cbd5e1;border-radius:12px;padding:14px;">
        <div style="font-weight:800;margin-bottom:10px;color:#1e293b;">선택 회원 수정</div>
        <div class="inp-row"><label>이름</label><input id="memberEditName" type="text" maxlength="40"></div>
        <div class="inp-row"><label>전화번호</label><input id="memberEditPhone" type="tel" maxlength="30"></div>
        <div class="inp-row"><label>회원정보 이메일</label><input id="memberEditEmail" type="email" maxlength="120"></div>
        <div id="memberEditMeta" style="font-size:.72rem;color:#64748b;line-height:1.55;margin:8px 0 12px;word-break:break-all;"></div>
        <button id="memberEditSaveBtn" type="button" class="btn-full bg-blue" onclick="saveMemberManagerEdit()" style="margin-top:0;">변경내용 저장</button>
      </div>
    </div>`;
    document.body.appendChild(el);
  }

  window.openMemberManager=async function(){
    if(!adminOk()) return alert('관리자만 사용할 수 있습니다.');
    ensureModal(); modal().style.display='flex';
    await window.loadMemberManager();
  };
  window.closeMemberManager=function(){ if(modal()) modal().style.display='none'; selectedMemberId=''; };

  window.loadMemberManager=async function(){
    if(!adminOk()) return;
    ensureModal();
    const list=document.getElementById('memberManagerList');
    list.innerHTML='<div style="padding:18px;text-align:center;color:#64748b;">회원 정보를 불러오는 중...</div>';
    try{
      const snap=await db.collection('users').get();
      memberRows=snap.docs.map(d=>({id:d.id,...(d.data()||{}) }));
      memberRows.sort((a,b)=>String(a.name||'').localeCompare(String(b.name||''),'ko'));
      window.filterMemberManager();
    }catch(err){ console.error(err); list.innerHTML='<div style="padding:18px;text-align:center;color:#dc2626;">불러오기 실패: '+esc(err.message||err)+'</div>'; }
  };

  window.filterMemberManager=function(){
    const q=String(document.getElementById('memberManagerSearch')?.value||'').trim().toLowerCase().replace(/\s+/g,'');
    const rows=!q?memberRows:memberRows.filter(x=>[x.name,x.phone,x.email].some(v=>String(v||'').toLowerCase().replace(/\s+/g,'').includes(q)));
    const count=document.getElementById('memberManagerCount'); if(count) count.textContent=`전체 ${memberRows.length}명 · 검색결과 ${rows.length}명`;
    const list=document.getElementById('memberManagerList'); if(!list) return;
    if(!rows.length){ list.innerHTML='<div style="padding:18px;text-align:center;color:#64748b;">검색 결과가 없습니다.</div>'; return; }
    list.innerHTML=rows.slice(0,300).map(x=>`<button type="button" onclick="selectMemberManager('${esc(x.id)}')" style="width:100%;text-align:left;border:0;border-bottom:1px solid #e2e8f0;background:white;padding:10px 12px;cursor:pointer;">
      <div style="font-weight:800;color:#0f172a;">${esc(x.name||'(이름 없음)')}</div>
      <div style="font-size:.75rem;color:#64748b;margin-top:3px;">${esc(x.phone||'-')} · ${esc(x.email||'-')}</div>
    </button>`).join('')+(rows.length>300?'<div style="padding:9px;text-align:center;font-size:.72rem;color:#64748b;">검색 결과가 많아 300명까지만 표시합니다. 검색어를 입력하세요.</div>':'');
  };

  window.selectMemberManager=function(id){
    const x=memberRows.find(r=>r.id===id); if(!x) return;
    selectedMemberId=id;
    document.getElementById('memberEditName').value=x.name||'';
    document.getElementById('memberEditPhone').value=x.phone||'';
    document.getElementById('memberEditEmail').value=x.email||'';
    document.getElementById('memberEditMeta').innerHTML=`UID: ${esc(id)}<br>시민인증: ${x.isCitizen===true?'인증':'미인증'} · 관리자 필드: ${x.isAdmin===true?'true':'false'}<br><b>UID·시민인증·관리자 권한은 이 화면에서 변경하지 않습니다.</b>`;
    document.getElementById('memberManagerEditor').style.display='block';
    document.getElementById('memberManagerEditor').scrollIntoView({behavior:'smooth',block:'nearest'});
  };

  window.saveMemberManagerEdit=async function(){
    if(!adminOk()) return alert('관리자만 사용할 수 있습니다.');
    const old=memberRows.find(r=>r.id===selectedMemberId); if(!old) return alert('수정할 회원을 먼저 선택해주세요.');
    const next={
      name:String(document.getElementById('memberEditName').value||'').trim(),
      phone:String(document.getElementById('memberEditPhone').value||'').trim(),
      email:String(document.getElementById('memberEditEmail').value||'').trim()
    };
    if(!next.name) return alert('이름을 입력해주세요.');
    if(next.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(next.email)) return alert('이메일 형식을 확인해주세요.');
    const changes=[];
    ['name','phone','email'].forEach(k=>{ if(String(old[k]||'')!==next[k]) changes.push(`${k==='name'?'이름':k==='phone'?'전화번호':'이메일'}: ${old[k]||'(없음)'} → ${next[k]||'(없음)'}`); });
    if(!changes.length) return alert('변경된 내용이 없습니다.');
    if(!confirm(`${old.name||'선택 회원'} 회원의 정보를 수정하시겠습니까?\n\n${changes.join('\n')}\n\n※ 로그인 계정 이메일은 변경되지 않습니다.`)) return;
    const btn=document.getElementById('memberEditSaveBtn'); const prev=btn.innerText; btn.disabled=true; btn.innerText='저장 중...';
    try{
      await db.collection('users').doc(selectedMemberId).set({...next, profileUpdatedAt:firebase.firestore.FieldValue.serverTimestamp(), profileUpdatedBy:'admin'}, {merge:true});
      Object.assign(old,next);
      try{ if(typeof currentUser!=='undefined' && currentUser && currentUser.uid===selectedMemberId) Object.assign(currentUser,next); }catch(_e){}
      alert('회원 정보가 수정되었습니다.');
      window.filterMemberManager();
    }catch(err){ console.error(err); alert('회원 정보 수정 실패: '+(err.message||err)); }
    finally{ btn.disabled=false; btn.innerText=prev; }
  };
})();
