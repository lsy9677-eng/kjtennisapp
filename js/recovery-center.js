/*
 * 국제테니스장 데이터 복구센터 v1
 * - 신규 Firestore 컬렉션을 만들지 않고 기존 settings 문서에 복구점을 분할 저장합니다.
 * - 현재 Firestore 규칙(settings: 관리자 write)과 호환됩니다.
 * - 자동 복구점: 관리자 예약/정기예약 삭제·변경 직전
 * - 수동 복구점: reservations / recurring / slot_locks / settings(global)
 */
(function(){
  'use strict';

  const META_PREFIX = 'recovery_meta_';
  const CHUNK_PREFIX = 'recovery_chunk_';
  const CHUNK_SIZE = 20;
  const MAX_VISIBLE_POINTS = 30;
  let recoveryBusy = false;

  function nowId(){
    const d = new Date();
    const pad = n => String(n).padStart(2,'0');
    return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}_${Math.random().toString(36).slice(2,7)}`;
  }

  function esc(v){
    return String(v == null ? '' : v)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }

  function actorInfo(){
    return {
      actorUid: (typeof auth !== 'undefined' && auth.currentUser) ? auth.currentUser.uid : '',
      actorName: (typeof currentUser !== 'undefined' && currentUser && currentUser.name) ? currentUser.name : ((typeof isAdmin !== 'undefined' && isAdmin) ? '관리자' : '')
    };
  }

  function normalizeItem(item){
    if(!item || !item.collection || !item.docId) return null;
    return {
      collection: String(item.collection),
      docId: String(item.docId),
      exists: item.exists !== false,
      data: item.exists === false ? null : (item.data || {})
    };
  }

  async function writeRecoveryPoint(label, operation, items, extra){
    if(typeof isAdmin !== 'undefined' && !isAdmin) return null;
    if(!items || !items.length) return null;

    const dedup = new Map();
    items.map(normalizeItem).filter(Boolean).forEach(item => {
      dedup.set(`${item.collection}/${item.docId}`, item);
    });
    const cleanItems = Array.from(dedup.values());
    if(!cleanItems.length) return null;

    const recoveryId = nowId();
    const chunks = [];
    for(let i=0;i<cleanItems.length;i+=CHUNK_SIZE) chunks.push(cleanItems.slice(i,i+CHUNK_SIZE));

    // chunk를 먼저 저장하고 마지막에 meta를 저장해야 불완전한 복구점이 목록에 보이지 않습니다.
    for(let i=0;i<chunks.length;i++){
      const ref = db.collection('recovery_chunks').doc(`${CHUNK_PREFIX}${recoveryId}_${String(i).padStart(3,'0')}`);
      await ref.set({
        recoveryType:'chunk', recoveryId, chunkIndex:i,
        items:chunks[i], createdAt:new Date(), createdAtMs:Date.now()
      });
    }

    const actor = actorInfo();
    const meta = {
      recoveryType:'meta', recoveryId,
      label: label || '자동 복구점',
      operation: operation || 'AUTO',
      createdAt:new Date(), createdAtMs:Date.now(),
      itemCount:cleanItems.length, chunkCount:chunks.length,
      center:(typeof currentCenter !== 'undefined' ? currentCenter : ''),
      status:'ACTIVE',
      ...actor,
      ...(extra || {})
    };
    await db.collection('recovery_points').doc(`${META_PREFIX}${recoveryId}`).set(meta);
    return recoveryId;
  }

  async function docsToItems(collectionName, docs){
    const items=[];
    for(const doc of (docs || [])){
      if(!doc) continue;
      if(doc.exists) items.push({collection:collectionName, docId:doc.id, exists:true, data:doc.data()});
      else items.push({collection:collectionName, docId:doc.id, exists:false, data:null});
    }
    return items;
  }

  async function getDocsByIds(collectionName, ids){
    const uniq=[...new Set((ids||[]).filter(Boolean))];
    return Promise.all(uniq.map(id=>db.collection(collectionName).doc(id).get()));
  }

  async function backupReservationIds(ids, label, operation){
    if(typeof isAdmin !== 'undefined' && !isAdmin) return null;
    if(window.__RECOVERY_RESTORING__) return null;
    const docs=await getDocsByIds('reservations',ids);
    let items=await docsToItems('reservations',docs.filter(d=>d.exists));

    // 예약과 슬롯 잠금은 항상 한 묶음으로 보관합니다.
    if(typeof slotLocksEnabled === 'undefined' || slotLocksEnabled){
      const lockIds=[];
      docs.forEach(doc=>{
        if(!doc.exists) return;
        const d=doc.data()||{};
        if(d.date == null || d.court == null || d.time == null) return;
        if(typeof buildSlotLockId === 'function') lockIds.push(buildSlotLockId(d.center || (typeof currentCenter!=='undefined'?currentCenter:''), d.date, d.court, d.time));
      });
      if(lockIds.length){
        const lockDocs=await getDocsByIds('slot_locks',lockIds);
        items=items.concat(await docsToItems('slot_locks',lockDocs));
      }
    }
    if(!items.length) return null;
    return writeRecoveryPoint(label || `예약 ${ids.length}건 삭제 전`, operation || 'RESERVATION_DELETE', items);
  }

  async function backupCollectionIds(collectionName, ids, label, operation){
    if(typeof isAdmin !== 'undefined' && !isAdmin) return null;
    if(window.__RECOVERY_RESTORING__) return null;
    const docs=await getDocsByIds(collectionName,ids);
    const items=await docsToItems(collectionName,docs.filter(d=>d.exists));
    if(!items.length) return null;
    return writeRecoveryPoint(label || `${collectionName} 변경 전`, operation || 'CHANGE', items);
  }

  async function backupSnapshots(collectionName, docs, label, operation){
    if(typeof isAdmin !== 'undefined' && !isAdmin) return null;
    if(window.__RECOVERY_RESTORING__) return null;
    const items=await docsToItems(collectionName,(docs||[]).filter(d=>d && d.exists));
    if(!items.length) return null;
    return writeRecoveryPoint(label || `${collectionName} 변경 전`, operation || 'CHANGE', items);
  }

  async function createManualRecoveryPoint(){
    if(!isAdmin) return alert('관리자만 사용할 수 있습니다.');
    if(recoveryBusy) return;
    if(!confirm('현재 예약 운영 상태의 복구점을 만들까요?\n\n예약, 정기예약, 슬롯잠금, 전역 설정을 저장합니다.')) return;
    recoveryBusy=true;
    const btn=document.getElementById('btnCreateRecoveryPoint');
    const old=btn?btn.innerText:'';
    if(btn){btn.disabled=true;btn.innerText='복구점 생성 중...';}
    try{
      const collections=['reservations','recurring'];
      if (typeof slotLocksEnabled !== 'undefined' && slotLocksEnabled) collections.push('slot_locks');
      let items=[];
      for(const col of collections){
        const snap=await db.collection(col).get();
        items=items.concat(await docsToItems(col,snap.docs));
      }
      const globalDoc=await db.collection('settings').doc('global').get();
      if(globalDoc.exists) items.push({collection:'settings',docId:'global',exists:true,data:globalDoc.data()});
      const id=await writeRecoveryPoint('수동 전체 예약 복구점','MANUAL_SNAPSHOT',items,{manual:true});
      alert(`✅ 복구점을 만들었습니다.\n저장 항목: ${items.length}건\n복구점 ID: ${id}`);
      await loadRecoveryPoints();
    }catch(err){
      console.error(err);
      alert('복구점 생성 실패: '+err.message);
    }finally{
      recoveryBusy=false;
      if(btn){btn.disabled=false;btn.innerText=old||'현재 복구점 만들기';}
    }
  }

  async function getRecoveryMetaList(){
    const snap=await db.collection('recovery_points').get();
    const rows=[];
    snap.forEach(doc=>{
      const d=doc.data()||{};
      if(d.recoveryType==='meta' && d.recoveryId && d.status!=='DELETED') rows.push({id:doc.id,...d});
    });
    rows.sort((a,b)=>(b.createdAtMs||0)-(a.createdAtMs||0));
    return rows.slice(0,MAX_VISIBLE_POINTS);
  }

  function fmtDate(ms){
    if(!ms) return '-';
    try{return new Date(ms).toLocaleString('ko-KR',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch(e){return '-';}
  }

  async function loadRecoveryItems(recoveryId, chunkCount){
    const items=[];
    for(let i=0;i<(chunkCount||0);i++){
      const id=`${CHUNK_PREFIX}${recoveryId}_${String(i).padStart(3,'0')}`;
      const doc=await db.collection('recovery_chunks').doc(id).get();
      if(!doc.exists) throw new Error(`복구 데이터 조각 ${i+1}이 없습니다.`);
      const d=doc.data()||{};
      (d.items||[]).forEach(x=>items.push(x));
    }
    return items;
  }

  async function previewRecovery(recoveryId){
    const metaDoc=await db.collection('recovery_points').doc(`${META_PREFIX}${recoveryId}`).get();
    if(!metaDoc.exists) throw new Error('복구점 정보를 찾을 수 없습니다.');
    const meta=metaDoc.data()||{};
    const items=await loadRecoveryItems(recoveryId,meta.chunkCount||0);
    let missing=0, existing=0, absentState=0;
    const current=await Promise.all(items.map(x=>db.collection(x.collection).doc(x.docId).get()));
    current.forEach((doc,i)=>{
      const item=items[i];
      if(item.exists===false){absentState++; return;}
      if(doc.exists) existing++; else missing++;
    });
    return {meta,items,current,missing,existing,absentState};
  }

  async function makeRollbackPointForExact(preview){
    const items=[];
    preview.items.forEach((item,i)=>{
      const cur=preview.current[i];
      items.push({collection:item.collection,docId:item.docId,exists:cur.exists,data:cur.exists?cur.data():null});
    });
    return writeRecoveryPoint(`복구 실행 직전 자동 안전점 - ${preview.meta.label||''}`,'BEFORE_RESTORE',items,{sourceRecoveryId:preview.meta.recoveryId});
  }

  async function applyRecoveryItems(items, mode){
    let restored=0, skipped=0, deleted=0;
    window.__RECOVERY_RESTORING__=true;
    try{
      // Firestore batch 500 제한보다 충분히 낮게 나눕니다.
      for(let start=0;start<items.length;start+=180){
        const slice=items.slice(start,start+180);
        const refs=slice.map(x=>db.collection(x.collection).doc(x.docId));
        const current=await Promise.all(refs.map(r=>r.get()));
        const batch=db.batch();
        let writes=0;
        slice.forEach((item,i)=>{
          const ref=refs[i], cur=current[i];
          if(mode==='SAFE'){
            if(item.exists===false || cur.exists){skipped++;return;}
            batch.set(ref,item.data||{}); writes++; restored++;
          }else{
            if(item.exists===false){
              if(cur.exists){batch.delete(ref);writes++;deleted++;} else skipped++;
            }else{
              batch.set(ref,item.data||{});writes++;restored++;
            }
          }
        });
        if(writes) await batch.commit();
      }
    } finally {
      window.__RECOVERY_RESTORING__=false;
    }
    return {restored,skipped,deleted};
  }

  async function restoreRecoveryPoint(recoveryId, mode){
    if(!isAdmin) return alert('관리자만 사용할 수 있습니다.');
    if(recoveryBusy) return;
    recoveryBusy=true;
    try{
      const p=await previewRecovery(recoveryId);
      const label=p.meta.label||'복구점';
      if(mode==='SAFE'){
        const msg=`[안전 복구]\n${label}\n\n삭제되어 현재 없는 문서만 되살립니다.\n복구 대상(현재 없음): ${p.missing}건\n현재 존재하여 건너뜀: ${p.existing}건\n\n진행하시겠습니까?`;
        if(!confirm(msg)) return;
      }else{
        const msg=`⚠️ [정확 복구 - 이전 상태로 되돌리기]\n${label}\n\n복구점 당시 값으로 기존 문서까지 덮어씁니다.\n대상: ${p.items.length}건\n현재 존재: ${p.existing}건\n현재 없음: ${p.missing}건\n\n실행 직전 상태도 자동으로 새 복구점에 저장됩니다.\n계속하시겠습니까?`;
        if(!confirm(msg)) return;
        await makeRollbackPointForExact(p);
      }
      const result=await applyRecoveryItems(p.items,mode);
      if(typeof _invalidateReservationsCache==='function') _invalidateReservationsCache(typeof currentCenter!=='undefined'?currentCenter:null);
      if(typeof _invalidateRecurringCache==='function') _invalidateRecurringCache(typeof currentCenter!=='undefined'?currentCenter:null);
      if(typeof _invalidateMyReservedDatesCache==='function') _invalidateMyReservedDatesCache(typeof currentCenter!=='undefined'?currentCenter:null);
      if(typeof scheduleLoadDB==='function') scheduleLoadDB(0);
      if(typeof drawCalendar==='function') drawCalendar();
      alert(`✅ 복구 완료\n복원/덮어쓰기: ${result.restored}건\n삭제(정확 복구의 과거 부재상태): ${result.deleted}건\n건너뜀: ${result.skipped}건`);
      await loadRecoveryPoints();
    }catch(err){
      console.error(err);
      alert('복구 실패: '+err.message);
    }finally{recoveryBusy=false;}
  }

  async function deleteRecoveryPoint(recoveryId){
    if(!isAdmin) return;
    const metaRef=db.collection('recovery_points').doc(`${META_PREFIX}${recoveryId}`);
    const metaDoc=await metaRef.get();
    if(!metaDoc.exists) return;
    const meta=metaDoc.data()||{};
    if(!confirm(`복구점 자체를 삭제하시겠습니까?\n\n${meta.label||recoveryId}\n이 작업은 되돌릴 수 없습니다.`)) return;
    for(let i=0;i<(meta.chunkCount||0);i++){
      await db.collection('recovery_chunks').doc(`${CHUNK_PREFIX}${recoveryId}_${String(i).padStart(3,'0')}`).delete();
    }
    await metaRef.delete();
    await loadRecoveryPoints();
  }

  async function loadRecoveryPoints(){
    const box=document.getElementById('recoveryPointList');
    if(!box) return;
    box.innerHTML='<div style="padding:20px;text-align:center;color:#64748b;">복구점 불러오는 중...</div>';
    try{
      const rows=await getRecoveryMetaList();
      if(!rows.length){
        box.innerHTML='<div style="padding:24px;text-align:center;color:#94a3b8;">아직 저장된 복구점이 없습니다.</div>';
        return;
      }
      box.innerHTML=rows.map(r=>`
        <div style="border:1px solid #e2e8f0;border-radius:12px;padding:12px;margin-bottom:9px;background:#fff;">
          <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start;">
            <div style="min-width:0;">
              <div style="font-weight:800;color:#1e293b;font-size:.9rem;word-break:break-word;">${esc(r.label||'복구점')}</div>
              <div style="font-size:.73rem;color:#64748b;margin-top:3px;">${esc(fmtDate(r.createdAtMs))} · ${Number(r.itemCount||0)}항목 · ${esc(r.operation||'')}</div>
            </div>
            <span style="font-size:.68rem;background:#f1f5f9;color:#475569;padding:3px 7px;border-radius:20px;white-space:nowrap;">${r.manual?'수동':'자동'}</span>
          </div>
          <div style="display:flex;gap:6px;margin-top:10px;flex-wrap:wrap;">
            <button onclick="restoreRecoveryPoint('${esc(r.recoveryId)}','SAFE')" style="flex:1;min-width:90px;border:0;border-radius:8px;padding:8px;background:#16a34a;color:#fff;font-weight:700;">안전 복구</button>
            <button onclick="restoreRecoveryPoint('${esc(r.recoveryId)}','EXACT')" style="flex:1;min-width:90px;border:0;border-radius:8px;padding:8px;background:#2563eb;color:#fff;font-weight:700;">정확 복구</button>
            <button onclick="deleteRecoveryPoint('${esc(r.recoveryId)}')" style="border:1px solid #fecaca;border-radius:8px;padding:8px 10px;background:#fff;color:#dc2626;font-weight:700;">삭제</button>
          </div>
        </div>`).join('');
    }catch(err){
      console.error(err);
      box.innerHTML=`<div style="padding:18px;color:#dc2626;">복구점 조회 실패: ${esc(err.message)}</div>`;
    }
  }

  function ensureModal(){
    if(document.getElementById('modalRecoveryCenter')) return;
    const modal=document.createElement('div');
    modal.className='modal-mask';
    modal.id='modalRecoveryCenter';
    modal.innerHTML=`
      <div class="modal-win" style="max-width:560px;max-height:88vh;display:flex;flex-direction:column;">
        <span class="modal-close" onclick="closeModal('modalRecoveryCenter')">×</span>
        <div class="modal-head">🛟 데이터 복구센터</div>
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:11px;font-size:.78rem;color:#166534;line-height:1.5;margin-bottom:10px;">
          예약 삭제·정기예약 변경 전에는 자동 복구점이 생성됩니다.<br>
          <b>안전 복구</b>는 현재 없는 문서만 되살리고, <b>정확 복구</b>는 복구점 당시 상태로 되돌립니다.
        </div>
        <div style="display:flex;gap:7px;margin-bottom:10px;">
          <button id="btnCreateRecoveryPoint" onclick="createManualRecoveryPoint()" style="flex:1;border:0;border-radius:9px;padding:10px;background:#0f766e;color:white;font-weight:800;">현재 복구점 만들기</button>
          <button onclick="loadRecoveryPoints()" style="border:1px solid #cbd5e1;border-radius:9px;padding:10px;background:white;color:#334155;font-weight:700;">새로고침</button>
        </div>
        <div id="recoveryPointList" style="overflow-y:auto;min-height:160px;padding-right:2px;"></div>
      </div>`;
    document.body.appendChild(modal);
  }

  function openRecoveryCenter(){
    if(!isAdmin) return alert('관리자만 사용할 수 있습니다.');
    ensureModal();
    openModal('modalRecoveryCenter');
    loadRecoveryPoints();
  }

  // 외부 호출 API
  window.recoveryWritePoint=writeRecoveryPoint;
  window.recoveryBackupReservationsByIds=backupReservationIds;
  window.recoveryBackupCollectionIds=backupCollectionIds;
  window.recoveryBackupSnapshots=backupSnapshots;
  window.createManualRecoveryPoint=createManualRecoveryPoint;
  window.openRecoveryCenter=openRecoveryCenter;
  window.loadRecoveryPoints=loadRecoveryPoints;
  window.restoreRecoveryPoint=restoreRecoveryPoint;
  window.deleteRecoveryPoint=deleteRecoveryPoint;

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',ensureModal,{once:true});
  else ensureModal();
})();
