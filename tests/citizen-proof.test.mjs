import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../js/auth.js',import.meta.url),'utf8');
function fixture(){
 const events=[],alerts=[],elements={btnSaveUserSettings:{disabled:false,textContent:'변경사항 저장'},citizenProofUploadStatus:{textContent:''},userSettingsProof:{files:[{name:'synthetic.png',type:'image/png',size:100}],value:'selected'},userSettingsNewPw:{value:''},userSettingsAddr:{value:'가상 주소'}};
 const c={currentUser:{uid:'demo-member',name:'가상회원',proofUrl:'old-proof'},auth:{currentUser:{uid:'demo-member',updatePassword:async()=>events.push('password')}},document:{getElementById:id=>elements[id]},setTimeout,clearTimeout,console,confirm:()=>true,alert:x=>alerts.push(x),compressImage:async()=>({type:'image/jpeg'}),storage:{ref:()=>({child:path=>({put:async(blob,meta)=>{events.push('upload');assert.equal(meta.contentType,'image/jpeg');assert.match(path,/^proofs\/demo-member_proof_\d+\.jpg$/);},getDownloadURL:async()=> 'new-proof'})})},db:{collection:()=>({doc:()=>({update:async value=>{events.push('profile');c.saved=value;}})})},deleteProofByUrl:async()=>events.push('delete-old'),appendCitizenAudit:async()=>events.push('audit'),syncBookingAccessUI:()=>events.push('sync')};
 vm.createContext(c);vm.runInContext(source.slice(source.indexOf('function citizenProofError')),c);return {c,elements,events,alerts};
}
test('proof upload saves PENDING only after upload and profile update, then removes old proof',async()=>{
 const f=fixture();await f.c.saveUserSettingsInfo();assert.deepEqual(f.events,['upload','profile','delete-old','audit','sync']);assert.equal(f.c.saved.verifStatus,'PENDING');assert.equal(f.c.saved.isCitizen,false);assert.equal(f.c.saved.proofUrl,'new-proof');assert.equal(f.elements.userSettingsProof.value,'');assert.equal(f.elements.btnSaveUserSettings.disabled,false);
});
test('profile write failure retains old proof and selected file, restores button and allows retry',async()=>{
 const f=fixture();let fail=true;f.c.db.collection=()=>({doc:()=>({update:async()=>{if(fail)throw Error('synthetic database failure');f.events.push('profile');}})});
 await f.c.saveUserSettingsInfo();assert.equal(f.c.currentUser.proofUrl,'old-proof');assert.ok(!f.events.includes('delete-old'));assert.equal(f.elements.userSettingsProof.value,'selected');assert.equal(f.elements.btnSaveUserSettings.disabled,false);assert.match(f.elements.citizenProofUploadStatus.textContent,/저장하지 못/);
 fail=false;await f.c.saveUserSettingsInfo();assert.equal(f.c.currentUser.proofUrl,'new-proof');
});
test('unsupported HEIC image and oversized file cannot create a pending application',async()=>{
 for(const oversized of [false,true]){const f=fixture();if(oversized)f.elements.userSettingsProof.files[0].size=21*1024*1024;else f.c.compressImage=async()=>{throw Error('decode');};await f.c.saveUserSettingsInfo();assert.equal(f.events.length,0);assert.equal(f.c.currentUser.proofUrl,'old-proof');assert.equal(f.elements.btnSaveUserSettings.disabled,false);assert.match(f.alerts.at(-1),oversized?/20MB/:/JPG/);}
});
test('double click shares one save, sign-out during upload cannot write a profile',async()=>{
 const f=fixture();let release;f.c.compressImage=()=>new Promise(r=>release=r);const a=f.c.saveUserSettingsInfo();await f.c.saveUserSettingsInfo();f.c.auth.currentUser=null;release({});await a;assert.ok(!f.events.includes('profile'));assert.ok(!f.events.includes('delete-old'));assert.equal(f.elements.btnSaveUserSettings.disabled,false);
});
test('storage authorization failure reports retry guidance without success or profile writes',async()=>{
 const f=fixture();f.c.storage.ref=()=>({child:()=>({put:async()=>{throw Object.assign(Error('private storage error'),{code:'storage/unauthorized'});}})});await f.c.saveUserSettingsInfo();assert.equal(f.events.length,0);assert.match(f.alerts.at(-1),/다시 로그인/);assert.ok(!f.alerts.some(x=>x.includes('신청이 완료')));
});
test('no file updates address without resetting citizenship or uploading',async()=>{
 const f=fixture();f.elements.userSettingsProof.files=[];await f.c.saveUserSettingsInfo();assert.deepEqual(f.events,['profile','sync']);assert.deepEqual(Object.keys(f.c.saved),['address']);
});
test('joining only marks a successfully uploaded proof as pending',()=>{
 assert.match(source,/proofUploadedAt: proofUrl \? new Date\(\) : null/);assert.match(source,/verifStatus: proofUrl \? "PENDING" : "NONE"/);assert.match(source,/회원가입은 완료되었지만 사진 첨부에 실패/);
});
test('joining with a failed photo creates a normal account without a false pending review',async()=>{
 const f=fixture();
 for(const id of ['joinEmail','joinPw','joinName','joinPh','joinBirth','joinAddr'])f.elements[id]={value:'synthetic'};
 for(const id of ['chkTerm1','chkTerm2','chkTerm3','chkAll'])f.elements[id]={checked:true};
 f.elements.joinProof={files:[{name:'synthetic.png',type:'image/png',size:100}],value:'selected'};f.elements.btnJoin={};
 f.c.auth.createUserWithEmailAndPassword=async()=>({user:{uid:'demo-join'}});
 f.c.db.collection=()=>({doc:()=>({set:async data=>{f.c.joined=data;}})});
 f.c.sanitizeKoreanRealNameInput=()=>{};f.c.requireValidKoreanRealName=()=> '가상회원';f.c.closeModal=()=>{};f.c.document.querySelectorAll=()=>[];
 f.c.uploadCitizenProof=async()=>{throw Error('synthetic upload failure');};f.c.console={error(){}};
 vm.runInContext(source.slice(source.indexOf('    async function doJoin()'),source.indexOf('    function toggleAllTerms()')),f.c);
 await f.c.doJoin();assert.equal(f.c.joined.verifStatus,'NONE');assert.equal(f.c.joined.proofUrl,'');assert.equal(f.c.joined.proofUploadedAt,null);assert.equal(f.elements.btnJoin.disabled,false);assert.match(f.alerts.at(-1),/사진 첨부에 실패/);
});

