/*
 * Step 8 - Board module extraction
 * Scope: 게시판/댓글/비밀글/취소요청 게시글 작성 기능만 분리.
 * Reservation save/payment/admin booking core remains in index.dev.html.
 */


// ===== openWrite =====
function openWrite() {
    // [추가] 새 글 작성 모드로 초기화
    editTargetId = null; 
    document.querySelector('#modalWrite .modal-head').innerText = "글쓰기";
    document.querySelector('#modalWrite .btn-full').innerText = "등록";

    // 관리자인 경우 공지사항 옵션 표시
    const noticeOpt = document.getElementById('noticeOption');
    if(isAdmin) {
        noticeOpt.style.display = 'block';
    } else {
        noticeOpt.style.display = 'none';
    }
    
    document.getElementById('chkNotice').checked = false;
    
    // 입력창 비우기
    document.getElementById('pstCat').value = "자유";
    document.getElementById('pstTitle').value = "";
    document.getElementById('pstContent').value = "";
    document.getElementById('pstPwd').value = "";
    
    if(currentUser) document.getElementById('pstAuthor').value = currentUser.name;
    else document.getElementById('pstAuthor').value = "";
    toggleFileBox();
    openModal('modalWrite');
}

// ===== savePost =====
async function savePost() {
    const cat = document.getElementById('pstCat').value;
    const title = document.getElementById('pstTitle').value.trim();
    const author = document.getElementById('pstAuthor').value.trim();
    const content = document.getElementById('pstContent').value.trim();
    const pwd = document.getElementById('pstPwd').value.trim();
    const isNotice = document.getElementById('chkNotice').checked;
    
    // [추가] 공지 순서 값 가져오기 (없으면 기본값 10)
    let noticeOrder = parseInt(document.getElementById('pstNoticeOrder').value);
    if(isNaN(noticeOrder)) noticeOrder = 10;

    const fileInput = document.getElementById('pstFile');
    const file = fileInput.files[0];

    if(!title || !author || !content) return alert("제목, 작성자, 내용은 필수입니다.");
    if(!editTargetId && !pwd) return alert("비밀번호를 입력해주세요.");

    const btn = document.querySelector('#modalWrite .btn-full'); 
    const originText = btn.innerText;
    btn.innerText = "저장 중..."; 
    btn.disabled = true;

    try {
        let fileUrl = null;
        let fileName = null;

        if (file) {
            const storageRef = storage.ref().child('board_files/' + Date.now() + '_' + file.name);
            await storageRef.put(file);
            fileUrl = await storageRef.getDownloadURL();
            fileName = file.name;
        }

        const data = {
            category: cat,  
            title, author, content,
            isNotice: (isAdmin && isNotice) ? true : false,
            // [추가] 순서 저장 (일반글은 자동으로 큰 숫자 999 부여해서 뒤로 밀기)
            noticeOrder: (isAdmin && isNotice) ? noticeOrder : 999, 
            uid: currentUser ? currentUser.uid : null 
        };

        if(pwd) {
            const hPw = await hashPassword(pwd);
            data.pwd = hPw;
        }

        if (fileUrl) {
            data.fileUrl = fileUrl;
            data.fileName = fileName;
        }

        if(editTargetId) {
            await db.collection("posts").doc(editTargetId).update(data);
            alert("수정되었습니다.");
        } else {
            data.at = new Date();
            await db.collection("posts").add(data);
            alert("등록되었습니다.");
        }
        
        closeModal('modalWrite');
        loadPosts(); 
        
    } catch(e) { 
        console.error(e);
        alert("오류: " + e.message); 
    } finally {
        btn.innerText = originText;
        btn.disabled = false;
        fileInput.value = ""; 
    }
}

// ===== tryEditPost =====
async function tryEditPost() {
    // 1. 관리자는 프리패스
    if(isAdmin) {
        openEditForm();
        return;
    }

    // 2. 일반 사용자는 비밀번호 확인
    const pw = prompt("글 작성 시 입력한 비밀번호를 입력하세요");
    if(!pw) return;

    try {
        const hPw = await hashPassword(pw);
        if(hPw === currPost.pwd) {
            openEditForm(); // 비밀번호 일치 시 수정창 열기
        } else {
            alert("비밀번호가 일치하지 않습니다.");
        }
    } catch(e) {
        alert("오류 발생: " + e.message);
    }
}

// ===== openEditForm =====
function openEditForm() {
    closeModal('modalView'); 
    
    editTargetId = currPostId;
    document.querySelector('#modalWrite .modal-head').innerText = "글 수정하기";
    document.querySelector('#modalWrite .btn-full').innerText = "수정 저장";

    document.getElementById('pstCat').value = currPost.category || "자유";
    document.getElementById('pstTitle').value = currPost.title;
    document.getElementById('pstAuthor').value = currPost.author;
    document.getElementById('pstContent').value = currPost.content;
    document.getElementById('chkNotice').checked = currPost.isNotice || false;
    
    // [추가] 저장된 순서가 있으면 불러오고, 없으면 1로 설정
    document.getElementById('pstNoticeOrder').value = currPost.noticeOrder || 1;
    
    document.getElementById('pstPwd').value = ""; 
    document.getElementById('pstPwd').placeholder = "변경하려면 입력 (비워두면 기존 유지)";

    const noticeOpt = document.getElementById('noticeOption');
    if(isAdmin) noticeOpt.style.display = 'block';
    else noticeOpt.style.display = 'none';

    openModal('modalWrite');
}

// ===== filterBoard =====
function filterBoard(cat, btn) {
    currentBoardFilter = cat;

    // 버튼 스타일 변경
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if(btn) btn.classList.add('active');

    // 필터가 바뀌면 1페이지부터 다시 로드
    loadPosts(false); 
}

// ===== loadPosts =====
function loadPosts(isPageMove = false) {
    const list = document.getElementById('postList');
    if (!list) return;

    const loadSeq = ++boardLoadSeq;
    const activeFilter = currentBoardFilter;

    if (!isPageMove) {
        boardCurrentPage = 1;
        boardPageSnapshots = [];
    }

    fixedNoticeIds.clear();
    list.innerHTML = "<div style='text-align:center; padding:20px;'>로딩중...</div>";

    // 게시글 전체 개수 계산용 전체 get()은 읽기 과금이 커서 제거합니다.
    const noticePromise = db.collection("posts")
        .where("isNotice", "==", true)
        .limit(10)
        .get();

    Promise.all([noticePromise])
        .then(([noticeSnap]) => {
            if (loadSeq !== boardLoadSeq) return;

            list.innerHTML = "";

            let notices = [];
            noticeSnap.forEach(doc => {
                notices.push({ id: doc.id, ...doc.data() });
            });

            notices.sort((a, b) => {
                const orderA = (a.noticeOrder !== undefined) ? Number(a.noticeOrder) : 99;
                const orderB = (b.noticeOrder !== undefined) ? Number(b.noticeOrder) : 99;

                if (orderA !== orderB) return orderA - orderB;

                const dateA = a.at && a.at.seconds ? a.at.seconds : 0;
                const dateB = b.at && b.at.seconds ? b.at.seconds : 0;
                return dateB - dateA;
            });

            notices.forEach(d => {
                const showNotice = (activeFilter === 'all') || d.category === activeFilter || d.category === '공지';
                if (!showNotice) return;

                const fakeDoc = { id: d.id, data: () => d };
                renderOnePost(fakeDoc, list, true);
                fixedNoticeIds.add(d.id);
            });

            fetchNormalPosts(list, loadSeq, activeFilter);
        })
        .catch(err => {
            if (loadSeq !== boardLoadSeq) return;
            console.error('공지글 로딩 실패:', err);
            list.innerHTML = "";
            fetchNormalPosts(list, loadSeq, activeFilter);
        });
}

// ===== fetchNormalPosts =====
function fetchNormalPosts(list, loadSeq, activeFilter) {
    let query = db.collection("posts");

    if (activeFilter !== 'all') {
        query = query.where("category", "==", activeFilter);
    }

    query = query.orderBy("at", "desc").limit(boardPageSize);

    if (boardCurrentPage > 1 && boardPageSnapshots[boardCurrentPage - 2]) {
        query = query.startAfter(boardPageSnapshots[boardCurrentPage - 2]);
    }

    query.get().then(snap => {
        if (loadSeq !== boardLoadSeq) return;

        if(!snap.empty) {
            boardPageSnapshots[boardCurrentPage - 1] = snap.docs[snap.docs.length - 1];
        }

        let renderedCount = 0;
        snap.forEach(doc => {
            if (fixedNoticeIds.has(doc.id)) return;
            renderOnePost(doc, list, false);
            renderedCount++;
        });

        if (fixedNoticeIds.size === 0 && renderedCount === 0) {
            list.innerHTML = "<p style='text-align:center;color:#b2bec3;margin-top:20px;'>작성된 글이 없습니다.</p>";
        }

        updateBoardPageUI(snap.size);

    }).catch(err => {
        if (loadSeq !== boardLoadSeq) return;
        handleIndexError(err, list);
    });
}

// ===== renderOnePost =====
function renderOnePost(doc, listElement, isFixedNotice) {
    const p = { id: doc.id, ...doc.data() };
    
    // 배지 스타일 설정
    let badgeClass = "cat-free"; // 기본 회색
    let badgeText = p.category || "기타";
    let cardClass = "post-card";
    
    if (isFixedNotice) {
        badgeClass = "cat-notice";
        cardClass += " notice-card";
        badgeText = "공지";
    } else if (p.category === "취소/환불") {
        badgeClass = "cat-cancel";
    } else if (p.category === "단체대관") {
        badgeClass = "cat-etc"; // 노란색 계열 (혹은 원하시는 색상)
    }

    // [핵심] 비밀글 처리 로직
    // 공지사항은 누구나 볼 수 있음. 그 외(단체대관, 취소환불 등)는 모두 비밀글
    let isSecret = !isFixedNotice; 
    let displayTitle = p.title;
    let lockIcon = "";

    // 관리자가 아니면 제목 가리기
    if (isSecret && !isAdmin) {
        displayTitle = "🔒 비밀글입니다.";
        lockIcon = "🔒 ";
    } else if (isSecret && isAdmin) {
        // 관리자는 자물쇠 표시는 보되 제목은 다 보임
        displayTitle = "🔒 " + p.title;
    }

    // 날짜 포맷
    let dateStr = "";
    if(p.at && p.at.seconds) {
        const d = new Date(p.at.seconds*1000);
        const today = new Date();
        if(d.toDateString() === today.toDateString()) {
            dateStr = d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        } else {
            dateStr = d.toLocaleDateString();
        }
    }

    const div = document.createElement('div');
    div.className = cardClass;
    
    // 공지사항 강조 스타일
    if(isFixedNotice) {
        div.style.backgroundColor = "#fff5f5"; 
        div.style.borderLeft = "4px solid #ef4444";
    }

    div.innerHTML = `
        <div style="font-weight:700;margin-bottom:6px; display:flex; align-items:center;">
            <span class="cat-badge ${badgeClass}">${badgeText}</span>
            <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:${isSecret && !isAdmin ? '#94a3b8' : '#333'}">
                ${displayTitle}
            </span>
        </div>
        <div style="font-size:0.8rem;color:#94a3b8; display:flex; justify-content:space-between;">
            <span>${p.author.substring(0,1)}**</span> <span>${dateStr}</span>
        </div>`;
    
    // [중요] 클릭 시 비밀번호 체크 함수 호출
    div.onclick = () => checkSecretAndShow(p.id, p, isSecret);
    
    listElement.appendChild(div);
}

// ===== changeBoardPageSize =====
function changeBoardPageSize() {
    boardPageSize = parseInt(document.getElementById('selBoardPageSize').value);
    loadPosts(false);
}

// ===== nextBoardPage =====
function nextBoardPage() {
    boardCurrentPage++;
    loadPosts(true);
}

// ===== prevBoardPage =====
function prevBoardPage() {
    if (boardCurrentPage > 1) {
        boardCurrentPage--;
        loadPosts(true);
    }
}

// ===== updateBoardPageUI =====
function updateBoardPageUI(currentFetchSize) {
    const btnPrev = document.getElementById('btnPrevBoard');
    const btnNext = document.getElementById('btnNextBoard');
    const txtInfo = document.getElementById('txtBoardPageInfo');

    // 전체 게시글 개수 계산을 하지 않고 현재 페이지 기준으로만 표시합니다.
    txtInfo.innerText = `${boardCurrentPage} 페이지`;

    btnPrev.disabled = (boardCurrentPage === 1);
    btnPrev.style.opacity = (boardCurrentPage === 1) ? 0.5 : 1;

    const isEnd = (typeof currentFetchSize === 'number') ? currentFetchSize < boardPageSize : false;
    btnNext.disabled = isEnd;
    btnNext.style.opacity = isEnd ? 0.5 : 1;
}

// ===== renderFilteredPosts =====
function renderFilteredPosts() {
    const list = document.getElementById('postList');
    list.innerHTML = "";

    // [중요] 공지사항(isNotice=true)과 일반글을 분리합니다.
    let notices = postsCache.filter(p => p.isNotice);
    let normals = postsCache.filter(p => !p.isNotice);

    // 필터가 선택되었을 때 일반글만 필터링 (공지사항은 항상 보여줌)
    if(currentBoardFilter !== 'all') {
        normals = normals.filter(p => p.category === currentBoardFilter);
    }

    // 공지사항을 먼저 합치고 그 뒤에 일반글을 붙입니다.
    const finals = [...notices, ...normals];

    if(finals.length === 0) {
        list.innerHTML="<p style='text-align:center;color:#b2bec3;margin-top:20px;'>작성된 글이 없습니다.</p>";
        return;
    }

    finals.forEach(p => {
        // 배지 스타일 결정
        let badgeClass = "cat-free";
        let cardClass = "post-card";

        if(p.isNotice) {
            badgeClass = "cat-notice"; // 빨간 배지
            cardClass += " notice-card"; // 빨간 테두리 카드
        } else if(p.category === "취소/환불") {
            badgeClass = "cat-cancel";
        } else if(p.category === "기타") {
            badgeClass = "cat-etc";
        }

        const div = document.createElement('div');
        div.className = cardClass;
        div.innerHTML = `
            <div style="font-weight:700;margin-bottom:6px;">
                <span class="cat-badge ${badgeClass}">${p.category || '자유'}</span>
                ${p.title}
            </div>
            <div style="font-size:0.8rem;color:#94a3b8; display:flex; justify-content:space-between;">
                <span>${p.author}</span>
                <span>${new Date(p.at.seconds*1000).toLocaleDateString()}</span>
            </div>`;
        div.onclick = () => showPost(p.id, p);
        list.appendChild(div);
    });
}

// ===== renderPostItem =====
function renderPostItem(container, id, d, isNotice) {
        const div = document.createElement('div'); 
        div.className = isNotice ? "post-card notice-card" : "post-card";
        
        let titleHtml = d.title;
        if(isNotice) titleHtml = `<span class="notice-badge">공지</span> ` + titleHtml;
        
        div.innerHTML = `<div style="font-weight:700;margin-bottom:6px;">${titleHtml}</div>
                         <div style="font-size:0.8rem;color:#94a3b8;">${d.author}</div>`;
        div.onclick = () => showPost(id, d);
        container.appendChild(div);
    }

// ===== showPost =====
function showPost(id, d) {
    currPostId = id; currPost = d;
    document.getElementById('vTitle').innerText = d.title;
    document.getElementById('vAuthor').innerText = d.author;
    document.getElementById('vContent').innerText = d.content;
    
    // ▼▼▼ [추가] 파일 다운로드 링크 처리 ▼▼▼
    const fileArea = document.getElementById('vFileArea');
    const fileLink = document.getElementById('vFileLink');
    const fileNameSpan = document.getElementById('vFileName');

    if (d.fileUrl) {
        // 파일이 있으면 보여줌
        fileArea.style.display = 'block';
        fileLink.href = d.fileUrl; // 다운로드 주소 연결
        fileNameSpan.innerText = d.fileName || "첨부파일 다운로드"; // 파일명 표시
    } else {
        // 없으면 숨김
        fileArea.style.display = 'none';
    }
    // ▲▲▲ 여기까지 추가됨 ▲▲▲
    
    document.getElementById('cmtName').value = currentUser ? currentUser.name : "";
    document.getElementById('cmtPw').value = "";
    document.getElementById('cmtTxt').value = "";
    
    loadComments();
    openModal('modalView');
}

// ===== saveComment =====
async function saveComment() {
        const name = document.getElementById('cmtName').value.trim();
        const pw = document.getElementById('cmtPw').value.trim();
        const txt = document.getElementById('cmtTxt').value.trim();

        if(!name || !pw || !txt) return alert("이름, 비밀번호, 내용을 모두 입력하세요.");
        
        try {
            const hPw = await hashPassword(pw);
            await db.collection("posts").doc(currPostId).collection("comments").add({
                name: name, pwd: hPw, text: txt, at: new Date()
            });
            document.getElementById('cmtTxt').value = "";
            loadComments();
        } catch(e) {
            alert("댓글 등록 실패: " + e.message);
        }
    }

// ===== loadComments =====
function loadComments() {
        const list = document.getElementById('commentList');
        list.innerHTML = "로딩중...";
        
        db.collection("posts").doc(currPostId).collection("comments").orderBy("at", "asc").get()
        .then(snap => {
            list.innerHTML = "";
            if(snap.empty) { list.innerHTML = "<div style='padding:10px; color:#aaa; text-align:center;'>첫 댓글을 남겨보세요.</div>"; return; }
            
            snap.forEach(doc => {
                const c = doc.data();
                const div = document.createElement('div');
                div.className = "cmt-item";
                div.innerHTML = `
                    <div>
                        <div class="cmt-info">${c.name}</div>
                        <div class="cmt-txt">${c.text}</div>
                    </div>
                    <div class="cmt-del" onclick="deleteComment('${doc.id}', '${c.pwd}')">삭제</div>
                `;
                list.appendChild(div);
            });
        });
    }

// ===== deleteComment =====
async function deleteComment(cmtId, originPwd) {
    if(!confirm("선택한 댓글을 삭제하시겠습니까?")) return;

    // 1. 관리자는 비밀번호 없이 바로 삭제
    if(isAdmin) {
        db.collection("posts").doc(currPostId).collection("comments").doc(cmtId).delete()
        .then(() => {
            alert("관리자 권한으로 삭제되었습니다.");
            loadComments();
        })
        .catch(err => alert("삭제 실패: " + err.message));
        return;
    }

    // 2. 일반 사용자는 비밀번호 확인
    const pw = prompt("댓글 작성 시 입력한 비밀번호를 입력하세요");
    if(!pw) return;

    try {
        const hPw = await hashPassword(pw);
        if(hPw === originPwd) {
            await db.collection("posts").doc(currPostId).collection("comments").doc(cmtId).delete();
            alert("댓글이 삭제되었습니다.");
            loadComments();
        } else {
            alert("비밀번호가 일치하지 않습니다.");
        }
    } catch(e) {
        alert("오류: " + e.message);
    }
}

// ===== deletePost =====
async function deletePost() {
    if(!confirm("정말 이 글을 삭제하시겠습니까?")) return;

    // 1. 관리자면 비밀번호 없이 즉시 삭제
    if(isAdmin) {
         db.collection("posts").doc(currPostId).delete().then(() => { 
             alert("관리자 권한으로 삭제되었습니다."); 
             closeModal('modalView'); 
             loadPosts(); 
         }).catch(err => alert("삭제 실패: " + err.message));
         return;
    }
    
    // 2. 일반 유저는 비밀번호 확인
    const pw = prompt("글 작성 시 입력한 비밀번호를 입력하세요"); 
    if(!pw) return;

    try {
        const hPw = await hashPassword(pw);
        if (hPw === currPost.pwd) { 
            await db.collection("posts").doc(currPostId).delete();
            alert("삭제되었습니다."); 
            closeModal('modalView'); 
            loadPosts(); 
        } else {
            alert("비밀번호가 일치하지 않습니다.");
        }
    } catch(e) {
        alert("오류 발생: " + e.message);
    }
}

// ===== handleIndexError =====
function handleIndexError(err, list) {
    // 에러 메시지에서 링크 주소 추출
    const match = err.message.match(/https:\/\/[^\s]+/);

    if((err.message.includes("index") || err.message.includes("indexes")) && match) {
        const url = match[0]; // 링크 주소
        
        list.innerHTML = `
            <div style="background:#fff1f2; color:#e11d48; padding:15px; border-radius:8px; border:1px solid #fca5a5; font-size:0.9rem; text-align:center;">
                <p style="font-weight:bold; margin-bottom:10px; font-size:1rem;">⚠️ 데이터베이스 설정 필요</p>
                <p style="margin-bottom:15px; color:#374151; line-height:1.4;">
                    새로운 검색 기능(이름 조회)을 사용하려면<br>
                    파이어베이스에 <b>'색인(Index)'</b>을 추가해야 합니다.<br>
                    아래 버튼을 누르면 자동으로 설정 화면으로 이동합니다.
                </p>
                <a href="${url}" target="_blank" style="display:inline-block; background:#2563eb; color:white; text-decoration:none; padding:12px 20px; border-radius:8px; font-weight:bold; box-shadow:0 2px 4px rgba(0,0,0,0.1);">
                    👉 설정 자동 추가하기 (클릭)
                </a>
                <p style="font-size:0.8rem; color:#64748b; margin-top:15px;">
                    * 버튼 클릭 후 <b>[색인 만들기]</b>를 꼭 눌러주세요.<br>
                    * 적용까지 <b>1~3분 정도 소요</b>됩니다. 잠시 후 다시 검색해보세요.
                </p>
            </div>
        `;
    } else {
        list.innerHTML = `<div style="padding:15px; color:red; text-align:center;">오류가 발생했습니다:<br>${err.message}</div>`;
    }
}

// ===== moveToCancelBoard =====
function moveToCancelBoard() {
    // 1. 계좌 정보 입력 확인
    const accountInfo = document.getElementById('rfAccount').value.trim();
    if (!accountInfo) {
        alert("환불받을 계좌 정보를 입력해주세요.");
        return;
    }

    // 2. 환불 불가 내역 경고 확인 (전역변수 tempCancelTargets 사용)
    const hasNoRefund = tempCancelTargets.some(t => t.refundRate === 0);
    if (hasNoRefund) {
        if(!confirm("규정상 [환불 불가] 내역이 포함되어 있습니다.\n그래도 취소 요청하시겠습니까?")) return;
    }

    // 3. 게시글 내용 구성
    const userName = currentUser ? currentUser.name : "회원";
    const totalAmt = tempCancelTargets.reduce((sum, t) => sum + t.refundAmt, 0);
    
    // 취소 대상 내역 텍스트 생성
    let detailsTxt = "";
    tempCancelTargets.forEach(t => {
        detailsTxt += `- ${t.date} ${t.court ? t.court + '코트 ' : ''}${t.time}:00 (환불예정: ${t.refundAmt.toLocaleString()}원)\n`;
    });

    const content = `[예약 취소 요청]
신청자: ${userName}
연락처: ${currentUser ? currentUser.phone : '-'}

[취소 대상]
${detailsTxt}
------------------
총 환불 예정 금액: ${totalAmt.toLocaleString()}원
환불 계좌: ${accountInfo}

위 예약의 취소를 요청합니다.`;

    // 4. 모달 전환 (환불 모달 닫기 -> 글쓰기 모달 열기)
    closeModal('modalRefund');
    openWrite(); // 글쓰기 창 열기 (초기화됨)

    // 5. 글쓰기 폼에 데이터 자동 입력
    // 카테고리 설정
    const catSelect = document.getElementById('pstCat');
    if(catSelect) catSelect.value = "취소/환불";
    
    // 제목 및 내용 설정
    document.getElementById('pstTitle').value = `[취소요청] ${userName} 예약 취소합니다.`;
    document.getElementById('pstContent').value = content;
    
    // 비밀번호 안내
    document.getElementById('pstPwd').placeholder = "비밀번호를 입력하세요 (필수)";

    alert("내용이 자동으로 입력되었습니다.\n비밀번호를 입력하고 [등록] 버튼을 눌러주세요.");
}

// ===== checkSecretAndShow =====
async function checkSecretAndShow(id, post, isSecret) {
    // 1. 공지사항이거나 관리자면 바로 통과
    if (!isSecret || isAdmin) {
        showPost(id, post);
        return;
    }

    // 2. 일반 글: 비밀번호 입력 받기
    const inputPw = prompt("🔒 비밀글입니다.\n작성 시 입력한 비밀번호를 입력하세요.");
    
    if (inputPw) {
        try {
            // 입력한 비번을 암호화해서 DB의 암호와 비교
            const hPw = await hashPassword(inputPw);
            
            if (hPw === post.pwd) {
                showPost(id, post); // 일치하면 내용 보여줌
            } else {
                alert("비밀번호가 일치하지 않습니다.");
            }
        } catch (e) {
            alert("오류가 발생했습니다.");
        }
    }
}

// ===== toggleFileBox =====
function toggleFileBox() {
    const cat = document.getElementById('pstCat').value;
    const fileRow = document.getElementById('fileUploadRow');
    
    // '단체대관'일 때만 보이고, 나머지는 숨김
    if(cat === '단체대관') {
        fileRow.style.display = 'block';
    } else {
        fileRow.style.display = 'none';
        // 숨겨질 때 선택된 파일도 초기화 (실수로 업로드 방지)
        document.getElementById('pstFile').value = ""; 
    }
}
