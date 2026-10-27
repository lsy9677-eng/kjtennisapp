// Resolve the Authentication account, never an arbitrary editable Firestore profile.
export async function findNaverEmailAccount({projectId,accessToken,email,fetcher=fetch}) {
    const normalized=String(email||'').trim().toLowerCase();
    if(!normalized)return null;
    const response=await fetcher('https://identitytoolkit.googleapis.com/v1/projects/'+encodeURIComponent(projectId)+'/accounts:lookup',{
        method:'POST',headers:{Authorization:'Bearer '+accessToken,'Content-Type':'application/json'},body:JSON.stringify({email:[normalized]})
    });
    if(!response.ok)throw new Error('기존 로그인 계정을 확인하지 못했습니다. 직접 입력 로그인을 이용하거나 잠시 후 다시 시도해 주세요.');
    const data=await response.json();
    if(data.users!==undefined&&!Array.isArray(data.users))throw new Error('로그인 계정 확인 응답이 올바르지 않습니다.');
    const users=(data.users||[]).filter(user=>String(user.email||'').trim().toLowerCase()===normalized);
    if(!users.length)return null;
    if(users.length!==1 || !users[0].localId)throw new Error('동일 이메일의 로그인 계정을 하나로 확인할 수 없습니다. 직접 입력 로그인 후 관리자에게 문의해 주세요.');
    if(users[0].disabled)throw new Error('사용이 중지된 로그인 계정입니다. 관리자에게 문의해 주세요.');
    return users[0].localId;
}
