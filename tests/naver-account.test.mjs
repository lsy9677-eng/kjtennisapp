import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {generateKeyPairSync} from 'node:crypto';
import {findNaverEmailAccount} from '../functions/_lib/naver-account.js';
import {onRequestGet} from '../functions/naver-auth.js';
test('Naver callback issues token for the actual email/password Auth UID without querying duplicate profiles',async()=>{
 const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
 const env={NAVER_CLIENT_ID:'fixture',NAVER_CLIENT_SECRET:'fixture',NAVER_REDIRECT_URI:'https://tenniskj-app.pages.dev/naver-auth?action=callback',NAVER_STATE_SECRET:'synthetic-fixture-state-only',FIREBASE_PROJECT_ID:'demo-fixture',FIREBASE_CLIENT_EMAIL:'fixture@example.invalid',FIREBASE_PRIVATE_KEY:privateKey,APP_BASE_URL:'https://tenniskj-app.pages.dev/'};
 const start=await onRequestGet({env,request:new Request('https://tenniskj-app.pages.dev/naver-auth?action=start')});
 const state=new URL(start.headers.get('location')).searchParams.get('state'),original=globalThis.fetch,requests=[];
 globalThis.fetch=async(url,options={})=>{const value=String(url);requests.push(value);const reply=data=>new Response(JSON.stringify(data),{status:200});
  if(value.startsWith('https://nid.naver.com/oauth2.0/token'))return reply({access_token:'naver-fixture'});
  if(value==='https://openapi.naver.com/v1/nid/me')return reply({resultcode:'00',response:{id:'provider-fixture',email:'Member@Example.Invalid'}});
  if(value==='https://oauth2.googleapis.com/token'){const jwt=new URLSearchParams(options.body).get('assertion');const claims=JSON.parse(Buffer.from(jwt.split('.')[1],'base64url'));assert.equal(claims.scope,'https://www.googleapis.com/auth/identitytoolkit');return reply({access_token:'google-fixture'});}
  if(value==='https://identitytoolkit.googleapis.com/v1/projects/demo-fixture/accounts:lookup'){assert.deepEqual(JSON.parse(options.body),{email:['member@example.invalid']});return reply({users:[{localId:'native-approved-uid',email:'member@example.invalid'}]});}
  throw Error('Unexpected network request: '+value);
 };
 try{const response=await onRequestGet({env,request:new Request('https://tenniskj-app.pages.dev/naver-auth?action=callback&code=fixture&state='+encodeURIComponent(state))});assert.equal(response.status,302);const token=new URLSearchParams(new URL(response.headers.get('location')).hash.slice(1)).get('naverCustomToken');const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url'));assert.equal(claims.uid,'native-approved-uid');assert.equal(requests.some(url=>url.includes('firestore.googleapis.com')),false);}finally{globalThis.fetch=original;}
});
test('account lookup failure, disabled accounts and ambiguous accounts fail closed',async()=>{
 const args={projectId:'demo',accessToken:'fixture',email:'m@example.invalid'};
 await assert.rejects(findNaverEmailAccount({...args,fetcher:async()=>new Response('{}',{status:403})}));
 for(const users of [[{email:args.email,localId:'x',disabled:true}],[{email:args.email,localId:'a'},{email:args.email,localId:'b'}]])await assert.rejects(findNaverEmailAccount({...args,fetcher:async()=>new Response(JSON.stringify({users}))}));
 assert.equal(await findNaverEmailAccount({...args,fetcher:async()=>new Response('{}')}),null);
});
test('Naver profile refresh never rewrites existing citizen approval or administrator fields',async()=>{
 const code=fs.readFileSync(new URL('../js/auth.js',import.meta.url),'utf8');const start=code.indexOf('    async function ensureNaverUserDocument('),end=code.indexOf('    async function ensureSocialUserDocument(',start);
 let saved;const c={auth:{currentUser:{uid:'native-approved-uid',displayName:'가상회원'}},db:{collection:()=>({doc:()=>({get:async()=>({exists:true,data:()=>({name:'가상회원',phone:'000-0000-0000',isCitizen:true,verifStatus:'APPROVED',isAdmin:true})}),set:async data=>{saved=data;}})})},normalizePhoneNumber:v=>v,normalizeKoreanRealName:v=>v,isValidKoreanRealName:()=>true};
 vm.createContext(c);vm.runInContext(code.slice(start,end),c);await c.ensureNaverUserDocument({email:'member@example.invalid'});
 for(const key of ['isCitizen','verifStatus','isAdmin'])assert.equal(Object.hasOwn(saved,key),false);
 assert.equal(saved.email,'member@example.invalid');
});
