import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
function fixture(){
 const storage=new Map(),pending=[],applied=[],nodes={};
 const c={APP_ENV:{isDevelopment:false},console:{warn(){}},document:{addEventListener(){},querySelectorAll:()=>[],getElementById:id=>nodes[id]||(nodes[id]={value:'2026-10-27',style:{},setAttribute(){}})},localStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v)},fetch:url=>new Promise(resolve=>pending.push({url,resolve})),setTimeout,clearTimeout};
 c.window=c;vm.createContext(c);for(const file of ['js/config.js','js/calendar.js'])vm.runInContext(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'),c);
 c.applyWeatherToCalendar=data=>applied.push(data.daily.temperature_2m_max[0]);c.updateWeatherBanner=()=>{};
 return {c,storage,pending,applied,nodes};
}
function data(temperature){return {daily:{time:['2026-10-27'],weathercode:[0],temperature_2m_max:[temperature],temperature_2m_min:[10],precipitation_probability_max:[0],wind_speed_10m_max:[2]}};}
test('late weather from previous venue is cached separately without overwriting active venue',async()=>{
 const f=fixture(),a=f.c.loadWeeklyWeather();f.c.currentCenter='동부';const b=f.c.loadWeeklyWeather();
 assert.notEqual(f.pending[0].url,f.pending[1].url);f.pending[1].resolve({ok:true,json:async()=>data(25)});await b;
 f.pending[0].resolve({ok:true,json:async()=>data(18)});await a;assert.deepEqual(f.applied,[25]);assert.equal(f.storage.size,2);
 f.c.currentCenter='국제';await f.c.loadWeeklyWeather();assert.deepEqual(f.applied,[25,18]);assert.equal(f.pending.length,2);
});
test('concurrent reads share request and stale legacy cache cannot stand in for a new venue',async()=>{
 const f=fixture();f.storage.set('tenniskj_weather_v2',JSON.stringify({timestamp:Date.now(),data:data(99)}));
 const a=f.c.loadWeeklyWeather(),b=f.c.loadWeeklyWeather();assert.equal(f.pending.length,1);assert.deepEqual(f.applied,[]);
 f.pending[0].resolve({ok:true,json:async()=>data(20)});await Promise.all([a,b]);assert.deepEqual(f.applied,[20]);
 f.c.currentCenter='원도심';const next=f.c.loadWeeklyWeather();f.pending[1].resolve({ok:false});assert.equal(await next,null);assert.deepEqual(f.applied,[20]);assert.equal(f.nodes.weatherBanner.style.display,'none');
});
test('malformed data is not cached and storage errors cannot break forecasts',async()=>{
 const f=fixture();const first=f.c.loadWeeklyWeather();f.pending[0].resolve({ok:true,json:async()=>({daily:{time:['2026-10-27']}})});assert.equal(await first,null);assert.equal(f.storage.size,0);
 f.c.localStorage={getItem(){throw Error('denied');},setItem(){throw Error('quota');}};const next=f.c.loadWeeklyWeather();f.pending[1].resolve({ok:true,json:async()=>data(21)});await next;assert.deepEqual(f.applied,[21]);
});
test('Naver weather search follows selected venue area and uses safe external window flags',()=>{
 const f=fixture();let opened;f.c.open=(...args)=>opened=args;
 for(const id of ['국제','능동','동부','원도심']){f.c.currentCenter=id;f.c.openNaverWeather();const url=new URL(opened[0]);assert.equal(url.searchParams.get('query'),f.c.CENTER_WEATHER[id].area+' 날씨');assert.equal(opened[2],'noopener,noreferrer');}
});
