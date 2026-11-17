/* Service worker: descifra los archivos del sitio con la clave guardada tras el login. No contiene secretos. */
const BASE=new URL('./',self.registration.scope).pathname;
let K=null,M=null;const CACHE=new Map();let CSZ=0;
const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open('fury-gate',1);r.onupgradeneeded=()=>r.result.createObjectStore('kv');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)});
const kvGet=async k=>{const d=await idb();return new Promise(r=>{const q=d.transaction('kv').objectStore('kv').get(k);q.onsuccess=()=>r(q.result);q.onerror=()=>r()})};
const kvDel=async()=>{const d=await idb();return new Promise(r=>{const t=d.transaction('kv','readwrite');t.objectStore('kv').clear();t.oncomplete=()=>r()})};
async function load(){if(K&&M)return true;const raw=await kvGet('key'),man=await kvGet('man');if(!raw||!man)return false;K=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);M=man;return true}
async function plain(ent){
  if(CACHE.has(ent.f))return CACHE.get(ent.f);
  const r=await fetch(BASE+ent.f);if(!r.ok)throw new Error('missing');
  const b=new Uint8Array(await r.arrayBuffer());
  const out=await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},K,b.slice(12));
  if(out.byteLength<30e6){CACHE.set(ent.f,out);CSZ+=out.byteLength;while(CSZ>80e6){const k=CACHE.keys().next().value;CSZ-=CACHE.get(k).byteLength;CACHE.delete(k)}}
  return out;
}
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{if(e.data==='reset'){K=M=null;CACHE.clear();CSZ=0}});
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);if(u.origin!==location.origin||e.request.method!=='GET')return;
  if(!u.pathname.startsWith(BASE))return;
  e.respondWith((async()=>{
    if(u.searchParams.has('logout')){await kvDel();K=M=null;CACHE.clear();return fetch(e.request)}
    let p=decodeURIComponent(u.pathname.slice(BASE.length));if(p===''||p.endsWith('/'))p+='index.html';
    if(!(await load()))return fetch(e.request);
    const ent=M[p];if(!ent)return fetch(e.request);
    try{
      const buf=await plain(ent),len=buf.byteLength,rg=e.request.headers.get('range');
      const h={'Content-Type':ent.t,'Accept-Ranges':'bytes','Cache-Control':'no-store'};
      if(rg){const m=/bytes=(\d*)-(\d*)/.exec(rg);if(m){let s=m[1]?+m[1]:0,en=m[2]?Math.min(+m[2],len-1):len-1;
        return new Response(buf.slice(s,en+1),{status:206,headers:{...h,'Content-Range':`bytes ${s}-${en}/${len}`,'Content-Length':String(en-s+1)}})}}
      return new Response(buf,{status:200,headers:{...h,'Content-Length':String(len)}});
    }catch(err){await kvDel();K=M=null;CACHE.clear();return fetch(e.request)}
  })());
});
