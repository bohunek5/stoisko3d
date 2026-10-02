let key=null,manifest=null,recovering=null;const decrypted=new Map(),waiting=new Set();const base=new URL('./',self.location.href),appBase=new URL('app/',base).pathname;
self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{
 if(e.data?.type==='CLAIM'){e.waitUntil(self.clients.claim());return;}
 if(e.data?.type!=='UNLOCK')return;
 e.waitUntil((async()=>{
  try{
   const nextKey=e.data.keyBytes?await crypto.subtle.importKey('raw',e.data.keyBytes,{name:'AES-GCM'},false,['decrypt']):e.data.key;
   if(!nextKey||!e.data.manifest?.files)throw Error('invalid unlock');
   key=nextKey;manifest=e.data.manifest;decrypted.clear();
   for(const resolve of waiting)resolve();waiting.clear();
   e.ports[0]?.postMessage({ok:true});
  }catch{e.ports[0]?.postMessage({ok:false});}
 })());
});
async function ensureKey(){
 if(key&&manifest)return;
 if(!recovering)recovering=(async()=>{
  let finish;
  const restored=new Promise(resolve=>{finish=resolve;waiting.add(resolve);});
  const timer=setTimeout(finish,8000);
  try{
   const clients=await self.clients.matchAll({type:'window',includeUncontrolled:true});
   for(const client of clients)client.postMessage({type:'KEY_NEEDED'});
   if(!key||!manifest)await restored;
  }finally{clearTimeout(timer);waiting.delete(finish);}
 })().finally(()=>{recovering=null;});
 return recovering;
}
async function fileBytes(path,entry){
 if(!decrypted.has(path))decrypted.set(path,(async()=>{const response=await fetch(new URL('vault/'+entry.file,base));if(!response.ok)throw Error('missing encrypted file');const raw=new Uint8Array(await response.arrayBuffer());let bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(0,12),additionalData:new TextEncoder().encode(path)},key,raw.slice(12));if(entry.gzip)bytes=await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();return bytes;})().catch(e=>{decrypted.delete(path);throw e;}));return decrypted.get(path);
}
self.addEventListener('fetch',event=>{const url=new URL(event.request.url);if(url.origin!==base.origin||!url.pathname.startsWith(appBase))return;event.respondWith((async()=>{
 await ensureKey();if(!key||!manifest)return new Response('Otwórz stoisko i wpisz hasło na stronie głównej.',{status:403,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}});
 const path=decodeURIComponent(url.pathname.slice(appBase.length))||'index.html',entry=manifest.files[path];if(!entry)return new Response('Nie znaleziono pliku.',{status:404});
 try{const bytes=await fileBytes(path,entry),total=bytes.byteLength;const headers={'Content-Type':entry.type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Accept-Ranges':'bytes'};const range=event.request.headers.get('range');if(range){const m=/^bytes=(\d*)-(\d*)$/.exec(range);if(!m||(!m[1]&&!m[2]))return new Response(null,{status:416,headers:{'Content-Range':`bytes */${total}`}});let start=m[1]?Number(m[1]):Math.max(0,total-Number(m[2])),end=m[1]&&m[2]?Math.min(Number(m[2]),total-1):total-1;if(start>=total||end<start)return new Response(null,{status:416,headers:{'Content-Range':`bytes */${total}`}});headers['Content-Range']=`bytes ${start}-${end}/${total}`;headers['Content-Length']=String(end-start+1);return new Response(bytes.slice(start,end+1),{status:206,headers});}headers['Content-Length']=String(total);return new Response(event.request.method==='HEAD'?null:bytes,{headers});}
 catch{return new Response('Nie udało się odczytać pliku. Odśwież pokaz.',{status:503});}
})());});
