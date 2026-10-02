const $=id=>document.getElementById(id);
const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const workerURL=new URL('./service-worker.js?v=login-2',location.href).href;
let keyBytes=null,manifest=null,preparing=null,sending=null;

function deadline(promise,ms,message){
  let timer;
  return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(message)),ms);})]).finally(()=>clearTimeout(timer));
}

function waitForController(){
  return new Promise((resolve,reject)=>{
    const check=()=>{
      const worker=navigator.serviceWorker.controller;
      if(worker?.scriptURL===workerURL&&worker.state==='activated'){cleanup();resolve(worker);}
    };
    const timer=setTimeout(()=>{cleanup();reject(Error('Uruchomienie trwa zbyt długo. Kliknij „Otwórz stoisko” ponownie.'));},12000);
    const poll=setInterval(check,100);
    const cleanup=()=>{clearTimeout(timer);clearInterval(poll);navigator.serviceWorker.removeEventListener('controllerchange',check);};
    navigator.serviceWorker.addEventListener('controllerchange',check);
    check();
  });
}

function prepareWorker(){
  if(preparing)return preparing;
  preparing=(async()=>{
    if(!('serviceWorker'in navigator)||!crypto.subtle)throw Error('Otwórz stronę w aktualnej przeglądarce przez HTTPS.');
    const registration=await deadline(navigator.serviceWorker.register(workerURL,{scope:'./',updateViaCache:'none'}),12000,'Nie udało się przygotować stoiska. Sprawdź połączenie i spróbuj ponownie.');
    // A hard reload may keep the installed worker but leave this document uncontrolled.
    registration.active?.postMessage({type:'CLAIM'});
    return waitForController();
  })().finally(()=>{preparing=null;});
  return preparing;
}

function requestUnlock(target){
  return new Promise((resolve,reject)=>{
    const channel=new MessageChannel();
    const finish=error=>{clearTimeout(timer);channel.port1.close();error?reject(error):resolve();};
    const timer=setTimeout(()=>finish(Error('Przeglądarka nie odpowiedziała. Spróbuj ponownie.')),4000);
    channel.port1.onmessage=e=>finish(e.data?.ok?null:Error('Nie udało się otworzyć stoiska. Spróbuj ponownie.'));
    channel.port1.onmessageerror=()=>finish(Error('Nie udało się potwierdzić dostępu. Spróbuj ponownie.'));
    channel.port1.start();
    // Plain bytes avoid Safari's CryptoKey structured-clone failure. Memory only.
    try{target.postMessage({type:'UNLOCK',keyBytes,manifest},[channel.port2]);}catch(error){finish(error);}
  });
}

function sendKey(){
  if(sending)return sending;
  sending=(async()=>{
    for(let attempt=0;attempt<2;attempt++){
      try{await requestUnlock(await prepareWorker());return;}
      catch(error){if(attempt===1)throw error;}
    }
  })().finally(()=>{sending=null;});
  return sending;
}

navigator.serviceWorker?.addEventListener('message',e=>{
  if(e.data?.type==='KEY_NEEDED'&&keyBytes&&manifest)sendKey().catch(error=>{$('status').textContent=error.message;});
});
navigator.serviceWorker?.startMessages?.();
prepareWorker().catch(error=>{$('status').textContent=error.message;});

async function download(path){
  const response=await fetch(path,{cache:'no-store',signal:AbortSignal.timeout(20000)});
  if(!response.ok)throw Error('Nie udało się pobrać stoiska. Sprawdź połączenie i spróbuj ponownie.');
  return response;
}

$('unlock').onsubmit=async event=>{
  event.preventDefault();
  if($('submit').disabled)return;
  $('submit').disabled=true;$('status').textContent='Otwieram stoisko…';
  try{
    await prepareWorker();
    const config=await(await download('./vault/config.json')).json();
    const raw=await crypto.subtle.importKey('raw',new TextEncoder().encode($('password').value),'PBKDF2',false,['deriveBits']);
    const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:decode(config.salt),iterations:config.iterations,hash:'SHA-256'},raw,256);
    const key=await crypto.subtle.importKey('raw',bits,{name:'AES-GCM'},false,['decrypt']);
    const blob=new Uint8Array(await(await download('./vault/catalog.bin')).arrayBuffer());
    let data;
    try{data=await crypto.subtle.decrypt({name:'AES-GCM',iv:blob.slice(0,12),additionalData:new TextEncoder().encode('catalog')},key,blob.slice(12));}
    catch{throw Error('Hasło nie pasuje. Spróbuj ponownie.');}
    manifest=JSON.parse(new TextDecoder().decode(data));keyBytes=bits;
    await sendKey();
    // Confirm the controlling worker can serve the show before hiding the form.
    await(await download('./app/index.html')).text();
    $('password').value='';$('status').textContent='';
    $('gate').hidden=true;$('show').hidden=false;$('show').src='./app/index.html';
  }catch(error){
    keyBytes=null;manifest=null;
    $('status').textContent=error.name==='TimeoutError'?'Pobieranie trwa zbyt długo. Sprawdź połączenie i spróbuj ponownie.':error.message;
  }finally{$('submit').disabled=false;}
};
