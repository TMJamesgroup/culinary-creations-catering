/* TAP3 mandatory privacy acknowledgment for Culinary Creations portals.
   This notices acknowledgment only, NOT consent to marketing or optional processing. */
(function(){
'use strict';
function el(tag,props={}){const n=document.createElement(tag);for(const [k,v] of Object.entries(props))k==='text'?n.textContent=v:k==='className'?n.className=v:n.setAttribute(k,v);return n}
function overlay(){
 const layer=el('div',{role:'dialog','aria-modal':'true','aria-label':'Required Privacy Policy Review'});
 layer.style.cssText='position:fixed;z-index:2147483647;inset:0;background:#101820eb;display:flex;align-items:center;justify-content:center;padding:12px;overflow:auto';
 const card=el('section');card.style.cssText='background:#fff;color:#192d3b;width:min(95vw,890px);padding:20px;border-radius:14px;font:15px system-ui;box-shadow:0 20px 60px #0008';
 const title=el('h2',{text:'Required Privacy Policy Review'});card.append(title);
 card.append(el('p',{text:'Review the full privacy policy and scroll to its end before acknowledging. This is not consent to marketing messages or optional data uses.'}));
 const link=el('a',{href:'/tap3-privacy-policy-draft.html',target:'_blank',rel:'noopener noreferrer',text:'Open the complete privacy policy in a new tab'});card.append(link);
 const frame=el('iframe',{src:'/tap3-privacy-policy-draft.html',title:'Complete TAP3 privacy policy'});frame.style.cssText='width:100%;height:52vh;min-height:300px;display:block;background:white;border:1px solid #a6b5c1;margin:14px 0';
 card.append(frame);
 const status=el('p',{text:'Scroll to the bottom of the policy to enable acknowledgment.'});card.append(status);
 const label=el('label');label.style.cssText='display:flex;gap:9px;align-items:flex-start';
 const check=el('input',{type:'checkbox'});check.disabled=true;check.style.cssText='width:22px;height:22px';label.append(check,el('span',{text:'I have read and acknowledge the privacy policy shown above.'}));card.append(label);
 const actions=el('div');actions.style.cssText='display:flex;gap:10px;margin-top:16px;flex-wrap:wrap';
 const accept=el('button',{type:'button',text:'Acknowledge and continue'});accept.disabled=true;
 const decline=el('button',{type:'button',text:'Decline and sign out'});for(const b of [accept,decline])b.style.cssText='padding:12px 16px;cursor:pointer';actions.append(accept,decline);card.append(actions);
 const error=el('p',{role:'alert'});card.append(error);layer.append(card);document.body.append(layer);
 return {layer,frame,status,check,accept,decline,error};
}
async function ensure({apiRoot,token,scope='customer'}){
 if(!token) return false;
 const endpoint=scope==='admin'?'admin':'customer';
 async function request(path,method='GET',payload){
   const r=await fetch(apiRoot+'/api/'+endpoint+'/privacy/'+path,{method,headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:payload?JSON.stringify(payload):undefined,cache:'no-store'});
   const d=await r.json().catch(()=>({}));
   if(!r.ok)throw Error(d.detail||'Privacy request unavailable ('+r.status+')');
   return d;
 }
 const current=await request('status');
 if(current.acknowledged)return true;
 const ui=overlay();
 return await new Promise(resolve=>{
   let read=false,busy=false;
   const setReady=()=>{ui.check.disabled=!read||busy;ui.accept.disabled=!read||!ui.check.checked||busy};
   const scrolled=()=>{try{const doc=ui.frame.contentDocument,root=doc.scrollingElement||doc.documentElement;if(root.scrollTop+root.clientHeight>=root.scrollHeight-36){read=true;ui.status.textContent='You have reached the end of the policy. Check the acknowledgment box.';setReady()}}catch{}};
   ui.frame.addEventListener('load',()=>{try{ui.frame.contentWindow.addEventListener('scroll',scrolled,{passive:true});ui.frame.contentDocument.addEventListener('scroll',scrolled,{passive:true})}catch{}scrolled()});
   ui.check.addEventListener('change',setReady);
   ui.accept.addEventListener('click',async()=>{if(ui.accept.disabled)return;busy=true;setReady();ui.error.textContent='';try{await request('acknowledge','POST',{version:current.version,confirmed:true});ui.layer.remove();resolve(true)}catch(e){busy=false;ui.error.textContent=e.message;setReady()}});
   ui.decline.addEventListener('click',()=>{ui.layer.remove();resolve(false)});
 });
}
window.CCPrivacy={ensure};
})();