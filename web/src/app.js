/* ---------- helpers ---------- */
const $ = (s,r=document)=>r.querySelector(s);
const esc = s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const CUR = Math.max(2026, new Date().getFullYear());
const COL = {clean:'rgb(31,99,83)', pend:'rgb(150,108,30)', due:'rgb(206,70,26)'};
const MON=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function dlabel(d){ const [y,m]=d.split('-'); return MON[+m-1]+' '+y; }
function dnum(d){ const [y,m]=d.split('-'); return +y*12+(+m-1); }
let LS={}; try{ LS=JSON.parse(localStorage.getItem('cryptorot_labels')||'{}'); }catch(e){}
for(const k in (DATA.reviews||{})) if(!(k in LS)) LS[k]=DATA.reviews[k];
function saveLS(){ try{ localStorage.setItem('cryptorot_labels',JSON.stringify(LS)); }catch(e){} }

/* ---------- state ---------- */
const S={page:'scan',repo:null,file:null,prim:null,clock:'all',conf:'all',q:'',unl:false,cur:0,v:null,
         year:CUR,tests:false,fix:{},trail:{},play:null,live:null,_rows:[]};

/* ---------- derived data. The engine's report is never modified. ---------- */
function prep(r){
  if(r._p) return r._p;
  const all=r.rep.findings.map((x,n)=>Object.assign({},x,{n,ctx:(r.ctx||{})[x.file+':'+x.line]||null}));
  const byFile={}; all.forEach(x=>(byFile[x.file]=byFile[x.file]||[]).push(x));
  const files=r.files.map(f=>({path:f.path,loc:f.loc,all:byFile[f.path]||[]}));
  return r._p={all,files};
}
const repo=()=>{ const r=DATA.repos[S.repo==null?0:S.repo]; return (S.page==='overview'&&r.versions&&S.v!=null)?r.versions[S.v]:r; };
const inScope=x=>S.tests||x.scope==='source';
const flat=r=>prep(r).all.filter(inScope);
const lkey=(r,x)=>r.name+'@'+r.version+'|'+x.file+'|'+x.line+'|'+x.primitive;

/* state of one finding in a given year */
function fstate(x,Y){ if(x.clock==='benign') return 'ok'; if(x.clock==='now') return 'due'; return Y>=x.due?'due':'pend'; }
function fcol(x,Y){ const s=fstate(x,Y); return s==='ok'?COL.clean:COL[s]; }
function fileInfo(f,Y){
  const xs=f.all.filter(inScope); let d=0,p=0;
  xs.forEach(x=>{ const s=fstate(x,Y); if(s==='due') d++; else if(s==='pend') p++; });
  const st=d?'due':p?'pend':'clean';
  return {n:xs.length,due:d,pend:p,state:st,col:COL[st],bite:d?Math.min(6,1+Math.floor(Math.log2(d))):0,xs};
}
function dueText(x){ return x.clock==='now'?'Today':x.clock==='benign'?'n/a':String(x.due); }
function dueLong(x){
  if(x.clock==='now') return 'Broken or prohibited today';
  if(x.clock==='benign') return 'Not counted as debt';
  const left=x.due-CUR;
  return left>0?`Due ${x.due}, in ${left} year${left===1?'':'s'}`:left===0?`Due ${x.due}, this year`:`Due ${x.due}, past due`;
}
function srcLinks(r,x){
  const S_=r.rep.sources||{};
  return (x.sources||[]).map(id=>{ const s=S_[id]||META.sources[id]; if(!s) return ''; return s.url?`<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.title)}</a>`:`<span>${esc(s.title)}</span>`; }).filter(Boolean);
}

/* ---------- treemap ---------- */
function squarify(items,rect){
  const total=items.reduce((a,b)=>a+b.v,0); if(!total) return [];
  const k=rect.w*rect.h/total; items.forEach(i=>i.a=i.v*k);
  let {x,y,w,h}=rect, out=[], row=[], q=items.slice().sort((a,b)=>b.a-a.a);
  const sum=r=>r.reduce((a,b)=>a+b.a,0);
  const worst=(r,side)=>{ const s=sum(r), mx=Math.max(...r.map(i=>i.a)), mn=Math.min(...r.map(i=>i.a)); return Math.max(side*side*mx/(s*s), s*s/(side*side*mn)); };
  const flush=()=>{ const s=sum(row); if(w>=h){ const cw=s/h; let cy=y; row.forEach(i=>{ const ch=i.a/cw; out.push({it:i,x,y:cy,w:cw,h:ch}); cy+=ch; }); x+=cw; w-=cw; } else { const rh=s/w; let cx=x; row.forEach(i=>{ const cw=i.a/rh; out.push({it:i,x:cx,y,w:cw,h:rh}); cx+=cw; }); y+=rh; h-=rh; } row=[]; };
  while(q.length){ const side=Math.min(w,h), n=q[0]; if(!row.length||worst(row.concat([n]),side)<=worst(row,side)) { row.push(n); q.shift(); } else flush(); }
  if(row.length) flush();
  return out;
}
/*VIEWS*/

/* ---------- render + events ---------- */
const PAGES=['scan','overview','findings','benchmark','selftest','how'];
function render(){
  const needs=(S.page==='overview'||S.page==='findings'), v=(needs&&S.repo==null)?pick:{overview,findings,benchmark,scan,selftest,how}[S.page];
  $('#app').innerHTML=v();
  document.querySelectorAll('#app table').forEach(t=>{ const w=document.createElement('div'); w.className='tw'; t.parentNode.insertBefore(w,t); w.appendChild(t); });
  document.querySelectorAll('#nav button').forEach(b=>{ if(b.dataset.go===S.page) b.setAttribute('aria-current','page'); else b.removeAttribute('aria-current'); });
  $('#repo').style.display=(needs&&S.repo!=null)?'':'none';
  if(S.repo!=null){ $('#repoName').textContent=repo().name; $('#repoVer').textContent=repo().version; }
  if(S.page==='overview'&&S.repo!=null) drawMap();
  bind();
}
function stopPlay(){ if(S.play){ clearInterval(S.play); S.play=null; } }
function go(p){ stopPlay(); S.page=p; window.scrollTo(0,0); render(); }
function bind(){
  if((S.page==='overview'||S.page==='findings')&&S.repo==null){ document.querySelectorAll('.pk').forEach(b=>b.onclick=()=>{ S.repo=+b.dataset.open; S.file=null; S.cur=0; S.prim=null; S.v=null; render(); window.scrollTo(0,0); }); return; }
  if(S.page==='overview'){
    document.querySelectorAll('.mk').forEach(b=>b.onclick=()=>{ stopPlay(); S.v=+b.dataset.v; render(); });
    const pl=$('#play'); if(pl) pl.onclick=()=>{ if(S.play){ stopPlay(); render(); return; } const n=DATA.repos[S.repo].versions.length; S.v=0; render(); S.play=setInterval(()=>{ if(S.v>=n-1){ stopPlay(); render(); return; } S.v++; render(); },1100); render(); };
    const rg=$('#yr'); if(rg) rg.oninput=e=>{ S.year=+e.target.value; refreshScenario(); };
    document.querySelectorAll('[data-scope]').forEach(b=>b.onclick=()=>{ S.tests=b.dataset.scope==='all'; S.file=null; render(); });
    bindCensus(); bindInsp(); bindExplainer();
  }
  if(S.page==='findings'){
    document.querySelectorAll('[data-clock]').forEach(b=>b.onclick=()=>{S.clock=b.dataset.clock;S.cur=0;render();});
    document.querySelectorAll('[data-conf]').forEach(b=>b.onclick=()=>{S.conf=b.dataset.conf;S.cur=0;render();});
    document.querySelectorAll('[data-prim]').forEach(b=>b.onclick=()=>{S.prim=b.dataset.prim||null;S.cur=0;render();});
    document.querySelectorAll('[data-scope]').forEach(b=>b.onclick=()=>{S.tests=b.dataset.scope==='all';S.cur=0;render();});
    $('#q').oninput=e=>{S.q=e.target.value;S.cur=0;const p=e.target.selectionStart;render();const q=$('#q');q.focus();q.setSelectionRange(p,p);};
    $('#unl').onchange=e=>{S.unl=e.target.checked;S.cur=0;render();};
    $('#exp').onclick=exportCSV; $('#expj').onclick=exportJSON; $('#expc').onclick=()=>exportStd('cbom'); $('#exps').onclick=()=>exportStd('sarif');
    document.querySelectorAll('tr.fr').forEach(tr=>tr.onclick=e=>{ if(e.target.closest('.vd')) return; S.cur=+tr.dataset.i; render(); });
    document.querySelectorAll('.vd button').forEach(b=>b.onclick=()=>{ S.cur=+b.parentNode.dataset.i; setV(S.cur,b.dataset.v,false); });
  }
  if(S.page==='benchmark'){
    document.querySelectorAll('tr[data-open]').forEach(tr=>tr.onclick=()=>{ S.repo=+tr.dataset.open;S.file=null;S.cur=0;S.prim=null;S.v=null; go('overview'); });
  }
  if(S.page==='scan') bindScan();
  if(S.page==='how'){
    document.querySelectorAll('[data-hs]').forEach(b=>b.onclick=()=>{ S.hstep=+b.dataset.hs; const y=scrollY; render(); scrollTo(0,y); });
    document.querySelectorAll('[data-sc]').forEach(b=>b.onclick=()=>{ const e=document.getElementById(b.dataset.sc); if(e) scrollTo({top:e.getBoundingClientRect().top+scrollY-92,behavior:'smooth'}); });
    document.querySelectorAll('.doc [data-go]').forEach(b=>b.onclick=e=>{ e.preventDefault(); go(b.dataset.go); });
  }
  if(S.page==='selftest'){
    const b=$('#live'); if(b) b.onclick=runLive;
    document.querySelectorAll('.st i').forEach(el=>{
      const tip=$('#tip');
      el.onmousemove=e=>{ tip.style.display='block'; tip.style.left=Math.min(innerWidth-360,e.clientX+14)+'px'; tip.style.top=(e.clientY+14)+'px'; tip.innerHTML=el.dataset.t; };
      el.onmouseleave=()=>tip.style.display='none';
    });
  }
}
function setV(i,v,adv){
  const r=repo(), x=S._rows[i]; if(!x) return; const k=lkey(r,x);
  if(LS[k]===v){ if(DATA.reviews&&DATA.reviews[k]) LS[k]=''; else delete LS[k]; } else LS[k]=v; saveLS();
  if(adv&&i<S._rows.length-1) S.cur=i+1;
  const y=window.scrollY; render(); window.scrollTo(0,y);
  const el=$('tr.fr.cur'); if(el){ const b=el.getBoundingClientRect(); if(b.top<140||b.bottom>innerHeight-40) el.scrollIntoView({block:'center'}); }
}
document.addEventListener('keydown',e=>{
  if(S.page!=='findings'||e.target.matches('input,textarea')||e.metaKey||e.ctrlKey) return;
  const k=e.key.toLowerCase();
  if(k==='j'||k==='arrowdown'){ e.preventDefault(); S.cur=Math.min(S._rows.length-1,S.cur+1); render(); const el=$('tr.fr.cur'); el&&el.scrollIntoView({block:'center'}); }
  else if(k==='k'||k==='arrowup'){ e.preventDefault(); S.cur=Math.max(0,S.cur-1); render(); const el=$('tr.fr.cur'); el&&el.scrollIntoView({block:'center'}); }
  else if(k==='r'||k==='f'||k==='u'){ e.preventDefault(); setV(S.cur,k,true); }
});

/* ---------- exports ---------- */
async function saveFile(fn,data,mime){
  try{ const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([data],{type:mime})); a.download=fn; a.click(); }catch(e){}
}
function exportCSV(){
  const r=repo(), q=s=>'"'+String(s).replace(/"/g,'""')+'"';
  const lines=['repo,version,file,line,primitive,clock,due,confidence,scope,role,snippet,verdict'];
  flat(r).forEach(x=>lines.push([r.name,r.version,x.file,x.line,x.primitive,x.clock,x.due||'',x.confidence,x.scope,x.role,q(x.snippet),{r:'real',f:'false_positive',u:'unsure'}[LS[lkey(r,x)]]||''].join(',')));
  saveFile(r.name+'-findings.csv',lines.join('\n'),'text/csv');
}
/* The terminal writes this exact text with: cryptorot <dir> -o report.json */
function exportJSON(){ const r=repo(); saveFile(r.name+'-report.json',JSON.stringify(r.rep,null,2),'application/json'); }
async function exportStd(kind){
  const r=repo(), btn=$(kind==='cbom'?'#expc':'#exps'); const old=btn.textContent; btn.textContent='Preparing...';
  try{
    const out=JSON.stringify(await callApi('/export',{kind,name:r.name,rep:r.rep}),null,2);
    saveFile(r.name+(kind==='cbom'?'.cbom.json':'.sarif'),out,'application/json');
  }catch(e){ }
  btn.textContent=old;
}

/* ---------- scan service (the engine runs on the server, the page only sends source and reads the report) ---------- */
async function callApi(path,body){
  if(!API) throw new Error('the scan service is not connected');
  let r; try{ r=await fetch(API+path,{method:'POST',headers:{'content-type':'application/json'},body:body?JSON.stringify(body):undefined}); }catch(e){ throw new Error('could not reach the scan service'); }
  if(!r.ok){ let m=''; try{ m=(await r.json()).detail; }catch(e){} throw new Error(m||('scan service answered '+r.status)); }
  return r.json();
}
async function doScan(inp){
  const msg=$('#msg'); msg.className='msg'; msg.textContent='Scanning...';
  try{
    let name, files={};
    if(inp.code!==undefined){
      if(!inp.code.trim()) throw new Error('paste some Python first');
      files['pasted/pasted.py']=inp.code; name='pasted code';
    }else{
      const fl=inp.files.filter(f=>f.name.endsWith('.py')&&!/(^|\/)\.git\//.test(f.webkitRelativePath));
      if(!fl.length) throw new Error('no .py files in that folder');
      name=(inp.files[0].webkitRelativePath||'folder').split('/')[0];
      for(const f of fl) files[name+'/'+f.webkitRelativePath.split('/').slice(1).join('/')]=await f.text();
    }
    const rp=await callApi('/scan',{name,files});
    DATA.repos.push(rp); S.repo=DATA.repos.length-1; S.file=null; S.prim=null; S.cur=0; S.v=null;
    const fs=prep(rp).all, n=fs.length;
    msg.textContent=n+' finding'+(n===1?'':'s')+' in '+rp.files.length+' file'+(rp.files.length===1?'':'s')+', '+rp.rep.blind_spots.length+' blind spot'+(rp.rep.blind_spots.length===1?'':'s')+'.';
    $('#res').innerHTML='<button class="btn" id="open" style="margin:0 0 20px">Open on the rot map</button>'+(n?scanList(rp):'<div class="empty">Nothing found.</div>');
    const o=$('#open'); o&&(o.onclick=()=>go('overview'));
    $('#repoName').textContent=rp.name;
  }catch(err){ msg.className='msg err'; msg.textContent='Could not scan: '+err.message; }
}
async function runLive(){
  const b=$('#live'); b.textContent='Running...';
  try{
    const t0=performance.now();
    const out=await callApi('/selftest');
    const ref={}; DATA.selftest.rows.forEach(r=>ref[r.id]=r.v04);
    const same=out.rows.filter(r=>ref[r.id]===r.state).length;
    S.live={n:out.rows.length,same,ms:Math.round(performance.now()-t0),s:out.s};
  }catch(e){ S.live={err:e.message}; }
  render();
}

/* repo switcher */
const rb=$('#repoBtn'), rm=$('#repoMenu');
function menu(){ rm.innerHTML=DATA.repos.map((r,i)=>`<button data-i="${i}"><span>${esc(r.name)} <span class="m">${esc(r.version)}</span></span><span class="m">${r.rep.findings.length} findings</span></button>`).join(''); rm.querySelectorAll('button').forEach(b=>b.onclick=()=>{S.repo=+b.dataset.i;S.file=null;S.cur=0;S.prim=null;S.v=null;rm.hidden=true;render();}); }
rb.onclick=e=>{ e.stopPropagation(); menu(); rm.hidden=!rm.hidden; };
document.addEventListener('click',()=>rm.hidden=true);
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',e=>{ e.preventDefault(); go(b.dataset.go); }));
let rz; addEventListener('resize',()=>{ clearTimeout(rz); rz=setTimeout(()=>{ if(S.page==='overview') drawMap(); },120); });
