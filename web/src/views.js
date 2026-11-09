const PRIM_ORDER=['md5','sha1','ecb_mode','hardcoded_key','weak_key','rsa','ecdsa','ecdh','dh'];
const BLIND_NAME={'dynamic-algorithm':'Hash chosen at runtime','curve-unresolved':'Elliptic curve unknown','key-size-unresolved':'RSA key size unknown','file-unparseable':'File could not be parsed','star-import':'Star import hides names','runtime-code':'Code built at runtime'};
const BLIND_WHY={'dynamic-algorithm':'The algorithm name is computed at runtime, so a scan cannot tell whether it is MD5.','curve-unresolved':'The curve comes from a variable the scanner could not trace.','key-size-unresolved':'The key size comes from input or a variable the scanner could not trace.','file-unparseable':'The file is invalid Python 3 syntax, so the scanner read none of it.','star-import':'A star import brings in names without listing them.','runtime-code':'eval and exec run code that exists only at runtime.'};
const MILE={2030:'NIST starts deprecating RSA, ECDSA and Diffie-Hellman. Federal key-establishment deadline. SHA-1 reaches end of use on 31 December.',2031:'Federal deadline for signatures.',2035:'Quantum-vulnerable public-key algorithms are disallowed (NIST IR 8547, NSM-10).'};
const REACH={'public-api':'public API','import-time':'runs on import','reached':'reachable','unreferenced':'no caller found','test':'test code'};
const md=s=>esc(s).replace(/`([^`]+)`/g,'<code>$1</code>');

function tally(r){
  const c={now:0,policy:0,quantum:0,benign:0,hn:0,ff:0,un:0};
  flat(r).forEach(x=>{ c[x.clock]++; if(x.clock==='quantum'){ if(x.exposure==='harvest-now') c.hn++; else if(x.exposure==='forgery-future') c.ff++; else c.un++; } });
  return c;
}
function fixFor(x){
  const s=x.snippet, p=x.primitive;
  if(p==='md5') return {k:'diff',a:s,b:s.replace(/md5/gi,m=>m==='MD5'?'SHA256':'sha256'),n:'SHA-256 for anything security related. For passwords use Argon2id or scrypt.'};
  if(p==='sha1') return {k:'diff',a:s,b:s.replace(/sha1/gi,m=>m==='SHA1'?'SHA256':'sha256'),n:'SHA-256 is a drop-in replacement for most uses.'};
  if(p==='ecb_mode') return {k:'diff',a:s,b:s.replace(/MODE_ECB/g,'MODE_GCM').replace(/modes\.ECB\(\)/g,'modes.GCM(nonce)'),n:'GCM needs a fresh nonce for every message, and the code around it must carry the tag.'};
  if(p==='hardcoded_key'){ const m=/^(\s*)((?:self\.)?)(\w+)\s*(?::[^=]+)?=/.exec(s); if(m) return {k:'diff',a:s,b:`${m[1]}${m[2]}${m[3]} = os.environ["${m[3].toUpperCase()}"]`,n:'Add import os, and keep the secret in the environment or a secrets manager. Rotate the old value, because it is already in your git history.'}; return {k:'pat',lines:['Load the key from the environment or a secrets manager, and rotate the exposed value.'],n:'The literal sits inside a call, so the change depends on how the key is passed in.'}; }
  if(p==='weak_key') return {k:'pat',lines:['RSA: at least 2048 bits, 3072 preferred.','Elliptic curve: P-256 or better.'],n:'Test keys are often small on purpose for speed. In shipped code this is a real finding.'};
  if(x.exposure==='harvest-now') return {k:'pat',lines:['Key exchange: hybrid X25519 + ML-KEM-768 (FIPS 203).','Keep the classical half during the cutover so nothing breaks.'],n:'A direction for the migration. The exact change depends on your crypto library.'};
  if(x.exposure==='forgery-future') return {k:'pat',lines:['Signatures: ML-DSA-65 (FIPS 204).','Long-lived roots: SLH-DSA (FIPS 205). Firmware and software signing: LMS or XMSS (SP 800-208).'],n:'A direction for the migration. The exact change depends on your crypto library.'};
  return {k:'pat',lines:['Encryption and key exchange: hybrid X25519 + ML-KEM-768 (FIPS 203).','Signatures: ML-DSA-65 (FIPS 204).'],n:'The code does not say which use this is, so both options are listed.'};
}
function fixHTML(x,key){
  if(x.clock==='benign') return '';
  const f=fixFor(x), open=S.fix[key];
  let body='';
  if(open){
    body=f.k==='diff'?`<pre class="diff"><span class="del">${esc(f.a)}</span><span class="add">${esc(f.b)}</span></pre>`:`<div class="pat">${f.lines.map(l=>`<div>${esc(l)}</div>`).join('')}</div>`;
    body+=`<p class="fxn">${esc(f.n)} Preview only. Your code stays as it is.</p>`;
  }
  return `<button class="fxb" data-fx="${esc(key)}">${open?'Hide fix':'Show fix'}</button>${body}`;
}
function trailHTML(x,key){
  const open=S.trail[key];
  const head=`<button class="fxb" data-tr="${esc(key)}">${open?'Hide proof':'Show proof'}</button>`;
  if(!open) return head;
  return head+`<ol class="trail">${x.trail.map(t=>`<li class="${t.kind==='verdict'?'vd2':''}"><span class="ln m">${t.line?'L'+t.line:(t.kind==='verdict'?'Verdict':'')}</span><span>${md(t.text)}</span></li>`).join('')}</ol>`;
}
function metaLine(x){
  const bits=[x.confidence, x.scope, x.role];
  return `<div class="ml m"><span class="cf-${x.confidence}">${x.confidence}</span> · ${x.scope} · ${x.role} · ${REACH[x.reach]||x.reach}${x.api?` · ${esc(x.api.length>46?'…'+x.api.slice(-45):x.api)}`:''}</div>`;
}

/* ---------- controls ---------- */
function controls(){
  const R=DATA.repos[S.repo]; let h='<div class="ctl">';
  if(R.versions&&R.versions.length>1){
    const vs=R.versions, cur=S.v==null?vs.length-1:S.v;
    const a=dnum(vs[0].date), b=dnum(vs[vs.length-1].date), span=Math.max(1,b-a);
    let mk='', tl='', lastP=-99, lastLow=false, anyLow=false;
    vs.forEach((r,i)=>{
      const pct=((dnum(r.date)-a)/span*100).toFixed(2), left=`calc(8px + (100% - 16px) * ${(pct/100).toFixed(4)})`;
      const xs=prep(r).all.filter(x=>x.scope==='source'), now=xs.filter(x=>x.clock==='now').length;
      const col=now?COL.due:xs.length?COL.pend:COL.clean;
      mk+=`<button class="mk${i===cur?' on':''}" data-v="${i}" style="left:${left};background:${col}" aria-label="${esc(r.version)}"></button>`;
      const low=(+pct-lastP)<9&&!lastLow; lastP=+pct; lastLow=low; if(low) anyLow=true;
      tl+=`<span class="tl${i===cur?' on':''}${low?' lo':''}" style="left:${left}">${esc(r.version)}<br>${r.date.slice(0,4)}</span>`; });
    h+=`<div class="r"><div class="n">History<small>${esc(dlabel(vs[cur].date))}, ${esc(vs[cur].version)}</small><button class="play" id="play" style="margin-top:8px">${S.play?'Stop':'Play'}</button></div><div class="tline${anyLow?' tall':''}"><div class="rail"></div>${mk}${tl}</div></div>`;
  }
  h+=`<div class="r"><div class="n">Calendar year<small>Move it forward</small></div><div class="yc"><div class="yw"><input type="range" id="yr" min="${CUR}" max="2036" step="1" value="${S.year}" style="--p:${yrPct()}%" aria-label="Calendar year">${yrTicks()}</div><div class="ro" id="yrro">${yrText()}</div></div></div>`;
  h+=`<div class="r"><div class="n">Scope<small>What is counted</small></div><div class="sc"><button class="tx${!S.tests?' on':''}" data-scope="src">Shipped code</button><button class="tx${S.tests?' on':''}" data-scope="all">Include tests and examples</button></div></div>`;
  return h+'</div>';
}
const yrPct=()=>((S.year-CUR)/(2036-CUR)*100).toFixed(1);
function yrTicks(){ return '<div class="ticks">'+[2030,2031,2035].map(y=>`<span style="left:${((y-CUR)/(2036-CUR)*100).toFixed(2)}%" title="${esc(MILE[y])}">${y}</span>`).join('')+'</div>'; }
function yrText(){
  const xs=flat(repo()).filter(x=>x.clock!=='benign'), d=xs.filter(x=>fstate(x,S.year)==='due').length, p=xs.length-d;
  const lead=S.year===CUR?'<b>Today.</b>':`<b>${S.year}.</b>`;
  return `${lead} ${d} of ${xs.length} finding${xs.length===1?'':'s'} ${S.year===CUR?'are':'would be'} due or past due, ${p} still ${p===1?'has':'have'} time.${MILE[S.year]?`<span class="mile">${esc(MILE[S.year])}</span>`:''}`;
}

/* ---------- census ---------- */
function clockText(p){ const c=META.prims[p].clock; return c==='now'?'Today':c==='policy'?'2030':'2030 to 2031'; }
function censusHTML(all,unit){
  return PRIM_ORDER.map(k=>{
    const list=all.filter(x=>x.primitive===k).sort((a,b)=>(a.confidence===b.confidence?0:a.confidence==='proven'?-1:1)||a.file.localeCompare(b.file)||a.line-b.line), n=list.length;
    const sq=[]; for(let i=0;i<Math.ceil(n/unit);i++){ const ch=list.slice(i*unit,(i+1)*unit), x=ch[0], c=fcol(x,S.year), solid=ch.every(z=>z.confidence==='proven');
      sq.push(`<i data-f="${esc(x.file)}" data-t="${esc(x.file)}:${x.line} · ${x.confidence}" style="${solid?`background:${c}`:`box-shadow:inset 0 0 0 2px ${c}`}"></i>`); }
    return `<div class="cr${n?'':' dim'}"><span class="n">${esc(META.prims[k].title)}</span><span class="k">${clockText(k)}</span><div class="sqs">${sq.join('')}</div><span class="c">${n}</span></div>`;
  }).join('');
}
function bindCensus(){
  const tip=$('#tip');
  document.querySelectorAll('.sqs i').forEach(i=>{
    i.onclick=()=>{ S.file=i.dataset.f; render(); };
    i.onmousemove=e=>{ tip.style.display='block'; tip.style.left=(e.clientX+14)+'px'; tip.style.top=(e.clientY+14)+'px'; tip.innerHTML='<span class="m">'+esc(i.dataset.t)+'</span>'; };
    i.onmouseleave=()=>tip.style.display='none';
  });
}
function censusUnit(all){ const c={}; all.forEach(x=>c[x.primitive]=(c[x.primitive]||0)+1); return Math.max(1,Math.ceil(Math.max(1,...Object.values(c))/56)); }
function refreshScenario(){
  drawMap(); const ins=$('#insp'); if(ins){ ins.innerHTML=inspector(); bindInsp(); }
  const all=flat(repo()), c=$('.census'); if(c){ c.innerHTML=censusHTML(all,censusUnit(all)); bindCensus(); }
  const ro=$('#yrro'); if(ro) ro.innerHTML=yrText(); const rg=$('#yr'); if(rg) rg.style.setProperty('--p',yrPct()+'%');
}
function bindInsp(){
  document.querySelectorAll('[data-fx]').forEach(b=>b.onclick=()=>{ const k=b.dataset.fx; S.fix[k]=!S.fix[k]; keep(); });
  document.querySelectorAll('[data-tr]').forEach(b=>b.onclick=()=>{ const k=b.dataset.tr; S.trail[k]=!S.trail[k]; keep(); });
}
function keep(){ const y=$('#insp').scrollTop; $('#insp').innerHTML=inspector(); bindInsp(); $('#insp').scrollTop=y; }

/* ---------- map ---------- */
function biteK(k){ return k; }
function bite(x,y,w,h,k){
  if(!k) return '';
  const p=Math.max(4,Math.min(10,Math.min(w,h)/6));
  let d='', last=null;
  for(let r=0;r<k;r++){ const ww=(k-r)*p; if(ww>w-4||(r+1)*p>h-4) break; d+=`M${x+w-ww},${y+h-(r+1)*p}h${ww}v${p}h-${ww}z`; last=r; }
  if(!d) return '';
  let out=`<path d="${d}" fill="var(--bone)"/>`;
  if(k>=4&&last!==null&&w>60&&h>40){
    const sz=Math.max(3,p*.55);
    [[0.34,0.30],[0.62,0.08]].forEach(([a,b],i)=>{ const sx=x+w-p*(k+.2)*a-sz-2, sy=y+h-p*(k+.2)*(1-b*.4)-sz*(1+i)-2; if(sx>x+4&&sy>y+4) out+=`<rect x="${sx.toFixed(1)}" y="${sy.toFixed(1)}" width="${sz.toFixed(1)}" height="${sz.toFixed(1)}" fill="var(--bone)"/>`; });
  }
  return out;
}
function legendSvg(){
  const items=[[COL.clean,0],[COL.pend,0],[COL.due,1],[COL.due,3]]; let s=`<svg width="${items.length*20-4}" height="16" viewBox="0 0 ${items.length*20-4} 16">`;
  items.forEach(([c,k],i)=>{ const x=i*20; s+=`<rect x="${x}" y="0" width="16" height="16" fill="${c}"/>`; for(let r=0;r<k;r++) s+=`<rect x="${x+16-(k-r)*4}" y="${16-(r+1)*4}" width="${(k-r)*4}" height="4" fill="var(--bone)"/>`; });
  return s+'</svg>';
}
function numeral(str,color,k){
  const w=str.length*41, H=88, p=7;
  let st=''; for(let r=0;r<k;r++){ const ww=(k-r)*p; st+=`M${w-ww-1},${H-6-(r+1)*p}h${ww}v${p}h-${ww}z`; }
  const sp=k>=2?`<rect x="${w+8}" y="${H-30}" width="7" height="7" fill="${color}"/><rect x="${w+20}" y="${H-12}" width="5" height="5" fill="${color}"/>`:'';
  return `<svg width="${w+30}" height="${H+6}" viewBox="0 0 ${w+30} ${H+6}" role="img" aria-label="${esc(str)}"><defs><mask id="nm"><rect width="${w+30}" height="${H+6}" fill="#fff"/><path d="${st}" fill="#000"/></mask></defs><text x="-3" y="${H-6}" font-family="Familjen Grotesk" font-weight="600" font-size="76" letter-spacing="-4" fill="${color}" mask="url(#nm)">${esc(str)}</text>${sp}</svg>`;
}
const HL={md5:/md5\w*/i,sha1:/sha-?1\w*/i,ecb_mode:/\w*ecb\w*/i,hardcoded_key:/b?(["'])[^"']{8,}\1/,weak_key:/(\b\d{2,4}\b|nist\d+p|secp\w+)/i,rsa:/rsa\w*/i,ecdsa:/(ecdsa\w*|signingkey|nist\d+p|secp\w+|ed25519\w*|ed448\w*|\bec\b)/i,ecdh:/(x25519\w*|x448\w*|ecdh\w*)/i,dh:/(diffiehellman\w*|dhparam\w*|\bdh\w*)/i};
function hl(x){ const m=(HL[x.primitive]||/$^/).exec(x.snippet); if(!m) return esc(x.snippet); const i=m.index; return esc(x.snippet.slice(0,i))+'<mark>'+esc(m[0])+'</mark>'+esc(x.snippet.slice(i+m[0].length)); }
function codeHTML(x){
  if(!x.ctx) return hl(x);
  const ind=Math.min(...x.ctx.filter(l=>l.trim()&&l!=='...').map(l=>l.match(/^ */)[0].length));
  const L=x.ctx.map(l=>l.slice(ind));
  return hl({primitive:x.primitive,snippet:L[0]})+'\n'+L.slice(1).map(esc).join('\n');
}
function drawMap(){
  const host=$('#map'); if(!host) return;
  const W=host.clientWidth, H=host.clientHeight, r=repo(), P=prep(r);
  const groups={}; P.files.forEach(f=>{ const d=f.path.includes('/')?f.path.slice(0,f.path.lastIndexOf('/')):'.'; (groups[d]=groups[d]||[]).push(f); });
  const gi=Object.entries(groups).map(([d,fs])=>({d,fs,v:fs.reduce((a,f)=>a+Math.max(f.loc,40),0)}));
  const gr=squarify(gi,{x:0,y:0,w:W,h:H});
  let svg=`<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Rot map of ${esc(r.name)}">`;
  gr.forEach(g=>{
    const gx=g.x+2,gy=g.y+2,gw=g.w-4,gh=g.h-4, lab=gh>44&&gw>70, top=lab?20:0;
    if(lab){ const dn=g.it.d+'/', mx=Math.floor((gw-4)/7.4); svg+=`<text class="gl" x="${gx}" y="${gy+12}">${esc(dn.length>mx?'…'+dn.slice(-(mx-1)):dn)}</text>`; }
    const fr=squarify(g.it.fs.map(f=>({f,v:Math.max(f.loc,40)})),{x:gx,y:gy+top,w:gw,h:gh-top});
    fr.forEach(c=>{
      const f=c.it.f,x=c.x+1.5,y=c.y+1.5,w=Math.max(0,c.w-3),h=Math.max(0,c.h-3),fi=fileInfo(f,S.year);
      const base=f.path.split('/').pop(), mc=Math.floor((w-16)/7.2);
      svg+=`<g class="cell${S.file===f.path?' sel':''}" data-f="${esc(f.path)}"><rect class="fill" x="${x}" y="${y}" width="${w}" height="${h}" fill="${fi.col}"/>${bite(x,y,w,h,fi.bite)}`
        +(w>78&&h>26?`<text class="cl" x="${x+9}" y="${y+18}">${esc(base.length>mc?base.slice(0,mc-1)+'…':base)}</text>`:'')
        +`<rect class="ol" x="${x+1}" y="${y+1}" width="${Math.max(0,w-2)}" height="${Math.max(0,h-2)}"/><rect class="hit" x="${x}" y="${y}" width="${w}" height="${h}"/></g>`;
    });
  });
  host.innerHTML=svg+'</svg>';
  const tip=$('#tip');
  host.querySelectorAll('.cell').forEach(el=>{
    const f=P.files.find(z=>z.path===el.dataset.f);
    el.addEventListener('click',()=>{ S.file=f.path; render(); });
    el.addEventListener('mousemove',e=>{ const fi=fileInfo(f,S.year); tip.style.display='block'; tip.style.left=(e.clientX+16)+'px'; tip.style.top=(e.clientY+16)+'px'; tip.innerHTML=`<b>${esc(f.path)}</b><span class="m">${fi.due} due · ${fi.pend} with time left · ${f.loc} lines</span>`; });
    el.addEventListener('mouseleave',()=>tip.style.display='none');
  });
}

/* ---------- overview ---------- */
function blindHTML(r){
  const bs=r.rep.blind_spots; if(!bs.length) return `<div class="sec-h"><h2>Blind spots</h2></div><p class="bsn">None. Every call to a crypto API in this repository could be resolved.</p>`;
  const g={}; bs.forEach(b=>(g[b.kind]=g[b.kind]||[]).push(b));
  const body=Object.keys(g).sort((a,b)=>g[b].length-g[a].length).map(k=>`<details class="bsd"><summary><b>${esc(BLIND_NAME[k]||k)}</b><span class="m">${g[k].length}</span></summary><p>${esc(BLIND_WHY[k]||'')}</p>${g[k].slice(0,40).map(b=>`<div class="bsr"><span class="m">${esc(b.file)}${b.line?':'+b.line:''}</span><span>${md(b.detail)}</span></div>`).join('')}${g[k].length>40?`<div class="bsr"><span class="m">…</span><span>${g[k].length-40} more in the JSON export.</span></div>`:''}</details>`).join('');
  return `<div class="sec-h"><h2>Blind spots</h2><div class="legend"><span>${bs.length} place${bs.length===1?'':'s'} the scanner could not resolve</span></div></div>
    <p class="bsn">These places are unresolved. A quiet scan would report them as clean, so CryptoRot lists each one.</p>${body}`;
}
function overview(){
  EXK='ideas'; EXS.t=0; EXS.shown=-1;
  const r=repo(), P=prep(r), all=flat(r), c=tally(r), cov=r.rep.coverage, N=all.length;
  const files=P.files.map(f=>({f,i:fileInfo(f,S.year)}));
  const worst=files.slice().sort((a,b)=>(b.i.due-a.i.due)||(b.i.pend-a.i.pend))[0];
  if(!S.file||!P.files.find(f=>f.path===S.file)) S.file=worst&&worst.i.n?worst.f.path:(P.files[0]&&P.files[0].path);
  const unit=censusUnit(all), rows=censusHTML(all,unit);
  const q=c.quantum, qparts=[];
  if(c.hn) qparts.push(`<b>${c.hn}</b> protect${c.hn===1?'s':''} encryption or key exchange, so recorded traffic is already exposed`);
  if(c.ff) qparts.push(`<b>${c.ff}</b> ${c.ff===1?'is a signature':'are signatures'}, which a quantum computer could forge in future`);
  if(c.un) qparts.push(`<b>${c.un}</b> ${c.un===1?'is':'are'} RSA with an unknown purpose`);
  const dead=all.filter(x=>x.reach==='unreferenced'&&x.clock!=='benign').length;
  const lede=N?`<b>${c.policy}</b> ${c.policy===1?'has':'have'} a standards deadline. <b>${q}</b> ${q===1?'waits':'wait'} on a quantum computer${qparts.length?': '+qparts.join(', and ')+'.':'.'} ${c.benign?`<b>${c.benign}</b> ${c.benign===1?'is':'are'} judged non-security (declared with usedforsecurity=False, or a building block inside the library) and ${c.benign===1?'is':'are'} not counted. `:''}${dead?`<b>${dead}</b> ${dead===1?'has':'have'} no caller in the repository and may be dead code. `:''}${cov.files_parsed} of ${cov.files_total} Python files were read, and ${r.rep.blind_spots.length} place${r.rep.blind_spots.length===1?'':'s'} could not be resolved (listed below).`
    :`${cov.files_parsed} of ${cov.files_total} Python files were read. None of them use a primitive this version tracks.`;
  const NN=all.filter(x=>x.clock!=='benign').length, head=NN?`${NN} finding${NN===1?'':'s'} ${S.tests?'in the whole repository':'in shipped code'}. <span class="rot">${c.now} broken today.</span>`:`Nothing weak found ${S.tests?'in the repository':'in shipped code'}.`;
  return `${explainer()}<div class="cols"><section>
    <p class="kick m">${esc(r.name)} ${esc(r.version)}</p>
    <h1 class="hl">${head}</h1>
    <p class="lede">${lede}</p>
    <div class="sec-h"><h2>Rot map</h2><div class="legend"><span>Block size is lines of code</span>${legendSvg()}<span>Green clean, ochre time left, rust due</span></div></div>
    ${controls()}
    <div id="map"></div>
    <div class="sec-h"><h2>Every finding</h2><div class="legend"><span>${unit>1?`One square is up to ${unit} findings`:'One square is one finding'}. Filled is proven, outlined is a guess by name. Click to open the file.</span></div></div>
    <div class="census">${rows}</div>
    <div style="height:56px"></div>
    ${blindHTML(r)}
  </section>
  <aside class="insp" id="insp">${inspector()}</aside></div>`;
}
function inspector(){
  const r=repo(), P=prep(r), f=P.files.find(z=>z.path===S.file);
  if(!f) return '<div class="empty">Select a block on the map.</div>';
  const dir=f.path.includes('/')?f.path.slice(0,f.path.lastIndexOf('/')+1):'', base=f.path.split('/').pop();
  const fi=fileInfo(f,S.year), xs=fi.xs;
  const order=[]; PRIM_ORDER.forEach(p=>{ if(xs.some(x=>x.primitive===p)) order.push(p); });
  const groups=order.map(p=>{
    const ys=xs.filter(x=>x.primitive===p), M=META.prims[p];
    const items=ys.map(x=>{ const key=r.version+'|'+f.path+'|'+x.line+'|'+p+'|'+x.n, links=srcLinks(r,x);
      return `<div class="fi"><div class="fi-h"><span class="m">line ${x.line}</span><span class="m due-${fstate(x,S.year)}">${esc(dueLong(x))}</span></div>
      <pre class="code">${codeHTML(x)}</pre>${metaLine(x)}<p class="st-line">${esc(x.status)}</p>
      <div class="acts">${trailHTML(x,key)}${fixHTML(x,key)}</div>
      ${links.length?`<div class="srcs m">${links.join('')}</div>`:''}</div>`; }).join('');
    return `<div class="rg"><div class="fi-h"><b><i style="background:${fcol(ys[0],S.year)}"></i>${esc(M.title)}</b><span class="m">${ys.length} in this file</span></div>
      <p>${esc(M.why)}</p>${items}</div>`; }).join('');
  let big, col=fi.col;
  if(!fi.n) big='Clean'; else if(xs.some(x=>x.clock==='now')) big='Today'; else big=String(Math.min(...xs.filter(x=>x.clock!=='benign').map(x=>x.due))||'');
  if(!big) big='Clean';
  return `<div class="path m">${esc(dir)}</div><h3>${esc(base)}</h3>
    <div class="land">${numeral(big,col,fi.bite)}<div class="lab">${big==='Clean'?'nothing to fix':'earliest deadline'}<br>${fi.n} finding${fi.n===1?'':'s'}<br>${f.loc} lines</div></div>${groups||'<div class="empty">No weak cryptography found in this file.</div>'}`;
}

/* ---------- findings sheet ---------- */
function findings(){
  const r=repo(); let all=flat(r);
  const labelled=all.filter(x=>LS[lkey(r,x)]), real=labelled.filter(x=>LS[lkey(r,x)]==='r').length, fp=labelled.filter(x=>LS[lkey(r,x)]==='f').length, un=labelled.filter(x=>LS[lkey(r,x)]==='u').length;
  const prec=(real+fp)?Math.round(real/(real+fp)*100)+'%':'–';
  const tier=['proven','probable','heuristic'].map(t=>{ const l=labelled.filter(x=>x.confidence===t&&LS[lkey(r,x)]!=='u'); const rr=l.filter(x=>LS[lkey(r,x)]==='r').length; return l.length?`${t} ${Math.round(rr/l.length*100)}% of ${l.length}`:null; }).filter(Boolean);
  let rows=all.filter(x=>(S.prim?x.primitive===S.prim:true)&&(S.clock==='all'||x.clock===S.clock)&&(S.conf==='all'||x.confidence===S.conf)&&(!S.q||(x.file+' '+x.snippet).toLowerCase().includes(S.q.toLowerCase()))&&(!S.unl||!LS[lkey(r,x)]));
  S._rows=rows; if(S.cur>=rows.length) S.cur=Math.max(0,rows.length-1);
  const body=rows.slice(0,400).map((x,i)=>{
    const v=LS[lkey(r,x)]||'', cur=i===S.cur, col=fcol(x,S.year);
    let tr=`<tr class="fr${cur?' cur':''}" data-i="${i}"><td><span class="dot" style="background:${col}"></span><b class="dy">${dueText(x)}</b></td>
      <td>${esc(x.title)}</td><td class="m cf-${x.confidence}">${x.confidence}</td>
      <td class="loc" title="${esc(x.file)}:${x.line}">${esc(x.file)}:${x.line}</td><td class="sn" title="${esc((x.ctx||[x.snippet]).join('\n'))}">${hl(x)}${x.ctx?`<span class="more"> +${x.ctx.length-1} lines</span>`:''}</td>
      <td><div class="vd" data-i="${i}"><button class="r${v==='r'?' on':''}" data-v="r">Real</button><button class="f${v==='f'?' on':''}" data-v="f">False positive</button><button class="u${v==='u'?' on':''}" data-v="u">Unsure</button></div></td></tr>`;
    if(cur) tr+=`<tr class="det"><td colspan="6"><div class="dt"><ol class="trail">${x.trail.map(t=>`<li class="${t.kind==='verdict'?'vd2':''}"><span class="ln m">${t.line?'L'+t.line:(t.kind==='verdict'?'Verdict':'')}</span><span>${md(t.text)}</span></li>`).join('')}</ol></div></td></tr>`;
    return tr;
  }).join('');
  const b=(attr,k,l,on)=>`<button class="tx${on?' on':''}" data-${attr}="${k}">${l}</button>`;
  return `<div class="hrow"><div><p class="kick m">${esc(r.name)} ${esc(r.version)}</p><h1 class="hl">Labelling sheet</h1></div><div class="exps"><button class="btn ghost" id="expj">${ic('json',16)}JSON</button><button class="btn ghost" id="expc">${ic('cbom',16)}CBOM</button><button class="btn ghost" id="exps">${ic('sarif',16)}SARIF</button><button class="btn ghost" id="exp">${ic('csv',16)}CSV</button></div></div>
    <div class="sum">
      <div><div class="v">${labelled.length}<small> of ${all.length}</small></div><div class="t">labelled</div></div>
      <div><div class="v" style="color:var(--rust)">${real}</div><div class="t">real problems</div></div>
      <div><div class="v">${fp}</div><div class="t">false positives${un?`, ${un} unsure`:''}</div></div>
      <div><div class="v">${prec}</div><div class="t">precision on labelled${tier.length>1?`<br>${esc(tier.join(' · '))}`:''}</div></div></div>
    <div class="tools">
      <div class="grp"><span>Clock</span>${b('clock','all','All',S.clock==='all')}${b('clock','now','Today',S.clock==='now')}${b('clock','policy','Deadline',S.clock==='policy')}${b('clock','quantum','Quantum',S.clock==='quantum')}${b('clock','benign','Non-security',S.clock==='benign')}</div>
      <div class="grp"><span>Confidence</span>${b('conf','all','All',S.conf==='all')}${b('conf','proven','Proven',S.conf==='proven')}${b('conf','probable','Probable',S.conf==='probable')}${b('conf','heuristic','Heuristic',S.conf==='heuristic')}</div>
      <div class="grp"><span>Primitive</span><button class="tx${!S.prim?' on':''}" data-prim="">All</button>${PRIM_ORDER.map(k=>`<button class="tx${S.prim===k?' on':''}" data-prim="${k}">${esc(META.prims[k].title)}</button>`).join('')}</div>
      <div class="grp sbar"><span>Find</span><input class="search" id="q" placeholder="Search file or code" value="${esc(S.q)}"><label class="ck"><input type="checkbox" id="unl" ${S.unl?'checked':''}> Unlabelled only</label><span class="sp"></span>${b('scope','src','Shipped code',!S.tests)}${b('scope','all','With tests',S.tests)}</div></div>
    <table class="fs"><thead><tr><th style="width:100px">Due</th><th style="width:210px">Finding</th><th style="width:90px">Evidence</th><th style="width:24%">Location</th><th>Code</th><th style="width:300px">Verdict</th></tr></thead><tbody>${body}</tbody></table>
    ${rows.length>400?`<div class="note">Showing the first 400 of ${rows.length}. Narrow with the filters.</div>`:''}
    <p class="kb"><kbd>J</kbd> <kbd>K</kbd> to move, <kbd>R</kbd> real, <kbd>F</kbd> false positive, <kbd>U</kbd> unsure. The open row shows its proof trail. Labels are saved in this browser.</p>`;
}

/* ---------- scan ---------- */
function scanList(rp){
  const P=prep(rp), by={}; P.all.forEach(x=>(by[x.file]=by[x.file]||[]).push(x));
  return Object.keys(by).sort().map(fp=>`<div class="fi"><div class="fi-h"><b>${esc(fp)}</b><span class="m">${by[fp].length} finding${by[fp].length===1?'':'s'}</span></div>`+by[fp].map(x=>
    `<pre class="code">${x.line}: ${esc(x.snippet)}</pre><div class="calc m">${esc(x.title)} · ${esc(dueLong(x))} · ${x.confidence}</div><p class="st-line">${esc(x.status)}</p><details class="pf"><summary>Proof trail</summary><ol class="trail">${x.trail.map(t=>`<li class="${t.kind==='verdict'?'vd2':''}"><span class="ln m">${t.line?'L'+t.line:(t.kind==='verdict'?'Verdict':'')}</span><span>${md(t.text)}</span></li>`).join('')}</ol></details>`).join('')+'</div>').join('');
}
/* ---------- self-test ---------- */
function selftest(){
  const T=DATA.selftest, s3=T.summary03, s4=T.summary04, rows=T.rows.filter(r=>r.mode==='detect'||r.mode==='declare_ok'), neg=T.rows.filter(r=>r.mode==='negative'||r.mode==='benign');
  const sq=(key)=>rows.map(r=>{ const st=r[key]; const c=st==='detected'?COL.clean:st==='declared'?COL.pend:COL.due; const solid=st!=='declared';
    return `<i data-t="<b>${esc(r.operator)}</b><span class='m'>${esc(r.family)} · ${st}</span><pre>${esc(r.code.trim())}</pre>" style="${solid?`background:${c}`:`box-shadow:inset 0 0 0 2px ${c}`}"></i>`; }).join('');
  const fam={}; rows.forEach(r=>{ const f=fam[r.family]=fam[r.family]||{n:0,a:0,b:0,d:0}; f.n++; if(r.v03==='detected') f.a++; if(r.v04==='detected') f.b++; if(r.v04==='declared') f.d++; });
  const famRows=Object.keys(fam).map(k=>`<tr><td>${esc(k)}</td><td class="num">${fam[k].n}</td><td class="num">${fam[k].a}</td><td class="num">${fam[k].b}${fam[k].d?` <span class="m" style="color:var(--ink3)">+${fam[k].d} declared</span>`:''}</td></tr>`).join('');
  const live=S.live?(S.live.err?`<p class="msg err">Could not run: ${esc(S.live.err)}</p>`:`<p class="msg"><b>Reproduced just now:</b> ${S.live.same} of ${S.live.n} results identical to the table above, ${S.live.ms} ms. ${S.live.s.missed} silent misses, ${S.live.s.false_positives} false positives.</p>`):'';
  const detail=Object.keys(fam).map(k=>`<details class="bsd"><summary><b>${esc(k)}</b><span class="m">${fam[k].n}</span></summary>${rows.filter(r=>r.family===k).map(r=>`<div class="stc"><div class="m">${esc(r.operator)}<span class="stt s-${r.v03}">v0.3 ${r.v03}</span><span class="stt s-${r.v04}">v0.4 ${r.v04}</span></div><pre class="code">${esc(r.code.trim())}</pre>${r.note?`<p class="fxn">${esc(r.note)}</p>`:''}</div>`).join('')}</details>`).join('');
  return `<div class="how"><p class="kick m">Does it work</p><h1 class="hl">We attack our own scanner</h1>
    <p class="lead">Studies of crypto-misuse detectors found that most misses come from code written slightly differently from the textbook example. So each known misuse below is rewritten the ways real code does it: an aliased import, a name held in a variable, a value passed through a helper. Every rewrite ends in one of three states.</p>
    <div class="trio"><div><b style="color:${COL.clean}">Detected</b><p>The scanner reported it.</p></div><div><b style="color:${COL.pend}">Declared</b><p>It could not resolve the code and listed it as a blind spot.</p></div><div><b style="color:${COL.due}">Silently missed</b><p>Nothing reported and nothing declared. This is the failure.</p></div></div>
    <div class="vs">
      <div><p class="kick m">v0.3, the engine from Phase 3</p><div class="big">${s3.missed}<small> of ${s3.mutants} silently missed</small></div><p class="vsn">${s3.detected} detected. ${s3.false_positives} false positive on the safe-code controls.</p></div>
      <div><p class="kick m">v0.4, this version</p><div class="big" style="color:var(--verd)">${s4.missed}<small> of ${s4.mutants} silently missed</small></div><p class="vsn">${s4.detected} detected, ${s4.declared} declared as blind spots. ${s4.false_positives} false positives on ${s4.controls} safe-code controls.</p></div></div>
    <div class="st"><div class="stl m">v0.3</div><div class="stg">${sq('v03')}</div><div class="stl m">v0.4</div><div class="stg">${sq('v04')}</div></div>
    <p class="fxn" style="margin:12px 0 40px">One square per rewritten misuse. Hover for the code.</p>
    <table class="rules"><thead><tr><th>Misuse</th><th class="num">Rewrites</th><th class="num">v0.3 detects</th><th class="num">v0.4 detects</th></tr></thead><tbody>${famRows}</tbody></table>
    <div class="live"><button class="btn" id="live" style="margin-left:0">Run it live</button>${live}</div>
    <div class="formula"><p class="kick m">How far to trust this number</p><p>We wrote these rewrites ourselves, which makes this a regression suite. The independent measure is the benchmark on real projects. The suite shows that the holes we thought of are closed and that the scanner reports what it cannot resolve. Other holes may exist. The list is plain code in the repository, so anyone can add rewrites and rerun it.</p></div>
    <div class="sec-h"><h2>Every rewrite</h2><span class="m" style="color:var(--ink3)">Open a group to read the code and both verdicts</span></div>${detail}</div>`;
}

/* ---------- benchmark ---------- */
function benchmark(){
  const rows=DATA.repos.map((r,i)=>{
    const all=r.rep.findings.map((x,j)=>({...x})), src=all.filter(x=>x.scope==='source'), c=k=>src.filter(x=>x.clock===k).length;
    const lab=all.filter(x=>LS[lkey(r,x)]), real=lab.filter(x=>LS[lkey(r,x)]==='r').length, fp=lab.filter(x=>LS[lkey(r,x)]==='f').length;
    return {i,r,all,src,c,lab:lab.length,real,fp,cov:r.rep.coverage};
  });
  const T=rows.reduce((a,x)=>({f:a.f+x.cov.files_parsed,l:a.l+x.cov.loc,n:a.n+x.all.length,s:a.s+x.src.length,lab:a.lab+x.lab,real:a.real+x.real,fp:a.fp+x.fp}),{f:0,l:0,n:0,s:0,lab:0,real:0,fp:0});
  const body=rows.map(x=>`<tr class="fr" data-open="${x.i}"><td><b>${esc(x.r.name)}</b></td><td class="m">${esc(x.r.version)}</td><td class="num">${x.cov.files_parsed}</td><td class="num">${x.cov.loc.toLocaleString()}</td><td class="num">${x.src.length}</td><td class="num" style="color:var(--rust)">${x.c('now')}</td><td class="num">${x.c('policy')}</td><td class="num">${x.c('quantum')}</td><td class="num">${x.all.length-x.src.length}</td><td class="num">${x.r.rep.blind_spots.length}</td><td class="num">${x.lab}/${x.src.filter(z=>z.clock!=='benign').length}</td><td class="num">${(x.real+x.fp)?Math.round(x.real/(x.real+x.fp)*100)+'%':'–'}</td></tr>`).join('');
  return `<div class="how" style="max-width:none"><p class="kick m">Benchmark</p><h1 class="hl">${DATA.repos.length} open-source Python projects</h1>
   <p class="lead" style="max-width:760px">Each project is pinned to the commit shown, so the numbers can be reproduced. Shipped means code outside tests and examples. Click a row to open that project. The ${Object.keys(DATA.reviews||{}).length} non-benign shipped findings were labelled by an automated review of the code around each one. Treat them as starting labels that nobody has checked independently yet. Change any verdict on the Findings page and the numbers here update. Precision is real divided by real plus false positive, with unsure left out.</p>
   <div class="sum"><div><div class="v">${T.f.toLocaleString()}</div><div class="t">Python files read</div></div><div><div class="v">${(T.l/1000).toFixed(0)}k</div><div class="t">lines of code</div></div><div><div class="v">${T.n}</div><div class="t">findings, ${T.s} in shipped code</div></div><div><div class="v">${(T.real+T.fp)?Math.round(T.real/(T.real+T.fp)*100)+'%':'–'}</div><div class="t">precision, ${T.lab} labelled</div></div></div>
   <table class="rules"><thead><tr><th>Project</th><th>Commit</th><th class="num">Files</th><th class="num">Lines</th><th class="num">Shipped</th><th class="num">Today</th><th class="num">2030</th><th class="num">Quantum</th><th class="num">Tests</th><th class="num">Blind</th><th class="num">Labelled</th><th class="num">Precision</th></tr></thead><tbody>${body}</tbody></table>
   <p class="fxn" style="margin-top:14px">Counts under Today, 2030 and Quantum are shipped code only. Labels are saved in this browser.</p></div>`;
}

/* ---------- scan workbench ---------- */
const SAMPLE=`import hashlib as h
from Crypto.Cipher import AES

ALGO = "md" + "5"
API_KEY = "k3Jx9fQ2mZ7pLw4Tn8Bv"

def fingerprint(data):
    return h.new(ALGO, data).hexdigest()

def seal(data):
    return AES.new(API_KEY.encode()[:16], AES.MODE_ECB).encrypt(data)
`;
function scan(){
  if(S.scode==null) S.scode=SAMPLE;
  EXK='land'; if(EXS.land!==1){ EXS.land=1; EXS.t=0; EXS.shown=-1; }
  const lines=S.scode.split('\n').length;
  return `<section class="hx"><canvas id="field" aria-hidden="true"></canvas><div class="in hx-in"><h1 class="hx-h"><span class="nb">Today's encryption</span><span class="nb">has an <em>expiry date.</em></span> <span class="nb">Find it in your code.</span></h1>
    <p class="hx-p">CryptoRot reads your Python, finds every weak or retiring cipher, and gives each one a fix-by year.</p>
    <div class="land-a"><button class="cta" data-tool>Check your code ${ic('arrow',20)}</button><button class="lnk" id="seerep">See a report on a real project</button></div></div></section>
    ${statBand()}
    <div class="in sec">${explainer()}</div>
    ${deadlines()}
    <div class="in sec" id="tool"><div class="wb"><div class="wb-h"><div><h2 class="wb-t">Try it on your own code</h2><p class="fxn" style="margin-top:8px">Paste Python or pick a folder. Your code goes to the scan service over HTTPS, is scanned in memory and discarded when the scan ends. CryptoRot does not store it, log it or keep a copy. Code you cannot send can be scanned with the offline command-line version.</p></div>
    <div class="wb-s"><span class="m" id="msg">${S.scanMsg?esc(S.scanMsg):''}</span><button class="lnk" id="gop">Scan a folder instead</button><input type="file" id="fld" webkitdirectory multiple hidden></div></div>
    <div class="wb-g"><div class="ed"><div class="gut" id="gut">${gutter(lines,S.scanRes)}</div><textarea id="src" spellcheck="false" wrap="off" aria-label="Python code to scan">${esc(S.scode)}</textarea></div>
    <div class="out" id="res">${scanOut(S.scanRes)}</div></div></div></div>
    <div class="in sec">${checks()}</div>
    ${endBand()}`;
}
function gutter(n,rp){
  const by={}; if(rp) rp.rep.findings.forEach(x=>{ by[x.line]=x; });
  let h=''; for(let i=1;i<=n;i++){ const x=by[i]; h+=`<div>${x?`<i style="background:${fcol(x,CUR)}"></i>`:''}<span>${i}</span></div>`; } return h;
}
function scanOut(rp){
  if(!rp) return '<p class="empty">Scanning. The service runs the same engine as the terminal.</p>';
  const fs=rp.rep.findings, bs=rp.rep.blind_spots;
  if(!fs.length&&!bs.length) return '<p class="empty">Nothing found in this code.</p>';
  let h=fs.map(x=>`<article class="fn"><div class="fn-h"><span class="m">line ${x.line}</span><span class="m" style="color:${fcol(x,CUR)}">${esc(dueLong(x))}</span></div>
    <h3>${esc(x.title)}</h3><pre class="code">${esc(x.snippet)}</pre><p class="st-line">${esc(x.status)}</p>
    <ol class="trail">${x.trail.filter(t=>t.kind!=='verdict').map(t=>`<li><span class="ln m">${t.line?'L'+t.line:(t.kind==='verdict'?'Verdict':'')}</span><span>${md(t.text)}</span></li>`).join('')}</ol></article>`).join('');
  if(bs.length) h+=`<article class="fn"><h3>Could not resolve</h3>${bs.map(b=>`<p class="bsr2"><span class="m">line ${b.line||'-'}</span> ${md(b.detail)}</p>`).join('')}</article>`;
  return h+`<button class="lnk" id="open">Open on the rot map</button>`;
}
let _st=null;
function scanSoon(){ clearTimeout(_st); _st=setTimeout(liveScan,450); }
async function liveScan(){
  const m=$('#msg'); if(!m) return;
  try{
    const t0=performance.now(), code=S.scode;
    const res=await callApi('/scan',{name:'pasted code',files:{'pasted/pasted.py':code}});
    if(S.page!=='scan'||S.scode!==code) return;
    S.scanRes=res;
    const n=S.scanRes.rep.findings.length, b=S.scanRes.rep.blind_spots.length;
    S.scanMsg=`${n} finding${n===1?'':'s'}${b?`, ${b} blind spot${b===1?'':'s'}`:''}, ${Math.max(1,Math.round(performance.now()-t0))} ms`;
    if($('#res')){ $('#res').innerHTML=scanOut(S.scanRes); $('#gut').innerHTML=gutter(S.scode.split('\n').length,S.scanRes); m.textContent=S.scanMsg; bindScanOut(); }
  }catch(e){ m.textContent='Could not scan: '+e.message; }
}
function bindScanOut(){
  const o=$('#open'); if(o) o.onclick=()=>{ const rp=JSON.parse(JSON.stringify(S.scanRes)); DATA.repos.push(rp); S.repo=DATA.repos.length-1; S.file=null; S.prim=null; S.cur=0; S.v=null; go('overview'); };
}
function bindScan(){
  const t=$('#src'), g=$('#gut');
  t.oninput=()=>{ S.scode=t.value; g.innerHTML=gutter(t.value.split('\n').length,S.scanRes); scanSoon(); };
  t.onscroll=()=>{ g.scrollTop=t.scrollTop; };
  $('#gop').onclick=()=>$('#fld').click();
  document.querySelectorAll('[data-tool]').forEach(b=>b.onclick=()=>$('#tool').scrollIntoView({behavior:REDUCE?'auto':'smooth'})); bindField(); $('#seerep').onclick=()=>go('overview'); bindExplainer();
  $('#fld').onchange=e=>doScan({files:Array.from(e.target.files)});
  bindScanOut(); liveScan();
}

/* ---------- how it works ---------- */
function howLines(code,hot){
  return code.split('\n').map((l,i)=>`<div class="cl2${hot.includes(i+1)?' hot':''}"><span class="m">${i+1}</span><code>${esc(l)||' '}</code></div>`).join('');
}
function timeline(){
  const Y0=CUR, Y1=2036, W=880, L=250, R=W-14, x=y=>L+(y-Y0)/(Y1-Y0)*(R-L), rows=[
    ['MD5','now'],['ECB mode','now'],['Hardcoded key','now'],['Key below 112 bits','now'],['SHA-1','p',2030],['RSA, ECDH, Diffie-Hellman','p',2030],['ECDSA and other signatures','p',2031]];
  const rh=34, top=44, H=top+rows.length*rh+14; let s=`<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="When each kind of finding falls due">`;
  [[2030,'2030'],[2031,'2031'],[2035,'2035']].forEach(([y,t],i)=>{ const xx=x(y); s+=`<line x1="${xx}" x2="${xx}" y1="${top-8}" y2="${H-8}" stroke="var(--line)"/><text x="${xx}" y="30" text-anchor="middle" class="tl-t">${t}</text>`; });
  s+=`<text x="${L}" y="30" text-anchor="start" class="tl-t">${Y0}</text>`;
  rows.forEach((r,i)=>{ const y=top+i*rh; s+=`<text x="0" y="${y+17}" class="tl-l">${r[0]}</text>`;
    if(r[1]==='now') s+=`<rect x="${L}" y="${y+4}" width="${R-L}" height="18" fill="${COL.due}"/>`;
    else { const d=x(r[2]); s+=`<rect x="${L}" y="${y+4}" width="${d-L}" height="18" fill="${COL.pend}"/><rect x="${d}" y="${y+4}" width="${R-d}" height="18" fill="${COL.due}"/>`; } });
  return s+'</svg>';
}
function how(){
  const E=HOW, f=E.finding, step=S.hstep==null?0:S.hstep, tr=f.trail.filter(t=>t.kind!=='verdict');
  const hot=tr[step]&&tr[step].line?[tr[step].line]:[];
  const steps=tr.map((t,i)=>`<li><button class="hs${i===step?' on':''}" data-hs="${i}"><span class="m">${t.line?'line '+t.line:'whole file'}</span><span>${md(t.text)}</span></button></li>`).join('');
  const blind=[['Hash chosen at runtime','`hashlib.new(name)` with a `name` from input or config. The scanner cannot know the value, so it lists the call.'],
    ['Key size unknown','`rsa.generate_private_key(key_size=n)` with an `n` the scanner cannot follow.'],
    ['Code built at runtime','`eval` and `exec` create code while the program runs.'],
    ['Files it cannot read','Python 2 syntax and broken files, each listed by name.']].map(b=>`<div class="bl"><b>${b[0]}</b><p>${md(b[1])}</p></div>`).join('');
  const refs=Object.keys(META.sources).map((k,i)=>`<li>${META.sources[k].url?`<a href="${esc(META.sources[k].url)}" target="_blank" rel="noopener">${esc(META.sources[k].title)}</a>`:esc(META.sources[k].title)}</li>`).join('');
  const st=DATA.selftest.summary04, nrep=DATA.repos.filter(r=>!r.rep.coverage.synthetic).length;
  const toc=[['one-finding','One finding, start to finish'],['dates','A date for every finding'],['harvest','Recorded now, forged later'],['blind','What it cannot see'],['proof','How we know it works'],['refs','References']];
  const html=`<article class="doc"><p class="kick m">How it works</p>
   <h1 class="hl">It reads your code the way a person would, then shows its working.</h1>
   <p class="lead">A grep for “md5” finds the easy cases and misses the rest. CryptoRot parses the code into a tree and follows each name to its value. It records every step on the way, so each finding comes with a proof you can read and argue with.</p>
   <h2 id="one-finding">One finding, start to finish</h2>
   <p>The code below builds the hash name from two strings and calls it through an aliased import, so the word <code>md5</code> never appears in a call. Pick a step to see the line it rests on.</p>
   <div class="ws"><div class="ws-c">${howLines(E.code,hot)}</div><ol class="ws-s">${steps}<li class="ws-v"><span class="m">verdict</span><span>${md(f.status)}</span></li></ol></div>
   <h2 id="dates">A date for every finding</h2>
   <p>MD5 is broken today, SHA-1 has a published end date, and RSA waits on a computer that does not exist yet. A single score would blend three different situations, so every finding gets its own date from a cited standard. The calendar slider on the overview answers one question: what falls due by a given year.</p>
   <figure class="fig">${timeline()}<figcaption class="m">Ochre is time left, rust is due. 2030 is when NIST starts deprecating and the federal key-establishment deadline lands, 2031 is the signature deadline, 2035 is when the quantum-vulnerable algorithms are disallowed (NIST IR 8547). The first four rows are already due.</figcaption></figure>
   <h2 id="harvest">Recorded now, forged later</h2>
   <p>An attacker on the network can copy encrypted traffic today and keep it. Traffic protected by RSA or Diffie-Hellman opens once a large quantum computer exists, so the exposure builds from now. A signature can only be forged after the machine arrives. The scanner tells the two apart from what the file does, and when it cannot tell it uses the earlier date and says so.</p>
   <h2 id="blind">What it cannot see</h2>
   <p>It reads Python and works statically. Where it cannot resolve something, it lists the place instead of reporting the code as clean.</p>
   <div class="bls">${blind}</div>
   <p>Two limits remain: the scanner infers whether a file signs or encrypts from its identifiers, and reachability is a name match, so “no caller found” means the code may be dead.</p>
   <h2 id="proof">How we know it works</h2>
   <p>We rewrote ${st.mutants} known misuses the ways real code writes them. The previous engine missed 55 without a word. This one misses ${st.missed}, detects ${st.detected}, and lists the other ${st.declared}. Twelve real projects are scanned and reviewed on the <a href="#benchmark" data-go="benchmark">Benchmark</a> page. We wrote the rewrites ourselves, so the first number is a regression test and the benchmark is the real measure.</p>
   <h2 id="refs">References</h2><ol class="refs">${refs}</ol></article>`;
  return `<div class="docw">${html}<nav class="toc" aria-label="On this page"><p class="kick m">On this page</p>${toc.map(t=>`<button data-sc="${t[0]}">${t[1]}</button>`).join('')}</nav></div>`;
}

function pick(){
  const cards=DATA.repos.map((r,i)=>{ const c=tally(r), n=flat(r).filter(x=>x.clock!=='benign').length;
    return `<button class="pk" data-open="${i}"><span class="pk-n">${esc(r.name)}</span><span class="m">${esc(r.version)}, ${r.rep.coverage.files_parsed} files</span><span class="pk-c"><b>${n}</b> finding${n===1?'':'s'}</span><span class="pk-r">${c.now} broken today</span><span class="pk-s" aria-hidden="true">${strip(r)}</span></button>`; }).join('');
  return `<div class="pick"><h1 class="hl">Pick a project</h1><p class="fxn" style="margin:12px 0 28px;max-width:620px">Real open-source Python projects, scanned at a pinned commit. Each opens as a report and a full findings list, with every finding's due year and proof trail.</p><div class="pkg">${cards}</div></div>`;
}

function checks(){
  const C=[['hash','Broken hashes','MD5 collides in practice and SHA-1 is being retired. Both still turn up in signatures, checksums and password code.','now','Today and by 2030'],
   ['blocks','ECB mode','Equal blocks of data encrypt to equal ciphertext, so the shape of the data stays visible.','now','Today'],
   ['key','Hardcoded keys','A key committed to source is readable by everyone who can read the code.','now','Today'],
   ['lock','RSA and Diffie-Hellman','They protect traffic that can be recorded now and opened once a large quantum computer exists.','quantum','By 2035'],
   ['curve','Elliptic curves','Signatures and key agreement on elliptic curves are deprecated in 2030 and disallowed in 2035.','year','By 2030 and 2035'],
   ['small','Undersized keys','Keys and curves below current minimum sizes are already brute-forceable or disallowed.','now','Today']];
  return `<section class="chk"><h2>What CryptoRot looks for</h2><p>Six kinds of problem, each filed under the date it has to be fixed by.</p><div class="chk-g">${C.map(([i,t,d,w,l])=>`<article class="chk-c c-${w}">${ic(i,48)}<h3>${t}</h3><p>${d}</p><span class="when">${ic(w)}${l}</span></article>`).join('')}</div></section>`;
}

function strip(r){
  const col={now:'#ce461a',policy:'#966c1e',quantum:'#14161a'}; const xs=flat(r).filter(x=>x.clock!=='benign').slice(0,48);
  return xs.map(x=>`<i style="background:${col[x.clock]||'#8b8a84'}"></i>`).join('');
}
