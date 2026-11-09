/* ---------- home page explainer: four scenes drawn from a clock ---------- */
const EXD=9000;
const bez=(x1,y1,x2,y2)=>x=>{ if(x<=0) return 0; if(x>=1) return 1; let a=0,b=1,t=x; for(let i=0;i<24;i++){ const cx=3*x1*t*(1-t)*(1-t)+3*x2*t*t*(1-t)+t*t*t; if(cx<x) a=t; else b=t; t=(a+b)/2; } return 3*y1*t*(1-t)*(1-t)+3*y2*t*t*(1-t)+t*t*t; };
const eOut=bez(.16,1,.3,1), eIO=bez(.76,0,.24,1);
const cl=(v,a=0,b=1)=>Math.min(b,Math.max(a,v)), sg=(t,a,b)=>cl((t-a)/(b-a)), lerp=(a,b,p)=>a+(b-a)*p;
const XC={ink:'#14161a',rust:'rgb(206,70,26)',och:'rgb(150,108,30)',verd:'rgb(31,99,83)',sunk:'#e2ddcd',line:'#d2ccbb',bone:'#ece8de',paper:'#f4f1e8',g:'#8b8a84'};
const T=(x,y,s,cls='ex-l',anchor='start',fill)=>`<text x="${x}" y="${y}" class="${cls}" text-anchor="${anchor}"${fill?` style="fill:${fill}"`:''}>${esc(s)}</text>`;
const R=(x,y,w,h,fill,extra='')=>`<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(0,w).toFixed(1)}" height="${h}" fill="${fill}" ${extra}/>`;
const EXCAP=[
 ['A hash is a fingerprint for data','A hash function turns any file into a short fingerprint. A good one never gives two different files the same print. In 2004 researchers produced the first MD5 collisions, and today two different contracts can carry one MD5 fingerprint and both pass the check.'],
 ['ECB repeats its own patterns','ECB encrypts every block of data on its own with the same key, so equal blocks become equal ciphertext and the shape of the data stays visible. GCM mixes a counter into every block, which makes the output look random.'],
 ['Encrypted today, opened later','An attacker on the network can copy encrypted traffic as it passes and store it. RSA and Diffie-Hellman keep it locked until a large quantum computer can break them. Data that must stay secret for ten years is exposed to copying that happens now.'],
 ['CryptoRot gives every finding a date','The scanner reads your code, follows each name to its real value, and files every finding under today, a standards deadline or the quantum clock. The sections below show what it found in real projects.']];
function doc(x,y,label,alt){
  const w=[120,134,100,130,90,124,110]; let s=R(x,y,170,200,XC.bone,`stroke="${XC.ink}" stroke-width="2"`);
  w.forEach((bw,i)=>{ const hot=alt&&i===3; s+=R(x+18,y+38+i*22,hot?bw*0.6:bw,9,hot?XC.rust:XC.line); });
  return s+T(x+18,y+24,label,'ex-s');
}
function hexRow(x,y,txt,fill){ return `<text x="${x}" y="${y}" class="ex-c" fill="${fill}">${txt}</text>`; }
const HX='0123456789abcdef', FA='a3f19c07e2b4', FB='7be4021d95c8';
function s1(t){
  let o=''; const pB=eOut(sg(t,1000,2300)), bx=lerp(880,570,pB);
  o+=R(570,50,170,200,'none',`stroke="${XC.g}" stroke-width="2" stroke-dasharray="6 6"`)+(pB<0.2?T(655,156,'A second contract','ex-s','middle'):'');
  o+=doc(90,50,'Contract A',false)+doc(bx,50,'Contract B',true);
  o+=`<path d="M175 252v34m-7 -8l7 8l7 -8" stroke="${XC.ink}" stroke-width="2" fill="none"/>`;
  o+=`<path d="M655 252v34m-7 -8l7 8l7 -8" stroke="${XC.ink}" stroke-width="2" fill="none" opacity="${pB>0.99?1:0}"/>`;
  o+=T(190,274,'Fingerprint','ex-s')+(pB>0.99?T(670,274,'Fingerprint','ex-s'):'');
  o+=R(90,296,170,46,XC.bone,`stroke="${XC.ink}" stroke-width="2"`)+hexRow(104,326,FA,XC.ink);
  if(pB>0.99){
    o+=R(570,296,170,46,XC.bone,`stroke="${XC.ink}" stroke-width="2"`);
    let ch=''; for(let i=0;i<12;i++){ const tf=4200+i*95; let c=t<tf-110?FB[i]:t<tf?HX[(i*7+Math.floor(t/60))%16]:FA[i]; ch+=c; }
    const same=t>=4200+11*95; o+=hexRow(584,326,ch,same?XC.rust:XC.ink);
    if(same){ const p=eOut(sg(t,5600,6000)); o+=`<text x="415" y="${336}" class="ex-big" text-anchor="middle" fill="${XC.rust}" transform="translate(0 ${(1-p)*8})" opacity="${p}">=</text>`; }
    if(t>6200){ const p=eOut(sg(t,6200,6700)); o+=T(415,372,'Two different documents, one fingerprint','ex-l','middle',XC.rust).replace('<text','<text opacity="'+p+'"'); }
  }
  return o;
}
function s2(t){
  const X=[30,305,580], Y=104, S=21, C=12, Rw=8; let o='';
  ['Your data','ECB','GCM'].forEach((l,i)=>{ o+=T(X[i],86,l,'ex-l'); });
  [['A shape made of repeated blocks'],['Equal blocks in, equal blocks out'],['A counter changes every block']].forEach((l,i)=>{ o+=T(X[i],Y+Rw*S+34,l[0],'ex-s'); });
  o+=`<path d="M287 190h12m-6 -6l6 6l-6 6" stroke="${XC.ink}" stroke-width="2" fill="none"/><path d="M562 190h12m-6 -6l6 6l-6 6" stroke="${XC.ink}" stroke-width="2" fill="none"/>`;
  const pal=[XC.verd,XC.och,XC.rust,XC.ink,XC.g];
  for(let r=0;r<Rw;r++) for(let c=0;c<C;c++){
    const shape=Math.abs(c-5.5)/6+Math.abs(r-3.5)/4<0.86, h=(c*7+r*13+c*r*3)%5;
    const col0=shape?XC.ink:XC.sunk;
    o+=R(X[0]+c*S,Y+r*S,S-2,S-2,col0);
    [[1,shape?XC.verd:XC.och,900+c*70],[2,pal[h],4800+(c+r)*45]].forEach(([gi,newc,st])=>{
      const p=sg(t,st,st+380), sc=Math.abs(Math.cos(p*Math.PI)), col=p<0.5?col0:newc, w=(S-2)*(p>0&&p<1?Math.max(0.06,sc):1);
      o+=R(X[gi]+c*S+((S-2)-w)/2,Y+r*S,w,S-2,col);
    });
  }
  return o;
}
function s3(t){
  let o=''; const wy=185;
  o+=R(30,wy-38,120,76,XC.bone,`stroke="${XC.ink}" stroke-width="2"`)+T(90,wy+5,'Browser','ex-l','middle');
  o+=R(710,wy-38,120,76,XC.bone,`stroke="${XC.ink}" stroke-width="2"`)+T(770,wy+5,'Server','ex-l','middle');
  o+=R(150,wy-1,560,2,XC.ink);
  o+=R(330,300,130,56,XC.bone,`stroke="${XC.ink}" stroke-width="2"`)+T(395,334,'Attacker','ex-l','middle');
  o+=T(540,288,'Stored copies','ex-s');
  const slots=[]; for(let i=0;i<6;i++) slots.push([540+i*46,300]);
  slots.forEach(([x,y])=>{ o+=R(x,y,38,38,'none',`stroke="${XC.g}" stroke-width="2" stroke-dasharray="4 4"`); });
  const lockedCol=XC.ink; const lock=(x,y,fill)=>R(x,y,26,26,fill)+R(x+8,y+9,10,9,XC.bone);
  for(let k=0;k<9;k++){
    const s=300+k*700, lt=t-s; if(lt<0||lt>2400) continue;
    const ex=lerp(170,690,lt/2400), cp=1015; // copy leaves the wire at x=390
    o+=lock(ex-13,wy-13,XC.ink);
    if(k<6&&lt>=cp){ const p=eOut(sg(lt,cp,cp+800)); const [sx,sy]=slots[k]; const open=sg(t,6900+k*130,6900+k*130+380);
      const w=open>0&&open<1?Math.max(0.06,Math.abs(Math.cos(open*Math.PI))):1, fill=open<0.5?lockedCol:XC.rust;
      /* copy in flight; settles into its slot */
      const cx=lerp(390,sx+6,p), cy=lerp(wy-13,sy+6,p); if(p<1) o+=lock(cx,cy,XC.ink);
    }
  }
  for(let k=0;k<6;k++){ const s=300+k*700+1015+800; if(t>=s){ const [sx,sy]=slots[k]; const open=sg(t,6900+k*130,6900+k*130+380), w=open>0&&open<1?Math.max(0.06,Math.abs(Math.cos(open*Math.PI))):1, fill=open<0.5?XC.ink:XC.rust; o+=R(sx+6+(26-26*w)/2,sy+6,26*w,26,fill)+(open<0.5?R(sx+14,sy+15,10,9,XC.bone):''); } }
  const yr=t<5000?2026:Math.min(2031,2026+Math.floor((t-5000)/300)); 
  o+=T(30,64,'Year','ex-s')+`<text x="30" y="118" class="ex-yr">${yr}</text>`;
  if(t>6500){ const p=eOut(sg(t,6500,7100)), y=lerp(-90,40,p); o+=R(560,y,230,70,XC.ink)+T(675,y+42,'Quantum computer','ex-l','middle',XC.bone); }
  if(t>7900){ const p=eOut(sg(t,7900,8300)); o+=T(540+6,378,'Opened and readable','ex-l','start',XC.rust).replace('<text','<text opacity="'+p+'"'); }
  return o;
}
function s4(t){
  const L=['import hashlib as h','ALGO = "md" + "5"','digest = h.new(ALGO, data)','cipher = AES.new(key, AES.MODE_ECB)','rsa.newkeys(2048)'];
  const Fd=[null,null,['MD5 hash','Today',XC.rust],['ECB mode','Today',XC.rust],['RSA key generation','2030',XC.och]];
  const ly=i=>66+i*56; let o=R(20,24,830,296,XC.bone,`stroke="${XC.ink}" stroke-width="2"`);
  const bp=eIO(sg(t,900,4300)), by=lerp(ly(0),ly(4),bp);
  o+=R(22,by-26,826,42,XC.rust,'opacity="0.14"')+R(22,by-26,5,42,XC.rust);
  L.forEach((l,i)=>{ o+=T(40,ly(i)+6,String(i+1),'ex-s')+`<text x="72" y="${ly(i)+6}" class="ex-c2">${esc(l)}</text>`; });
  o+=R(560,24,1,296,XC.line);
  Fd.forEach((f,i)=>{ if(!f) return; if(by>=ly(i)-12){ const st=by>=ly(i)-12?900+ (i/4)*3400:0; const ap=sg(t,st,st+700);
      const w=eOut(ap)*270; o+=`<clipPath id="cp${i}"><rect x="580" y="${ly(i)-24}" width="${w.toFixed(1)}" height="40"/></clipPath><g clip-path="url(#cp${i})">${R(582,ly(i)-12,14,14,f[2])}${T(606,ly(i)+3,f[0],'ex-l')}${T(836,ly(i)+3,f[1],'ex-l','end',f[2])}</g>`; } });
  if(by>=ly(2)-12){ const p=sg(t,900+(2/4)*3400,900+(2/4)*3400+500); o+=`<text x="330" y="${ly(1)+6}" class="ex-s" opacity="${p}" text-anchor="start">ALGO resolves to "md5"</text>`; }
  if(t>6200){ const p=eOut(sg(t,6200,6900)); o+=`<g opacity="${p}">${T(24,362,'3 findings: 2 due today, 1 due in 2030','ex-l')}</g>`; }
  return o;
}
function s5(t){
  const cols=[['Today',XC.rust,[['MD5 hash'],['ECB mode'],['Hardcoded key']]],['By 2030',XC.och,[['RSA key generation'],['ECDSA signature']]],['2031 and later',XC.ink,[['RSA key exchange'],['Diffie-Hellman']]]];
  let o=''; let n=0;
  cols.forEach(([h,col,items],ci)=>{
    const x=40+ci*270; const hp=eOut(sg(t,200+ci*200,900+ci*200));
    o+=`<g opacity="${hp}">`+T(x,52,h,'ex-big',undefined,col).replace('class="ex-big"','class="ex-l" style="font-size:26px;font-weight:600;fill:'+col+'"')+R(x,66,240,3,col)+'</g>';
    items.forEach(([lb],i)=>{
      const st=1400+n*520; n++; const p=eOut(sg(t,st,st+700)), y=lerp(-40,92+i*64,p);
      o+=`<g opacity="${cl(p*3)}">`+R(x,y,240,48,XC.bone,`stroke="${XC.ink}" stroke-width="2"`)+R(x,y,6,48,col)+T(x+22,y+30,lb,'ex-l')+'</g>';
    });
  });
  const ep=eOut(sg(t,5600,6400));
  o+=`<g opacity="${ep}">`+R(40,308,780,1,XC.line)+T(40,348,'Export the list as JSON, CycloneDX CBOM, SARIF or CSV','ex-l')+T(40,374,'Fix the first column now. Plan the rest.','ex-s')+'</g>';
  return o;
}
const LCAP=[
 ['Encrypted today, opened later','Attackers copy encrypted traffic now and keep it. RSA and Diffie-Hellman protect it only until a large quantum computer can break them, and standards bodies plan for that between 2030 and 2035. Anything that must stay secret for ten years is already exposed.'],
 ['CryptoRot reads your code','It follows every name to its real value, even one built from pieces like "md" + "5", and lists each weak or retiring algorithm with the line it sits on.'],
 ['You get a dated to-do list','Every finding lands under Today, a 2030 standards deadline, or the quantum clock for 2031 and later. Hand it to your team, your auditor or your tracker.']];
const SETS={ideas:{sc:[s1,s2,s3,s4],cap:EXCAP,k:true},land:{sc:[s3,s4,s5],cap:LCAP,k:false}};
let EXK='ideas'; const EXSET=()=>SETS[EXK], EXN=()=>SETS[EXK].sc.length;
const EXS={t:0,playing:true,last:0,shown:-1};
function explainer(){
  return `<section class="ex" aria-label="Four ideas behind every finding"><div class="ex-stage"><svg id="exs" viewBox="0 0 860 390" role="img" aria-label="Animated explanation"></svg></div>
   <div class="ex-side"><p class="kick" id="exk"></p><h3 id="exh"></h3><p id="exp"></p>
   <div class="ex-ctl"><div class="ex-sq">${EXSET().sc.map((_,i)=>`<button data-ex="${i}" aria-label="Scene ${i+1}"></button>`).join('')}</div><button class="lnk" id="explay">Pause</button></div></div></section>`;
}
function exCaption(i){
  const h=$('#exh'); if(!h) return; EXS.shown=i; $('#exk').textContent=EXSET().k?`${i+1} of ${EXN()}`:''; $('#exk').style.display=EXSET().k?'':'none'; h.textContent=EXSET().cap[i][0]; $('#exp').textContent=EXSET().cap[i][1];
  document.querySelectorAll('[data-ex]').forEach(b=>b.classList.toggle('on',+b.dataset.ex===i));
}
function exDraw(){
  const svg=$('#exs'); if(!svg) return; const i=Math.floor(EXS.t/EXD)%EXN(), lt=EXS.t-i*EXD;
  svg.innerHTML=EXSET().sc[i](lt); if(EXS.shown!==i||!$('#exh').textContent) exCaption(i);
}
const REDUCE=matchMedia('(prefers-reduced-motion: reduce)').matches;
function exTick(ts){ requestAnimationFrame(exTick); const svg=$('#exs'); if(!svg){ EXS.last=0; return; } if(!EXS.last) EXS.last=ts; const dt=Math.min(100,ts-EXS.last); EXS.last=ts; if(EXS.playing&&!REDUCE) EXS.t=(EXS.t+dt)%(EXD*EXN()); exDraw(); }
function bindExplainer(){
  document.querySelectorAll('[data-ex]').forEach(b=>b.onclick=()=>{ EXS.t=+b.dataset.ex*EXD+(REDUCE?EXD-1:0); exDraw(); });
  const p=$('#explay'); if(p){ p.textContent=EXS.playing?'Pause':'Play'; p.onclick=()=>{ EXS.playing=!EXS.playing; p.textContent=EXS.playing?'Pause':'Play'; }; }
  EXS.shown=-1; exDraw();
}
