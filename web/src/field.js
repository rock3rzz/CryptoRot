/* ---------- landing: live rot field, stats, timeline ---------- */
function bindField(){
  const cv=$('#field'); if(!cv) return;
  const hero=cv.parentNode, ctx=cv.getContext('2d'), dpr=Math.min(2,window.devicePixelRatio||1);
  const S=34,G=6,P=S+G; let W=0,H=0,mx=-999,my=-999,vis=true;
  const size=()=>{ const r=hero.getBoundingClientRect(); W=r.width; H=r.height; cv.width=W*dpr; cv.height=H*dpr; cv.style.width=W+'px'; cv.style.height=H+'px'; ctx.setTransform(dpr,0,0,dpr,0,0); };
  size(); hero.__size=size;
  if(!window._fieldResize){ window._fieldResize=true; addEventListener('resize',()=>{ const c=$('#field'); if(c&&c.parentNode.__size) c.parentNode.__size(); }); }
  hero.onmousemove=e=>{ const r=cv.getBoundingClientRect(); mx=e.clientX-r.left; my=e.clientY-r.top; };
  hero.onmouseleave=()=>{ mx=my=-999; };
  if('IntersectionObserver' in window) new IntersectionObserver(es=>{ vis=es[0].isIntersecting; }).observe(hero);
  const rnd=(c,r)=>{ const s=Math.sin(c*127.1+r*311.7)*43758.5453; return s-Math.floor(s); };
  const V=[43,128,107], O=[150,108,30], Rr=[206,70,26];
  const mix=(a,b,p)=>`rgb(${Math.round(a[0]+(b[0]-a[0])*p)},${Math.round(a[1]+(b[1]-a[1])*p)},${Math.round(a[2]+(b[2]-a[2])*p)})`;
  function frame(ts){
    if(!document.body.contains(cv)) return;
    requestAnimationFrame(frame);
    if(!vis) return;
    ctx.clearRect(0,0,W,H);
    const cols=Math.ceil(W/P)+1, rows=Math.ceil(H/P)+1;
    const sl=REDUCE?0.35:1, t=((ts*sl)/5200)%1.7, front=1.15-Math.min(t,1.15), fade=t>1.15?1-(t-1.15)/0.55:1;
    for(let r=0;r<rows;r++) for(let c=0;c<cols;c++){
      const u=c/cols, k=rnd(c,r);
      let lv=cl((u+r/rows*0.18+(k-0.5)*0.22-front)*5,0,1)*fade; const rp=0.5+0.5*Math.sin(ts*sl/650-u*10-r*0.35+k*3); lv=Math.min(1,lv+rp*0.3*(0.4+u));
      const x=c*P, y=r*P, dx=x+S/2-mx, dy=y+S/2-my, d=Math.sqrt(dx*dx+dy*dy);
      if(d<150) lv=Math.max(lv,(1-d/150)*0.95);
      const col=lv<0.5?mix(V,O,lv*2):mix(O,Rr,(lv-0.5)*2);
      const s=S*(1-0.34*lv*(0.4+k));
      ctx.globalAlpha=0.5+0.5*lv; ctx.fillStyle=col; ctx.fillRect(x+(S-s)/2,y+(S-s)/2,s,s);
    }
    ctx.globalAlpha=1;
  }
  requestAnimationFrame(frame);
}
function statBand(){
  const rs=DATA.repos.filter(r=>!r.rep.coverage.synthetic);
  const files=rs.reduce((a,r)=>a+r.rep.coverage.files_parsed,0), loc=rs.reduce((a,r)=>a+r.rep.coverage.loc,0);
  const v=Object.values(DATA.reviews||{}), rl=v.filter(x=>x==='r').length, fp=v.filter(x=>x==='f').length;
  const st=DATA.selftest.summary04;
  const I=[[rs.length,'open-source projects scanned'],[(loc/1e6).toFixed(1)+'M','lines of Python read'],[Math.round(100*rl/(rl+fp))+'%','of labelled findings were real'],[st.detected,'of '+st.mutants+' planted weaknesses caught']];
  return `<section class="stats in">${I.map(([n,l])=>`<div class="sn"><b>${n}</b><span>${l}</span></div>`).join('')}</section>`;
}
function deadlines(){
  const X0=60, ST=120, yrs=[...Array(10)].map((_,i)=>2026+i), BY=150;
  const flag=(yr,top,h,col,tc,t1,t2,w,dx)=>{ const x=X0+(yr-2026)*ST, bx=Math.max(10,Math.min(x+dx,1190-w));
    const stem=top<BY?`<path d="M${x} ${BY}V${top+h}" stroke="${col}" stroke-width="3"/>`:`<path d="M${x} ${BY+44}V${top}" stroke="${col}" stroke-width="3"/>`;
    return stem+`<rect x="${x-7}" y="${BY-7}" width="14" height="14" fill="${col}"/><rect x="${bx}" y="${top}" width="${w}" height="${h}" fill="${col}"/><text x="${bx+20}" y="${top+36}" class="tl-y" fill="${tc}">${t1}</text><text x="${bx+20}" y="${top+66}" class="tl-s" fill="${tc}">${t2}</text>`; };
  return `<section class="tl in"><h2>Your code sits under every one of these dates.</h2><p class="tl-p"><em>CryptoRot lists the exact lines.</em></p>
  <div class="tl-w"><svg viewBox="0 0 1200 340" role="img" aria-label="Timeline from 2026 to 2035 showing the 2029, 2030 and 2035 deadlines">
  <path d="M${X0} ${BY}H${X0+9*ST}" stroke="#14161a" stroke-width="4"/>
  ${yrs.map((y,i)=>`<path d="M${X0+i*ST} ${BY-8}v16" stroke="#14161a" stroke-width="3"/><text x="${X0+i*ST}" y="${BY+36}" text-anchor="middle" class="tl-n${[2026,2029,2030,2035].includes(y)?' on':''}">${y}</text>`).join('')}
  ${flag(2026,6,82,'#ce461a','#fff','Today','MD5, ECB, hardcoded keys',270,-30)}
  ${flag(2029,6,82,'#1f6353','#fff','2029','Google Cloud targets PQC readiness',330,-60)}
  ${flag(2030,230,82,'#7a5712','#fff','2030','NIST deprecates RSA, EC and SHA-1',350,-90)}
  ${flag(2035,6,82,'#14161a','#f4f1e8','2035','NIST disallows them',250,-30)}
  </svg></div>
  <ol class="tl-m"><li class="a"><b>Today</b><span>MD5, ECB, hardcoded keys</span></li><li class="b"><b>2029</b><span>Google Cloud targets PQC readiness</span></li><li class="c"><b>2030</b><span>NIST deprecates RSA, EC and SHA-1</span></li><li class="d"><b>2035</b><span>NIST disallows them</span></li></ol></section>`;
}
function endBand(){
  return `<section class="band"><div class="in"><h2>Find out what your code owes.</h2><button class="cta" data-tool>Check your code ${ic('arrow',24)}</button></div></section>`;
}
