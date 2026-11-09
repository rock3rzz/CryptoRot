/* ---------- icon set: 24px grid, square caps, one rust pixel per icon ---------- */
const ICON={
 scan:'<path d="M8 6 3 12l5 6M16 6l5 6-5 6"/><rect class="ac" x="10.75" y="10.75" width="2.5" height="2.5"/>',
 projects:'<rect x="3.5" y="3.5" width="7" height="7"/><rect x="13.5" y="3.5" width="7" height="7"/><rect x="3.5" y="13.5" width="7" height="7"/><rect class="ac" x="15" y="15" width="4" height="4"/>',
 benchmark:'<path d="M4 20V4M4 20h16"/><path d="M8.5 16v-4M12.5 16V9M16.5 16v-6"/><rect class="ac" x="11.25" y="5" width="2.5" height="2.5"/>',
 compare:'<rect x="3.5" y="4" width="7" height="16"/><rect x="13.5" y="4" width="7" height="16"/><rect class="ac" x="15.5" y="6" width="3" height="3"/>',
 selftest:'<rect x="3.5" y="3.5" width="17" height="17"/><path d="m7.5 12 3 3 6-6.5"/><rect class="ac" x="16" y="3.5" width="4.5" height="4.5" opacity="0"/>',
 how:'<rect x="3.5" y="4" width="5" height="5"/><rect class="ac" x="15.5" y="15" width="5" height="5"/><path d="M8.5 6.5h4.5a3 3 0 0 1 3 3V15"/>',
 now:'<rect x="3.5" y="3.5" width="17" height="17"/><path d="M12 7.5V12l3.5 2"/><rect class="ac" x="10.75" y="10.75" width="2.5" height="2.5"/>',
 year:'<rect x="3.5" y="5" width="17" height="15.5"/><path d="M3.5 10h17M8 3v4M16 3v4"/><rect class="ac" x="13.5" y="13" width="4" height="4"/>',
 quantum:'<path d="M12 3 21 12 12 21 3 12Z"/><path d="M12 8v8M8 12h8" opacity=".0"/><rect class="ac" x="10.5" y="10.5" width="3" height="3"/>',
 hash:'<path d="M9.5 4 7.5 20M16.5 4l-2 16M4 9h16M3.5 15h16"/><rect class="ac" x="17.5" y="17.5" width="3" height="3"/>',
 blocks:'<rect class="ac" x="3" y="6" width="5.5" height="12"/><rect class="ac" x="9.25" y="6" width="5.5" height="12"/><rect x="15.5" y="6" width="5.5" height="12"/>',
 key:'<rect x="3.5" y="8" width="8" height="8"/><path d="M11.5 12h9M17 12v3.5M20.5 12v2.5"/><rect class="ac" x="5.5" y="10" width="4" height="4"/>',
 lock:'<rect x="5" y="11" width="14" height="9.5"/><path d="M8.5 11V7.5a3.5 3.5 0 0 1 7 0V11"/><rect class="ac" x="11" y="14.5" width="2" height="3"/>',
 curve:'<path d="M3 19c6 0 5-14 9-14s3 14 9 14"/><rect class="ac" x="10.75" y="3" width="2.5" height="2.5"/>',
 swap:'<path d="M4 8h14M14 4l4 4-4 4M20 16H6M10 12l-4 4 4 4"/><rect class="ac" x="10.75" y="10.75" width="2.5" height="2.5" opacity="0"/>',
 json:'<path d="M9 4H7v5l-3 3 3 3v5h2M15 4h2v5l3 3-3 3v5h-2"/><rect class="ac" x="10.75" y="10.75" width="2.5" height="2.5"/>',
 cbom:'<path d="M4 6h16M4 12h16M4 18h9"/><rect class="ac" x="16" y="15.5" width="4" height="4"/>',
 sarif:'<path d="M5 21V4M5 5h13l-3 4 3 4H5"/><rect class="ac" x="8" y="7.5" width="3" height="3"/>',
 csv:'<rect x="3.5" y="4.5" width="17" height="15"/><path d="M3.5 10h17M3.5 15h17M10 4.5v15"/><rect class="ac" x="12" y="11.5" width="6" height="2.5" opacity="0"/>',
 small:'<rect x="3.5" y="3.5" width="17" height="17"/><rect class="ac" x="9" y="9" width="6" height="6"/>',
 arrow:'<path d="M4 12h15M13 6l6 6-6 6"/>',
 back:'<path d="M20 12H5M11 6l-6 6 6 6"/>'
};
const ic=(n,s=20)=>`<svg class="ic" width="${s}" height="${s}" viewBox="0 0 24 24" aria-hidden="true">${ICON[n]||''}</svg>`;
/* the rot mosaic used in the hero: a grid that dissolves from verdigris into rust */
function mosaic(){
  const C=15,Rw=10,S=38,G=6; let o='';
  for(let r=0;r<Rw;r++) for(let c=0;c<C;c++){
    if(c+r<2||(c>12&&r>7)) continue;
    const d=c-r*0.5, v=(c*7+r*13+c*r*3);
    const col=(d>=10&&v%2===0)?'#ce461a':(d>=8&&v%3!==0)?'#966c1e':'#1f6353';
    o+=`<rect x="${c*(S+G)}" y="${r*(S+G)}" width="${S}" height="${S}" fill="${col}"/>`;
  }
  return `<svg class="mos" viewBox="0 0 ${C*(S+G)} ${Rw*(S+G)}" aria-hidden="true">${o}</svg>`;
}
