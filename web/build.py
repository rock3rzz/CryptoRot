import base64, json, re, sys, os
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB=os.path.join(ROOT,'web')
sys.path.insert(0,WEB)
sys.path.insert(0,os.path.join(ROOT,'engine'))
import adapter
os.chdir(ROOT)
def font(fam,slug,w):
    b=base64.b64encode(open(f'web/fonts/{slug}-latin-{w}-normal.woff2','rb').read()).decode()
    return f"@font-face{{font-family:'{fam}';font-weight:{w};font-style:normal;font-display:swap;src:url(data:font/woff2;base64,{b}) format('woff2')}}"
fonts='\n'.join([font('Familjen Grotesk','familjen-grotesk',w) for w in (400,500,600)]+[font('Commit Mono','commit-mono',w) for w in (400,500)])
data=json.load(open('web/data/findings.json'))
icon=open('web/assets/logo.svg').read()
logo=re.sub(r'viewBox="[^"]*"','viewBox="44 32 150 188"',icon,count=1)
eng={n:open(p).read() for n,p in [('rules.py','engine/rules.py'),('model.py','engine/model.py'),('ast_scanner.py','engine/ast_scanner.py'),('report.py','engine/report.py'),('selftest.py','engine/selftest.py'),('adapter.py','web/adapter.py')]}
import tempfile, shutil, report as _rep
_hw=tempfile.mkdtemp(); _code='import hashlib as h\n\nALGO = "md" + "5"\n\ndef fingerprint(data):\n    return h.new(ALGO, data).hexdigest()\n'
open(_hw+'/ex.py','w').write(_code)
_how=dict(code=_code.rstrip('\n'),finding=_rep.analyze(_hw)['findings'][0])
boot="""(function(){ requestAnimationFrame(exTick);const h=location.hash.slice(1); if(PAGES.includes(h)) S.page=h; render();})();"""
html=open('web/src/template.html').read()
for k,v in [('/*ENGINE*/',json.dumps(eng)),('/*FONTS*/',fonts),('/*DATA*/',json.dumps(data,separators=(',',':'))),('/*META*/',json.dumps(adapter.meta())),('/*HOW*/',json.dumps(_how)),
            ('/*APP*/',open('web/src/app.js').read()),('/*VIEWS*/',open('web/src/views.js').read()+open('web/src/motion.js').read()),('/*BOOT*/',boot),('/*LOGO*/',logo),('/*ICON64*/',base64.b64encode(icon.encode()).decode())]:
    html=html.replace(k,v) if k not in ('/*APP*/','/*VIEWS*/','/*BOOT*/') else html.replace(k,(lambda s:s)(v),1)
os.makedirs('public',exist_ok=True); open('public/index.html','w').write(html); print(len(html)//1024,'KB')
