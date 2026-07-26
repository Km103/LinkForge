package metrics

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LinkForge Control Deck</title>
<style>
:root{color-scheme:dark;--bg:#07111b;--panel:#0d1b28;--line:#203446;--text:#e8f1f7;--muted:#89a0b3;--cyan:#3ad6e7;--lime:#b8f36b;--red:#ff6b7d;--amber:#ffc857}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% -10%,#17344d 0,transparent 38%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,sans-serif;min-height:100vh}
.shell{width:min(1180px,calc(100% - 32px));margin:auto;padding:28px 0 48px}.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px}.brand{display:flex;gap:13px;align-items:center}.mark{width:43px;height:43px;display:grid;place-items:center;border:1px solid #3ad6e744;background:#3ad6e710;clip-path:polygon(25% 0,100% 0,75% 100%,0 100%)}.mark:before{content:"";width:19px;height:19px;border:3px solid var(--cyan);border-left-color:var(--lime);transform:rotate(45deg)}h1{font-size:20px;letter-spacing:.04em;margin:0}.subtitle{color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase}.actions{display:flex;align-items:center;gap:10px}.state{display:flex;align-items:center;gap:9px;border:1px solid var(--line);background:#0b1823;padding:8px 12px;border-radius:999px}.dot{width:8px;height:8px;border-radius:50%;background:var(--amber);box-shadow:0 0 12px currentColor}.state.ready .dot,.healthy .dot{background:var(--lime)}.state.down .dot,.unhealthy .dot{background:var(--red)}button{border:0;border-radius:999px;padding:10px 16px;font-weight:700;background:linear-gradient(90deg,var(--cyan),var(--lime));color:#07111b;cursor:pointer}button.stop{background:var(--red);color:white}button:disabled{opacity:.45;cursor:wait}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:linear-gradient(145deg,#102231dd,#0b1722ee);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 18px 50px #0003}.metric{grid-column:span 3;min-height:118px}.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}.value{font-size:31px;font-weight:650;letter-spacing:-.04em;margin-top:13px}.unit{font-size:12px;color:var(--muted);margin-left:5px}.chart{grid-column:span 8;min-height:292px}.health{grid-column:span 4;min-height:292px}.paths{grid-column:1/-1}.head{display:flex;align-items:center;justify-content:space-between;margin-bottom:15px}.head h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;margin:0}.tag{font:11px ui-monospace,monospace;color:var(--cyan);border:1px solid #3ad6e744;padding:3px 7px;border-radius:5px}canvas{width:100%;height:220px}.health-list{display:grid;gap:14px;margin-top:22px}.health-row{display:flex;justify-content:space-between;padding-bottom:12px;border-bottom:1px solid var(--line)}.health-row span:last-child{font-family:ui-monospace,monospace}
table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--muted);font-size:10px;letter-spacing:.1em;text-transform:uppercase;font-weight:500;padding:10px 8px;border-bottom:1px solid var(--line)}td{padding:14px 8px;border-bottom:1px solid #20344688;font-variant-numeric:tabular-nums}.path-state{display:flex;align-items:center;gap:9px}.bar{width:100%;max-width:190px;height:6px;border-radius:4px;background:#1b3041;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--cyan),var(--lime));border-radius:4px}.empty{text-align:center;color:var(--muted);padding:30px}.foot{color:var(--muted);font-size:11px;margin-top:14px;display:flex;justify-content:space-between}
@media(max-width:800px){.metric{grid-column:span 6}.chart,.health{grid-column:1/-1}.shell{width:min(100% - 20px,1180px)}.table-wrap{overflow-x:auto}table{min-width:760px}}
</style>
</head>
<body><main class="shell">
<header class="top"><div class="brand"><div class="mark"></div><div><h1>LINKFORGE</h1><div class="subtitle">Multipath control deck</div></div></div><div class="actions"><button id="control" hidden>Aggregate traffic</button><div id="state" class="state"><i class="dot"></i><span>Standby</span></div></div></header>
<section class="grid">
<article class="card metric"><div class="label">Combined uplink</div><div class="value" id="up">0.00<span class="unit">Mbps</span></div></article>
<article class="card metric"><div class="label">Combined downlink</div><div class="value" id="down">0.00<span class="unit">Mbps</span></div></article>
<article class="card metric"><div class="label">Healthy paths</div><div class="value" id="paths">0 / 0</div></article>
<article class="card metric"><div class="label">Transferred</div><div class="value" id="total">0<span class="unit">B</span></div></article>
<article class="card chart"><div class="head"><h2>Bonded throughput</h2><span class="tag" id="role">—</span></div><canvas id="chart"></canvas></article>
<article class="card health"><div class="head"><h2>Integrity</h2><span class="tag">LIVE</span></div><div class="health-list">
<div class="health-row"><span>Authentication failures</span><span id="auth">0</span></div>
<div class="health-row"><span>No-path drops</span><span id="drops">0</span></div>
<div class="health-row"><span>Reorder skips</span><span id="reorder">0</span></div>
<div class="health-row"><span>Invalid packets</span><span id="invalid">0</span></div>
<div class="health-row"><span>TUN errors</span><span id="tunerr">0</span></div>
<div class="health-row"><span>Active sessions</span><span id="sessions">0</span></div>
</div></article>
<article class="card paths"><div class="head"><h2>Transport paths</h2><span class="tag">ADAPTIVE WEIGHTED RR</span></div><div class="table-wrap"><table><thead><tr><th>Path</th><th>State</th><th>RTT</th><th>Sent</th><th>Received</th><th>Traffic share</th><th>Errors</th></tr></thead><tbody id="rows"></tbody></table></div></article>
</section><footer class="foot"><span>Refresh 1s · /api/v1/status · /metrics</span><span id="uptime">Uptime —</span></footer>
</main>
<script>
const $=id=>document.getElementById(id),history=[],maxPoints=90,controlToken='__CONTROL_TOKEN__';let previous=null,previousAt=0,busy=false;
const fmtBytes=n=>{const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1000&&i<u.length-1){n/=1000;i++}return n.toFixed(i?1:0)+' '+u[i]};
const fmtRate=n=>(n*8/1e6).toFixed(2);
function render(s,now){s.paths=Array.isArray(s.paths)?s.paths:[];const elapsed=previous?Math.max((now-previousAt)/1000,.001):1,up=previous?(s.sent_bytes-previous.sent_bytes)/elapsed:0,down=previous?(s.received_bytes-previous.received_bytes)/elapsed:0;
 $('up').innerHTML=fmtRate(up)+'<span class="unit">Mbps</span>';$('down').innerHTML=fmtRate(down)+'<span class="unit">Mbps</span>';
 const healthy=s.paths.filter(p=>p.healthy).length;$('paths').textContent=healthy+' / '+s.paths.length;$('total').textContent=fmtBytes(s.sent_bytes+s.received_bytes);$('role').textContent=s.role.toUpperCase();
 $('auth').textContent=s.auth_failures;$('drops').textContent=s.no_path_drops;$('reorder').textContent=s.reorder_skips;$('invalid').textContent=s.invalid_packets;$('tunerr').textContent=s.tun_read_errors+s.tun_write_errors;$('sessions').textContent=s.active_sessions;
 $('uptime').textContent='Uptime '+formatTime(s.uptime_seconds);const state=$('state');state.className='state '+(s.ready?'ready':(s.control&&s.control.state==='error'?'down':''));state.querySelector('span').textContent=s.ready?'Traffic aggregated':(s.control?s.control.state.replace('_',' '):'Telemetry ready');const button=$('control');if(s.control){button.hidden=false;button.disabled=busy||['calibrating','starting','stopping'].includes(s.control.state);const active=['running','starting','calibrating'].includes(s.control.state);button.textContent=active?'Stop aggregation':'Aggregate traffic';button.className=active?'stop':'';button.dataset.action=active?'stop':'start';button.title=s.control.error||''}else{button.hidden=true}
 history.push({up,down});if(history.length>maxPoints)history.shift();draw();
 const totalPath=Math.max(1,s.paths.reduce((a,p)=>a+p.sent_bytes+p.received_bytes,0));$('rows').innerHTML=s.paths.length?s.paths.map(p=>"<tr><td><strong>"+escapeHTML(p.name)+"</strong></td><td><span class='path-state "+(p.healthy?"healthy":"unhealthy")+"'><i class='dot'></i>"+(p.healthy?"Healthy":"Unavailable")+"</span></td><td>"+(p.rtt_ms?p.rtt_ms.toFixed(1)+" ms":"—")+"</td><td>"+fmtBytes(p.sent_bytes)+"</td><td>"+fmtBytes(p.received_bytes)+"</td><td><div class='bar'><i style='width:"+Math.max(2,(p.sent_bytes+p.received_bytes)*100/totalPath)+"%'></i></div></td><td>"+(p.auth_failures+p.replay_drops+p.write_errors)+"</td></tr>").join(''):'<tr><td colspan="7" class="empty">Waiting for authenticated paths…</td></tr>';previous=s;previousAt=now}
function draw(){const c=$('chart'),d=devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;c.width=w*d;c.height=h*d;const x=c.getContext('2d');x.scale(d,d);x.clearRect(0,0,w,h);x.strokeStyle='#203446';x.lineWidth=1;for(let i=1;i<5;i++){x.beginPath();x.moveTo(0,h*i/5);x.lineTo(w,h*i/5);x.stroke()}const peak=Math.max(1,...history.flatMap(p=>[p.up,p.down]));[['up','#b8f36b'],['down','#3ad6e7']].forEach(([key,color])=>{x.beginPath();history.forEach((p,i)=>{const px=i*w/(maxPoints-1),py=h-(p[key]/peak)*(h-15)-7;i?x.lineTo(px,py):x.moveTo(px,py)});x.strokeStyle=color;x.lineWidth=2;x.stroke()})}
const formatTime=s=>{s=Math.floor(s);const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h+'h '+m+'m'};const escapeHTML=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function poll(){try{const r=await fetch('/api/v1/status',{cache:'no-store'});if(!r.ok)throw Error(r.status);render(await r.json(),performance.now())}catch(e){const s=$('state');s.className='state down';s.querySelector('span').textContent='Telemetry offline'}setTimeout(poll,1000)}poll();addEventListener('resize',draw);
$('control').addEventListener('click',async()=>{busy=true;const b=$('control');b.disabled=true;try{const r=await fetch('/api/v1/control/'+b.dataset.action,{method:'POST',headers:{'X-LinkForge-Control':controlToken}});const body=await r.json();if(!r.ok)throw Error(body.error||r.status)}catch(e){b.title=e.message}finally{busy=false}});
</script></body></html>`
