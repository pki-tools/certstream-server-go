package certstream

// dashboardHTML is the static shell for /dashboard. All figures are fetched from
// /dashboard/data so switching time range never reloads the page.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CT Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:#f9f9f7;color:#0b0b0b;padding:24px 32px;min-height:100vh}
h1{font-size:1.375rem;font-weight:700;margin-bottom:4px;letter-spacing:-0.01em}
h2{font-size:0.8125rem;font-weight:600;color:#0b0b0b;margin-bottom:2px}
.sub{font-size:0.6875rem;color:#898781;margin-bottom:12px}
.meta{font-size:0.8125rem;color:#52514e;margin-bottom:16px}
.meta strong{color:#0b0b0b}

.rangebar{display:flex;gap:6px;align-items:center;margin-bottom:18px;flex-wrap:wrap}
.rangebar .lbl{font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;color:#898781;font-weight:600;margin-right:4px}
.rangebar button{border:1px solid #e1e0d9;background:#fff;color:#52514e;font:inherit;font-size:0.75rem;font-weight:600;padding:5px 13px;border-radius:7px;cursor:pointer}
.rangebar button:hover{border-color:#c3c2b7}
.rangebar button[aria-pressed=true]{background:#2a78d6;border-color:#2a78d6;color:#fff}

.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:18px}
.stat{background:#fff;border-radius:10px;padding:13px 16px;box-shadow:0 1px 3px rgba(11,11,11,.06),0 0 0 1px rgba(11,11,11,.05)}
.stat-label{font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;color:#898781;font-weight:600}
.stat-value{font-size:1.5rem;font-weight:700;color:#0b0b0b;margin-top:3px;line-height:1.15}
.stat-sub{font-size:0.6875rem;color:#898781;margin-top:2px}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px;margin-bottom:14px;align-items:start}
.card{background:#fff;border-radius:10px;padding:15px 17px 12px;box-shadow:0 1px 3px rgba(11,11,11,.06),0 0 0 1px rgba(11,11,11,.05)}
.chart{position:relative;width:100%}
.chart svg{display:block;width:100%;overflow:visible}

.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:8px}
.legend span{display:inline-flex;align-items:center;gap:6px;font-size:0.6875rem;color:#52514e}
.legend i{width:9px;height:9px;border-radius:2px;flex:none}

.tip{position:absolute;pointer-events:none;background:#fff;border:1px solid rgba(11,11,11,.12);border-radius:7px;
     box-shadow:0 3px 10px rgba(11,11,11,.13);padding:7px 10px;font-size:0.6875rem;color:#0b0b0b;z-index:5;
     white-space:nowrap;opacity:0;transition:opacity .08s}
.tip .tt{color:#898781;margin-bottom:3px}
.tip .tr{display:flex;align-items:center;gap:6px;line-height:1.5}
.tip .tr i{width:8px;height:8px;border-radius:2px;flex:none}
.tip .tv{font-weight:700;font-variant-numeric:tabular-nums;margin-left:auto;padding-left:12px}

table{width:100%;border-collapse:collapse;font-size:0.8125rem}
thead tr{background:#f9f9f7}
th{padding:8px 12px;text-align:left;color:#52514e;font-weight:600;font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
td{padding:8px 12px;border-top:1px solid #f0efec;white-space:nowrap}
td.num{font-variant-numeric:tabular-nums}
.muted{color:#898781}
.empty{padding:34px 10px;text-align:center;color:#898781;font-size:0.8125rem}
.wrap{overflow-x:auto}
@media(max-width:560px){body{padding:16px}.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>CT Dashboard</h1>
<p class="meta">
  Updated <strong id="gen">—</strong> &nbsp;·&nbsp;
  <span id="hist">—</span> &nbsp;·&nbsp;
  Auto-refreshes every 60 s
</p>

<div class="rangebar" role="group" aria-label="Time range">
  <span class="lbl">Range</span>
  <button data-r="1h">1 hour</button>
  <button data-r="12h">12 hours</button>
  <button data-r="24h" aria-pressed="true">24 hours</button>
  <button data-r="3d">3 days</button>
  <button data-r="7d">7 days</button>
</div>

<div class="stat-row" id="stats"></div>

<div class="grid">
  <div class="card">
    <h2>Ingestion rate</h2><p class="sub">Certificates + precertificates per second</p>
    <div class="chart" id="c-rate"></div>
  </div>
  <div class="card">
    <h2>Total backlog</h2><p class="sub">Entries behind, summed across all logs</p>
    <div class="chart" id="c-backlog"></div>
  </div>
  <div class="card">
    <h2>Backlog by log</h2><p class="sub">The five logs furthest behind right now</p>
    <div class="chart" id="c-laggards"></div>
  </div>
  <div class="card">
    <h2>Log health</h2><p class="sub">Logs caught up vs. logs behind</p>
    <div class="chart" id="c-health"></div>
  </div>
  <div class="card">
    <h2>Connected clients</h2><p class="sub">Websocket subscribers by stream type</p>
    <div class="chart" id="c-clients"></div>
  </div>
  <div class="card">
    <h2>Fastest logs</h2><p class="sub">Current entries per second</p>
    <div class="chart" id="c-toprate"></div>
  </div>
</div>

<div class="card">
  <h2>Logs furthest behind</h2><p class="sub">Current state, ranked by entries outstanding</p>
  <div class="wrap"><table>
    <thead><tr><th>Log</th><th>Operator</th><th>Type</th><th>Behind</th><th>Rate (e/s)</th><th>Est. catch-up</th></tr></thead>
    <tbody id="lagbody"></tbody>
  </table></div>
</div>

<script>
var NS = 'http://www.w3.org/2000/svg';
var P  = {blue:'#2a78d6', orange:'#eb6834', aqua:'#1baf7a', yellow:'#eda100', magenta:'#e87ba4', red:'#e34948'};
var INK = {grid:'#e1e0d9', axis:'#c3c2b7', muted:'#898781', surface:'#ffffff'};
var SERIES5 = [P.blue, P.orange, P.aqua, P.yellow, P.magenta];

var state = {range:'24h', data:null};

function mk(n, a){ var e=document.createElementNS(NS,n); for(var k in a){ e.setAttribute(k,a[k]); } return e; }

function fmtNum(v){
  v = Number(v)||0;
  var s = v<0 ? '-' : ''; v = Math.abs(v);
  if(v>=1e9) return s+(v/1e9).toFixed(v>=1e10?0:1)+'B';
  if(v>=1e6) return s+(v/1e6).toFixed(v>=1e7?0:1)+'M';
  if(v>=1e3) return s+(v/1e3).toFixed(v>=1e4?0:1)+'k';
  return s+String(Math.round(v));
}
function fmtRate(v){
  v = Number(v)||0;
  if(v>=100) return String(Math.round(v));
  if(v>=10)  return v.toFixed(1);
  return v.toFixed(2);
}
function fmtFull(v){ return (Number(v)||0).toLocaleString('en-US'); }
function fmtDur(s){
  if(s<0) return '—';
  if(s===0) return 'Live';
  var h=Math.floor(s/3600), m=Math.floor(s%3600/60);
  if(h>=24){ var d=Math.floor(h/24); return d+'d '+(h%24)+'h'; }
  if(h>0) return h+'h '+m+'m';
  if(m>0) return m+'m '+Math.floor(s%60)+'s';
  return Math.floor(s)+'s';
}
function fmtClock(ts){
  var d = new Date(ts*1000);
  var wide = state.range==='3d' || state.range==='7d';
  var hh = String(d.getHours()).padStart(2,'0'), mm = String(d.getMinutes()).padStart(2,'0');
  if(wide) return (d.getMonth()+1)+'/'+d.getDate()+' '+hh+':'+mm;
  return hh+':'+mm;
}
function niceMax(v){
  if(!(v>0)) return 1;
  var e = Math.pow(10, Math.floor(Math.log10(v))), f = v/e;
  var m = f<=1?1 : f<=2?2 : f<=2.5?2.5 : f<=5?5 : 10;
  return m*e;
}
function emptyNote(msg){
  var d = document.createElement('div');
  d.className='empty'; d.textContent = msg || 'Collecting data — charts fill in as samples are written.';
  return d;
}
// Rounded only on the data end; the baseline end stays square.
function barPath(x,y,w,h,r){
  r = Math.min(r, Math.max(w,0), h/2);
  if(w<=r) return 'M'+x+','+y+'h'+Math.max(w,0)+'v'+h+'h'+(-Math.max(w,0))+'Z';
  return 'M'+x+','+y+'H'+(x+w-r)+'a'+r+','+r+' 0 0 1 '+r+','+r+
         'V'+(y+h-r)+'a'+r+','+r+' 0 0 1 '+(-r)+','+r+'H'+x+'Z';
}
function tipFor(host){
  var t = host.querySelector('.tip');
  if(!t){ t=document.createElement('div'); t.className='tip'; host.appendChild(t); }
  return t;
}
function placeTip(host, tip, px, py){
  var hw = host.clientWidth, tw = tip.offsetWidth;
  var x = px + 14; if(x + tw > hw) x = px - tw - 14; if(x < 0) x = 0;
  tip.style.left = x+'px';
  tip.style.top  = Math.max(0, py - tip.offsetHeight - 10)+'px';
  tip.style.opacity = 1;
}
function legendFor(card, series){
  var old = card.querySelector('.legend'); if(old) old.remove();
  if(series.length < 2) return;
  var l = document.createElement('div'); l.className='legend';
  series.forEach(function(s){
    var sp=document.createElement('span');
    var i=document.createElement('i'); i.style.background=s.color;
    sp.appendChild(i); sp.appendChild(document.createTextNode(s.name));
    l.appendChild(sp);
  });
  card.appendChild(l);
}

// timeChart renders a line or stacked-area chart with a crosshair tooltip.
// cfg: {ts:[unix], series:[{name,color,vals:[]}], stacked:bool, area:bool, fmt:fn}
function timeChart(host, cfg){
  host.innerHTML='';
  var ts = cfg.ts||[], series = (cfg.series||[]).filter(function(s){ return s.vals && s.vals.length; });
  legendFor(host.parentNode, series);
  if(!ts.length || !series.length){ host.appendChild(emptyNote()); return; }

  var fmt = cfg.fmt || fmtNum;
  var W = host.clientWidth||600, H = 190, m = {t:10, r:12, b:22, l:54};
  var iw = Math.max(W-m.l-m.r, 10), ih = H-m.t-m.b;
  var n = ts.length;

  // Stacked series are plotted as cumulative tops, drawn back-to-front.
  var tops = series.map(function(s, si){
    return ts.map(function(_, i){
      var v = Number(s.vals[i])||0;
      if(cfg.stacked){ for(var k=0;k<si;k++){ v += Number(series[k].vals[i])||0; } }
      return v;
    });
  });

  var peak = 0;
  tops.forEach(function(arr){ arr.forEach(function(v){ if(v>peak) peak=v; }); });
  var ymax = niceMax(peak);

  var x = function(i){ return n===1 ? m.l+iw/2 : m.l + iw*i/(n-1); };
  var y = function(v){ return m.t + ih - ih*(Number(v)||0)/ymax; };

  var svg = mk('svg',{viewBox:'0 0 '+W+' '+H, height:H, role:'img'});

  // Recessive grid + y ticks.
  for(var g=0; g<=4; g++){
    var gv = ymax*g/4, gy = y(gv);
    svg.appendChild(mk('line',{x1:m.l, x2:m.l+iw, y1:gy, y2:gy,
      stroke: g===0?INK.axis:INK.grid, 'stroke-width':1}));
    var tl = mk('text',{x:m.l-8, y:gy+3.5, 'text-anchor':'end', fill:INK.muted,
      'font-size':10, 'font-variant-numeric':'tabular-nums'});
    // Axis ticks stay compact whole numbers; the tooltip carries the precise value.
    tl.textContent = fmtNum(gv); svg.appendChild(tl);
  }

  // X ticks, thinned to avoid collisions on narrow cards.
  var xticks = Math.max(2, Math.min(5, Math.floor(iw/95)));
  for(var t=0; t<=xticks; t++){
    var idx = Math.round((n-1)*t/xticks);
    var xt = mk('text',{x:x(idx), y:H-6, 'text-anchor': t===0?'start':(t===xticks?'end':'middle'),
      fill:INK.muted, 'font-size':10, 'font-variant-numeric':'tabular-nums'});
    xt.textContent = fmtClock(ts[idx]); svg.appendChild(xt);
  }

  function line(arr){
    return arr.map(function(v,i){ return (i?'L':'M')+x(i).toFixed(1)+','+y(v).toFixed(1); }).join('');
  }

  for(var si=series.length-1; si>=0; si--){
    var s = series[si], top = tops[si], d = line(top);

    if(cfg.stacked || cfg.area){
      var base = cfg.stacked && si>0
        ? tops[si-1].map(function(v,i){ return 'L'+x(i).toFixed(1)+','+y(v).toFixed(1); }).reverse().join('')
        : 'L'+x(n-1).toFixed(1)+','+y(0)+'L'+x(0).toFixed(1)+','+y(0);
      svg.appendChild(mk('path',{d:d+base+'Z', fill:s.color,
        'fill-opacity': cfg.stacked?0.82:0.13}));
      // 2px surface gap so adjacent stacked fills never touch.
      if(cfg.stacked) svg.appendChild(mk('path',{d:d, fill:'none', stroke:INK.surface, 'stroke-width':2.5}));
    }
    svg.appendChild(mk('path',{d:d, fill:'none', stroke:s.color, 'stroke-width':2,
      'stroke-linejoin':'round', 'stroke-linecap':'round'}));
  }

  // Crosshair layer.
  var cross = mk('line',{y1:m.t, y2:m.t+ih, stroke:INK.axis, 'stroke-width':1, opacity:0});
  svg.appendChild(cross);
  var dots = series.map(function(s){
    var c = mk('circle',{r:4, fill:s.color, stroke:INK.surface, 'stroke-width':2, opacity:0});
    svg.appendChild(c); return c;
  });

  var hit = mk('rect',{x:m.l, y:m.t, width:iw, height:ih, fill:'transparent'});
  svg.appendChild(hit);
  var tip = tipFor(host);

  hit.addEventListener('mousemove', function(ev){
    var r = svg.getBoundingClientRect();
    var px = (ev.clientX - r.left) * (W / r.width);
    var i = n===1 ? 0 : Math.round((px - m.l) / iw * (n-1));
    i = Math.max(0, Math.min(n-1, i));

    cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('opacity', 1);

    var html = '<div class="tt">'+fmtClock(ts[i])+'</div>';
    series.forEach(function(s, si){
      dots[si].setAttribute('cx', x(i)); dots[si].setAttribute('cy', y(tops[si][i]));
      dots[si].setAttribute('opacity', 1);
      html += '<div class="tr"><i style="background:'+s.color+'"></i>'+s.name+
              '<span class="tv">'+fmt(s.vals[i])+'</span></div>';
    });
    tip.innerHTML = html;
    placeTip(host, tip, x(i) * (r.width / W), y(tops[0][i]) * (r.height / H));
  });
  hit.addEventListener('mouseleave', function(){
    cross.setAttribute('opacity',0);
    dots.forEach(function(d){ d.setAttribute('opacity',0); });
    tip.style.opacity = 0;
  });

  host.appendChild(svg);
}

// hbarChart renders a horizontal bar chart with per-bar hover tooltips.
// cfg: {items:[{label,value,sub}], color, fmt}
function hbarChart(host, cfg){
  host.innerHTML='';
  var old = host.parentNode.querySelector('.legend'); if(old) old.remove();
  var items = cfg.items||[];
  if(!items.length){ host.appendChild(emptyNote(cfg.emptyMsg)); return; }

  var fmt = cfg.fmt||fmtNum;
  var W = host.clientWidth||600, rowH = 30, barH = 15;
  var labelW = Math.min(170, Math.max(90, Math.round(W*0.32)));
  var valueW = 62, pad = 10;
  var iw = Math.max(W - labelW - valueW - pad, 10);
  var H = items.length*rowH + 6;
  var peak = niceMax(Math.max.apply(null, items.map(function(d){ return Number(d.value)||0; })));

  var svg = mk('svg',{viewBox:'0 0 '+W+' '+H, height:H, role:'img'});
  host.appendChild(svg); // must be in the document before text can be measured
  var tip = tipFor(host);

  items.forEach(function(d, i){
    var y0 = i*rowH + 4, w = iw * (Number(d.value)||0) / peak;

    var lab = mk('text',{x:0, y:y0+barH/2+4, fill:'#52514e', 'font-size':11});
    lab.textContent = d.label;
    svg.appendChild(lab);

    // Trim to the real rendered width so a long log name never runs under its bar.
    var maxW = labelW - 12, s = d.label;
    while(s.length > 1 && lab.getComputedTextLength() > maxW){
      s = s.slice(0, -1);
      lab.textContent = s + '…';
    }
    lab.appendChild(mk('title',{})).textContent = d.label;

    // Track behind the bar gives the row a readable extent at low values.
    svg.appendChild(mk('rect',{x:labelW, y:y0, width:iw, height:barH, rx:4, fill:'#f0efec'}));
    svg.appendChild(mk('path',{d:barPath(labelW, y0, w, barH, 4), fill:cfg.color}));

    var val = mk('text',{x:W, y:y0+barH/2+4, 'text-anchor':'end', fill:'#0b0b0b',
      'font-size':11, 'font-weight':600, 'font-variant-numeric':'tabular-nums'});
    val.textContent = fmt(d.value); svg.appendChild(val);

    var hit = mk('rect',{x:0, y:y0-4, width:W, height:rowH, fill:'transparent'});
    hit.addEventListener('mousemove', function(ev){
      var r = svg.getBoundingClientRect();
      tip.innerHTML = '<div class="tt">'+d.label+'</div><div class="tr"><i style="background:'+cfg.color+
        '"></i>'+(d.sub||'Value')+'<span class="tv">'+fmtFull(d.value)+'</span></div>';
      placeTip(host, tip, ev.clientX-r.left, ev.clientY-r.top);
    });
    hit.addEventListener('mouseleave', function(){ tip.style.opacity=0; });
    svg.appendChild(hit);
  });
}

function renderStats(s){
  var live = s.logsTotal ? Math.round(s.logsLive/s.logsTotal*100) : 0;
  var tiles = [
    ['Current rate',  fmtRate(s.currentRate),  'certs/sec'],
    ['Peak in window',fmtRate(s.peakRate),     'certs/sec'],
    ['Average',       fmtRate(s.avgRate),      'certs/sec'],
    ['Seen in window',fmtNum(s.certsInWindow), fmtFull(s.certsInWindow)+' certificates'],
    ['Total backlog', fmtNum(s.totalBehind),   fmtFull(s.totalBehind)+' entries behind'],
    ['Logs caught up',s.logsLive+' / '+s.logsTotal, live+'% live · '+s.logsBehind+' behind'],
    ['Clients',       String(s.clientsNow),    'connected now'],
    ['Processed',     fmtNum(s.processedTotal),'since start']
  ];
  document.getElementById('stats').innerHTML = tiles.map(function(t){
    return '<div class="stat"><div class="stat-label">'+t[0]+'</div>'+
           '<div class="stat-value">'+t[1]+'</div><div class="stat-sub">'+t[2]+'</div></div>';
  }).join('');
}

function renderTable(rows){
  var b = document.getElementById('lagbody');
  if(!rows.length){
    b.innerHTML = '<tr><td colspan="6" class="empty">Every log is caught up.</td></tr>';
    return;
  }
  b.innerHTML = rows.map(function(r){
    return '<tr><td>'+r.name+'</td><td class="muted">'+r.operator+'</td><td class="muted">'+r.type+'</td>'+
      '<td class="num">'+fmtFull(r.behind)+'</td><td class="num">'+fmtRate(r.rate)+'</td>'+
      '<td class="num">'+fmtDur(r.etaSecs)+'</td></tr>';
  }).join('');
}

function render(){
  var d = state.data; if(!d) return;

  document.getElementById('gen').textContent = d.generatedAt;
  var h = d.stats.historySecs;
  document.getElementById('hist').textContent = d.stats.sampleCount
    ? fmtFull(d.stats.sampleCount)+' samples over '+fmtDur(h)
    : 'No samples stored yet';

  renderStats(d.stats);
  renderTable(d.topLagging);

  timeChart(document.getElementById('c-rate'), {
    ts:d.ts, area:true, fmt:fmtRate,
    series:[{name:'Rate', color:P.blue, vals:d.rate}]});

  timeChart(document.getElementById('c-backlog'), {
    ts:d.ts, area:true, fmt:fmtNum,
    series:[{name:'Backlog', color:P.orange, vals:d.backlog}]});

  timeChart(document.getElementById('c-laggards'), {
    ts:d.ts, fmt:fmtNum,
    series:(d.laggards||[]).map(function(s,i){
      return {name:s.name, color:SERIES5[i%SERIES5.length], vals:s.vals}; })});

  timeChart(document.getElementById('c-health'), {
    ts:d.ts, fmt:fmtNum, series:[
      {name:'Caught up', color:P.blue, vals:d.logsLive},
      {name:'Behind',    color:P.red,  vals:d.logsBehind}]});

  timeChart(document.getElementById('c-clients'), {
    ts:d.ts, stacked:true, fmt:fmtNum, series:[
      {name:'Full',        color:P.blue,   vals:d.clientsFull},
      {name:'Lite',        color:P.orange, vals:d.clientsLite},
      {name:'Domains only',color:P.aqua,   vals:d.clientsDomain}]});

  hbarChart(document.getElementById('c-toprate'), {
    color:P.blue, fmt:fmtRate, sub:'Rate', emptyMsg:'No rate readings yet.',
    items:(d.topRate||[]).map(function(r){ return {label:r.name, value:r.rate, sub:'Entries/sec'}; })});
}

function load(){
  fetch('/dashboard/data?range='+encodeURIComponent(state.range))
    .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
    .then(function(d){ state.data = d; render(); })
    .catch(function(e){ console.error('dashboard load failed', e); });
}

document.querySelectorAll('.rangebar button').forEach(function(b){
  b.addEventListener('click', function(){
    document.querySelectorAll('.rangebar button').forEach(function(o){ o.removeAttribute('aria-pressed'); });
    b.setAttribute('aria-pressed','true');
    state.range = b.dataset.r;
    load();
  });
});

var rt; window.addEventListener('resize', function(){ clearTimeout(rt); rt=setTimeout(render,150); });
setInterval(load, 60000);
load();
</script>
</body>
</html>`
