/* Home-page map of database-wide detection associations. No AI/network egress. */
(function(global){
 'use strict';
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const num=v=>Number(v||0).toLocaleString(),time=v=>v==null?'Unknown':new Date(v*1000).toLocaleString();
 const responseCache=new Map();
 function geometry(data){
  const nodes=new Map(data.nodes.map(n=>[n.id,{...n}]));
  const groups=['ip','account','host'].map(kind=>[...nodes.values()].filter(n=>n.kind===kind).sort((a,b)=>a.label.localeCompare(b.label)));
  const headings=[];let left=30,height=600;
  groups.forEach((group,k)=>{const cols=Math.max(2,Math.min(16,Math.ceil(Math.sqrt(group.length)))),width=cols*110+50;
   headings.push({x:left+width/2,label:['IP ENDPOINTS','ACCOUNTS','ASSETS / INTERNAL ENDPOINTS'][k]});
   group.forEach((n,i)=>{n.x=left+65+(i%cols)*110;n.y=135+Math.floor(i/cols)*88});
   height=Math.max(height,Math.ceil(group.length/cols)*88+170);left+=width+45;
  });
  return {nodes,width:Math.max(1000,left),height,headings,edges:data.edges.map((e,i)=>({...e,id:'o-link-'+i}))};
 }
 function drawing(data,g){
  let out=`<svg class="overview-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.width} ${g.height}" tabindex="0" role="group" aria-label="All-incident evidence map. Select nodes or edges for details; plus/minus zoom, arrows pan, Home fits."><defs><pattern id="overview-dots" width="25" height="25" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".7" fill="#36424f"/></pattern><marker id="overview-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0L10 5L0 10z" fill="#8ea7c8"/></marker></defs><rect width="${g.width}" height="${g.height}" fill="#121a23"/><rect width="${g.width}" height="${g.height}" fill="url(#overview-dots)"/>`;
  for(const {x,label} of g.headings)out+=`<text x="${x}" y="48" text-anchor="middle" fill="#92a7c1" font-size="13" font-family="system-ui,sans-serif" letter-spacing="1.4">${label}</text>`;
  for(const e of g.edges){
   const a=g.nodes.get(e.source),b=g.nodes.get(e.target);if(!a||!b)continue;
   const bend=(a.x+b.x)/2,offset=e.relation==='account'?0:-25;
   const path=`M${a.x} ${a.y} C${bend} ${a.y+offset},${bend} ${b.y+offset},${b.x} ${b.y}`;
   out+=`<g class="overview-edge" data-o-edge="${e.id}" tabindex="0" role="button" aria-label="${esc(a.label+' to '+b.label+', '+e.detections+' detections, '+e.hosts+' hosts in evidence')}"><title>${esc(a.label+' → '+b.label+' | '+num(e.detections)+' detections | '+num(e.hosts)+' hosts | '+num(e.impact_signals)+' impact signals')}</title><path class="o-flow" d="${path}" fill="none" stroke="${e.impact_signals?'#e59a9e':'#8eace1'}" stroke-width="1.3" marker-end="url(#overview-arrow)"/><path class="o-hit" d="${path}" fill="none" stroke="transparent" stroke-width="13"/><g class="o-edge-label"><rect x="${bend-29}" y="${(a.y+b.y)/2-11+offset*.75}" width="58" height="22" rx="5" fill="#253345"/><text x="${bend}" y="${(a.y+b.y)/2+4+offset*.75}" text-anchor="middle" fill="#e2ebfa" font-size="11" font-family="monospace">${num(e.detections)}</text></g></g>`;
  }
  for(const n of g.nodes.values()){
   const color=n.kind==='account'?'#b5a0e8':n.kind==='ip'?'#d8b17d':n.impact_signals?'#e99da4':'#85b8eb';
   const label=n.label.length>19?n.label.slice(0,17)+'…':n.label;
   out+=`<g class="overview-node" data-o-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(n.label+', '+n.detections+' detections, '+n.incidents+' incidents')}"><title>${esc(n.label+' | '+num(n.detections)+' detections | '+num(n.incidents)+' incidents')}</title><circle class="o-halo" cx="${n.x}" cy="${n.y}" r="29" fill="none" stroke="${color}" opacity=".16"/><circle cx="${n.x}" cy="${n.y}" r="20" fill="#213046" stroke="${color}" stroke-width="2"/><text x="${n.x}" y="${n.y+4}" text-anchor="middle" fill="${color}" font-size="11" font-family="system-ui,sans-serif">${n.kind==='host'?'H':n.kind==='account'?'U':'IP'}</text><text x="${n.x}" y="${n.y+40}" text-anchor="middle" fill="#dce7f6" font-size="12" font-family="monospace">${esc(label)}</text><text x="${n.x}" y="${n.y+55}" text-anchor="middle" fill="#91a5bf" font-size="10" font-family="system-ui,sans-serif">${num(n.detections)} detections</text></g>`;
  }
  if(!g.nodes.size)out+='<text x="695" y="250" text-anchor="middle" fill="#9fb2ca" font-family="system-ui,sans-serif">No detection evidence for this scope</text>';
  return out+'</svg>';
 }
 function metricCards(t={}){return [['Asset identities',t.assets??t.hosts],['Accounts involved',t.accounts],['Incidents',t.incidents],['Detections',t.detections],['Impact signals',t.impact_signals],['Remaining unaffected',null]].map(([label,value])=>`<div><strong>${value==null?'Unknown':num(value)}</strong><span>${label}</span></div>`).join('')}
 function shell(){return `<section class="evidence-workspace overview-workspace" aria-label="Full incident overview graph"><div class="graph-heading"><div><span class="o-kicker">ALL-INCIDENT EXPLORER</span><h3>Attack activity overview</h3><p>One map of hosts, accounts and IPs across the analysis</p></div><div class="graph-tools"><button data-o-action="play" aria-pressed="false">Animate activity</button><button data-o-action="out" aria-label="Zoom out">−</button><output class="o-zoom">100%</output><button data-o-action="in" aria-label="Zoom in">+</button><button data-o-action="fit">Fit</button><button data-o-action="clear">Clear</button><button data-o-action="expand">Expand</button></div></div><div class="graph-metrics o-metrics">${metricCards()}</div><div class="graph-filters"><label>Scope <select class="o-status"><option value="active">Active incidents</option><option value="suppressed">Suppressed signals</option><option value="all">All findings</option></select></label><label>Stage <select class="o-stage"><option value="">All stages</option><option value="0">Initial attempts</option><option value="1">Persistent foothold</option><option value="2">Exploration</option><option value="3">Propagation</option><option value="4">Exfiltration / impact</option></select></label><label class="o-find-label"><input class="o-find" aria-label="Find a host, account or IP in the overview graph" placeholder="Find host, account or IP"><button data-o-action="find">Find</button></label><span class="o-progress" role="status">Loading graph...</span></div><div class="graph-body"><div class="graph-canvas o-canvas"></div><aside class="graph-inspector o-inspector" aria-live="polite"><h4>Explore the full picture</h4><p>Click a node to review its attack techniques and related incidents. Click a connection to inspect its event counts and affected host signals.</p><p>Confirmed exploitation and remaining unaffected assets are unknown without independent evidence and an inventory.</p></aside></div><div class="graph-foot"><span>H Host · U Account · IP Endpoint · Red: impact signals present</span><span>Line animation illustrates associations; it is not a chronological replay.</span></div><p class="graph-scope o-scope">Database-wide summaries. Detection signals do not prove exploitation or damage.</p></section>`}
 function detailHTML(detail,heading,totals={}){
  const m=detail.metrics||{},share=totals.detections?Math.min(100,(m.detections||0)/totals.detections*100):0;
  return `<span class="graph-inspect-label">SELECTED EVIDENCE</span><h4>${esc(heading)}</h4><div class="o-share"><span>${share.toFixed(1)}% of scoped detections</span><i style="width:${share}%"></i></div><dl><dt>Detections / matching events</dt><dd>${num(m.detections)} / ${num(m.matching_events)}</dd><dt>Asset identities linked</dt><dd>${num(m.assets??m.hosts)}</dd><dt>Accounts involved</dt><dd>${num(m.accounts)}</dd><dt>Related incidents</dt><dd>${num(m.incidents)}</dd><dt>Impact technique signals</dt><dd>${num(m.impact_signals)}</dd><dt>Provider-reported alerts</dt><dd>${num(m.provider_reports)}</dd><dt>Confirmed exploited</dt><dd>Unknown</dd><dt>Remaining unaffected</dt><dd>Unknown</dd><dt>First / last observed</dt><dd>${esc(time(m.first))}<br>${esc(time(m.last))}</dd></dl><p class="r2">Impact signals are not confirmed damage. An inventory and independent validation are required to measure remaining/unaffected assets.</p><h5>Attack techniques detected</h5>${(detail.techniques||[]).map(t=>`<div class="o-technique"><strong>${esc(t.technique)} <b>${num(t.detections)}</b></strong><span>${esc(t.name)}</span><small>${esc(t.tactic)}</small></div>`).join('')||'<p>No matching detections.</p>'}<h5>Related incidents · top 12</h5>${(detail.incidents||[]).map(i=>`<a class="o-incident" href="#incident/${encodeURIComponent(i.id)}"><b>${esc(i.name)}</b><span>Risk ${num(i.risk)} · ${num(i.detections)} detections · #${esc(i.id)}</span></a>`).join('')}<h5>Source evidence · first eight detections</h5><ol>${(detail.evidence||[]).map(e=>`<li><b>${esc(e.technique)}</b> ${esc(e.rule_name)}<small>${esc(e.file)} @ byte ${esc(e.offset)}</small></li>`).join('')}</ol>`;
 }
 function mount(root,options){
  if(!root)return;root.innerHTML=shell();let data=null,g=null,box=null,drag=null,request=0,selection=0,alive=true,playing=false;const cache=new Map();
  const q=s=>root.querySelector(s),status=()=>q('.o-status').value||'active',stage=()=>q('.o-stage').value;
  const query=()=>new URLSearchParams({status:status(),...(stage()===''?{}:{stage:stage()})});
  function fetchData(endpoint){const key=String(options.generation||'')+endpoint;if(responseCache.has(key))return responseCache.get(key);const pending=options.api(endpoint).catch(error=>{responseCache.delete(key);throw error});responseCache.set(key,pending);if(responseCache.size>32)responseCache.delete(responseCache.keys().next().value);return pending}
  function setBox(){q('svg')?.setAttribute('viewBox',`${box.x} ${box.y} ${box.w} ${box.h}`);q('.o-zoom').textContent=Math.round(g.width/box.w*100)+'%'}
  function fit(){if(!g)return;box={x:0,y:0,w:g.width,h:g.height};setBox()}
  function zoom(factor){if(!box)return;const w=Math.max(g.width/15,Math.min(g.width*2,box.w*factor)),ratio=w/box.w;box={x:box.x+(box.w-w)/2,y:box.y+(box.h-box.h*ratio)/2,w,h:box.h*ratio};setBox()}
  function clear(){selection++;root.querySelectorAll('.overview-node,.overview-edge').forEach(el=>el.classList.remove('o-dim','o-selected'));q('.o-inspector').innerHTML='<h4>Explore the full picture</h4><p>Select a host, account, IP or connection for techniques, impact signals, related incidents and source evidence.</p><p>Remaining/unaffected assets and confirmed exploitation are unknown.</p>'}
  async function load(){
   const version=++request;selection++;cache.clear();q('.o-progress').textContent='Loading graph...';
   try{const result=await fetchData('/overview/graph?'+query());if(!alive||version!==request)return;
    data=result;g=geometry(data);q('.o-canvas').innerHTML=drawing(data,g);q('.o-metrics').innerHTML=metricCards(data.totals);fit();clear();
    q('.o-progress').textContent=num(data.nodes.length)+' entities · '+num(data.edges.length)+' connections';
    q('.o-scope').textContent=(data.scope||'Selected scope')+' · '+num(data.nodes.length)+' / '+num(data.total_nodes)+' entities and '+num(data.edges.length)+' / '+num(data.total_edges)+' associations drawn'+(data.limited?' · Drawing is capped at 600 entities / 1,500 associations; summary metrics cover the entire scope.':'.')+' '+(data.interpretation||'');
   }catch(error){if(alive&&version===request){q('.o-progress').textContent='Graph unavailable';q('.o-canvas').innerHTML='<div class="empty-state">'+esc(error.message)+'. <button data-o-action="retry">Retry</button></div>'}}
  }
  async function inspect(nodeID,edgeID){
   if(!g)return;const version=++selection,params=query();let heading,connected,links,key;
   if(nodeID){const n=g.nodes.get(nodeID);if(!n)return;heading=n.label;params.set('node',nodeID);connected=new Set([nodeID]);links=new Set(g.edges.filter(e=>e.source===nodeID||e.target===nodeID).map(e=>{connected.add(e.source);connected.add(e.target);return e.id}));key='node:'+nodeID}
   else{const e=g.edges.find(e=>e.id===edgeID);if(!e)return;heading=g.nodes.get(e.source).label+' → '+g.nodes.get(e.target).label;params.set('source',e.source);params.set('target',e.target);params.set('relation',e.relation);connected=new Set([e.source,e.target]);links=new Set([edgeID]);key=edgeID}
   root.querySelectorAll('[data-o-node]').forEach(el=>{el.classList.toggle('o-dim',!connected.has(el.dataset.oNode));el.classList.toggle('o-selected',el.dataset.oNode===nodeID)});
   root.querySelectorAll('[data-o-edge]').forEach(el=>{el.classList.toggle('o-dim',!links.has(el.dataset.oEdge));el.classList.toggle('o-selected',links.has(el.dataset.oEdge))});
   q('.o-inspector').innerHTML='<h4>'+esc(heading)+'</h4><p>Loading attack details and source evidence...</p>';
   try{const detail=cache.get(key)||await fetchData('/overview/graph/details?'+params);if(!alive||version!==selection)return;cache.set(key,detail);q('.o-inspector').innerHTML=detailHTML(detail,heading,data.totals)}
   catch(error){if(alive&&version===selection)q('.o-inspector').innerHTML='<h4>'+esc(heading)+'</h4><p>'+esc(error.message)+'</p>'}
  }
  function find(){if(!g)return;const text=q('.o-find').value.trim().toLowerCase();if(!text)return;const n=[...g.nodes.values()].find(n=>n.label.toLowerCase().includes(text));if(n){const w=Math.min(900,g.width),h=w*g.height/g.width;box={x:n.x-w/2,y:n.y-h/2,w,h};setBox();inspect(n.id)}else q('.o-progress').textContent='No displayed entity matches; check the scope or drawing limits.'}
  root.addEventListener('click',event=>{const action=event.target.closest('[data-o-action]')?.dataset.oAction;
   if(action==='play'){playing=!playing;root.classList.toggle('overview-playing',playing);event.target.textContent=playing?'Pause animation':'Animate activity';event.target.setAttribute('aria-pressed',String(playing))}
   else if(action==='in')zoom(.8);else if(action==='out')zoom(1.25);else if(action==='fit')fit();else if(action==='clear')clear();else if(action==='find')find();else if(action==='retry')load();
   else if(action==='expand'){const surface=q('.overview-workspace');if(document.fullscreenElement===surface)document.exitFullscreen?.();else surface.requestFullscreen?.().catch(()=>{})}
   else{const n=event.target.closest('[data-o-node]'),e=event.target.closest('[data-o-edge]');if(n)inspect(n.dataset.oNode);else if(e)inspect(null,e.dataset.oEdge)}
  });
  root.addEventListener('change',event=>{if(event.target.matches('.o-status,.o-stage'))load()});
  root.addEventListener('wheel',event=>{if(!event.target.closest('svg')||!box)return;event.preventDefault();zoom(event.deltaY<0?.9:1.1)},{passive:false});
  root.addEventListener('pointerdown',event=>{const svg=event.target.closest('svg');if(!svg||event.target.closest('[data-o-node],[data-o-edge]')||event.button!==0)return;drag={x:event.clientX,y:event.clientY,box:{...box},id:event.pointerId};svg.setPointerCapture(event.pointerId)});
  root.addEventListener('pointermove',event=>{if(!drag||event.pointerId!==drag.id)return;const r=q('svg').getBoundingClientRect(),scale=Math.min(r.width/drag.box.w,r.height/drag.box.h);box.x=drag.box.x-(event.clientX-drag.x)/scale;box.y=drag.box.y-(event.clientY-drag.y)/scale;setBox()});
  root.addEventListener('pointerup',()=>{drag=null});root.addEventListener('pointercancel',()=>{drag=null});
  root.addEventListener('keydown',event=>{
   if(event.target.matches('.o-find')&&event.key==='Enter'){event.preventDefault();find();return}
   const n=event.target.closest('[data-o-node]'),e=event.target.closest('[data-o-edge]');
   if((event.key==='Enter'||event.key===' ')&&(n||e)){event.preventDefault();inspect(n?.dataset.oNode,e?.dataset.oEdge);return}
   if(!event.target.closest('svg')||!box)return;
   if(['+','=','-','Home','ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key))event.preventDefault();
   if(event.key==='+'||event.key==='=')zoom(.8);else if(event.key==='-')zoom(1.25);else if(event.key==='Home')fit();else if(event.key==='Escape')clear();else if(event.key.startsWith('Arrow')){box.x+=({'ArrowLeft':-1,'ArrowRight':1}[event.key]||0)*box.w*.08;box.y+=({'ArrowUp':-1,'ArrowDown':1}[event.key]||0)*box.h*.08;setBox()}
  });
  load();return {destroy(){alive=false;request++;selection++;root.classList.remove('overview-playing')},inspect};
 }
 global.OverviewGraph={geometry,drawing,metricCards,detailHTML,mount};
})(globalThis);
