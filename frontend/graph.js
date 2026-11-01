/* Evidence graph: full-incident metrics, bounded SVG rendering, no network calls. */
(function(global){
 'use strict';
 const colors=['#86b4ef','#bd9deb','#64c6b5','#e1ad72','#ed8995'];
 const stageNames=['Initial attempts','Persistent foothold','Exploration','Propagation','Exfiltration / impact'];
 const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const number=value=>Number(value||0).toLocaleString();
 const stamp=value=>Number.isFinite(value)?new Date(value*1000).toLocaleString():'Unknown';
 function duration(seconds){seconds=Math.max(0,seconds||0);return seconds<60?`${Math.round(seconds)}s`:seconds<3600?`${Math.floor(seconds/60)}m ${Math.round(seconds%60)}s`:`${Math.floor(seconds/3600)}h ${Math.floor(seconds%3600/60)}m`}
 function internal(value){return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80:|::1$)/i.test(value)}
 function ip(value){return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)||value.includes(':')}
 function model(path,options={}){
  const all=path.timeline||[],begin=all.reduce((m,e)=>Math.min(m,e.ts),Infinity),end=all.reduce((m,e)=>Math.max(m,e.last_ts??e.ts),-Infinity);
  const cutoff=Number.isFinite(begin)?begin+(end-begin)*(options.percent??100)/100:Infinity;
  const nodes=new Map(),edges=new Map();let matching=0,detections=0,first=Infinity,last=-Infinity;
  function node(value,account=false,ghost=false){
   value=value||'Unattributed';const key=(account?'account:':'endpoint:')+value;
   if(!nodes.has(key))nodes.set(key,{id:key,label:value,kind:account?'account':ghost?'historical':internal(value)||!ip(value)?'internal':'external',ghost,indices:[],count:0,techniques:new Map(),first:Infinity,last:-Infinity});
   const n=nodes.get(key);if(!ghost)n.ghost=false;return n;
  }
  function edge(a,b,relation,event,index){
   const key=JSON.stringify([a.id,b.id,relation]);
   if(!edges.has(key))edges.set(key,{id:'link-'+edges.size,source:a.id,target:b.id,relation,indices:[],count:0,techniques:new Map(),stages:[0,0,0,0,0],first:Infinity,last:-Infinity});
   const link=edges.get(key);
   if(event){link.indices.push(index);link.count+=Number(event.count)||1;link.techniques.set(event.tech,(link.techniques.get(event.tech)||0)+1);link.stages[event.stage]++;link.first=Math.min(link.first,event.ts);link.last=Math.max(link.last,event.last_ts??event.ts)}
   return link;
  }
  all.forEach((event,index)=>{
   if(event.ts>cutoff||(options.stage!=null&&Number(options.stage)!==Number(event.stage)))return;
   detections++;matching+=Number(event.count)||1;first=Math.min(first,event.ts);last=Math.max(last,event.last_ts??event.ts);
   const a=node(event.src,event.src===event.user&&!!event.user),b=node(event.dst,event.dst===event.user&&!!event.user),account=event.user?node(event.user,true):null;
   edge(a,b,'observed',event,index);
   if(account&&account.id!==a.id&&account.id!==b.id)edge(account,b,'account',event,index);
   for(const n of new Set([a,b,...(account?[account]:[])])){n.indices.push(index);n.count+=Number(event.count)||1;n.first=Math.min(n.first,event.ts);n.last=Math.max(n.last,event.last_ts??event.ts);n.techniques.set(event.tech,(n.techniques.get(event.tech)||0)+1)}
  });
  if(options.history!==false)for(const fact of path.next_hops||[]){
   // Historical access facts are not filtered detections or proof of permission.
   const a=node(fact.from,false,true),b=node(fact.to,false,true);edge(a,b,'historical',null,-1);
  }
  for(const n of nodes.values()){n.incoming=0;n.outgoing=0}
  for(const e of edges.values()){nodes.get(e.source).outgoing++;nodes.get(e.target).incoming++}
  const ranked=[...nodes.values()].sort((a,b)=>b.indices.length-a.indices.length||a.id.localeCompare(b.id));
  const visibleNodes=ranked.slice(0,100),visibleIDs=new Set(visibleNodes.map(n=>n.id));
  const visibleEdges=[...edges.values()].filter(e=>visibleIDs.has(e.source)&&visibleIDs.has(e.target)).sort((a,b)=>b.indices.length-a.indices.length||a.id.localeCompare(b.id)).slice(0,180);
  const observed=[...nodes.values()].filter(n=>n.indices.length);
  return {nodes,edges,visibleNodes,visibleEdges,cutoff,begin,end,
   metrics:{endpoints:observed.filter(n=>n.kind!=='account').length,accounts:observed.filter(n=>n.kind==='account').length,
    links:[...edges.values()].filter(e=>e.relation!=='historical').length,detections,matching,seconds:Number.isFinite(first)?last-first:0,first,last},
   limited:visibleNodes.length<nodes.size||visibleEdges.length<edges.size};
 }
 function layout(data){
  const lanes=['external','account','internal','historical'],groups=lanes.map(kind=>data.visibleNodes.filter(n=>n.kind===kind).sort((a,b)=>a.label.localeCompare(b.label)));
  const width=1120,height=Math.max(440,...groups.map(group=>group.length*92+110));
  groups.forEach((group,column)=>group.forEach((node,row)=>{node.x=145+column*275;node.y=105+row*92}));
  return {width,height,groups};
 }
 function drawing(data,geometry){
  const {width,height}=geometry;
  let svg=`<svg class="evidence-svg" viewBox="0 0 ${width} ${height}" data-width="${width}" data-height="${height}" role="group" tabindex="0" aria-label="Interactive incident evidence graph. Use plus and minus to zoom, arrows to pan, Home to fit, Escape to clear selection." xmlns="http://www.w3.org/2000/svg"><defs><pattern id="graph-grid" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".7" fill="#303944"/></pattern><marker id="graph-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#90a3bb"/></marker></defs><rect width="${width}" height="${height}" fill="#14191f"/><rect width="${width}" height="${height}" fill="url(#graph-grid)"/>`;
  ['Outside endpoints','Accounts','Internal assets / hosts','Historical access'].forEach((label,i)=>{svg+=`<text x="${145+i*275}" y="35" text-anchor="middle" fill="#a9b6c8" font-family="system-ui,sans-serif" font-size="12">${label}</text><line x1="${282+i*275}" y1="55" x2="${282+i*275}" y2="${height-20}" stroke="#29323c" stroke-dasharray="3 8"/>`});
  for(const link of data.visibleEdges){
   const a=data.nodes.get(link.source),b=data.nodes.get(link.target),same=a.id===b.id,dx=b.x-a.x;
   const x1=a.x+(dx>0?86:dx<0?-86:0),x2=b.x+(dx>0?-92:dx<0?92:0);
   let d,mx,my;
   if(same){d=`M${a.x+50} ${a.y-28} C${a.x+130} ${a.y-90},${a.x+130} ${a.y+90},${a.x+50} ${a.y+28}`;mx=a.x+113;my=a.y}
   else if(!dx){const side=a.y<b.y?1:-1;d=`M${a.x+85*side} ${a.y} C${a.x+135*side} ${a.y},${b.x+135*side} ${b.y},${b.x+85*side} ${b.y}`;mx=a.x+120*side;my=(a.y+b.y)/2}
   else{const bend=(x1+x2)/2;d=`M${x1} ${a.y} C${bend} ${a.y},${bend} ${b.y},${x2} ${b.y}`;mx=bend;my=(a.y+b.y)/2}
   const stage=link.stages.indexOf(Math.max(...link.stages)),color=link.relation==='historical'?'#e1ad72':link.relation==='account'?'#788ba4':colors[stage];
   const label=link.relation==='historical'?'history':number(link.indices.length);
   svg+=`<g class="graph-edge ${link.relation}" data-edge="${link.id}" tabindex="0" role="button" aria-label="${escape(a.label+' to '+b.label+', '+link.relation+', '+link.indices.length+' detections')}"><title>${escape(a.label+' → '+b.label+' · '+link.relation+' · '+link.indices.length+' detections')}</title><path d="${d}" fill="none" stroke="${color}" stroke-width="${Math.min(5,1.5+Math.log2(link.indices.length+1)/2)}" ${link.relation!=='observed'?'stroke-dasharray="5 6"':''} marker-end="url(#graph-arrow)"/><path class="graph-hit" d="${d}" fill="none" stroke="transparent" stroke-width="18"/><rect x="${mx-24}" y="${my-11}" width="48" height="22" rx="5" fill="#1d2733" stroke="${color}"/><text x="${mx}" y="${my+4}" text-anchor="middle" fill="#e0e7ef" font-family="system-ui,sans-serif" font-size="11">${label}</text></g>`;
  }
  for(const node of data.visibleNodes){
   const color=node.kind==='account'?'#bd9deb':node.kind==='external'?'#e1ad72':node.ghost?'#8390a0':'#86b4ef';
   const short=node.label.length>23?node.label.slice(0,21)+'…':node.label;
   svg+=`<g class="graph-node" data-node="${escape(node.id)}" tabindex="0" role="button" aria-label="${escape(node.label+', '+node.kind+', '+node.indices.length+' detections')}"><title>${escape(node.label)}</title><rect x="${node.x-86}" y="${node.y-29}" width="172" height="58" rx="${node.kind==='account'?24:8}" fill="#202b39" stroke="${color}" stroke-width="1.5" ${node.ghost?'stroke-dasharray="5 4"':''}/><circle cx="${node.x-69}" cy="${node.y-10}" r="3" fill="${color}"/><text x="${node.x-60}" y="${node.y-6}" fill="${color}" font-family="system-ui,sans-serif" font-size="10">${node.kind==='internal'?'ASSET / HOST':node.kind.toUpperCase()}</text><text x="${node.x-70}" y="${node.y+13}" fill="#eef2f7" font-family="monospace" font-size="11">${escape(short)}</text><text x="${node.x+70}" y="${node.y-6}" text-anchor="end" fill="#bdc8d6" font-family="monospace" font-size="10">${number(node.indices.length)}</text></g>`;
  }
  if(!data.visibleNodes.length)svg+='<text x="560" y="200" text-anchor="middle" fill="#a9b6c8" font-family="system-ui,sans-serif" font-size="16">No evidence matches these filters</text>';
  return svg+'</svg>';
 }
 function metrics(data){const m=data.metrics;return [['Endpoints',m.endpoints],['Accounts',m.accounts],['Observed links',m.links],['Detections',m.detections],['Matching events',m.matching],['Duration',duration(m.seconds)]].map(([label,value])=>`<div><strong>${typeof value==='number'?number(value):value}</strong><span>${label}</span></div>`).join('')}
 function markup(path){
  const data=model(path,{history:false}),geo=layout(data);
  return `<section class="evidence-workspace" aria-label="Incident evidence explorer"><div class="graph-heading"><div><h3>Evidence map</h3><p>Grouped connections across the full incident</p></div><div class="graph-tools"><button type="button" data-graph-action="out" aria-label="Zoom out">−</button><output class="graph-zoom" aria-label="Zoom level">100%</output><button type="button" data-graph-action="in" aria-label="Zoom in">+</button><button type="button" data-graph-action="fit">Fit</button><button type="button" data-graph-action="clear">Clear selection</button><button type="button" data-graph-action="download">Save SVG</button><button type="button" data-graph-action="fullscreen">Expand</button></div></div><div class="graph-metrics">${metrics(data)}</div><div class="graph-filters"><label>Stage <select class="graph-stage"><option value="">All stages</option>${stageNames.map((name,i)=>`<option value="${i}">${name}</option>`).join('')}</select></label><label class="graph-time-label">Time <input class="graph-time" type="range" min="0" max="100" value="100" aria-label="Include detections through this percentage of incident time"><output class="graph-time-value">Full incident</output></label><label><input class="graph-history" type="checkbox"> Historical access</label></div><div class="graph-body"><div class="graph-canvas">${drawing(data,geo)}</div><aside class="graph-inspector" aria-live="polite"><h4>Inspect the evidence</h4><p>Select an endpoint, account or connection to measure its activity.</p><p>Connection labels count reduced detections. Repeated connections are grouped; they are not separate attack steps.</p></aside></div><div class="graph-foot"><span><i style="background:#86b4ef"></i> Observed connection <i style="background:#788ba4"></i> Account association <i style="background:#e1ad72"></i> Historical access (dashed)</span><span>Scroll to zoom · Drag canvas to pan · Keyboard + / − / arrows</span></div><p class="graph-scope">${scope(data)}</p></section>`;
 }
 function scope(data){return `${data.metrics.detections.toLocaleString()} detections in filter · ${data.visibleNodes.length} / ${data.nodes.size} entities and ${data.visibleEdges.length} / ${data.edges.size} grouped links drawn${data.limited?' · Display capped at 100 entities / 180 links; metrics cover all filtered evidence':''}. Matching-event counts may overlap between rules. Associations do not prove causality or current permissions.`}
 function mount(root,path,options={}){
  if(!root)return;root.innerHTML=markup(path);
  let data,geo,box,drag=null,selected=null;const filters={history:false,stage:null,percent:100};
  const q=selector=>root.querySelector(selector);
  function setBox(){q('svg').setAttribute('viewBox',`${box.x} ${box.y} ${box.w} ${box.h}`);q('.graph-zoom').textContent=Math.round(geo.width/box.w*100)+'%'}
  function fit(){box={x:0,y:0,w:geo.width,h:geo.height};setBox()}
  function clear(){selected=null;root.querySelectorAll('[data-node],[data-edge]').forEach(el=>el.classList.remove('graph-dim','graph-selected'));q('.graph-inspector').innerHTML='<h4>Inspect the evidence</h4><p>Select an endpoint, account or connection. Metrics above reflect the current time and stage filters.</p>';options.onSelect?.(null)}
  function render(){data=model(path,filters);geo=layout(data);q('.graph-canvas').innerHTML=drawing(data,geo);q('.graph-metrics').innerHTML=metrics(data);q('.graph-scope').textContent=scope(data);q('.graph-time-value').textContent=filters.percent===100?'Full incident':stamp(data.cutoff);fit();clear()}
  function zoom(factor,point){const next=Math.max(geo.width/20,Math.min(geo.width*2,box.w*factor)),ratio=next/box.w;const anchor=point||{x:box.x+box.w/2,y:box.y+box.h/2};box={x:anchor.x-(anchor.x-box.x)*ratio,y:anchor.y-(anchor.y-box.y)*ratio,w:next,h:box.h*ratio};setBox()}
  function select(kind,id){
   const item=kind==='node'?data.nodes.get(id):[...data.edges.values()].find(e=>e.id===id);if(!item)return;
   selected={kind,id};const connected=new Set(kind==='node'?[item.id]:[item.source,item.target]);
   const links=new Set(kind==='edge'?[item.id]:[...data.edges.values()].filter(e=>e.source===id||e.target===id).map(e=>{connected.add(e.source);connected.add(e.target);return e.id}));
   root.querySelectorAll('[data-node]').forEach(el=>{el.classList.toggle('graph-dim',!connected.has(el.dataset.node));el.classList.toggle('graph-selected',kind==='node'&&el.dataset.node===id)});
   root.querySelectorAll('[data-edge]').forEach(el=>{el.classList.toggle('graph-dim',!links.has(el.dataset.edge));el.classList.toggle('graph-selected',kind==='edge'&&el.dataset.edge===id)});
   const heading=kind==='node'?item.label:data.nodes.get(item.source).label+' → '+data.nodes.get(item.target).label;
   const techniques=[...item.techniques].sort((a,b)=>b[1]-a[1]);
   const facts=kind==='node'?`<dt>Incoming / outgoing links</dt><dd>${item.incoming} / ${item.outgoing}</dd>`:`<dt>Relationship</dt><dd>${escape(item.relation==='account'?'Account mentioned in detection':item.relation==='historical'?'Historical access, not current permission':'Observed detection endpoints')}</dd>`;
   const evidence=item.indices.slice(0,5).map(i=>{const e=path.timeline[i];return `<li>${escape(e.tech)} · ${escape(stamp(e.ts))}<small>${escape(e.file||'')} @ byte ${escape(e.offset??'unknown')}</small></li>`}).join('');
   q('.graph-inspector').innerHTML=`<span class="graph-inspect-label">${kind==='node'?'ENTITY':'CONNECTION'}</span><h4>${escape(heading)}</h4><dl><dt>Detections</dt><dd>${number(item.indices.length)}</dd><dt>Matching events</dt><dd>${number(item.count)}</dd>${facts}<dt>Activity span</dt><dd>${duration(item.last-item.first)}</dd><dt>First observed</dt><dd>${escape(stamp(item.first))}</dd><dt>Last observed</dt><dd>${escape(stamp(item.last))}</dd></dl><h5>Techniques · detection count</h5>${techniques.length?techniques.map(([tech,count])=>`<div class="graph-tech"><span>${escape(tech)}</span><b>${number(count)}</b></div>`).join(''):'<p>No detection attached to this historical-access link.</p>'}<h5>Source evidence · first five detections</h5><ol>${evidence||'<li>Consult the incident historical-access evidence.</li>'}</ol><p class="r2">Matching visible timeline entries are highlighted. Use Export evidence for all source references.</p>`;
   options.onSelect?.(new Set(item.indices));
  }
  root.addEventListener('click',event=>{
   const action=event.target.closest('[data-graph-action]')?.dataset.graphAction;
   if(action==='in')zoom(.8);else if(action==='out')zoom(1.25);else if(action==='fit')fit();else if(action==='clear')clear();
   else if(action==='fullscreen'){const surface=q('.evidence-workspace');if(document.fullscreenElement===surface)document.exitFullscreen?.();else surface.requestFullscreen?.().catch(()=>{})}
   else if(action==='download'){const svg=q('svg').cloneNode(true);svg.setAttribute('viewBox',`0 0 ${geo.width} ${geo.height}`);svg.setAttribute('width',geo.width);svg.setAttribute('height',geo.height);svg.querySelectorAll('.graph-dim').forEach(el=>el.classList.remove('graph-dim'));const url=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(svg)],{type:'image/svg+xml'}));const a=document.createElement('a');a.href=url;a.download='incident-'+String(path.id||'graph').replace(/[^a-zA-Z0-9-]/g,'')+'.svg';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
   else{const node=event.target.closest('[data-node]'),edge=event.target.closest('[data-edge]');if(node)select('node',node.dataset.node);else if(edge)select('edge',edge.dataset.edge)}
  });
  root.addEventListener('change',event=>{if(event.target.matches('.graph-stage')){filters.stage=event.target.value===''?null:Number(event.target.value);render()}else if(event.target.matches('.graph-history')){filters.history=event.target.checked;render()}});
  root.addEventListener('input',event=>{if(event.target.matches('.graph-time')){filters.percent=Number(event.target.value);render()}});
  root.addEventListener('wheel',event=>{if(!event.target.closest('svg'))return;event.preventDefault();const rect=q('svg').getBoundingClientRect();const scale=Math.min(rect.width/box.w,rect.height/box.h),left=(rect.width-box.w*scale)/2,top=(rect.height-box.h*scale)/2;zoom(event.deltaY<0?.9:1.1,{x:box.x+(event.clientX-rect.left-left)/scale,y:box.y+(event.clientY-rect.top-top)/scale})},{passive:false});
  root.addEventListener('pointerdown',event=>{const svg=event.target.closest('svg');if(!svg||event.target.closest('[data-node],[data-edge]')||event.button!==0)return;drag={x:event.clientX,y:event.clientY,box:{...box},id:event.pointerId};svg.setPointerCapture(event.pointerId);svg.classList.add('panning')});
  root.addEventListener('pointermove',event=>{if(!drag||drag.id!==event.pointerId)return;const rect=q('svg').getBoundingClientRect(),scale=Math.min(rect.width/drag.box.w,rect.height/drag.box.h);box.x=drag.box.x-(event.clientX-drag.x)/scale;box.y=drag.box.y-(event.clientY-drag.y)/scale;setBox()});
  function endDrag(){drag=null;q('svg')?.classList.remove('panning')}
  root.addEventListener('pointerup',endDrag);root.addEventListener('pointercancel',endDrag);
  root.addEventListener('keydown',event=>{
   const node=event.target.closest('[data-node]'),edge=event.target.closest('[data-edge]');
   if((event.key==='Enter'||event.key===' ')&&(node||edge)){event.preventDefault();select(node?'node':'edge',node?node.dataset.node:edge.dataset.edge);return}
   if(!event.target.closest('svg'))return;
   if(['+','=','-','Home','Escape','ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key))event.preventDefault();
   if(event.key==='+'||event.key==='=')zoom(.8);else if(event.key==='-')zoom(1.25);else if(event.key==='Home')fit();else if(event.key==='Escape')clear();else if(event.key.startsWith('Arrow')){box.x+=({'ArrowLeft':-1,'ArrowRight':1}[event.key]||0)*box.w*.08;box.y+=({'ArrowUp':-1,'ArrowDown':1}[event.key]||0)*box.h*.08;setBox()}
  });
  function highlightDetection(index){const link=data.visibleEdges.find(e=>e.relation==='observed'&&e.indices.includes(index));if(link)select('edge',link.id)}
  render();return {getModel:()=>data,getViewBox:()=>({...box}),select,clear,fit,highlightDetection};
 }
 global.AttackGraph={model,layout,drawing,markup,mount,duration};
})(globalThis);
