const {test}=require('node:test');
const assert=require('node:assert/strict');
require('../frontend/graph.js');
const G=globalThis.AttackGraph;
const event=(i,extra={})=>({ts:100+i,last_ts:100+i,src:'198.51.100.1',dst:'10.0.0.7',user:'alice',stage:0,tech:'T1078',count:1,alert_id:String(i),file:'auth.log',offset:i,...extra});

test('metrics cover the full timeline and repeated connections are grouped',()=>{
 const p={timeline:Array.from({length:1400},(_,i)=>event(i,{count:2}))};
 const m=G.model(p,{history:false});
 assert.equal(m.metrics.detections,1400);assert.equal(m.metrics.matching,2800);
 assert.equal(m.metrics.endpoints,2);assert.equal(m.metrics.accounts,1);
 assert.equal(m.edges.size,2);assert.equal(m.metrics.links,2);
 assert.equal(m.nodes.get('account:alice').indices.length,1400);
 assert.equal(m.metrics.seconds,1399);
 assert.equal(m.edges.values().next().value.indices.length,1400);
 assert(G.markup(p).length<20000);
});

test('stage and time filters change measurements without changing source evidence',()=>{
 const p={timeline:[event(0),event(10,{stage:1}),event(20,{stage:4})]};
 const before=JSON.stringify(p);
 assert.equal(G.model(p,{percent:50,history:false}).metrics.detections,2);
 assert.equal(G.model(p,{stage:4,history:false}).metrics.detections,1);
 assert.equal(G.model(p,{stage:3,history:false}).metrics.detections,0);
 assert.equal(JSON.stringify(p),before);
 const html=G.markup(p);
 assert(html.includes('<option value="2">Exploration</option>'));
 assert(html.includes('<option value="3">Propagation</option>'));
});

test('historical access never adds to detection or observed-link counts',()=>{
 const p={timeline:[event(0)],next_hops:[{from:'10.0.0.7',to:'FS-02',why:'historical'}]};
 const plain=G.model(p,{history:false}),history=G.model(p,{history:true});
 assert.deepEqual(history.metrics,plain.metrics);
 assert.equal(history.edges.size,plain.edges.size+1);
 assert([...history.nodes.values()].some(n=>n.label==='FS-02'&&n.ghost));
});

test('render caps do not silently truncate full-incident measurements',()=>{
 const p={timeline:Array.from({length:400},(_,i)=>event(i,{src:`outside-${i}`,dst:`server-${i}`,user:`user-${i}`}))};
 const m=G.model(p,{history:false});
 assert.equal(m.metrics.detections,400);assert.equal(m.metrics.endpoints,800);assert.equal(m.metrics.accounts,400);
 assert(m.limited);assert(m.visibleNodes.length<=100);assert(m.visibleEdges.length<=180);
 const text=G.markup(p);assert(text.includes('Display capped'));assert(text.includes('Keyboard'));
});

test('empty incident and hostile entity names are rendered safely',()=>{
 const empty=G.model({timeline:[]},{history:false});assert.equal(empty.metrics.seconds,0);
 assert(G.markup({timeline:[]}).includes('No evidence matches'));
 const html=G.markup({timeline:[event(0,{dst:'<script>alert(1)</script>'})]});
 assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;'));
});

test('self connections keep one entity and one evidence reference',()=>{
 const m=G.model({timeline:[event(0,{src:'10.0.0.7',user:''})]},{history:false});
 assert.equal(m.nodes.size,1);assert.equal(m.edges.size,1);
 assert.equal(m.nodes.values().next().value.indices.length,1);
 assert(G.drawing(m,G.layout(m)).includes('C'));
});
