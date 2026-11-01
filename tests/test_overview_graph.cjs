const {test}=require('node:test'),assert=require('node:assert/strict');
require('../frontend/overview-graph.js');
const G=globalThis.OverviewGraph;
const data={nodes:[{id:'host:HR-07',kind:'host',label:'HR-07',detections:20,incidents:1,impact_signals:2},{id:'account:a',kind:'account',label:'alice',detections:20,incidents:1},{id:'ip:1',kind:'ip',label:'198.51.100.1',detections:20,incidents:1}],edges:[{source:'account:a',target:'host:HR-07',relation:'account',detections:20,hosts:1,impact_signals:2}]};
test('summary graph preserves database counts without inventing event records',()=>{
 const g=G.geometry(data);assert.equal(g.nodes.size,3);assert.equal(g.edges.length,1);
 assert.equal(g.edges[0].detections,20);assert.equal(g.edges[0].hosts,1);
 const svg=G.drawing(data,g);assert(svg.includes('20 detections, 1 hosts'));assert(svg.includes('data-o-node'));
 assert.equal(data.nodes[0].x,undefined);
});
test('impact and remaining assets are labelled without inventing confirmed exploitation',()=>{
 const html=G.detailHTML({metrics:{detections:5,hosts:2,impact_signals:2},techniques:[],incidents:[],evidence:[]},'HR-07',{detections:10});
 assert(html.includes('50.0%'));assert(html.includes('Impact technique signals'));assert(html.includes('<dt>Remaining unaffected</dt><dd>Unknown</dd>'));
 assert(html.includes('<dt>Confirmed exploited</dt><dd>Unknown</dd>'));
});
test('untrusted source labels and evidence are escaped',()=>{
 const copy=JSON.parse(JSON.stringify(data));copy.nodes[0].label='<script>alert(1)</script>';
 assert(!G.drawing(copy,G.geometry(copy)).includes('<script>'));
 assert(!G.detailHTML({metrics:{},evidence:[{file:'<img onerror=1>'}]},'<script>').includes('<script>'));
 assert(G.drawing({nodes:[],edges:[]},G.geometry({nodes:[],edges:[]})).includes('No detection evidence'));
});

test('home controller loads summaries, opens details, and toggles animation',async()=>{
 const elements=new Map(),handlers=new Map(),classes=new Set(),calls=[];
 const classList={add:v=>classes.add(v),remove:v=>classes.delete(v),toggle(v,on){on?classes.add(v):classes.delete(v)}};
 const element=s=>{if(!elements.has(s))elements.set(s,{innerHTML:'',textContent:'',value:s==='.o-status'?'active':'',classList,setAttribute(){}});return elements.get(s)};
 const root={innerHTML:'',classList,querySelector:element,querySelectorAll:()=>[],addEventListener:(name,fn)=>handlers.set(name,fn)};
 const full={...data,totals:{detections:20,assets:1,accounts:1,incidents:1,impact_signals:2},total_nodes:3,total_edges:1,scope:'All active incidents'};
 const api=async endpoint=>{calls.push(endpoint);return endpoint.includes('/details?')?{metrics:{detections:20,assets:1,impact_signals:2},techniques:[{technique:'T1486',name:'Impact signal',detections:2}],incidents:[],evidence:[]}:full};
 const controller=G.mount(root,{api,generation:'unit-home-controller'});
 await new Promise(setImmediate);
 assert(element('.o-canvas').innerHTML.includes('data-o-node'));
 assert(element('.o-scope').textContent.includes('3 / 3'));
 await controller.inspect('host:HR-07');
 assert(element('.o-inspector').innerHTML.includes('T1486'));
 assert(element('.o-inspector').innerHTML.includes('Remaining unaffected'));
 const button={textContent:'',setAttribute(){},closest:()=>({dataset:{oAction:'play'}})};
 handlers.get('click')({target:button});assert(classes.has('overview-playing'));assert.equal(button.textContent,'Pause animation');
 handlers.get('click')({target:button});assert(!classes.has('overview-playing'));
 controller.destroy();assert(!classes.has('overview-playing'));
 assert.equal(calls.length,2);
});
