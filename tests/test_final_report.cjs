const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');

function setup(){
 const elements=new Map();
 const get=s=>{if(!elements.has(s))elements.set(s,{innerHTML:'',textContent:'',hidden:false,style:{},addEventListener(){},classList:{toggle(){}}});return elements.get(s)};
 const context={document:{querySelector:get,addEventListener(){}},location:{hash:'#home'},addEventListener(){},setTimeout(){},clearTimeout(){},console};
 vm.createContext(context);
 const source=fs.readFileSync('frontend/index.html','utf8').match(/<script>([\s\S]*?)<\/script>/)[1].replace('load();poll();','');
 vm.runInContext(source,context);
 vm.runInContext("S.d={scan:{run_id:'run',publication_digest:'digest'}}",context);
 return {context,get,run:code=>vm.runInContext(code,context)};
}
function report(){return {run_id:'run',publication_digest:'digest',cached:false,metadata_bytes:200,
 sampled_incidents:1,total_active_incidents:10,validation_status:'UNVERIFIED',evidence:{e1:{incident_id:'123',alert_id:'a'}},
 review:{assessment:'insufficient_evidence',summary:'<script>bad</script>',findings:[{explanation:'Review backup',evidence_ids:['e1']}],
 next_steps:['<img src=x>'],limitations:['Sampling only']}}}

test('final report renders escaped analysis, sampling scope, recommendations and incident links',async()=>{
 const {context,get,run}=setup();context.response=report();run('api=async()=>response');
 await run('generateFinalReport()');
 const html=get('#final-ai-content').innerHTML;
 assert.ok(html.includes('&lt;script&gt;')&&!html.includes('<script>'));
 assert.ok(html.includes('&lt;img src=x&gt;'));
 assert.ok(html.includes('1 of 10 active incidents sampled'));
 assert.ok(html.includes('#incident/123'));
 assert.equal(get('#final-ai-download').hidden,false);
});

test('provider failure is visible and stale responses cannot replace a new scan report',async()=>{
 const {context,get,run}=setup();run("api=async()=>{throw Error('Quota reached')}");
 await run('generateFinalReport()');assert.match(get('#final-ai-content').textContent,/Quota reached/);
 context.response=report();run("api=async()=>{S.d.scan.run_id='new-run';return response}");
 await run('generateFinalReport()');assert.equal(run('finalAI.result'),null);
});

test('scan completion requests one final report and polling does not repeat AI requests',async()=>{
 const {context,run}=setup();context.calls=[];context.response=report();
 run("load=async()=>{};renderScanProgress=()=>{};api=async path=>{calls.push(path);return path==='/ai/status'?{configured:true}:path==='/ai/final-report'?response:{running:false}};autoFinalReport=true");
 await run('poll()');await run('poll()');
 assert.equal(context.calls.filter(x=>x==='/ai/final-report').length,1);
 assert.equal(run('finalAI.busy'),false);
});
