import json, statistics as st, pathlib, itertools, hashlib, sys
root=pathlib.Path(sys.argv[1]); dest=pathlib.Path(sys.argv[2]); dest.mkdir(parents=True,exist_ok=True)
def load(p): return json.loads(p.read_text(encoding='utf-8-sig'))
def stats(a):return dict(median=st.median(a),min=min(a),max=max(a),raw=a)
def device(r,key):return (r.get(key) or {}).get('device',{}).get('times',{})
cfgs=['v1-cpu','v1-tate','v1-gpu','v5-cpu','v6-cpu','v9-cpu','v9-gpu']; out={}; rows=[]; breakdown=[]; dispatch=[]; networks=[]; crosses=[]; speed=[]
for n in [64,256,1024]:
 path=root/f'engine-n{n}/secure_bench.json'
 if not path.exists(): path=root/f'engine_n{n}.json'
 j=load(path); elected=j['secure_bench']['results'][0]; runs=elected['runs']; assert len(runs)==21
 out[n]={}
 for c in cfgs:
  rr=[r for r in runs if r['configuration']==c];assert len(rr)==3
  assert all(r['oracle_agrees'] and r['replay']['accepted'] and r['independent_cpu_individual']['accepted'] and r['replay']['decision']==r['tally']['decision']==r['independent_cpu_individual']['decision'] for r in rr)
  met={k:stats([r[part][field] for r in rr]) for k,part,field in [('tally','tally','seconds_total'),('produce','tally','seconds_produce'),('process','tally','seconds_process'),('replay','replay','seconds_total'),('bytes','tally','transcript_message_bytes'),('initialization','x','y')] if k!='initialization'}
  met['initialization']=stats([r['initialization_seconds'] for r in rr]);met['prof']={k:stats([r['replay']['prof'][k] for r in rr]) for k in rr[0]['replay']['prof']}
  out[n][c]=met
  fmt=lambda k:f"{met[k]['median']:.3f} [{met[k]['min']:.3f}, {met[k]['max']:.3f}]"
  rows.append(f"| {n} | {c} | {fmt('tally')} | {fmt('replay')} | {met['produce']['median']:.3f} | {met['process']['median']:.3f} | {met['bytes']['median']/1e6:.3f} |")
  if c.startswith('v9'):
   p=met['prof'];gpu={k:stats([device(r,'telemetry_after_replay').get(k,0)-device(r,'telemetry_after_tally').get(k,0) for r in rr]) for k in ['jobs','batches','pack','h2d','kernel','d2h','unpack']};met['gpu_replay']=gpu
   runjobs=stats([r['replay_batches']['jobs'] for r in rr]); met['scalar_jobs']=runjobs; met['scalar_seconds']=stats([sum(b['seconds'] for b in r['replay_batches']['by_size']) for r in rr])
   # Gate finishing uses 2 multiplications per gate. All remaining run jobs are CSZ jobs.
   expected_csz=10*5*elected['gates'];assert runjobs['median']==expected_csz+2*elected['gates']
   met['csz_jobs']=expected_csz
   gpujobs=gpu['jobs']['median']; total_terms=runjobs['median']+p['jobs']['median']-expected_csz; met['gpu_fraction_all_backend_terms']=gpujobs/total_terms
   eligible=st.median(sum(b['jobs'] for b in r['replay_batches']['by_size'] if b['jobs_lo']>=4096) for r in rr); met['csz_gpu_fraction_lower_bound']=max(0,eligible-2*elected['gates'])/expected_csz; met['csz_gpu_fraction_upper_bound']=min(1,eligible/expected_csz)
   breakdown.append(f"| {n} | {c} | {p['decode']['median']:.3f} | {p['subgroup']['median']:.3f} | {met['scalar_seconds']['median']:.3f} | {p['batch_run']['median']:.3f} | {p['batch_build']['median']+p['batch_check']['median']:.3f} | {p['finish']['median']:.3f} |")
   dispatch.append(f"| {n} | {c} | {expected_csz:,} | {int(total_terms):,} | {int(gpujobs):,} | {100*gpujobs/total_terms:.1f}% | {gpu['kernel']['median']:.3f} | {gpu['pack']['median']:.3f} | {gpu['h2d']['median']:.3f} | {gpu['d2h']['median']:.3f} | {gpu['unpack']['median']:.3f} |")
 cpu=out[n]['v9-cpu']['replay']['median'];gpu=out[n]['v9-gpu']['replay']['median'];v6=out[n]['v6-cpu']['replay']['median'];speed.append(f"| {n} | {cpu/gpu:.3f} | {100*(1-gpu/cpu):.1f}% | {gpu/v6:.3f} |")
 choices=['v5-cpu','v6-cpu','v9-cpu','v9-gpu'];out[n]['network']={};out[n]['crossovers_mbps']={}
 for bw in [10,25,50,100,250,1000]:
  costs={c:out[n][c]['replay']['median']+8*out[n][c]['bytes']['median']/(bw*1e6) for c in choices};out[n]['network'][bw]=costs;winner=min(costs,key=costs.get);networks.append(f"| {n} | {bw} | "+' | '.join(f'{costs[c]:.3f}' for c in choices)+f" | {winner} |")
 for a,b in itertools.combinations(choices,2):
  dt=out[n][a]['replay']['median']-out[n][b]['replay']['median'];db=out[n][a]['bytes']['median']-out[n][b]['bytes']['median'];bw=-8*db/dt/1e6 if dt else None
  valid=bw is not None and bw>0;out[n]['crossovers_mbps'][a+'/'+b]=bw if valid else None;crosses.append(f"| {n} | {a} / {b} | "+(f'{bw:.3f}' if valid else 'no positive crossover')+' |')
for name,lines in [('performance',rows),('breakdown',breakdown),('dispatch',dispatch),('network',networks),('crossovers',crosses),('speed',speed)]:
 (dest/f'{name}.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
(dest/'summary.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8');print('validated 63 runs; summary written to',dest)
