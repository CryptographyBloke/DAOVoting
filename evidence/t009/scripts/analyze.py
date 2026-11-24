import json, sys, statistics as st, os
O = sys.argv[1]
def load(p):
    return json.load(open(os.path.join(O, p)))
def med(v):
    return st.median(v)
def rng(v):
    return f"[{min(v):.3f}, {max(v):.3f}]" if len(v) > 1 else ""

res = []
for f in ['engine-small/secure_bench.json', 'engine-1024/secure_bench.json', 'engine_n8_64_256.json', 'engine_n1024.json']:
    p = os.path.join(O, f)
    if os.path.exists(p):
        res += load(f)['secure_bench']['results']

order = ['v1-cpu','v1-tate','v3-cpu','v3-individual','v4-cpu','v5-cpu','v5-individual','v6-cpu','v7-cpu','v8-cpu','v9-cpu']
summary = {}
for r in res:
    n = r['n']; by = {}
    for x in r['runs']:
        by.setdefault(x['configuration'], []).append(x)
    for c, runs in by.items():
        t = [x['tally']['seconds_total'] for x in runs]
        rp = [x['replay']['seconds_total'] for x in runs]
        prod = [x['tally']['seconds_produce'] for x in runs]
        pr = runs[0]['replay']['prof']
        def pm(k):
            return med([x['replay']['prof'].get(k, 0) for x in runs])
        summary[(n, c)] = dict(
            reps=len(runs), tally=med(t), tally_r=rng(t), replay=med(rp), replay_r=rng(rp), prod=med(prod),
            bytes=runs[0]['tally']['transcript_message_bytes'], msgs=runs[0]['tally']['messages'], gates=r['gates'],
            decode=pm('decode'), cof=pm('cofactor_decode'), sub=pm('subgroup'), run=pm('batch_run'), build=pm('batch_build'),
            check=pm('batch_check'), inline=pm('verify_inline'), apply=pm('apply'), finish=pm('finish'), sig=pm('signature'),
            jobs=pr['jobs'], batches=pr['batches'], maxb=pr['max_batch'],
            stream=runs[0]['tally'].get('stream'),
            indep_ok=all(x['independent_cpu_individual']['accepted'] for x in runs),
            replay_ok=all(x['replay']['accepted'] for x in runs),
            dec_ok=all(x['tally']['decision'] == x['replay']['decision'] for x in runs))
json.dump({f"{k[0]}|{k[1]}": v for k, v in summary.items()}, open(os.path.join(O, 'engine_summary.json' if os.path.exists(os.path.join(O, 'engine_n1024.json')) else 'summary.json'), 'w'), indent=1)
ns = sorted({k[0] for k in summary})
for n in ns:
    base_t = summary.get((n, 'v1-cpu'), {}).get('tally'); base_r = summary.get((n, 'v1-cpu'), {}).get('replay')
    bt = summary.get((n, 'v1-tate'), {})
    print(f"\n### n = {n} (gates {summary[(n, 'v1-cpu')]['gates']}, reps {summary[(n, 'v1-cpu')]['reps']})")
    print("| config | tally s | produce s | replay s | decode s | subgroup s | verify arithmetic s | build s | MB | S replay vs v1-tate | S replay vs v1 |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for c in order:
        if (n, c) not in summary: continue
        s = summary[(n, c)]
        arith = s['run'] + s['check'] + s['inline']
        print(f"| {c} | {s['tally']:.3f} {s['tally_r']} | {s['prod']:.3f} | {s['replay']:.3f} {s['replay_r']} | {s['decode']:.3f} | {s['sub']:.3f} | {arith:.3f} | {s['build']:.3f} | {s['bytes']/1e6:.2f} | {bt.get('replay', float('nan'))/s['replay']:.2f} | {base_r/s['replay']:.2f} |")
    oks = all(summary[(n, c)]['indep_ok'] and summary[(n, c)]['replay_ok'] and summary[(n, c)]['dec_ok'] for c in order if (n, c) in summary)
    print(f"\nall accepted, decisions equal, independent individual replay accepted: {oks}")
# stream composition at largest n
n = max(ns)
print(f"\n### stream composition n = {n}")
for c in ['v1-cpu', 'v3-cpu', 'v4-cpu', 'v5-cpu', 'v6-cpu', 'v8-cpu', 'v9-cpu']:
    if (n, c) not in summary: continue
    s = summary[(n, c)]['stream']; tot = summary[(n, c)]['bytes']
    fam = s['families']
    parts = ", ".join(f"{k}: {v['bytes']/1e6:.2f} MB ({100*v['bytes']/tot:.0f}%, {v['points']} pts)" for k, v in fam.items())
    print(f"{c}: total {tot/1e6:.2f} MB; {parts}; framing+sig {s['framing_and_signature_bytes']/1e6:.2f} MB")
