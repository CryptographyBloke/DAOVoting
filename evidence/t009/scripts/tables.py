"""Generate the T009 report tables from the evidence directory (JSON)."""
import json, os, sys, statistics as st
E = sys.argv[1]           # evidence dir (copied JSON)
OUTF = sys.argv[2]        # tables.json with markdown snippets
def J(p): return json.load(open(os.path.join(E, p)))
med = st.median
T = {}

# ---------- engine ----------
S = {tuple([int(k.split('|')[0]), k.split('|')[1]]): v for k, v in J('engine_summary.json').items()}
ORDER = ['v1-cpu', 'v1-tate', 'v3-cpu', 'v3-individual', 'v4-cpu', 'v5-cpu', 'v5-individual', 'v6-cpu', 'v7-cpu', 'v8-cpu', 'v9-cpu']
DESC = {'v1-cpu': 'V1, [q]P checks, batched CPU', 'v1-tate': 'V1, exact Tate checks, batched CPU',
        'v3-cpu': 'V3 lifts, per-item commitment-form proofs, one MSM/msg', 'v3-individual': 'V3, per-relation (individual)',
        'v4-cpu': 'V4 = V3 with affine points', 'v5-cpu': '**V5** = V3 + batched linear proof', 'v5-individual': 'V5, per-relation (individual)',
        'v6-cpu': '**V6** = V4 + batched linear proof', 'v7-cpu': 'V7 native points + Tate, per-item proofs',
        'v8-cpu': '**V8** = V7 + batched linear proof', 'v9-cpu': '**V9** = V8 with challenge–response CSZ'}
ns = sorted({k[0] for k in S})
eng = []
for n in ns:
    g = S[(n, 'v1-cpu')]
    eng.append(f"\n**n = {n:,}** ({g['gates']:,} gates, {g['msgs']} messages, {g['reps']} repetition{'s' if g['reps'] > 1 else ''}; median [min, max])\n")
    eng.append("| configuration | MB | tally s | produce s | replay s | decode s | of which exact subgroup s | verification arithmetic s | replay vs V1-Tate | replay vs V3 |")
    eng.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for c in ORDER:
        if (n, c) not in S: continue
        s = S[(n, c)]
        ar = s['run'] + s['check'] + s['inline']
        eng.append(f"| {DESC[c]} | {s['bytes']/1e6:.2f} | {s['tally']:.2f} {s['tally_r']} | {s['prod']:.2f} | {s['replay']:.2f} {s['replay_r']} | {s['decode']:.2f} | {s['sub']:.2f} | {ar:.2f} | {S[(n,'v1-tate')]['replay']/s['replay']:.2f}× | {S[(n,'v3-cpu')]['replay']/s['replay']:.2f}× |")
    ok = all(S[(n, c)]['indep_ok'] and S[(n, c)]['replay_ok'] and S[(n, c)]['dec_ok'] for c in ORDER if (n, c) in S)
    eng.append(f"\nAll {sum(S[(n,c)]['reps'] for c in ORDER if (n,c) in S)} runs: replay accepted, decision equal to the tally and to the plaintext oracle, independent individual CPU replay accepted: **{ok}**.")
T['ENGINE_TABLES'] = "\n".join(eng)

# paired format effects
pe = ["| n | V5 vs V3: bytes | replay | tally | produce | V6 vs V4: bytes | replay | tally | V8 vs V5 replay (exact native vs lifts) | V9 vs V1-Tate: bytes | replay |", "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
for n in ns:
    a = lambda c: S[(n, c)]
    r = lambda x, y, k: a(y)[k] / a(x)[k]
    pe.append(f"| {n:,} | {100*(a('v5-cpu')['bytes']/a('v3-cpu')['bytes']-1):+.1f}% | {r('v5-cpu','v3-cpu','replay'):.2f}× | {r('v5-cpu','v3-cpu','tally'):.2f}× | {100*(a('v5-cpu')['prod']/a('v3-cpu')['prod']-1):+.0f}% | {100*(a('v6-cpu')['bytes']/a('v4-cpu')['bytes']-1):+.1f}% | {r('v6-cpu','v4-cpu','replay'):.2f}× | {r('v6-cpu','v4-cpu','tally'):.2f}× | {100*(a('v8-cpu')['replay']/a('v5-cpu')['replay']-1):+.0f}% | {100*(a('v9-cpu')['bytes']/a('v1-tate')['bytes']-1):+.1f}% | {r('v9-cpu','v1-tate','replay'):.2f}× |")
T['PAIRED'] = "\n".join(pe)

# stream composition at largest n
n = max(ns)
sc = ["| format | total MB | mask + CSZ | rerandomizers (+ZKP0) | shares (+DLEQ) | linear batch proofs | framing + signatures | transmitted points |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
for c in ['v1-cpu', 'v3-cpu', 'v4-cpu', 'v5-cpu', 'v6-cpu', 'v8-cpu', 'v9-cpu']:
    s = S[(n, c)]; fam = s['stream']['families']; tot = s['bytes']
    def f(prefix):
        b = sum(v['bytes'] for k, v in fam.items() if k.startswith(prefix))
        return f"{b/1e6:.2f} ({100*b/tot:.0f}%)"
    pts = sum(v['points'] for v in fam.values())
    sc.append(f"| {c.split('-')[0].upper()} | {tot/1e6:.2f} | {f('mask')} | {f('reveal')} | {f('share')} | {f('linear')} | {s['stream']['framing_and_signature_bytes']/1e6:.2f} | {pts:,} |")
T['STREAM'] = "\n".join(sc)
# per gate-trustee
pg = ["| format | bytes / (gate·trustee) | points / (gate·trustee) | verifier MSM terms or jobs / (gate·trustee) |", "|---|---:|---:|---:|"]
for c in ['v1-cpu', 'v1-tate', 'v3-cpu', 'v5-cpu', 'v8-cpu', 'v9-cpu']:
    s = S[(n, c)]; fam = s['stream']['families']
    units = sum(v['items'] for k, v in fam.items() if k.startswith('mask'))
    pts = sum(v['points'] for v in fam.values())
    pg.append(f"| {c} | {s['bytes']/units:.0f} | {pts/units:.1f} | {s['jobs']/units:.1f} |")
T['PER_GATE'] = "\n".join(pg)

# ---------- model ----------
M = J('model.json')
u = M['unit_costs_seconds']
names = {'p_comp': 'compressed point decode (+clear or nothing)', 'p_aff': 'affine point decode', 'p_tate': 'exact Tate check per point',
         'p_q': '[q]P check per point', 'msm': 'MSM, per (term / log2 of average MSM size)', 'jobs': 'independent variable-base multiplication',
         'items': 'per item (hashing, state, apply)', 'msgs': 'per message (signature, framing, finish)'}
mm = ["| operation | fitted wall cost (µs, 4 vCPU) |", "|---|---:|"] + [f"| {names[k]} | {v*1e6:.2f} |" for k, v in u.items()]
mm.append(f"\nTraining (n = 8, 64; 18 workloads): MAPE {100*M['train_mape']:.1f}%. **Held-out** (n = {', '.join(str(k) for k in sorted({r['n'] for r in M['test']}))}): MAPE **{100*M['test_mape']:.1f}%**, worst {100*M['test_max_abs_rel_err']:.1f}%.\n")
mm.append("| held-out n | configuration | measured replay s | predicted s | error |")
mm.append("|---:|---|---:|---:|---:|")
for r in M['test']:
    mm.append(f"| {r['n']:,} | {r['config']} | {r['measured']:.2f} | {r['predicted']:.2f} | {100*r['rel_err']:+.1f}% |")
mm.append("")
for n_, r in M['ranking'].items():
    mm.append(f"* n = {int(n_):,}: pairwise order agreement {100*r['pairwise_order_agreement']:.0f}%; best measured {r['best_measured']}, best predicted {r['best_predicted']}; bandwidth-selection agreement {r['bandwidth_selection_agreement']}.")
xp = M['cross_protocol_tdec']
mm.append(f"* Cross-protocol (threshold decryption, unit costs from CGY n ≤ 64 only): method ranking correct for every k ({', '.join(str(int(100*a))+'%' for a in M['cross_protocol_order_agreement'])} pairwise agreement at k = 256…16,384); absolute errors {min(100*x['rel_err'] for x in xp):+.0f}% to {max(100*x['rel_err'] for x in xp):+.0f}% (largest for single MSMs of 10⁴–10⁵ terms, beyond the training range).")
T['MODEL'] = "\n".join(mm)
sel = ["| n | 10 Mbit/s | 25 | 50 | 100 | 250 | 1,000 | 10,000 | Pareto set (bytes, replay) |", "|---:|---|---|---|---|---|---|---|---|"]
for n_, d in M['selection'].items():
    sel.append(f"| {int(n_):,} | " + " | ".join(d[str(b)]['best'] for b in [10, 25, 50, 100, 250, 1000, 10000]) + " | " + ", ".join(d['pareto']) + " |")
T['SELECTION'] = "\n".join(sel)

# ---------- tdec ----------
def tdec_tables(file, methods):
    d = J(file)['tdec']
    rows = []
    for r in d['rows']:
        by = {}
        for s in r['samples']: by.setdefault(s['method'], []).append(s)
        rows.append((r['k'], by))
    return d, rows
if os.path.exists(os.path.join(E, 'tdec_attribution.json')):
    d, rows = tdec_tables('tdec_attribution.json', None)
    lad = ['rfc9497', 'rfc9497-128', 'rfc9497-opt', 'lin-sep', 'lin-nomerge', 'lin']
    step = {'rfc9497': 'RFC 9497 structure (full-width composites, per-composite hash, challenge–response, 2 MSMs per trustee)',
            'rfc9497-128': '(1) 128-bit composites', 'rfc9497-opt': '(5) composites from one batch-normalized statement hash (strongest CR baseline)',
            'lin-sep': '(4) commitment form: 1 MSM per trustee, no explicit M, Z', 'lin-nomerge': '(3) one MSM for all trustees', 'lin': '(2) shared bases u_j merged across trustees = `lin`'}
    a = ["| step | verify s (k = 16,384) | step factor | cumulative | MSM terms | coefficient derivation s | public-input total s |", "|---|---:|---:|---:|---:|---:|---:|"]
    k, by = rows[-1]
    prev = None; base = None
    for m in lad:
        v = med(x['verify_seconds'] for x in by[m]); cs = med(x['coef_seconds'] for x in by[m]); pub = med(x['public_total_seconds'] for x in by[m])
        base = base or v
        a.append(f"| {step[m]} | {v:.4f} | {('%.2f×' % (prev / v)) if prev else '—'} | {base / v:.2f}× | {by[m][0]['info']['msm_or_vmul_terms']:,} | {cs:.4f} | {pub:.3f} |")
        prev = v
    a.append(f"\nk = {k:,}, t = {d['t']}, {d['reps']} repetitions, rotated order; medians. Steps at all k:\n")
    a.append("| k | " + " | ".join(lad) + " |")
    a.append("|---:|" + "---:|" * len(lad))
    for k, by in rows:
        a.append(f"| {k:,} | " + " | ".join(f"{med(x['verify_seconds'] for x in by[m]):.4f}" for m in lad) + " |")
    T['TDEC_ATTRIB'] = "\n".join(a)
if os.path.exists(os.path.join(E, 'tdec_public.json')):
    d, rows = tdec_tables('tdec_public.json', None)
    M5 = ['cp', 'cp-msm', 'rfc9497', 'lin', 'joint']
    p = ["| k | method | wire bytes (measured) | analytical shares+proof bytes | decode + exact validation s | verify s | public total s | in-memory verify s |", "|---:|---|---:|---:|---:|---:|---:|---:|"]
    for k, by in rows:
        if k not in (1024, 16384): continue
        for m in M5:
            x = by[m]
            p.append(f"| {k:,} | {m} | {x[0]['wire_bytes_measured']:,} | {x[0]['bytes_public']:,} | {med(y['public_decode_validate_seconds'] for y in x):.4f} | {med(y['public_verify_seconds'] for y in x):.4f} | {med(y['public_total_seconds'] for y in x):.4f} | {med(y['verify_seconds'] for y in x):.4f} |")
    T['TDEC_PUBLIC'] = "\n".join(p)
# ---------- main tdec tables ----------
d = J('tdec_sweep.json')['tdec']
M5 = ['cp', 'cp-msm', 'rfc9497', 'lin', 'joint']
def byk(r):
    b = {}
    for x in r['samples']: b.setdefault(x['method'], []).append(x)
    return b
v = ["| k | cp | cp-msm | rfc9497 | lin | joint | lin vs rfc9497 | lin vs cp-msm | joint vs rfc9497 |", "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
pr = ["| k | cp | cp-msm | rfc9497 | lin | joint |", "|---:|---:|---:|---:|---:|---:|"]
for r in d['rows']:
    b = byk(r); m = {x: med(y['verify_seconds'] for y in b[x]) for x in M5}
    v.append(f"| {r['k']:,} | " + " | ".join(f"{m[x]:.4f}" for x in M5) + f" | {m['rfc9497']/m['lin']:.2f}× | {m['cp-msm']/m['lin']:.2f}× | {m['rfc9497']/m['joint']:.2f}× |")
    pr.append(f"| {r['k']:,} | " + " | ".join(f"{med(y['prove_seconds'] for y in b[x]):.4f}" for x in M5) + " |")
b = byk(d['rows'][-1])
by_ = ["| method | public bytes (analytical: shares or combined decryptions + proofs) | trustee-to-trustee bytes | trustee rounds | verifier MSM / multiplication terms |", "|---|---:|---:|---:|---:|"]
for x in M5:
    y = b[x][0]; by_.append(f"| {x} | {y['bytes_public']:,} | {y['bytes_internal']:,} | {y['rounds']} | {y['info']['msm_or_vmul_terms']:,} |")
T['TDEC_VERIFY'] = "\n".join(v); T['TDEC_PROVE'] = "\n".join(pr); T['TDEC_BYTES'] = "\n".join(by_)
json.dump(T, open(OUTF, 'w'), indent=1)
print("tables:", list(T))

# ---------- modeled communication (labelled projection) ----------
n = max(ns)
rounds = S[(n, 'v1-cpu')]['msgs'] / 5
cm = [f"Modeled for n = {n:,} (**[projection]**: measured bytes and compute, analytical network). Board egress = 4 × transcript bytes (each message forwarded to the other four trustees); public verifier = replay + transcript download. Communication rounds are identical for every format ({S[(n,'v1-cpu')]['msgs']} messages ≈ {rounds:.0f} per trustee); at RTT r they add ≈ {rounds:.0f}·r to every distributed tally, independent of the format.\n",
      "| format | MB | board egress at 10 / 100 / 1,000 Mbit/s (s) | public verifier: replay + download at 10 / 100 / 1,000 Mbit/s (s) |", "|---|---:|---|---|"]
for c in ['v1-cpu', 'v1-tate', 'v3-cpu', 'v4-cpu', 'v5-cpu', 'v6-cpu', 'v8-cpu', 'v9-cpu']:
    s = S[(n, c)]; B = s['bytes']
    eg = " / ".join(f"{4*B*8/(bw*1e6):.1f}" for bw in (10, 100, 1000))
    pv = " / ".join(f"{s['replay'] + B*8/(bw*1e6):.1f}" for bw in (10, 100, 1000))
    cm.append(f"| {c} | {B/1e6:.1f} | {eg} | {pv} |")
T['COMM'] = "\n".join(cm)
sub = J('subgroup_bench.json')['subgroup']['rows']
ops = {}
for r in sub: ops.setdefault(r['op'], []).append(r['us_per_point'])
lab = {'decode_compressed': 'compressed decode (square root)', 'decode_affine_with_curve_check': 'affine decode + curve check',
       'subgroup_q_mul': 'exact: [q]P (wNAF)', 'subgroup_tate': 'exact: order-8 Tate test', 'cofactor_clear8': 'cofactor image [8]Q'}
T['SUBGROUP'] = "\n".join(["| operation | µs per point, median [min, max] |", "|---|---:|"] + [f"| {lab[k]} | {med(v):.2f} [{min(v):.2f}, {max(v):.2f}] |" for k, v in ops.items()])
json.dump(T, open(OUTF, 'w'), indent=1)
print("tables:", list(T))
