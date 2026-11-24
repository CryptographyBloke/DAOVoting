"""T009 cost model and format selection.

Fits per-operation wall-clock costs (4 vCPU, Rayon) on the training
workloads n in {8, 64} and predicts the held-out n in {256, 1024}.
Features are exact operation counts derived from the measured transcripts.
"""
import json, sys, os, itertools, statistics as st
import numpy as np

def nnls(A, b, iters=500):
    """Lawson-Hanson active-set non-negative least squares."""
    m, n = A.shape
    P = np.zeros(n, bool); x = np.zeros(n)
    w = A.T @ (b - A @ x)
    for _ in range(iters):
        if P.all() or w[~P].max() <= 1e-12:
            break
        j = np.argmax(np.where(~P, w, -np.inf)); P[j] = True
        while True:
            z = np.zeros(n)
            z[P] = np.linalg.lstsq(A[:, P], b, rcond=None)[0]
            if (z[P] > 0).all():
                x = z; break
            Q = P & (z <= 0)
            alpha = np.min(x[Q] / (x[Q] - z[Q]))
            x = x + alpha * (z - x)
            P = P & (x > 1e-15)
        w = A.T @ (b - A @ x)
    return x, None

O = sys.argv[1]
def P(*c):
    for x in c:
        if os.path.exists(os.path.join(O, x)): return os.path.join(O, x)
    raise FileNotFoundError(c)
S = {tuple([int(k.split('|')[0]), k.split('|')[1]]): v for k, v in json.load(open(P('summary.json', 'engine_summary.json'))).items()}
WIDE = {'v4-cpu', 'v6-cpu'}
NATIVE = {'v7-cpu', 'v8-cpu', 'v9-cpu'}
CSZ_CR_JOBS = 10  # Csz::jobs per challenge-response mask (v1, v9)

def feats(n, c):
    s = S[(n, c)]
    fam = s['stream']['families']
    pts = sum(v['points'] for v in fam.values())
    masks = sum(v['items'] for k, v in fam.items() if k.startswith('mask'))
    items = sum(v['items'] for v in fam.values())
    f = dict(p_comp=0, p_aff=0, p_tate=0, p_q=0, msm=0, jobs=0, items=items, msgs=s['msgs'])
    if c == 'v1-cpu':
        f['p_comp'] = pts; f['p_q'] = pts; f['jobs'] = s['jobs'] - pts
    elif c == 'v1-tate':
        f['p_comp'] = pts; f['p_tate'] = pts; f['jobs'] = s['jobs']
    else:
        f['p_aff' if c in WIDE else 'p_comp'] = pts
        if c in NATIVE:
            f['p_tate'] = pts
        if c == 'v9-cpu':
            f['jobs'] = CSZ_CR_JOBS * masks; f['msm'] = s['jobs'] - f['jobs']
        else:
            f['msm'] = s['jobs']
    if f['msm']:
        f['msm'] = f['msm'] / np.log2(max(2.0, f['msm'] / max(1, s['batches'])))
    return f

KEYS = ['p_comp', 'p_aff', 'p_tate', 'p_q', 'msm', 'jobs', 'items', 'msgs']
CONF = ['v1-cpu', 'v1-tate', 'v3-cpu', 'v4-cpu', 'v5-cpu', 'v6-cpu', 'v7-cpu', 'v8-cpu', 'v9-cpu']
ns = sorted({k[0] for k in S})
train = [(n, c) for n in ns if n <= 64 for c in CONF if (n, c) in S]
test = [(n, c) for n in ns if n > 64 for c in CONF if (n, c) in S]
X = np.array([[feats(*k)[f] for f in KEYS] for k in train], float)
y = np.array([S[k]['replay'] for k in train])
# relative-error weighting: each workload counts equally
w = 1.0 / y
coef, _ = nnls(X * w[:, None], y * w)
unit = dict(zip(KEYS, coef))
out = {'unit_costs_seconds': unit, 'train': [], 'test': []}
def pred(k):
    f = feats(*k)
    return sum(unit[x] * f[x] for x in KEYS)
for name, ks in [('train', train), ('test', test)]:
    for k in ks:
        p = pred(k); m = S[k]['replay']
        out[name].append(dict(n=k[0], config=k[1], measured=m, predicted=p, rel_err=(p - m) / m))
for name in ['train', 'test']:
    errs = [abs(r['rel_err']) for r in out[name]]
    if errs:
        out[name + '_mape'] = sum(errs) / len(errs)
        out[name + '_max_abs_rel_err'] = max(errs)
# ranking agreement on held-out n
rank = {}
for n in [n for n in ns if n > 64]:
    rows = [r for r in out['test'] if r['n'] == n]
    pairs = list(itertools.combinations(rows, 2))
    agree = sum((a['measured'] < b['measured']) == (a['predicted'] < b['predicted']) for a, b in pairs)
    best_m = min(rows, key=lambda r: r['measured'])['config']
    best_p = min(rows, key=lambda r: r['predicted'])['config']
    rank[n] = dict(pairwise_order_agreement=agree / len(pairs), best_measured=best_m, best_predicted=best_p)
    ag = 0
    for mbit in [10, 25, 50, 100, 250, 1000, 10000]:
        bw = mbit * 1e6 / 8
        bm = min(rows, key=lambda r: r['measured'] + S[(n, r['config'])]['bytes'] / bw)['config']
        bp = min(rows, key=lambda r: r['predicted'] + S[(n, r['config'])]['bytes'] / bw)['config']
        ag += bm == bp
    rank[n]['bandwidth_selection_agreement'] = f"{ag}/7"
out['ranking'] = rank

# selection under bandwidth: T = replay + bytes / bandwidth (receive the transcript once)
sel = {}
for n in ns:
    rows = [(c, S[(n, c)]['replay'], S[(n, c)]['bytes']) for c in CONF if (n, c) in S]
    sel[n] = {}
    for mbit in [10, 25, 50, 100, 250, 1000, 10000]:
        bw = mbit * 1e6 / 8
        best = min(rows, key=lambda r: r[1] + r[2] / bw)
        sel[n][mbit] = dict(best=best[0], total_seconds=best[1] + best[2] / bw)
    # Pareto frontier (bytes, replay)
    front = [r for r in rows if not any((o[1] <= r[1] and o[2] <= r[2]) and (o[1] < r[1] or o[2] < r[2]) for o in rows)]
    sel[n]['pareto'] = sorted([r[0] for r in front])
out['selection'] = sel
json.dump(out, open(os.path.join(O, 'model.json'), 'w'), indent=1)
print('unit costs (us):', {k: round(v * 1e6, 3) for k, v in unit.items()})
print('train MAPE %.3f  test MAPE %.3f  test max %.3f' % (out['train_mape'], out.get('test_mape', float('nan')), out.get('test_max_abs_rel_err', float('nan'))))
for r in out['test']:
    print(f"  n={r['n']:5d} {r['config']:8s} measured {r['measured']:7.2f} predicted {r['predicted']:7.2f} err {100*r['rel_err']:+5.1f}%")
print('ranking', json.dumps(rank))
for n in ns:
    print(n, json.dumps(sel[n]))

# ---------------- physical model (preferred) ----------------
# single-thread unit costs from subgroup-bench (us), measured on this VM
SUB = json.load(open(P('subgroup/subgroup_bench.json', 'subgroup_bench.json')))['subgroup']['rows']
u = {}
for r in SUB:
    u.setdefault(r['op'], []).append(r['us_per_point'])
u = {k: st.median(v) * 1e-6 for k, v in u.items()}
LIFTED = {'v3-cpu', 'v4-cpu', 'v5-cpu', 'v6-cpu'}
def pfeat(n, c):
    f = feats(n, c)
    s = S[(n, c)]
    point_work = (f['p_comp'] * u['decode_compressed'] + f['p_aff'] * u['decode_affine_with_curve_check']
                  + f['p_tate'] * u['subgroup_tate']
                  + (f['p_comp'] + f['p_aff']) * (u['cofactor_clear8'] if c in LIFTED else 0))
    jobs = s['jobs'] if c in ('v1-cpu', 'v1-tate') else f['jobs']
    # Pippenger: cost per term ~ 1/log2(average MSM size per message)
    return point_work, f['msm'], jobs, f['items']
# per-term MSM and per-job wall costs measured on TRAINING runs only
msm_rates = [S[k]['run'] / pfeat(*k)[1] for k in train if k[1] in LIFTED | {'v7-cpu', 'v8-cpu'} and S[k]['jobs']]
job_rates = [S[k]['run'] / S[k]['jobs'] for k in train if k[1] in ('v1-cpu', 'v1-tate')]
msm_us, job_us = st.median(msm_rates), st.median(job_rates)
# fit 1/P (parallel factor for point work) and per-item overhead by least squares on training
A = []; b = []
for k in train:
    pw, m, j, it = pfeat(*k)
    A.append([pw, it]); b.append((S[k]['replay'] - m * msm_us - j * job_us) / S[k]['replay'])
    A[-1] = [A[-1][0] / S[k]['replay'], A[-1][1] / S[k]['replay']]
sol = np.linalg.lstsq(np.array(A), np.array(b), rcond=None)[0]
inv_p, o_item = sol
def ppred(k):
    pw, m, j, it = pfeat(*k)
    return inv_p * pw + m * msm_us + j * job_us + o_item * it
phys = {'unit_single_thread_us': {k: v * 1e6 for k, v in u.items()}, 'msm_wall_us_per_term_log2N': msm_us * 1e6,
        'job_wall_us': job_us * 1e6, 'parallel_speedup_point_work': 1 / inv_p, 'item_overhead_us': o_item * 1e6,
        'rows': []}
for name, ks in [('train', train), ('test', test)]:
    for k in ks:
        p = ppred(k); m = S[k]['replay']
        phys['rows'].append(dict(set=name, n=k[0], config=k[1], measured=m, predicted=p, rel_err=(p - m) / m))
for name in ['train', 'test']:
    e = [abs(r['rel_err']) for r in phys['rows'] if r['set'] == name]
    if e: phys[name + '_mape'] = sum(e) / len(e); phys[name + '_max'] = max(e)
prank = {}
for n in [n for n in ns if n > 64]:
    rows = [r for r in phys['rows'] if r['set'] == 'test' and r['n'] == n]
    pairs = list(itertools.combinations(rows, 2))
    prank[n] = dict(pairwise_order_agreement=sum((a['measured'] < b['measured']) == (a['predicted'] < b['predicted']) for a, b in pairs) / len(pairs),
                    best_measured=min(rows, key=lambda r: r['measured'])['config'], best_predicted=min(rows, key=lambda r: r['predicted'])['config'])
    # predicted selection agrees with measured selection under each bandwidth?
    agree = 0; tot = 0
    for mbit in [10, 25, 50, 100, 250, 1000, 10000]:
        bw = mbit * 1e6 / 8
        bm = min(rows, key=lambda r: r['measured'] + S[(n, r['config'])]['bytes'] / bw)['config']
        bp = min(rows, key=lambda r: r['predicted'] + S[(n, r['config'])]['bytes'] / bw)['config']
        agree += bm == bp; tot += 1
    prank[n]['bandwidth_selection_agreement'] = f"{agree}/{tot}"
phys['ranking'] = prank
out['physical_model'] = phys
json.dump(out, open(os.path.join(O, 'model.json'), 'w'), indent=1)
print('\nPHYSICAL MODEL', {k: (round(v, 3) if isinstance(v, float) else v) for k, v in phys.items() if k not in ('rows', 'unit_single_thread_us')})
for r in phys['rows']:
    if r['set'] == 'test':
        print(f"  n={r['n']:5d} {r['config']:8s} measured {r['measured']:7.2f} predicted {r['predicted']:7.2f} err {100*r['rel_err']:+5.1f}%")
print(json.dumps(prank))

# ---------------- cross-protocol check: threshold decryption ----------------
T = json.load(open(P('tdec/tdec_sweep.json', 'tdec_sweep.json')))['tdec']
tt = T['t']
def tfeat(method, k):
    L = lambda N, B=1: (N / np.log2(max(2.0, N / B))) if N else 0.0
    f = dict(p_comp=0, p_aff=0, p_tate=0, p_q=0, msm=0.0, jobs=0, items=tt * k, msgs=0)
    if method == 'cp': f['jobs'] = 2 * tt * k
    elif method == 'cp-msm': f['msm'] = L(4 * tt * k)
    elif method == 'rfc9497': f['msm'] = L(2 * tt * k, 2 * tt)
    elif method == 'lin': f['msm'] = L((tt + 1) * k + 3 * tt)
    elif method == 'joint': f['msm'] = L(2 * k + 3); f['items'] = k
    return f
xp = []
for r in T['rows']:
    if r['k'] < 256: continue
    by = {}
    for s_ in r['samples']: by.setdefault(s_['method'], []).append(s_['verify_seconds'])
    for m, v in by.items():
        f = tfeat(m, r['k']); p = sum(unit[x] * f[x] for x in KEYS)
        xp.append(dict(k=r['k'], method=m, measured=st.median(v), predicted=p, rel_err=(p - st.median(v)) / st.median(v)))
out['cross_protocol_tdec'] = xp
order_ok = []
for kk in sorted({x['k'] for x in xp}):
    rows = [x for x in xp if x['k'] == kk]
    pairs = list(itertools.combinations(rows, 2))
    order_ok.append(sum((a['measured'] < b['measured']) == (a['predicted'] < b['predicted']) for a, b in pairs) / len(pairs))
out['cross_protocol_order_agreement'] = order_ok
json.dump(out, open(os.path.join(O, 'model.json'), 'w'), indent=1)
print('\nCROSS-PROTOCOL (unit costs fitted on CGY n<=64 only)')
for x in xp:
    print(f"  k={x['k']:6d} {x['method']:8s} measured {x['measured']:.4f} predicted {x['predicted']:.4f} err {100*x['rel_err']:+6.1f}%")
print('pairwise order agreement per k:', [round(a, 2) for a in order_ok])
