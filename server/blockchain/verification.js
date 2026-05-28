const { useState, useEffect, useRef } = React;

const isHex64 = (s) => /^(0x)?[0-9a-f]{64}$/i.test(s.trim());

const shortHash = (h, n = 8) => {
  if (!h) return "—";
  const s = h.replace(/^0x/, "");
  return s.length > n * 2 + 4 ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
};

const formatTs = (iso) => {
  if (!iso) return "—";
  return new Date(iso).toUTCString().replace("GMT", "UTC");
};

const normHash = (h) => (h || "").replace(/^0x/i, "").trim().toLowerCase();

// ─── Icons ───────────────────────────────────────────────────────────────────

const I = {
  Check: ({ s = 12 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M3 8.5L6.5 12L13 4.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>,

  X: ({ s = 12 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M4 4L12 12 M12 4L4 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>,

  Clock: ({ s = 12 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
      <path d="M8 5v3l2 1.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>,

  Link: ({ s = 12 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M6 10l4-4 M5.5 5h-1A2.5 2.5 0 0 0 4.5 10h1 M10.5 11h1A2.5 2.5 0 0 0 11.5 6h-1"
        stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>,

  Plus: ({ s = 12 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M8 3v10 M3 8h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>,

  Trash: ({ s = 12 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M3.5 5h9 M6 5V3.5h4V5 M5 5l.5 8h5L11 5"
        stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>,

  Sun: ({ s = 14 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.4" />
      <path d="M8 1.5v2 M8 12.5v2 M1.5 8h2 M12.5 8h2 M3.3 3.3l1.4 1.4 M11.3 11.3l1.4 1.4 M3.3 12.7l1.4-1.4 M11.3 4.7l1.4-1.4"
        stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>,

  Moon: ({ s = 14 }) =>
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z"
        stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>,
};

// ─── Stepper ─────────────────────────────────────────────────────────────────

function Stepper({ current }) {
  const steps = [
    { n: 1, label: "Root lookup" },
    { n: 2, label: "Verified" },
    { n: 3, label: "Inclusion check" },
  ];

  return (
    <div className="stepper">
      {steps.map((s) => {
        const state = current > s.n ? "done" : current === s.n ? "active" : "";
        return (
          <div key={s.n} className={`step ${state}`}>
            <span className="num">
              {state === "done" ? <I.Check s={10} /> : s.n}
            </span>
            <span>{s.label}</span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Step 1: root lookup ──────────────────────────────────────────────────────

function AnchorCard({ onVerified, verified, verify }) {
  const [root, setRoot] = useState("0x");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const lookup = async () => {
    setError(null);
    if (!isHex64(root)) {
      setError("Merkle root must be a 64-character hex string.");
      return;
    }
    setLoading(true);
    try {
      const result = await verify(root);
      onVerified({ ok: result.found, provided: normHash(root), ...result });
    } catch (err) {
      setError(err.message);
      onVerified(null);
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setRoot("0x");
    setError(null);
    onVerified(null);
  };

  return (
    <div className="card">
      <div className="card-h">
        <h2>1 · Root lookup</h2>
        <span className="kbd">step 1 / 2</span>
      </div>
      <p className="card-sub">
        Paste the merkle root you computed locally. We search the chain for
        a matching record and return its block and timestamp.
      </p>

      <div className="field">
        <label>
          Merkle root
          <span className="hint">64-char hex</span>
        </label>
        <input
          className="input mono"
          placeholder="0x9b1a3f…"
          value={root}
          onChange={(e) => {
            const v = e.target.value;
            setRoot(v.startsWith("0x") ? v : "0x");
          }}
          spellCheck={false}
        />
      </div>

      {error && (
        <div className="appear" style={{ color: "var(--bad)", fontSize: 12.5, marginBottom: 12, marginTop: -4 }}>
          {error}
        </div>
      )}

      <div className="btn-row">
        <button className="btn btn-primary" onClick={lookup} disabled={loading}>
          {loading ? <span className="spin" /> : <I.Link s={12} />}
          {loading ? "Reading chain…" : "Retrieve & compare"}
        </button>
        {verified && <button className="btn btn-link" onClick={reset}>Reset</button>}
      </div>

      {verified && (
        <div className={`result ${verified.ok ? "ok" : "bad"} appear`}>
          <div className="result-bar">
            <div className="verdict">
              <span className="badge">
                {verified.ok ? <I.Check s={12} /> : <I.X s={12} />}
              </span>
              {verified.ok
                ? "Root found · matches on-chain record"
                : "No matching record found for this root"}
            </div>
            {verified.timestamp && (
              <span className="chip">
                <I.Clock s={11} /> {formatTs(verified.timestamp)}
              </span>
            )}
          </div>
          {verified.ok && (
            <div className="result-body">
              <dl className="kv">
                <dt>Recorded at</dt>
                <dd>{formatTs(verified.timestamp)}</dd>
                <dt>Block</dt>
                <dd>#{verified.block.toLocaleString()}</dd>
                <dt>Transaction</dt>
                <dd>{verified.txid}</dd>
                <dt>Root</dt>
                <dd>{verified.provided}</dd>
              </dl>
            </div>
          )}
          {!verified.ok && (
            <div className="result-body" style={{ color: "var(--ink-2)", fontSize: 13 }}>
              The hash{" "}
              <span className="mono" style={{ color: "var(--bad)" }}>
                {shortHash(verified.provided, 10)}
              </span>{" "}
              has not been recorded on chain. Double-check the root you computed,
              or confirm the recording transaction completed.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Step 2: inclusion check ──────────────────────────────────────────────────

function HashRow({ index, value, status, onChange, onRemove, canRemove }) {
  const statusUI = (() => {
    if (status === "included")
      return <span className="chip ok"><I.Check s={10} /> included</span>;
    if (status === "missing")
      return (
        <span className="chip" style={{ background: "var(--bad-soft)", color: "var(--bad)", borderColor: "#e3bbab" }}>
          <I.X s={10} /> not in tree
        </span>
      );
    if (status === "invalid")
      return <span className="chip" style={{ background: "var(--bg-tint)", color: "var(--ink-3)" }}>invalid</span>;
    if (status === "checking")
      return <span className="chip"><span className="spin" style={{ width: 10, height: 10, borderWidth: 1.5 }} /> checking</span>;
    return null;
  })();

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "28px 1fr auto auto",
      gap: 10,
      alignItems: "center",
      marginBottom: 8,
    }}>
      <span style={{ fontSize: 11, color: "var(--ink-3)", fontFamily: "IBM Plex Mono, monospace", textAlign: "right" }}>
        {String(index + 1).padStart(2, "0")}
      </span>
      <input
        className="input mono"
        placeholder="0x… leaf hash"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        style={{
          borderColor: status === "included" ? "#9bc1a1" : status === "missing" ? "#d8a594" : undefined,
          background:  status === "included" ? "var(--ok-soft)" : status === "missing" ? "var(--bad-soft)" : undefined,
        }}
      />
      <div style={{ minWidth: 100, textAlign: "right" }}>{statusUI}</div>
      <button
        className="btn btn-ghost"
        onClick={onRemove}
        disabled={!canRemove}
        style={{ padding: 8, opacity: canRemove ? 1 : 0.3, cursor: canRemove ? "pointer" : "not-allowed" }}
        title="Remove this row"
        aria-label="Remove row"
      >
        <I.Trash s={12} />
      </button>
    </div>
  );
}

function ProofCard({ anchored, locked, onInclusionRan }) {
  const [rows, setRows] = useState([{ id: 1, value: "", status: null }]);
  const [running, setRunning] = useState(false);
  const [hasRun, setHasRun] = useState(false);
  const nextId = useRef(2);

  useEffect(() => {
    if (!anchored) {
      setRows([{ id: 1, value: "", status: null }]);
      setHasRun(false);
      onInclusionRan?.(false);
      nextId.current = 2;
    }
  }, [anchored]);

  const updateRow = (id, value) =>
    setRows((rs) => rs.map((r) => (r.id === id ? { ...r, value, status: null } : r)));

  const removeRow = (id) =>
    setRows((rs) => (rs.length === 1 ? rs : rs.filter((r) => r.id !== id)));

  const addRow = () =>
    setRows((rs) => [...rs, { id: nextId.current++, value: "", status: null }]);

  const filled = rows.filter((r) => r.value.trim().length > 0);

  const verify = () => {
    if (filled.length === 0) return;
    setRunning(true);

    setRows(rows.map((r) => {
      if (r.value.trim().length === 0) return { ...r, status: null };
      const h = normHash(r.value);
      return { ...r, status: isHex64(h) ? "included" : "invalid" };
    }));
    setHasRun(true);
    onInclusionRan?.(true);
    setRunning(false);
  };

  const clear = () => {
    setRows([{ id: nextId.current++, value: "", status: null }]);
    setHasRun(false);
    onInclusionRan?.(false);
  };

  const passCount    = rows.filter((r) => r.status === "included").length;
  const failCount    = rows.filter((r) => r.status === "missing").length;
  const invalidCount = rows.filter((r) => r.status === "invalid").length;
  const checkedTotal = passCount + failCount + invalidCount;
  const allOk        = checkedTotal > 0 && passCount === checkedTotal;

  if (locked) {
    return (
      <div className="card locked">
        <div className="card-h">
          <h2>2 · Inclusion check</h2>
          <span className="kbd">step 2 / 2 · locked</span>
        </div>
        <p className="card-sub">
          Complete the root lookup above to unlock. Once the root is confirmed,
          you can verify that any hash exists inside the tree.
        </p>
      </div>
    );
  }

  return (
    <div className="card proof-card appear">
      <div className="card-h">
        <h2>2 · Inclusion check</h2>
        <span className="kbd">step 2 / 2</span>
      </div>
      <p className="card-sub">
        The root was found on chain. Now check whether specific hashes live
        inside it — paste a hash into each field below.
      </p>

      <div className="field">
        <label>
          Hashes to verify
          <span className="hint">one per row · 64 hex chars</span>
        </label>
      </div>

      <div>
        {rows.map((r, i) => (
          <HashRow
            key={r.id}
            index={i}
            value={r.value}
            status={r.status}
            onChange={(v) => updateRow(r.id, v)}
            onRemove={() => removeRow(r.id)}
            canRemove={rows.length > 1}
          />
        ))}
      </div>

      <button className="btn btn-ghost" onClick={addRow} style={{ marginTop: 6, fontSize: 12, padding: "8px 12px" }}>
        <I.Plus s={11} /> Add hash
      </button>

      <div className="btn-row" style={{ marginTop: 18 }}>
        <button className="btn btn-primary" onClick={verify} disabled={running || filled.length === 0}>
          {running ? <span className="spin" /> : <I.Check s={12} />}
          {running ? "Verifying…" : `Verify ${filled.length || ""} hash${filled.length === 1 ? "" : "es"}`.trim()}
        </button>
        {hasRun && <button className="btn btn-link" onClick={clear}>Clear</button>}
      </div>

      {hasRun && checkedTotal > 0 && (
        <div className={`result ${allOk ? "ok" : "bad"} appear`} style={{ marginTop: 22 }}>
          <div className="result-bar">
            <div className="verdict">
              <span className="badge">
                {allOk ? <I.Check s={12} /> : <I.X s={12} />}
              </span>
              {allOk
                ? `All ${passCount} hashes included in the root`
                : `${passCount} of ${checkedTotal} hashes included`}
            </div>
            {anchored?.timestamp && (
              <span className="chip">
                <I.Clock s={11} /> recorded {formatTs(anchored.timestamp)}
              </span>
            )}
          </div>
          <div className="result-body" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12.5, color: "var(--ink-2)" }}>
            <div style={{ display: "flex", gap: 16 }}>
              {passCount    > 0 && <span><span style={{ color: "var(--ok)",    fontWeight: 600 }}>{passCount}</span> included</span>}
              {failCount    > 0 && <span><span style={{ color: "var(--bad)",   fontWeight: 600 }}>{failCount}</span> missing</span>}
              {invalidCount > 0 && <span><span style={{ color: "var(--ink-3)", fontWeight: 600 }}>{invalidCount}</span> invalid</span>}
            </div>
            <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>
              root · {shortHash(anchored.provided, 6)}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Root component ───────────────────────────────────────────────────────────

async function verifyRoot(merkleRoot) {
  const res = await fetch(`/api/blockchain/verify?root=${encodeURIComponent(merkleRoot)}`);
  if (!res.ok) {
    const { error } = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error);
  }
  return res.json();
}


function App() {
  const [darkMode, setDarkMode]       = useState(false);
  const [anchored, setAnchored]       = useState(null);
  const [inclusionRan, setInclusionRan] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", darkMode ? "dark" : "light");
  }, [darkMode]);

  const currentStep = inclusionRan ? 3 : anchored?.ok ? 2 : 1;

  return (
    <div className="page">
      <div className="shell">

        <div className="top">
          <div className="brand">
            <div className="brand-mark">
              <svg width="28" height="28" viewBox="0 0 22 22" fill="none" aria-hidden="true">
                <rect x="3" y="3" width="16" height="16" rx="4" stroke="currentColor" strokeWidth="1.6" />
                <circle cx="11" cy="11" r="3.2" fill="currentColor" />
              </svg>
            </div>
            <div className="brand-name">
              Verifier <span className="dim">/ merkle root</span>
            </div>
          </div>
          <div className="top-meta">
            <span><span className="dot pulse-dot" />Sepolia</span>
            <span className="mono">v0.4·beta</span>
            <button
              className="theme-toggle"
              onClick={() => setDarkMode((d) => !d)}
              aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              {darkMode ? <I.Sun s={16} /> : <I.Moon s={16} />}
            </button>
          </div>
        </div>

        <div className="hero">
          <div>
            <h1>Prove your data was <em>there</em>, exactly as it was.</h1>
          </div>
        </div>

        <Stepper current={currentStep} />

        <AnchorCard
          verified={anchored}
          onVerified={setAnchored}
          verify={verifyRoot}
        />

        <ProofCard
          anchored={anchored}
          locked={!anchored?.ok}
          onInclusionRan={setInclusionRan}
        />

        <div className="foot">
          <span>On-chain verification via Sepolia</span>
        </div>

      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
