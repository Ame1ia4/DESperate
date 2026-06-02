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

// ─── Copy button ─────────────────────────────────────────────────────────────

function CopyBtn({ value }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      className="btn btn-link"
      onClick={copy}
      style={{ padding: "0 6px", fontSize: 11, marginLeft: 6, verticalAlign: "middle" }}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// ─── Stepper ─────────────────────────────────────────────────────────────────

function Stepper({ current }) {
  const steps = [
    { n: 1, label: "Root lookup" },
    { n: 2, label: "Inclusion check" },
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
                <dd>{verified.txid}<CopyBtn value={verified.txid} /></dd>
                <dt>Root</dt>
                <dd>{verified.provided}<CopyBtn value={verified.provided} /></dd>
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

function hexOrBase64ToBytes(input) {
  const s = input.trim();
  if (/^(0x)?[0-9a-f]+$/i.test(s)) {
    return ethers.getBytes(s.startsWith("0x") ? s : "0x" + s);
  }
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function ProofCard({ anchored, locked, onInclusionRan }) {
  const [ciphertext, setCiphertext] = useState("");
  const [result, setResult]         = useState(null); // { ok, reason, leaf }
  const [running, setRunning]       = useState(false);

  useEffect(() => {
    if (!anchored) {
      setCiphertext("");
      setResult(null);
      onInclusionRan?.(false);
    }
  }, [anchored]);

  const verify = async () => {
    if (!ciphertext.trim()) return;
    setRunning(true);
    setResult(null);
    try {
      const ctBytes = hexOrBase64ToBytes(ciphertext);
      const leaf    = ethers.keccak256(ctBytes);

      const res  = await fetch("/blockchain/verify-leaf", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ leaf, root: anchored.provided }),
      });
      const body = await res.json();

      if (!res.ok) throw new Error(body.error || res.statusText);

      setResult({ ok: body.verified, reason: body.reason, leaf });
      onInclusionRan?.(body.verified);
    } catch (err) {
      setResult({ ok: false, reason: err.message, leaf: null });
      onInclusionRan?.(false);
    } finally {
      setRunning(false);
    }
  };

  const clear = () => {
    setCiphertext("");
    setResult(null);
    onInclusionRan?.(false);
  };

  if (locked) {
    return (
      <div className="card locked">
        <div className="card-h">
          <h2>2 · Inclusion check</h2>
          <span className="kbd">step 2 / 2 · locked</span>
        </div>
        <p className="card-sub">
          Complete the root lookup above to unlock. Once the root is confirmed
          on-chain, paste your message ciphertext below to prove it is included.
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
        The root was found on-chain. Paste the raw message ciphertext (hex or
        base64) to prove it is included in this Merkle tree.
      </p>

      <div className="field">
        <label>
          Ciphertext
          <span className="hint">hex or base64</span>
        </label>
        <textarea
          className="input mono"
          rows={4}
          placeholder="0x… or base64…"
          value={ciphertext}
          onChange={(e) => { setCiphertext(e.target.value); setResult(null); }}
          spellCheck={false}
          style={{ resize: "vertical", fontFamily: "IBM Plex Mono, monospace", fontSize: 12 }}
        />
      </div>

      <div className="btn-row">
        <button
          className="btn btn-primary"
          onClick={verify}
          disabled={running || !ciphertext.trim()}
        >
          {running ? <span className="spin" /> : <I.Check s={12} />}
          {running ? "Verifying…" : "Verify inclusion"}
        </button>
        {result && <button className="btn btn-link" onClick={clear}>Clear</button>}
      </div>

      {result && (
        <div className={`result ${result.ok ? "ok" : "bad"} appear`} style={{ marginTop: 22 }}>
          <div className="result-bar">
            <div className="verdict">
              <span className="badge">
                {result.ok ? <I.Check s={12} /> : <I.X s={12} />}
              </span>
              {result.ok
                ? "Ciphertext is included in the on-chain root"
                : result.reason || "Ciphertext not found in this root"}
            </div>
            {anchored?.timestamp && (
              <span className="chip">
                <I.Clock s={11} /> recorded {formatTs(anchored.timestamp)}
              </span>
            )}
          </div>
          {result.ok && result.leaf && (
            <div className="result-body">
              <dl className="kv">
                <dt>Leaf (keccak256)</dt>
                <dd>{result.leaf}<CopyBtn value={result.leaf} /></dd>
                <dt>Root</dt>
                <dd>{anchored.provided}<CopyBtn value={anchored.provided} /></dd>
              </dl>
            </div>
          )}
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
