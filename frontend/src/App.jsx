import { useCallback, useEffect, useState } from "react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

function formatApiError(error) {
  const detail = error?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || "Invalid input").join("; ");
  }
  return error?.message || "The request could not be completed.";
}

async function requestApi(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...options.headers },
    });
  } catch {
    throw new Error(`Cannot reach the API at ${API_BASE}. Start FastAPI and try again.`);
  }

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(formatApiError(body) || `API request failed (${response.status}).`);
  }
  return body;
}

function priorityFor(score) {
  if (score >= 76) return "CRITICAL";
  if (score >= 51) return "HIGH";
  if (score >= 26) return "MEDIUM";
  return "LOW";
}

function displayList(items) {
  if (!Array.isArray(items) || items.length === 0) return <span className="muted">No associations found</span>;
  return (
    <ul className="association-list">
      {items.map((item) => <li key={item}>{item}</li>)}
    </ul>
  );
}

function App() {
  const [value, setValue] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [error, setError] = useState("");
  const [historyError, setHistoryError] = useState("");
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const items = await requestApi("/api/investigations?limit=20");
      setHistory(items);
    } catch (requestError) {
      setHistoryError(formatApiError(requestError));
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  const investigate = async (indicator) => {
    const submittedValue = indicator.trim();
    if (!submittedValue) {
      setError("Enter an IOC to investigate.");
      return;
    }

    setLoading(true);
    setError("");
    try {
      const data = await requestApi("/api/investigate", {
        method: "POST",
        body: JSON.stringify({ value: submittedValue }),
      });
      setResult(data);
      setValue(data.ioc.value);
      setSelectedId(data.ioc.id);
      await refreshHistory();
    } catch (requestError) {
      setError(formatApiError(requestError));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (event) => {
    event.preventDefault();
    investigate(value);
  };

  const selectHistoryItem = (item) => {
    investigate(item.value);
  };

  const ioc = result?.ioc;
  const analysis = result?.analysis || {};
  const correlations = result?.correlations || {};
  const factors = analysis.factors || [];
  const malware = correlations.related_malware || correlations.malware || [];
  const actors = correlations.threat_actors || (correlations.threat_actor ? [correlations.threat_actor] : []);
  const campaigns = correlations.campaigns || (correlations.campaign ? [correlations.campaign] : []);
  const techniques = correlations.mitre_techniques || (correlations.mitre_technique ? [correlations.mitre_technique] : []);
  const indicators = correlations.related_indicators || [];
  const score = ioc?.risk_score ?? 0;
  const priority = analysis.priority || priorityFor(score);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-mark" aria-hidden="true">CTI</div>
        <div className="topbar-copy">
          <span className="eyebrow">THREAT INTELLIGENCE WORKSPACE</span>
          <span className="service-status"><span className="status-dot" /> Local API dashboard</span>
        </div>
      </header>

      <main className="page-content">
        <section className="page-heading">
          <p className="eyebrow">INVESTIGATION CONSOLE</p>
          <h1>AI-Assisted IOC Investigation and Cyber Threat Intelligence Platform</h1>
          <p className="heading-description">Inspect an indicator, review its demo intelligence, and see the evidence behind its risk score.</p>
        </section>

        <section className="panel search-panel" aria-labelledby="investigate-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">NEW INVESTIGATION</p>
              <h2 id="investigate-heading">Analyze an indicator</h2>
            </div>
            <span className="api-label">POST /api/investigate</span>
          </div>
          <form className="search-form" onSubmit={onSubmit}>
            <label className="sr-only" htmlFor="ioc-input">IOC value</label>
            <input
              id="ioc-input"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder="IP address, domain, URL, email, or file hash"
              autoComplete="off"
              maxLength={512}
              disabled={loading}
            />
            <button className="primary-button" type="submit" disabled={loading}>
              {loading ? "Investigating…" : "Investigate IOC"}
              {!loading && <span aria-hidden="true">→</span>}
            </button>
          </form>
          <p className="form-hint">Supports IPv4, IPv6, domains, URLs, email addresses, MD5, SHA1, and SHA256.</p>
          {error && <div className="error-message" role="alert">{error}</div>}
        </section>

        {result && (
          <section className="results-section" aria-live="polite">
            <div className="section-title-row">
              <div>
                <p className="eyebrow">INVESTIGATION RESULT</p>
                <h2>Indicator assessment</h2>
              </div>
              <span className={`priority-pill priority-${priority.toLowerCase()}`}>{priority} PRIORITY</span>
            </div>

            <div className="panel result-overview">
              <div className="indicator-heading">
                <span className="type-icon" aria-hidden="true">⌁</span>
                <div className="indicator-value-wrap">
                  <span className="eyebrow">INVESTIGATED IOC</span>
                  <h3 className="indicator-value">{ioc.value}</h3>
                </div>
              </div>
              <div className="metric-grid">
                <Metric label="IOC type" value={ioc.type.toUpperCase()} />
                <Metric label="Reputation" value={ioc.reputation} />
                <Metric label="Risk score" value={`${score} / 100`} />
                <Metric label="Confidence" value={`${Math.round((ioc.confidence || 0) * 100)}%`} />
              </div>
              <div className="risk-meter" aria-label={`Risk score ${score} out of 100`}>
                <div className="risk-meter-label"><span>Risk level</span><strong>{priority}</strong></div>
                <div className="risk-track"><span style={{ width: `${Math.min(Math.max(score, 0), 100)}%` }} /></div>
              </div>
            </div>

            <div className="detail-grid">
              <DetailCard title="Why this score" eyebrow="RISK FACTORS">
                {factors.length ? (
                  <ul className="factor-list">{factors.map((factor) => <li key={factor}><span className="factor-check">+</span>{factor}</li>)}</ul>
                ) : <p className="muted">No risk factors returned.</p>}
              </DetailCard>
              <DetailCard title="Threat associations" eyebrow="CORRELATED INTELLIGENCE">
                <div className="association-grid">
                  <Association label="Related malware">{displayList(malware)}</Association>
                  <Association label="Threat actor">{displayList(actors)}</Association>
                  <Association label="Campaign">{displayList(campaigns)}</Association>
                  <Association label="MITRE ATT&CK technique">{displayList(techniques)}</Association>
                </div>
              </DetailCard>
            </div>

            <div className="detail-grid lower-detail-grid">
              <DetailCard title="Related indicators" eyebrow="OBSERVED CONNECTIONS">
                {indicators.length ? (
                  <div className="indicator-list">
                    {indicators.map((indicator) => (
                      <div className="related-indicator" key={`${indicator.type}:${indicator.value}`}>
                        <span className="type-tag">{indicator.type}</span>
                        <code>{indicator.value}</code>
                      </div>
                    ))}
                  </div>
                ) : <p className="muted">No related indicators found.</p>}
              </DetailCard>
              <DetailCard title="AI analysis summary" eyebrow="ANALYST BRIEF">
                <p className="analysis-summary">{analysis.summary || "No analysis summary was returned."}</p>
                {analysis.key_findings?.length > 0 && (
                  <>
                    <strong>Key findings</strong>
                    <ul className="factor-list">{analysis.key_findings.map((finding) => <li key={finding}>{finding}</li>)}</ul>
                  </>
                )}
                {analysis.recommended_action && <p><strong>Recommended action:</strong> {analysis.recommended_action}</p>}
                <p className="demo-note">Analysis provider: {analysis.provider === "gemini" ? "Gemini" : "deterministic fallback"}.</p>
              </DetailCard>
            </div>
          </section>
        )}

        <section className="panel history-panel" aria-labelledby="history-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">RECENT ACTIVITY</p>
              <h2 id="history-heading">Investigation history</h2>
            </div>
            <span className="api-label">GET /api/investigations</span>
          </div>
          {historyError && <div className="error-message history-error" role="alert">{historyError}</div>}
          {historyLoading ? (
            <p className="empty-state">Loading recent investigations…</p>
          ) : history.length === 0 ? (
            <p className="empty-state">No investigations yet. Submit an IOC above to get started.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>IOC value</th><th>Type</th><th>Reputation</th><th>Risk score</th><th>Priority</th><th><span className="sr-only">Action</span></th></tr>
                </thead>
                <tbody>
                  {history.map((item) => {
                    const itemPriority = priorityFor(item.risk_score);
                    return (
                      <tr key={item.id} className={selectedId === item.id ? "selected-row" : ""}>
                        <td><button className="history-value" onClick={() => selectHistoryItem(item)} disabled={loading} title="Reopen this investigation">{item.value}</button></td>
                        <td><span className="type-tag">{item.type}</span></td>
                        <td>{item.reputation || "Unknown"}</td>
                        <td><strong>{item.risk_score}</strong><span className="score-suffix"> / 100</span></td>
                        <td><span className={`table-priority priority-${itemPriority.toLowerCase()}`}>{itemPriority}</span></td>
                        <td><button className="open-button" onClick={() => selectHistoryItem(item)} disabled={loading}>View</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <footer className="page-footer">CTI Intel · College capstone MVP · Demo intelligence only</footer>
      </main>
    </div>
  );
}

function Metric({ label, value }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function DetailCard({ eyebrow, title, children }) {
  return (
    <section className="panel detail-card">
      <p className="eyebrow">{eyebrow}</p>
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function Association({ label, children }) {
  return <div className="association"><span>{label}</span>{children}</div>;
}

export default App;
