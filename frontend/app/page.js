"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import styles from "./page.module.css";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/*  Threat Score Gauge Component  */
function ThreatGauge({ score, classification }) {
  const color =
    classification === "CRITICAL" ? "#FF4444" :
    classification === "HIGH" ? "#FF8C00" :
    classification === "MEDIUM" ? "#FFD700" : "#00FF88";
  const circumference = 2 * Math.PI * 54;
  const dashOffset = circumference - (score / 100) * circumference;

  return (
    <div className={styles.gaugeContainer}>
      <svg viewBox="0 0 120 120" className={styles.gaugeSvg}>
        <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
        <circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="8"
          strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={dashOffset}
          transform="rotate(-90 60 60)" style={{ transition: "stroke-dashoffset 1.5s ease" }} />
      </svg>
      <div className={styles.gaugeValue} style={{ color }}>
        <span className={styles.gaugeNumber}>{score}</span>
        <span className={styles.gaugeLabel}>/ 100</span>
      </div>
      <span className={`badge badge-${classification?.toLowerCase() || "clean"}`} style={{ marginTop: 8 }}>
        {classification || "CLEAN"}
      </span>
    </div>
  );
}

/*  Upload Drop Zone  */
function UploadZone({ onUpload, isAnalyzing }) {
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef(null);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith(".apk")) onUpload(file);
  }, [onUpload]);

  const handleChange = (e) => {
    const file = e.target.files[0];
    if (file) onUpload(file);
  };

  return (
    <div
      className={`${styles.dropZone} ${dragOver ? styles.dropZoneActive : ""} ${isAnalyzing ? styles.dropZoneDisabled : ""}`}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onClick={() => !isAnalyzing && fileRef.current?.click()}
    >
      <input ref={fileRef} type="file" accept=".apk" onChange={handleChange} style={{ display: "none" }} id="apk-upload" />
      <div className={styles.dropIcon}>
        {isAnalyzing ? <div className="spinner" /> : ""}
      </div>
      <h3>{isAnalyzing ? "Analyzing..." : "Drop APK Here"}</h3>
      <p>{isAnalyzing ? "Please wait while we analyze the APK" : "or click to browse · .apk files only"}</p>
    </div>
  );
}

/* Progress Stage */
function ProgressStage({ stages, currentIdx }) {
  return (
    <div className={styles.progressContainer}>
      <div style={{ color: "var(--accent-orange)", fontSize: 12, marginBottom: 16, borderBottom: "1px solid #222", paddingBottom: 8, fontFamily: "var(--font-mono)", fontWeight: "bold" }}>
        ANALYSIS SEQUENCE INITIATED
      </div>
      <div className={styles.stageList}>
        {stages.map((s, i) => (
          <div key={i} className={`${styles.stageItem} ${i < currentIdx ? styles.stageDone : i === currentIdx ? styles.stageCurrent : styles.stagePending}`}>
            <span className={styles.stageIcon}>
              {i < currentIdx ? "✓" : i === currentIdx ? "►" : " "}
            </span>
            <span>{s.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* Terminal Output */
function TerminalOutput({ caseId, isAnalyzing, liveLogs }) {
  const endRef = useRef(null);
  
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [liveLogs]);

  return (
    <div className={styles.terminalContainer}>
      <div className={styles.terminalHeader}>
        <span>TACTICAL COMMAND / SYSTEMS MONITOR</span>
        <span>STATUS: {isAnalyzing ? 'ACTIVE SCAN' : 'OFFLINE'}</span>
      </div>
      <div className={styles.terminalOutput}>
        {liveLogs.map((log, i) => (
          <div key={i} className={styles.terminalLine}>
            <span className={styles.terminalTime}>[{log.time}]</span>
            <span className={styles.terminalMsg}>{log.msg}</span>
          </div>
        ))}
        {isAnalyzing && (
          <div className={styles.terminalLine}>
            <span className={styles.terminalTime}>[{new Date().toISOString().substring(11,19)}]</span>
            <span className={`${styles.terminalMsg} ${styles.highlight}`}>Awaiting intelligence data... <span className={styles.terminalCursor}></span></span>
          </div>
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}

/*  Results Panel  */
function ResultsPanel({ report }) {
  const [activeTab, setActiveTab] = useState("overview");
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState([]);
  const [chatLoading, setChatLoading] = useState(false);

  const ai = report.ai_analysis || {};
  const risk = ai.risk_assessment || {};
  const behavior = ai.behavior_context || {};
  const codeAnalysis = ai.code_analysis || {};
  const staticSummary = report.static_analysis?.summary || {};
  const c2s = report.c2_infrastructure || [];
  const rag = report.rag_results || {};
  const mitre = behavior.mitre_techniques || [];

  const handleChat = async () => {
    if (!chatInput.trim()) return;
    const q = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [...prev, { role: "user", content: q }]);
    setChatLoading(true);

    try {
      const res = await fetch(`${API_URL}/api/v1/chat/${report.case_id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json();
      setChatMessages((prev) => [...prev, { role: "assistant", content: data.answer || "Sorry, I couldn't process that." }]);
    } catch {
      setChatMessages((prev) => [...prev, { role: "assistant", content: "Error connecting to server." }]);
    }
    setChatLoading(false);
  };

  const tabs = [
    { id: "overview", label: "Overview", icon: "" },
    { id: "static", label: "Static", icon: "" },
    { id: "dynamic", label: "Dynamic (Frida)", icon: "" },
    { id: "network", label: "C2 / Network", icon: "" },
    { id: "ai", label: "AI Analysis", icon: "🧠" },
    { id: "report", label: "Reports", icon: "" },
    { id: "chat", label: "Investigator Chat", icon: "" },
  ];

  return (
    <div className={styles.results} style={{ animation: "slideUp 0.6s ease" }}>
      {/* Hero Score */}
      <div className={styles.heroSection}>
        <ThreatGauge score={report.threat_score} classification={report.classification} />
        <div className={styles.heroInfo}>
          <h2 style={{ fontSize: 28 }}>{report.package_name || "Unknown Package"}</h2>
          <p className={styles.heroFamily}>{report.malware_family || "No classification"}</p>
          <div className={styles.heroMeta}>
            <span className={styles.metaItem}>{(report.size_bytes / 1024).toFixed(0)} KB</span>
            <span className={styles.metaItem} style={{fontFamily: "var(--font-mono)"}}>SHA-256: {report.apk_sha256}</span>
            {rag.best_match && <span className={styles.metaItem}>RAG: {rag.similarity_pct}% → {rag.best_match}</span>}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className={styles.tabBar}>
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`${styles.tab} ${activeTab === t.id ? styles.tabActive : ""}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className={styles.tabContent}>
        {activeTab === "overview" && (
          <div className={styles.overviewGrid}>
            {/* Quick Stats */}
            <div className={`card ${styles.statCard}`}>
              <span className={styles.statLabel}>VirusTotal</span>
              <span className={styles.statValue} style={{ color: "var(--accent-red)" }}>
                {report.threat_intel?.hash_check?.detection_ratio || "N/A"}
              </span>
              <span className={styles.statSub}>engines flagged</span>
            </div>
            <div className={`card ${styles.statCard}`}>
              <span className={styles.statLabel}>RAG Match</span>
              <span className={styles.statValue} style={{ color: "var(--accent-cyan)" }}>
                {rag.similarity_pct ? `${rag.similarity_pct}%` : "N/A"}
              </span>
              <span className={styles.statSub}>{rag.best_match || "no match"}</span>
            </div>
            <div className={`card ${styles.statCard}`}>
              <span className={styles.statLabel}>C2 Servers</span>
              <span className={styles.statValue} style={{ color: "var(--accent-orange)" }}>
                {c2s.length}
              </span>
              <span className={styles.statSub}>endpoints found</span>
            </div>
            <div className={`card ${styles.statCard}`}>
              <span className={styles.statLabel}>YARA Hits</span>
              <span className={styles.statValue} style={{ color: "var(--accent-purple)" }}>
                {staticSummary.yara_hits || 0}
              </span>
              <span className={styles.statSub}>rules matched</span>
            </div>

            {/* Key Behaviors */}
            <div className={`card ${styles.wideCard}`}>
              <h3 style={{ marginBottom: 12 }}>Key Findings</h3>
              {risk.chain_of_reasoning ? (
                <div style={{ color: "var(--text-secondary)", lineHeight: 1.8, fontSize: 14, whiteSpace: "pre-wrap" }}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {risk.chain_of_reasoning}
                  </ReactMarkdown>
                </div>
              ) : risk.raw_response ? (
                <div style={{ color: "var(--text-secondary)", lineHeight: 1.8, fontSize: 14, whiteSpace: "pre-wrap" }}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {risk.raw_response}
                  </ReactMarkdown>
                </div>
              ) : (
                <p style={{ color: "var(--text-muted)" }}>No AI reasoning available yet.</p>
              )}
            </div>

            {/* MITRE Techniques */}
            {mitre.length > 0 && (
              <div className={`card ${styles.wideCard}`}>
                <h3 style={{ marginBottom: 12 }}>MITRE ATT&CK Techniques</h3>
                <div className={styles.mitreGrid}>
                  {mitre.map((t, i) => {
                    const isStr = typeof t === "string";
                    const id = isStr ? (t.match(/T\d{4}/) ? t.match(/T\d{4}/)[0] : "T-UNK") : (t.id || "T-UNK");
                    const name = isStr ? t.replace(/T\d{4}[^\w]*/, "") : (t.name || t);
                    return (
                      <div key={i} className={styles.mitreItem}>
                        <span className={styles.mitreId}>{id}</span>
                        <span className={styles.mitreName}>{name}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "static" && (
          <div>
            {/* Permissions */}
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 style={{ marginBottom: 16 }}>Dangerous Permissions ({(staticSummary.dangerous_permissions || []).length})</h3>
              <div className={styles.permGrid}>
                {(staticSummary.dangerous_permissions || []).map((p, i) => (
                  <div key={i} className={`badge badge-critical`} style={{ fontSize: 11 }}>
                    {p.replace("android.permission.", "")}
                  </div>
                ))}
              </div>
            </div>

            {/* YARA */}
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 style={{ marginBottom: 16 }}>YARA Rule Matches</h3>
              {(report.static_analysis?.yara_matches || []).map((y, i) => (
                <div key={i} className={styles.yaraItem}>
                  <span className={`badge badge-${y.severity?.toLowerCase() === "critical" ? "critical" : "high"}`}>{y.severity}</span>
                  <strong>{y.rule}</strong>
                  <span style={{ color: "var(--text-muted)", fontSize: 13 }}>{y.meta?.description}</span>
                </div>
              ))}
            </div>

            {/* C2 Candidates */}
            <div className="card">
              <h3 style={{ marginBottom: 16 }}>C2 Candidate URLs</h3>
              {(report.static_analysis?.c2_candidates || []).map((c, i) => (
                <div key={i} className={styles.c2Item}>
                  <code style={{ fontFamily: "var(--font-mono)", color: "var(--accent-red)" }}>{c.url}</code>
                  <span className={`badge badge-high`}>{c.reason}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === "dynamic" && (
          <div>
            <div className="card">
              <h3 style={{ marginBottom: 16 }}>Frida Runtime Hooks</h3>
              {(!report.dynamic_analysis || !report.dynamic_analysis.events || report.dynamic_analysis.events.length === 0) ? (
                <p style={{ color: "var(--text-muted)" }}>No dynamic analysis logs available for this case.</p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {report.dynamic_analysis.events.map((e, idx) => {
                    const isErr = e.type === "error" || e.type === "warning" || e.severity === "CRITICAL";
                    const isHigh = e.severity === "HIGH";
                    const badgeClass = isErr ? "badge-critical" : isHigh ? "badge-high" : "badge-clean";
                    
                    return (
                      <div key={idx} style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)", borderLeft: `3px solid ${isErr ? "var(--accent-red)" : isHigh ? "var(--accent-orange)" : "var(--accent-green)"}` }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                          <span className={`badge ${badgeClass}`} style={{ fontSize: 10 }}>{e.type || "event"}</span>
                          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}</span>
                        </div>
                        <p style={{ fontSize: 13, fontFamily: "var(--font-mono)", color: "var(--text-primary)", wordBreak: "break-all" }}>
                          {e.message || JSON.stringify(e)}
                        </p>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "network" && (
          <div>
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 style={{ marginBottom: 16 }}>C2 Infrastructure Map</h3>
              {c2s.length === 0 ? (
                <p style={{ color: "var(--text-muted)" }}>No C2 servers identified</p>
              ) : (
                <div className={styles.c2Table}>
                  <div className={styles.c2Header}>
                    <span>IP Address</span><span>Country</span><span>ASN</span><span>Risk</span>
                  </div>
                  {c2s.map((c, i) => (
                    <div key={i} className={styles.c2Row}>
                      <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-red)" }}>{c.ip}</span>
                      <span>{c.country || c.vt?.country || "?"}</span>
                      <span style={{ fontSize: 12 }}>{c.asn || c.vt?.asn || "Unknown"}</span>
                      <span>
                        <div className={styles.riskBar}>
                          <div className={styles.riskFill} style={{
                            width: `${c.composite_risk || 0}%`,
                            background: c.composite_risk > 70 ? "var(--accent-red)" : c.composite_risk > 40 ? "var(--accent-orange)" : "var(--accent-yellow)"
                          }} />
                        </div>
                        <span style={{ fontSize: 11 }}>{c.composite_risk || 0}%</span>
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {/* AbuseIPDB details */}
            {c2s.some(c => c.abuseipdb) && (
              <div className="card">
                <h3 style={{ marginBottom: 16 }}>AbuseIPDB Intelligence</h3>
                {c2s.filter(c => c.abuseipdb).map((c, i) => (
                  <div key={i} style={{ marginBottom: 12, padding: 12, background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)" }}>
                    <strong style={{ color: "var(--accent-red)" }}>{c.ip}</strong>
                    <span style={{ float: "right", color: "var(--text-muted)" }}>Confidence: {c.abuseipdb.confidence}%</span>
                    <div style={{ marginTop: 8, fontSize: 13, color: "var(--text-secondary)" }}>
                      ISP: {c.abuseipdb.isp} · Reports: {c.abuseipdb.reports} · {c.abuseipdb.country}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "ai" && (
          <div>
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 style={{ marginBottom: 12 }}>Executive Summary</h3>
              <div style={{ color: "var(--text-secondary)", lineHeight: 1.8, fontSize: 14, padding: 16, background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)", borderLeft: "3px solid var(--accent-cyan)", whiteSpace: "pre-wrap" }}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {risk.chain_of_reasoning || risk.raw_response || "Not available"}
                </ReactMarkdown>
              </div>
            </div>
            {risk.recommendations && (
              <div className="card" style={{ marginBottom: 16 }}>
                <h3 style={{ marginBottom: 12 }}>Recommended Actions</h3>
                {risk.recommendations.map((r, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 8 }}>
                    <span style={{ color: "var(--accent-orange)", fontWeight: 700 }}>{i + 1}.</span>
                    <span style={{ color: "var(--text-secondary)", fontSize: 14 }}>{r}</span>
                  </div>
                ))}
              </div>
            )}
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 style={{ marginBottom: 12 }}>Non-Technical Summary</h3>
              <p style={{ color: "var(--text-secondary)", lineHeight: 1.8, fontSize: 14, fontStyle: "italic" }}>
                {ai.non_technical_summary || "Not available"}
              </p>
            </div>
            {codeAnalysis.simple_explanation && (
              <div className="card">
                <h3 style={{ marginBottom: 12 }}>Code Analysis</h3>
                <p style={{ fontSize: 14, color: "var(--text-secondary)" }}>{codeAnalysis.simple_explanation}</p>
                {codeAnalysis.hidden_indicators && (
                  <div style={{ marginTop: 12 }}>
                    <strong style={{ fontSize: 13 }}>Hidden Indicators:</strong>
                    {(Array.isArray(codeAnalysis.hidden_indicators) ? codeAnalysis.hidden_indicators : [codeAnalysis.hidden_indicators]).map((h, i) => (
                      <div key={i} className={`badge badge-critical`} style={{ display: "block", marginTop: 4, fontSize: 11 }}>
                        {typeof h === 'object' && h !== null ? JSON.stringify(h) : h}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === "report" && (
          <div className={styles.reportGrid}>
            <button className={`btn btn-primary ${styles.reportBtn}`}
              onClick={() => window.open(`${API_URL}/api/v1/report/${report.case_id}/pdf`, "_blank")}>
              Download Technical Report (PDF)
            </button>
            <button className={`btn btn-ghost ${styles.reportBtn}`}
              onClick={async () => {
                const r = await fetch(`${API_URL}/api/v1/explain/${report.case_id}`, { method: "POST" });
                const d = await r.json();
                alert(d.summary || "Could not generate summary");
              }}>
              Generate Police Summary
            </button>
            <button className={`btn btn-ghost ${styles.reportBtn}`}
              onClick={() => {
                const json = JSON.stringify(report, null, 2);
                const blob = new Blob([json], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url; a.download = `report_${report.case_id}.json`; a.click();
              }}>
              Export Full JSON
            </button>
          </div>
        )}

        {activeTab === "chat" && (
          <div className={styles.chatContainer}>
            <div className={styles.chatMessages}>
              {chatMessages.length === 0 && (
                <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  <p style={{ fontSize: 40 }}></p>
                  <p>Ask questions about this analysis</p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center", marginTop: 16 }}>
                    {["What data was stolen?", "Where is the C2 server?", "Explain the risk score", "Is this a known malware family?"].map(q => (
                      <button key={q} className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => { setChatInput(q); }}>{q}</button>
                    ))}
                  </div>
                </div>
              )}
              {chatMessages.map((m, i) => (
                <div key={i} className={`${styles.chatMsg} ${m.role === "user" ? styles.chatUser : styles.chatBot}`}>
                  <span className={styles.chatRole}>{m.role === "user" ? "You" : "AI Analyst"}</span>
                  <p>{m.content}</p>
                </div>
              ))}
              {chatLoading && <div className={styles.chatMsg}><div className="spinner" /></div>}
            </div>
            <div className={styles.chatInput}>
              <input value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Ask about this case..."
                onKeyDown={(e) => e.key === "Enter" && handleChat()} id="chat-input" />
              <button className="btn btn-primary" onClick={handleChat} disabled={chatLoading} id="chat-send">
                Send
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/*  Main Page  */
export default function Home() {
  const [mode, setMode] = useState("upload");
  const [urlInput, setUrlInput] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState([]);
  const [currentStage, setCurrentStage] = useState(0);
  const [liveLogs, setLiveLogs] = useState([{ time: new Date().toISOString().substring(11,19), msg: "SYSTEM INITIALIZED. Awaiting target APK..." }]);
  const [report, setReport] = useState(null);
  const [recentCases, setRecentCases] = useState([]);
  const [error, setError] = useState("");

  const STAGES = [
    { pct: 5, label: "Ingesting APK..." },
    { pct: 15, label: "Static analysis (MobSF + YARA)..." },
    { pct: 35, label: "Querying threat intelligence..." },
    { pct: 55, label: "Dynamic analysis (Frida)..." },
    { pct: 75, label: "GenAI analyzing findings..." },
    { pct: 90, label: "RAG memory search..." },
    { pct: 95, label: "Generating forensic report..." },
    { pct: 100, label: " Analysis complete!" },
  ];

  // Load recent cases & demo data on mount
  useEffect(() => {
    fetch(`${API_URL}/api/v1/cases`).then(r => r.json()).then(d => setRecentCases(d.cases || [])).catch(() => {});
  }, []);

  const handleUpload = async (file) => {
    setError("");
    setIsAnalyzing(true);
    setReport(null);
    setCurrentStage(0);
    setLiveLogs([{ time: new Date().toISOString().substring(11,19), msg: `Uplink established. Transmitting target: ${file.name}` }]);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_URL}/api/v1/analyze`, {
        method: "POST",
        body: formData,
      });
      const data = await res.json();

      if (data.case_id) {
        let wsConnected = false;
        const wsUrl = `${API_URL.replace(/^http/, "ws")}/api/v1/ws/${data.case_id}`;
        let ws;

        const startPolling = () => {
          let attempts = 0;
          const pollInterval = setInterval(async () => {
            if (wsConnected) {
              clearInterval(pollInterval);
              return;
            }
            attempts++;
            try {
              const rr = await fetch(`${API_URL}/api/v1/report/${data.case_id}`);
              if (rr.ok) {
                const reportData = await rr.json();
                if (reportData.status === "complete") {
                  clearInterval(pollInterval);
                  setCurrentStage(STAGES.length - 1);
                  setReport(reportData);
                  setIsAnalyzing(false);
                } else if (reportData.status === "failed") {
                  clearInterval(pollInterval);
                  setError(reportData.error || "Analysis failed");
                  setIsAnalyzing(false);
                }
              } else {
                const statusRes = await fetch(`${API_URL}/api/v1/status/${data.case_id}`);
                if (statusRes.ok) {
                  const statusData = await statusRes.json();
                  const stageMap = {
                    "ingesting": 0,
                    "static_analysis": 1,
                    "threat_intel": 2,
                    "dynamic_analysis": 3,
                    "ai_analysis": 4,
                    "rag_search": 5,
                    "reporting": 6,
                    "complete": 7,
                    "failed": 0
                  };
                  const mappedIdx = stageMap[statusData.status];
                  if (mappedIdx !== undefined) {
                    setCurrentStage(mappedIdx);
                  }
                  if (statusData.status === "failed") {
                    clearInterval(pollInterval);
                    setError(statusData.error || "Analysis failed");
                    setIsAnalyzing(false);
                  }
                }
              }
            } catch {
              // keep polling
            }
            if (attempts > 120) {
              clearInterval(pollInterval);
              setError("Analysis timed out. Check the backend logs.");
              setIsAnalyzing(false);
            }
          }, 3000);
        };

        try {
          ws = new WebSocket(wsUrl);
          ws.onopen = () => {
            wsConnected = true;
          };
          ws.onmessage = (event) => {
            try {
              const progressData = JSON.parse(event.data);
              
              setLiveLogs(prev => [...prev, { 
                time: new Date().toISOString().substring(11,19), 
                msg: progressData.message || `Phase shift: ${progressData.status?.toUpperCase()} [${progressData.progress || 0}%]` 
              }]);

              const stageMap = {
                "ingesting": 0,
                "static_analysis": 1,
                "threat_intel": 2,
                "dynamic_analysis": 3,
                "ai_analysis": 4,
                "rag_search": 5,
                "reporting": 6,
                "complete": 7,
                "failed": 0
              };
              const mappedIdx = stageMap[progressData.status];
              if (mappedIdx !== undefined) {
                setCurrentStage(mappedIdx);
              }
              if (progressData.status === "complete") {
                ws.close();
                fetch(`${API_URL}/api/v1/report/${data.case_id}`)
                  .then(r => r.json())
                  .then(reportData => {
                    setReport(reportData);
                    setIsAnalyzing(false);
                    setCurrentStage(7);
                  });
              } else if (progressData.status === "failed") {
                ws.close();
                setError(progressData.message || "Analysis failed");
                setIsAnalyzing(false);
              }
            } catch (e) {
              console.error("Failed to parse WS message:", e);
            }
          };
          ws.onerror = () => {
            if (!wsConnected) startPolling();
          };
          ws.onclose = () => {
            if (!wsConnected) startPolling();
          };

          setTimeout(() => {
            if (!wsConnected) {
              startPolling();
            }
          }, 3000);

        } catch (e) {
          startPolling();
        }
      } else {
        setError("Failed to start analysis: No case ID received.");
        setIsAnalyzing(false);
      }
    } catch (err) {
      setError(`Upload failed: ${err.message}. Is the backend running on ${API_URL}?`);
      setIsAnalyzing(false);
    }
  };

  const loadDemo = async () => {
    setIsAnalyzing(true);
    setReport(null);
    setCurrentStage(0);

    // Animate through stages
    for (let i = 0; i < STAGES.length; i++) {
      setCurrentStage(i);
      await new Promise((r) => setTimeout(r, 600));
    }

    try {
      const res = await fetch(`${API_URL}/api/v1/demo/report`);
      const data = await res.json();
      setReport(data);
    } catch {
      // Use inline demo data if backend is down
      setReport(DEMO_REPORT);
    }
    setIsAnalyzing(false);
  };

  return (
    <div className={styles.page}>
      {/* Sidebar */}
      <aside className={styles.sidebar}>
        <div className={styles.logo}>
          <img src="/logo.png" alt="SecureX Logo" style={{ width: 120, height: 120, borderRadius: 8, objectFit: 'cover' }} />
          <div>
            <h1 className={styles.logoText}>SecureX</h1>
            <p className={styles.logoSub}>AI-Powered Forensics</p>
          </div>
        </div>

        <nav className={styles.nav}>
          <button onClick={() => setMode("upload")} className={`${styles.navItem} ${mode === "upload" ? styles.navActive : ""}`} id="nav-upload">
            Single APK
          </button>
          <button onClick={() => setMode("url")} className={`${styles.navItem} ${mode === "url" ? styles.navActive : ""}`} id="nav-url">
            URL / WhatsApp Link
          </button>
          <button onClick={() => setMode("qr")} className={`${styles.navItem} ${mode === "qr" ? styles.navActive : ""}`} id="nav-qr">
            QR Code Scan
          </button>
        </nav>

        <div className={styles.sidebarFooter}>
          <button className={`btn btn-ghost`} onClick={loadDemo} style={{ width: "100%", marginTop: 12 }} id="demo-btn">
            Load Demo Report
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className={styles.main}>
        <header className={styles.header}>
          <div>
            <h2 className={styles.pageTitle}>
              {mode === "upload" ? "APK Analysis" : mode === "url" ? "URL Analysis" : "QR Code Scan"}
            </h2>
            <p className={styles.pageSubtitle}>
              Upload an APK. Get a technical forensic report powered by GenAI.
            </p>
          </div>
        </header>

        {/* Error Banner */}
        {error && (
          <div className={styles.errorBanner}>
            <span></span> {error}
            <button onClick={() => setError("")} style={{ marginLeft: "auto", background: "none", border: "none", color: "#fff", cursor: "pointer" }}></button>
          </div>
        )}

        {/* Input Area */}
        {!report && (
          <section className={styles.inputSection}>
            {mode === "upload" && <UploadZone onUpload={handleUpload} isAnalyzing={isAnalyzing} />}
            {mode === "url" && (
              <div className={styles.urlInput}>
                <input value={urlInput} onChange={(e) => setUrlInput(e.target.value)} placeholder="https://bit.ly/suspicious-link or wa.me/..." id="url-input" />
                <button className="btn btn-primary" disabled={isAnalyzing || !urlInput} id="analyze-url-btn"
                  onClick={async () => {
                    setIsAnalyzing(true);
                    try {
                      const res = await fetch(`${API_URL}/api/v1/analyze/url`, {
                        method: "POST", headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ url: urlInput }),
                      });
                      const data = await res.json();
                      setReport(data);
                    } catch (e) { setError(`URL analysis failed: ${e.message}`); }
                    setIsAnalyzing(false);
                  }}>
                  Analyze
                </button>
              </div>
            )}
            {mode === "qr" && (
              <UploadZone
                onUpload={async (file) => {
                  setError("QR code scanning requires the backend running with pyzbar installed.");
                }}
                isAnalyzing={isAnalyzing}
              />
            )}
          </section>
        )}

        {/* Progress */}
        {isAnalyzing && (
          <div className={styles.topSection}>
            <ProgressStage stages={STAGES} currentIdx={currentStage} />
            <TerminalOutput caseId={null} isAnalyzing={isAnalyzing} liveLogs={liveLogs} />
          </div>
        )}

        {/* Results */}
        {report && <ResultsPanel report={report} />}

        {/* Back button */}
        {report && (
          <button className="btn btn-ghost" style={{ marginTop: 24 }}
            onClick={() => { setReport(null); setCurrentStage(0); }}>
            ← New Analysis
          </button>
        )}

        {/* Recent Cases */}
        {!report && !isAnalyzing && (
          <section className={styles.recentSection}>
            <h3 style={{ marginBottom: 16 }}>Recent Analyses</h3>
            {recentCases.length === 0 ? (
              <p style={{ color: "var(--text-muted)" }}>No analyses yet. Upload an APK or load the demo.</p>
            ) : (
              <div className={styles.caseList}>
                {recentCases.map((c, i) => (
                  <div key={i} className={`card ${styles.caseItem}`} onClick={async () => {
                    try {
                      const r = await fetch(`${API_URL}/api/v1/report/${c.id}`);
                      if (r.ok) setReport(await r.json());
                    } catch {}
                  }}>
                    <div className={styles.caseItemHeader}>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>#{c.id?.slice(0, 6)}</span>
                      <span className={`badge badge-${(c.classification || "clean").toLowerCase()}`}>
                        {c.classification || "CLEAN"}
                      </span>
                    </div>
                    <div className={styles.caseItemPackage} title={c.package_name || "unknown"}>
                      {c.package_name || "unknown"}
                    </div>
                    <div className={styles.caseItemScore}>Threat Score: {c.threat_score || 0}/100</div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

/* Inline demo data in case backend is down */
const DEMO_REPORT = {
  case_id: "demo-001", package_name: "com.fake.sbi.yono",
  apk_sha256: "a3f9c2d1e5b87fa2c3d4e5f6a7b8c9d0e1f2a3b4", apk_md5: "7d4a2b9c3e8f",
  size_bytes: 4847293, source: "file_upload", status: "complete",
  threat_score: 94, classification: "CRITICAL", malware_family: "SpyNote RAT / Banking Trojan",
  static_analysis: {
    summary: {
      dangerous_permissions: ["android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA", "android.permission.READ_CONTACTS"],
      total_permissions: 23, c2_candidates_count: 3, yara_hits: 2,
      critical_yara: [{ rule: "Android_SpyNote_C2_Beacon", severity: "CRITICAL" }, { rule: "Android_Banker_SMS_Intercept", severity: "CRITICAL" }],
      is_repackaged: true, package_name: "com.fake.sbi.yono"
    },
    yara_matches: [
      { rule: "Android_SpyNote_C2_Beacon", severity: "CRITICAL", meta: { description: "SpyNote RAT — C2 connection pattern" } },
      { rule: "Android_Banker_SMS_Intercept", severity: "CRITICAL", meta: { description: "OTP-stealing banker — aborts incoming SMS broadcast" } }
    ],
    c2_candidates: [
      { url: "http://185.220.101.45:4444", reason: "direct_ip_address" },
      { url: "https://malware-c2.xyz/beacon", reason: "suspicious_tld" }
    ]
  },
  threat_intel: { hash_check: { known: true, malicious: 41, total_engines: 70, detection_ratio: "41/70", threat_level: "CRITICAL" } },
  ai_analysis: {
    code_analysis: { purpose: "Banking credential theft via overlay attack", hidden_indicators: ["Hardcoded C2 IP 185.220.101.45:4444", "AES key in assets/config.dat"], simple_explanation: "This code creates a fake banking login screen to steal passwords and OTP codes.", severity: "CRITICAL" },
    behavior_context: { behavior_narrative: "The app mimics SBI YONO. It intercepts SMS, sends GPS and OTP codes to 185.220.101.45 every 57 seconds.", mitre_techniques: [{ id: "T1412", name: "Capture SMS" }, { id: "T1430", name: "Location Tracking" }, { id: "T1437.001", name: "C2 over HTTPS" }], malware_classification: "Mobile RAT / SMS Stealer" },
    risk_assessment: { score: 94, classification: "CRITICAL", chain_of_reasoning: "This application was assigned a risk score of 94/100: (1) Hardcoded C2 at 185.220.101.45:4444 matching SpyNote RAT. (2) YARA rules matched CRITICAL patterns. (3) SMS interception via abortBroadcast. (4) VirusTotal: 41/70 engines flagged. (5) C2 IP on bulletproof hosting with 47 abuse reports.", recommendations: ["Block IP 185.220.101.45 immediately", "File abuse report with hosting provider", "Issue advisory to SBI YONO users"], mitre_ttps: ["T1412", "T1430", "T1437.001"], confidence: "HIGH", malware_family: "SpyNote RAT" },
    non_technical_summary: "This app looks exactly like the real SBI YONO banking app. When installed, it secretly reads all incoming text messages to steal OTP codes. Every minute, it sends stolen codes and GPS location to a criminal server in Germany. That server has been reported by 47 organizations. Any customer who installed this should change passwords immediately."
  },
  rag_results: { similar_samples: [{ label: "SpyNote 3.2", similarity_pct: 94.2, match_strength: "HIGH" }], best_match: "SpyNote 3.2", similarity_pct: 94.2 },
  c2_infrastructure: [
    { ip: "185.220.101.45", country: "DE", asn: "AS12345 BulletProof Hosting", composite_risk: 92, abuseipdb: { confidence: 89, reports: 47, isp: "BulletProof GmbH", country: "DE" }, vt: { malicious: 15 } },
    { ip: "91.134.10.22", country: "FR", asn: "AS16276 OVH", composite_risk: 67, abuseipdb: { confidence: 45, reports: 12, isp: "OVH SAS", country: "FR" }, vt: { malicious: 8 } }
  ],
  mitre_ttps: ["T1412", "T1430", "T1437.001", "T1633.001"],
  custody_chain: { case_id: "demo-001", entry_count: 6, integrity: "VERIFIED" },
  dynamic_analysis: {
    events: [
      { type: "tcp_connect", message: "Outbound connection to C2: 185.220.101.45:4444 established", timestamp: "2026-06-14T02:00:00Z", thread: "OkHttp ConnectionPool" },
      { type: "sms_send", message: "Intercepted outbound SMS to +919876543210: 'SBI OTP: 483921'", timestamp: "2026-06-14T02:00:05Z", severity: "CRITICAL" },
      { type: "location_read", message: "Location accessed: Latitude 28.6139, Longitude 77.2090 (GPS)", timestamp: "2026-06-14T02:00:10Z", severity: "HIGH" },
      { type: "emulator_bypass", message: "Bypassed emulator check: build fingerprint altered to samsung/SM-G998B", timestamp: "2026-06-14T02:00:12Z" }
    ]
  }
};
