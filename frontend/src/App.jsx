

import { useEffect, useRef, useState } from "react";

import Papa from "papaparse";

import {

  Activity,

  AlertTriangle,

  BrainCircuit,

  ChartNoAxesCombined,

  CheckCircle2,

  CircleHelp,

  Clock3,

  Database,

  Eye,

  FileSpreadsheet,

  LayoutDashboard,

  LoaderCircle,

  Network,

  Radio,

  Search,

  Settings,

  Shield,

  ShieldAlert,

  ShieldCheck,

  Upload,

  Wifi,

  XCircle,

} from "lucide-react";

import "./App.css";

const API_BASE = "http\://127.0.0.1:8000";

const MAX_ROWS_PER_RUN = 50;

const navigation = [

  { label: "Overview", icon: LayoutDashboard },

  { label: "Threat Detection", icon: ShieldAlert },

  { label: "Network Intelligence", icon: Network },

  { label: "Investigations", icon: Eye },

  { label: "Event History", icon: Database },

  { label: "Model Analytics", icon: ChartNoAxesCombined },

];

const categories = [

  { label: "Normal", keys: ["Normal"] },

  { label: "DoS / DDoS", keys: ["DoS/DDoS", "DoS / DDoS", "DDoS", "DoS"] },

  { label: "Port Scan", keys: ["Port Scan", "PortScan"] },

  { label: "Brute Force", keys: ["Brute Force", "BruteForce"] },

  { label: "Web Attack", keys: ["Web Attack", "WebAttack"] },

  { label: "Botnet", keys: ["Botnet"] },

];

function formatDate(value) {

  if (!value) return "Timestamp unavailable";

  const date = new Date(value);

  return Number.isNaN(date.getTime())

    ? String(value)

    : date.toLocaleString();

}

function getErrorMessage(data, fallback) {

  if (typeof data?.detail === "string") return data.detail;

  if (Array.isArray(data?.detail)) {

    return data.detail.map((item) => item.msg || "Invalid input").join("; ");

  }

  return fallback;

}

function ThreatDetectionPage() {

  const fileInputRef = useRef(null);

  const [modelInfo, setModelInfo] = useState(null);

  const [file, setFile] = useState(null);

  const [parsedRows, setParsedRows] = useState([]);

  const [groundTruthAvailable, setGroundTruthAvailable] = useState(false);

  const [results, setResults] = useState([]);

  const [status, setStatus] = useState("Loading model information...");

  const [error, setError] = useState("");

  const [loadingModel, setLoadingModel] = useState(true);

  const [processing, setProcessing] = useState(false);

  const [progress, setProgress] = useState(0);

  useEffect(() => {

    let cancelled = false;

    async function loadModelInfo() {

      try {

        const response = await fetch(`${API_BASE}/model-info`);

        const data = await response.json();

        if (!response.ok) {

          throw new Error(getErrorMessage(data, "Unable to load model information."));

        }

        if (!Array.isArray(data.feature_names) || data.feature_names.length !== 78) {

          throw new Error("The API did not return the expected 78 model features.");

        }

        if (!cancelled) {

          setModelInfo(data);

          setStatus("Model ready. Select a compatible CSV file.");

        }

      } catch (err) {

        if (!cancelled) {

          setError(err.message || "Cannot connect to the backend.");

          setStatus("Backend unavailable");

        }

      } finally {

        if (!cancelled) setLoadingModel(false);

      }

    }

    loadModelInfo();

    return () => {

      cancelled = true;

    };

  }, []);

  function handleFileChange(event) {

    const selectedFile = event.target.files?.[0];

    setError("");

    setResults([]);

    setProgress(0);

    setParsedRows([]);

    setGroundTruthAvailable(false);

    setFile(null);

    if (!selectedFile) return;

    if (!selectedFile.name.toLowerCase().endsWith(".csv")) {

      setError("Please select a .csv file.");

      event.target.value = "";

      return;

    }

    if (!modelInfo) {

      setError("Model information is not available. Check that the backend is running.");

      event.target.value = "";

      return;

    }

    setFile(selectedFile);

    setStatus("Reading CSV file...");

    Papa.parse(selectedFile, {

      header: true,

      skipEmptyLines: "greedy",

      transformHeader: (header) => header.trim(),

      complete: (parsed) => {

        const headers = (parsed.meta.fields || []).map((header) => header.trim());

        const uniqueHeaders = new Set(headers);

        if (uniqueHeaders.size !== headers.length) {

          setError("The CSV contains duplicate column names. Please correct the file and try again.");

          setStatus("CSV validation failed");

          return;

        }

        const missing = modelInfo.feature_names.filter(

          (feature) => !uniqueHeaders.has(feature)

        );

        if (missing.length > 0) {

          setError(

            `Missing ${missing.length} required model feature(s): ${missing.slice(0, 8).join(", ")}${missing.length > 8 ? ", ..." : ""}`

          );

          setStatus("CSV validation failed");

          return;

        }

        if (parsed.errors?.length) {

          setError(

            `CSV parsing reported an issue: ${parsed.errors[0].message || "Please check the file format."}`

          );

          setStatus("CSV parsing failed");

          return;

        }

        const rows = (parsed.data || []).filter((row) =>

          modelInfo.feature_names.some(

            (feature) => String(row[feature] ?? "").trim() !== ""

          )

        );

        if (rows.length === 0) {

          setError("The CSV contains no usable data rows.");

          setStatus("No data found");

          return;

        }

        setParsedRows(rows);

        setGroundTruthAvailable(headers.includes("Category"));

        setStatus(

          `${rows.length.toLocaleString()} data rows validated. Up to ${MAX_ROWS_PER_RUN} rows can be analyzed per run.`

        );

      },

      error: (err) => {

        setError(err.message || "Unable to read the CSV file.");

        setStatus("CSV reading failed");

      },

    });

  }

  async function runDetection() {

    if (!modelInfo || parsedRows.length === 0 || processing) return;

    const rowsToProcess = parsedRows.slice(0, MAX_ROWS_PER_RUN);

    setProcessing(true);

    setResults([]);

    setProgress(0);

    setError("");

    setStatus("Analyzing network-flow records...");

    const collected = [];

    try {

      for (let index = 0; index < rowsToProcess.length; index += 1) {

        const row = rowsToProcess[index];

        const features = {};

        for (const feature of modelInfo.feature_names) {

          const rawValue = row[feature];

          const value = Number(String(rawValue ?? "").trim());

          if (

            String(rawValue ?? "").trim() === "" ||

            !Number.isFinite(value)

          ) {

            throw new Error(

              `Row ${index + 2}: "${feature}" must contain a valid numeric value.`

            );

          }

          features[feature] = value;

        }

        const response = await fetch(`${API_BASE}/predict`, {

          method: "POST",

          headers: { "Content-Type": "application/json" },

          body: JSON.stringify({ features }),

        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {

          throw new Error(

            `Row ${index + 2}: ${getErrorMessage(data, "Prediction request failed.")}`

          );

        }

        if (typeof data.predicted_category !== "string") {

          throw new Error(`Row ${index + 2}: The API returned an invalid prediction.`);

        }

                const result = {

          rowNumber: index + 2,

          predicted_category: data.predicted_category,

          confidence: Number(data.confidence),

          confidence_percent:

            data.confidence_percent != null

              ? Number(data.confidence_percent)

              : Number(data.confidence) * 100,

          risk_score: Number(data.risk_score ?? 0),

          risk_level: data.risk_level ?? "Unavailable",

          risk_reason: data.risk_reason ?? "",

          actual_category: row.Category || "",

        };

        collected.push(result);

        setResults([...collected]);

        setProgress(Math.round(((index + 1) / rowsToProcess.length) * 100));

      }

      setStatus(

        `Analysis complete: ${collected.length} row(s) processed by the model.`

      );

    } catch (err) {

      setError(err.message || "Prediction processing failed.");

      setStatus("Analysis stopped");

    } finally {

      setProcessing(false);

    }

  }

  const threatCount = results.filter(

    (result) => result.predicted_category.trim().toLowerCase() !== "normal"

  ).length;

  const normalCount = results.length - threatCount;

  return (

    <section className="detection-page">

      <div className="detection-intro">

        <div className="eyebrow">

          <span className="eyebrow-line" /> MODEL-POWERED ANALYSIS

        </div>

        <h1>Threat Detection</h1>

        <p>

          Upload network-flow data and classify it using your trained Random

          Forest model. This page analyzes dataset records; it does not monitor

          live network traffic.

        </p>

      </div>

      <article className="upload-panel">

        <div className="panel-title-row">

          <FileSpreadsheet size={20} />

          <h2>Analyze network traffic</h2>

        </div>

        <p>

          Choose a CIC-IDS2017-compatible CSV containing all required numeric

          model features.

        </p>

        <div className="upload-zone">

          <Upload size={36} />

          <h3>{file ? file.name : "Upload a network traffic CSV"}</h3>

          <p>

            The file must contain the 78 model features. A Category column is

            optional and is used only for comparison.

          </p>

          <input

            ref={fileInputRef}

            className="upload-file-input"

            type="file"

            accept=".csv,text/csv"

            onChange={handleFileChange}

            disabled={processing}

          />

          <div className="upload-actions">

            <button

              className="upload-button"

              type="button"

              onClick={() => fileInputRef.current?.click()}

              disabled={processing || loadingModel || !modelInfo}

            >

              <Upload size={16} />

              Select CSV file

            </button>

            <button

              className="run-detection-button"

              type="button"

              onClick={runDetection}

              disabled={processing || !modelInfo || parsedRows.length === 0}

            >

              {processing ? (

                <LoaderCircle size={16} className="spin-icon" />

              ) : (

                <ShieldCheck size={16} />

              )}

              {processing ? "Analyzing..." : "Run detection"}

            </button>

          </div>

        </div>

        <div className={`detection-notice ${error ? "detection-error" : ""}`}>

          {error ? (

            <XCircle size={16} style={{ verticalAlign: "middle", marginRight: 7 }} />

          ) : (

            <CheckCircle2 size={16} style={{ verticalAlign: "middle", marginRight: 7 }} />

          )}

          {error || status}

        </div>

        {processing && (

          <div style={{ marginTop: 16 }}>

            <div

              style={{

                display: "flex",

                justifyContent: "space-between",

                marginBottom: 8,

                fontSize: 13,

              }}

            >

              <span>Prediction progress</span>

              <strong>{progress}%</strong>

            </div>

            <div

              style={{

                height: 8,

                background: "#e7edf5",

                borderRadius: 99,

                overflow: "hidden",

              }}

            >

              <div

                style={{

                  height: "100%",

                  width: `${progress}%`,

                  background: "#2563eb",

                  transition: "width 150ms ease",

                }}

              />

            </div>

          </div>

        )}

        {parsedRows.length > 0 && (

          <div className="detection-summary">

            <div className="detection-summary-card">

              <span>CSV rows available</span>

              <strong>{parsedRows.length.toLocaleString()}</strong>

            </div>

            <div className="detection-summary-card">

              <span>Rows in this run</span>

              <strong>{Math.min(parsedRows.length, MAX_ROWS_PER_RUN)}</strong>

            </div>

            <div className="detection-summary-card">

              <span>Required features</span>

              <strong>{modelInfo?.feature_count ?? 78}</strong>

            </div>

          </div>

        )}

        {parsedRows.length > MAX_ROWS_PER_RUN && (

          <div className="detection-notice">

            This file contains {parsedRows.length.toLocaleString()} rows.

            This run processes only the first {MAX_ROWS_PER_RUN} rows to keep

            analysis manageable. You can run another analysis after selecting

            a smaller CSV sample.

          </div>

        )}

      </article>

      {results.length > 0 && (

        <>

          <div className="detection-summary">

            <div className="detection-summary-card">

              <span>Rows analyzed</span>

              <strong>{results.length}</strong>

            </div>

            <div className="detection-summary-card">

              <span>Threat classifications</span>

              <strong>{threatCount}</strong>

            </div>

            <div className="detection-summary-card">

              <span>Normal classifications</span>

              <strong>{normalCount}</strong>

            </div>

          </div>

          <article className="results-panel">

            <div className="panel-title-row">

              <ShieldAlert size={19} />

              <h2>Prediction results</h2>

            </div>

            <p>

              These classifications come from the model response. Confidence

              is the classifier's reported confidence, not a guarantee that a

              prediction is correct.

            </p>

            <div className="results-table-wrap">

              <table className="results-table">

                <thead>

                  <tr>

                    <th>CSV row</th>

                    <th>Predicted category</th>

                    <th>Confidence</th>

                    <th>Risk score</th>

                    <th>Risk level</th>

                    {groundTruthAvailable && <th>CSV Category</th>}

                  </tr>

                </thead>

                <tbody>

                  {results.map((result) => (

                    <tr key={result.rowNumber}>

                      <td>{result.rowNumber}</td>

                      <td>

                        <span

                          className={

                            "prediction-tag" +

                            (result.predicted_category.toLowerCase() === "normal"

                              ? " normal"

                              : "")

                          }

                        >

                          {result.predicted_category}

                        </span>

                      </td>

                      <td>

                        {Number.isFinite(result.confidence_percent)

                          ? `${result.confidence_percent.toFixed(2)}%`

                          : "Unavailable"}

                      </td>

                      <td>{result.risk_score}/100</td>

                      <td>

                        <span

                          className={`risk-level-tag ${String(

                            result.risk_level

                          ).toLowerCase()}`}

                          title={result.risk_reason}

                        >

                          {result.risk_level}

                        </span>

                      </td>

                      {groundTruthAvailable && (

                        <td>{result.actual_category || "Not provided"}</td>

                      )}

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </article>

        </>

      )}

    </section>

  );

}

function EventHistoryPage() {
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("All");

  async function loadHistory() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/history?limit=100`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(getErrorMessage(data, "Unable to load prediction history."));
      }

      setPredictions(Array.isArray(data.predictions) ? data.predictions : []);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message || "Could not connect to the backend.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const timer = setTimeout(() => {
      loadHistory();
    }, 0);

    return () => clearTimeout(timer);
  }, []);

  const filteredPredictions = predictions.filter((item) => {
    const query = searchTerm.trim().toLowerCase();
    const matchesSearch =
      !query ||
      String(item.id).includes(query) ||
      String(item.predicted_category || "").toLowerCase().includes(query);

    const matchesCategory =
      categoryFilter === "All" || item.predicted_category === categoryFilter;

    return matchesSearch && matchesCategory;
  });

  return (
    <section className="detection-page">
      <div className="detection-intro">
        <div className="eyebrow">
          <span className="eyebrow-line" /> SECURITY WORKSPACE
        </div>
        <h1>Event History</h1>
        <p>Review predictions saved by the CyberGuard AI detection pipeline.</p>
      </div>

      <article className="upload-panel">
        <div className="panel-title-row">
          <Database size={20} />
          <h2>Saved prediction events</h2>
          <button
            className="upload-button"
            type="button"
            onClick={loadHistory}
            disabled={loading}
          >
            <Activity size={16} />
            {loading ? "Loading..." : "Refresh"}
          </button>
        </div>

        <div className="history-filters">
          <input
            type="text"
            className="history-search"
            placeholder="Search by event ID or category..."
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            aria-label="Search prediction history"
          />
          <select
            className="history-category-filter"
            value={categoryFilter}
            onChange={(event) => setCategoryFilter(event.target.value)}
            aria-label="Filter by predicted category"
          >
            <option value="All">All categories</option>
            <option value="Normal">Normal</option>
            <option value="DoS/DDoS">DoS/DDoS</option>
            <option value="Port Scan">Port Scan</option>
            <option value="Brute Force">Brute Force</option>
            <option value="Web Attack">Web Attack</option>
            <option value="Botnet">Botnet</option>
          </select>
        </div>

        <div className="detection-summary">
          <div className="detection-summary-card">
            <span>Loaded events</span>
            <strong>{predictions.length}</strong>
          </div>
          <div className="detection-summary-card">
            <span>Threat events</span>
            <strong>
              {
                predictions.filter(
                  (item) => item.predicted_category !== "Normal"
                ).length
              }
            </strong>
          </div>
          <div className="detection-summary-card">
            <span>Last refreshed</span>
            <strong>{lastUpdated ? lastUpdated.toLocaleTimeString() : "—"}</strong>
          </div>
        </div>

        {error && <p className="detection-error">{error}</p>}

        {loading && predictions.length === 0 ? (
          <p>Loading saved prediction events...</p>
        ) : !loading && !error && predictions.length === 0 ? (
          <p>No saved predictions were found.</p>
        ) : (
          <div className="results-table-wrap">
            <table className="results-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp</th>
                  <th>Predicted category</th>
                  <th>Confidence</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                </tr>
              </thead>
              <tbody>
                {filteredPredictions.map((item) => (
                  <tr key={item.id}>
                    <td>#{item.id}</td>
                    <td>{formatDate(item.timestamp)}</td>
                    <td>
                      <span className="prediction-tag">
                        {item.predicted_category}
                      </span>
                    </td>
                    <td>
                      {Number.isFinite(Number(item.confidence))
                        ? `${(Number(item.confidence) * 100).toFixed(2)}%`
                        : "Unavailable"}
                    </td>
                    <td>
                      {item.risk_score != null
                        ? `${item.risk_score}/100`
                        : "Unavailable"}
                    </td>
                    <td>
                      <span
                        className={`risk-level-tag ${
                          item.risk_level
                            ? String(item.risk_level).toLowerCase()
                            : "unavailable"
                        }`}
                      >
                        {item.risk_level ?? "Unavailable"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="detection-notice">
          Showing up to 100 most recent saved predictions. These are model
          classifications, not confirmed security incidents.
        </p>
      </article>
    </section>
  );
}

function PlaceholderPage({ section }) {

  const descriptions = {

    "Network Intelligence":

      "Network topology is currently illustrative. Live network telemetry is not connected.",

    Investigations:

      "Investigation workflows are not implemented yet. Prediction history is stored by the backend.",

    "Event History":

      "Review the latest records returned by the prediction history API.",

    "Model Analytics":

      "Model evaluation and feature-importance reports are available in the project reports folder.",

  };

  return (

    <section className="detection-page">

      <div className="detection-intro">

        <div className="eyebrow">

          <span className="eyebrow-line" /> SECURITY WORKSPACE

        </div>

        <h1>{section}</h1>

        <p>{descriptions[section] || "This section is not implemented yet."}</p>

      </div>

      <article className="upload-panel">

        <div className="panel-title-row">

          <Database size={20} />

          <h2>{section}</h2>

        </div>

        <p>

          This section will be developed after the Threat Detection workflow

          has been tested.

        </p>

      </article>

    </section>

  );

}

function App() {

  const [stats, setStats] = useState(null);

  const [history, setHistory] = useState([]);

  const [apiStatus, setApiStatus] = useState("Connecting...");

  const [lastUpdated, setLastUpdated] = useState(null);

  const [activeSection, setActiveSection] = useState("Overview");

  useEffect(() => {

    let active = true;

    const fetchDashboardData = async () => {

      try {

        const response = await fetch(`${API_BASE}/stats`);

        if (!response.ok) throw new Error("Statistics request failed");

        const data = await response.json();

        if (!active) return;

        setStats(data);

        setApiStatus("API connected");

        setLastUpdated(new Date());

      } catch {

        if (active) setApiStatus("API unavailable");

      }

      try {

        const response = await fetch(`${API_BASE}/history?limit=5`);

        if (!response.ok) throw new Error("History request failed");

        const data = await response.json();

        if (!active) return;

        const records = Array.isArray(data)

          ? data

          : Array.isArray(data.predictions)

            ? data.predictions

            : Array.isArray(data.history)

              ? data.history

              : Array.isArray(data.items)

                ? data.items

                : [];

        setHistory(records);

      } catch {

        if (active) setHistory([]);

      }

    };

    fetchDashboardData();

    const interval = setInterval(fetchDashboardData, 10000);

    return () => {

      active = false;

      clearInterval(interval);

    };

  }, []);

  const categoryCounts = stats?.category_counts ?? {};

  const totalPredictions = Number(stats?.total_predictions ?? 0);

  const threatsDetected = Object.entries(categoryCounts)

    .filter(([category]) => category.trim().toLowerCase() !== "normal")

    .reduce((total, [, count]) => total + Number(count || 0), 0);

  const metrics = [

    {

      label: "Total Predictions",

      value: stats ? totalPredictions.toLocaleString() : "—",

      detail: stats ? "Recorded predictions" : "Waiting for API",

      icon: Activity,

    },

    {

      label: "Threats Detected",

      value: stats ? threatsDetected.toLocaleString() : "—",

      detail: "Non-normal classifications",

      icon: ShieldAlert,

    },

    {

  label: "High-Risk Events",

  value: stats ? (stats.high_risk_events ?? 0).toLocaleString() : "—",

  detail: "High and Critical risk classifications",

  icon: AlertTriangle,

},

    {

      label: "Model Accuracy",

      value: "99.76%",

      detail: "Baseline test-set accuracy",

      icon: BrainCircuit,

    },

  ];

  return (

    <div className="app-shell">

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-icon">

            <ShieldCheck size={25} />

          </div>

          <div>

            <h2>

              CyberGuard <span>AI</span>

            </h2>

            <p>THREAT INTELLIGENCE</p>

          </div>

        </div>

        <div className="workspace-label">SECURITY WORKSPACE</div>

        <nav className="navigation">

          {navigation.map(({ label, icon: Icon }) => (

            <button

              className={"nav-item " + (activeSection === label ? "active" : "")}

              key={label}

              type="button"

              onClick={() => setActiveSection(label)}

            >

              <Icon size={18} strokeWidth={1.8} />

              <span>{label}</span>

              {label === "Event History" && <span className="nav-count">DB</span>}

            </button>

          ))}

        </nav>

        <div className="sidebar-bottom">

          <div className="environment-label">ENVIRONMENT</div>

          <div className="environment-row">

            <span className="status-dot" />

            <div>

              <strong>Local deployment</strong>

              <p>Development mode</p>

            </div>

          </div>

          <div className="sidebar-footer">

            <CircleHelp size={15} /> CyberGuard AI Prototype

          </div>

        </div>

      </aside>

      <main className="main-content">

        <header className="topbar">

          <div className="breadcrumb">

            Security Workspace <span>/</span> <strong>{activeSection}</strong>

          </div>

          <div className="topbar-right">

            <div className="connection-status">

              <span className="status-dot" /> {apiStatus}

            </div>

            <button className="icon-button" aria-label="Settings" type="button">

              <Settings size={17} />

            </button>

            <div className="avatar">CG</div>

          </div>

        </header>

        {activeSection === "Overview" && (

          <>

            <section className="welcome">

              <div>

                <div className="eyebrow">

                  <span className="eyebrow-line" /> SECURITY OPERATIONS CENTER

                </div>

                <h1>Threat Intelligence Center</h1>

                <p className="subtitle">

                  A unified view of network activity, threat classifications,

                  and security events.

                </p>

              </div>

              <div className="header-actions">

                <div className="model-chip">

                  <BrainCircuit size={17} />

                  <span>Random Forest</span>

                  <span className="chip-version">v1</span>

                </div>

                <button className="refresh-button" type="button" disabled>

                  <Radio size={15} /> Monitoring inactive

                </button>

              </div>

            </section>

            <section className="metrics-grid">

              {metrics.map(({ label, value, detail, icon: Icon }, index) => (

                <article className="metric-card" key={label}>

                  <div className="metric-top">

                    <span>{label}</span>

                    <div className={"metric-icon metric-icon-" + index}>

                      <Icon size={19} />

                    </div>

                  </div>

                  <h2>{value}</h2>

                  <p>{detail}</p>

                </article>

              ))}

            </section>

            <section className="intel-grid">

              <article className="panel network-panel">

                <div className="panel-heading">

                  <div>

                    <div className="panel-title-row">

                      <Network size={17} />

                      <h3>Network Intelligence</h3>

                    </div>

                    <p>Threat landscape and network-flow overview</p>

                  </div>

                  <span className="preview-tag">VISUALIZATION PREVIEW</span>

                </div>

                <div className="network-visual">

                  <div className="network-grid" />

                  <svg

                    className="network-lines"

                    viewBox="0 0 600 270"

                    preserveAspectRatio="none"

                    aria-hidden="true"

                  >

                    <g className="network-lines-muted">

                      <line x1="300" y1="135" x2="130" y2="65" />

                      <line x1="300" y1="135" x2="465" y2="55" />

                      <line x1="300" y1="135" x2="510" y2="155" />

                      <line x1="300" y1="135" x2="430" y2="225" />

                      <line x1="300" y1="135" x2="180" y2="220" />

                      <line x1="130" y1="65" x2="60" y2="145" />

                      <line x1="465" y1="55" x2="540" y2="35" />

                      <line x1="180" y1="220" x2="80" y2="245" />

                      <line x1="430" y1="225" x2="535" y2="245" />

                    </g>

                    <g className="network-lines-active">

                      <line x1="300" y1="135" x2="130" y2="65" />

                      <line x1="300" y1="135" x2="465" y2="55" />

                      <line x1="300" y1="135" x2="510" y2="155" />

                      <line x1="300" y1="135" x2="180" y2="220" />

                    </g>

                  </svg>

                  <div className="network-node node-center">

                    <ShieldCheck size={24} />

                    <span>MODEL</span>

                  </div>

                  <div className="network-node node-one">

                    <Wifi size={17} />

                    <span>FLOW 01</span>

                  </div>

                  <div className="network-node node-two">

                    <Database size={17} />

                    <span>FLOW 02</span>

                  </div>

                  <div className="network-node node-three">

                    <Activity size={17} />

                    <span>FLOW 03</span>

                  </div>

                  <div className="network-node node-four">

                    <Network size={17} />

                    <span>FLOW 04</span>

                  </div>

                  <div className="network-node node-five">

                    <ShieldAlert size={17} />

                    <span>FLOW 05</span>

                  </div>

                  <div className="network-node node-six">

                    <Wifi size={17} />

                    <span>FLOW 06</span>

                  </div>

                  <div className="network-caption">

                    <span className="legend-dot" />

                    Illustrative topology · Not live network telemetry

                  </div>

                </div>

                <div className="network-footer">

                  <div>

                    <span className="mini-indicator" />

                    Model status <strong>{stats ? "Ready" : "Checking"}</strong>

                  </div>

                  <div>

                    <span className="mini-indicator muted-indicator" />

                    Live traffic <strong>Not connected</strong>

                  </div>

                </div>

              </article>

              <article className="panel distribution-panel">

                <div className="panel-heading">

                  <div>

                    <div className="panel-title-row">

                      <ChartNoAxesCombined size={17} />

                      <h3>Attack Distribution</h3>

                    </div>

                    <p>Classifier categories</p>

                  </div>

                </div>

                {!stats && (

                  <div className="distribution-empty">

                    <div className="distribution-ring">

                      <Shield size={27} />

                    </div>

                    <h4>Awaiting prediction data</h4>

                    <p>Category statistics will appear when the API is available.</p>

                  </div>

                )}

                {stats && totalPredictions === 0 && (

                  <div className="distribution-empty">

                    <div className="distribution-ring">

                      <Shield size={27} />

                    </div>

                    <h4>No predictions recorded</h4>

                    <p>Run a prediction to populate the category statistics.</p>

                  </div>

                )}

                <div className="category-list">

                  {categories.map(({ label, keys }) => {

                    const count = keys.reduce(

                      (sum, key) => sum + Number(categoryCounts[key] || 0),

                      0

                    );

                    const percentage = totalPredictions

                      ? (count / totalPredictions) * 100

                      : 0;

                    return (

                      <div className="category-row" key={label}>

                        <span>{label}</span>

                        <div className="category-track">

                          <div style={{ width: `${percentage}%` }} />

                        </div>

                        <strong>{stats ? count : "—"}</strong>

                      </div>

                    );

                  })}

                </div>

              </article>

            </section>

            <section className="bottom-grid">

              <article className="panel activity-panel">

                <div className="panel-heading">

                  <div>

                    <div className="panel-title-row">

                      <Activity size={17} />

                      <h3>Traffic Activity</h3>

                    </div>

                    <p>Historical prediction volume</p>

                  </div>

                  <span className="muted-label">

                    <Clock3 size={13} />{" "}

                    {lastUpdated ? "Updated just now" : "Historical data"}

                  </span>

                </div>

                <div className="chart-placeholder">

                  <div className="chart-y-labels">

                    <span>100</span>

                    <span>75</span>

                    <span>50</span>

                    <span>25</span>

                    <span>0</span>

                  </div>

                  <div className="chart-area">

                    {[0, 1, 2, 3, 4].map((n) => (

                      <div className="chart-gridline" key={n} />

                    ))}

                    <div className="chart-empty">

                      <Activity size={20} />

                      <span>

                        {totalPredictions

                          ? `${totalPredictions.toLocaleString()} predictions recorded. Timeline requires timestamp aggregation.`

                          : "Traffic timeline will load from stored predictions"}

                      </span>

                    </div>

                    <div className="chart-x-labels">

                      <span>Earlier</span>

                      <span>Recent</span>

                      <span>Latest</span>

                    </div>

                  </div>

                </div>

              </article>

              <article className="panel alerts-panel">

                <div className="panel-heading">

                  <div>

                    <div className="panel-title-row">

                      <AlertTriangle size={17} />

                      <h3>Recent Events</h3>

                    </div>

                    <p>Latest prediction history</p>

                  </div>

                  <button

                    className="text-button"

                    type="button"

                    onClick={() => setActiveSection("Event History")}

                  >

                    View history <Search size={13} />

                  </button>

                </div>

                {history.length === 0 ? (

                  <div className="events-empty">

                    <Database size={23} />

                    <strong>

                      {apiStatus === "API connected"

                        ? "No events loaded"

                        : "Waiting for API"}

                    </strong>

                    <span>

                      {apiStatus === "API connected"

                        ? "No history records were returned by the history endpoint."

                        : "Stored predictions will appear when the backend connects."}

                    </span>

                  </div>

                ) : (

                  <div className="category-list">

                    {history.slice(0, 5).map((event, index) => (

                      <div className="category-row" key={event.id ?? index}>

                        <span>

                          {event.predicted_category ?? event.category ?? "Unknown"}

                        </span>

                        <span>{formatDate(event.timestamp)}</span>

                        <strong>

                          {event.confidence == null

                            ? "—"

                            : `${(Number(event.confidence) * 100).toFixed(1)}%`}

                        </strong>

                      </div>

                    ))}

                  </div>

                )}

              </article>

            </section>

            <footer className="dashboard-footer">

              <span>

                CyberGuard AI <i>•</i> Defensive cybersecurity research prototype

              </span>

              <span>

                Data-driven threat intelligence <i>•</i>{" "}

                <ShieldCheck size={13} /> Model-assisted analysis

              </span>

            </footer>

          </>

        )}

{activeSection === "Threat Detection" && <ThreatDetectionPage />}

{activeSection === "Event History" && <EventHistoryPage />}

{activeSection !== "Overview" &&

  activeSection !== "Threat Detection" &&

  activeSection !== "Event History" && (

    <PlaceholderPage section={activeSection} />

  )}

      </main>

    </div>

  );

}

export default App;