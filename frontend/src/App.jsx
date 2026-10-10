
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  ChartNoAxesCombined,
  ChevronDown,
  CircleHelp,
  Clock3,
  Database,
  Eye,
  LayoutDashboard,
  Network,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

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

function App() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [apiStatus, setApiStatus] = useState("Connecting...");
  const [lastUpdated, setLastUpdated] = useState(null);

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
      value: "—",
      detail: "Risk engine not implemented",
      icon: AlertTriangle,
    },
    {
      label: "Model Accuracy",
      value: "99.76%",
      detail: "Baseline test-set accuracy",
      icon: BrainCircuit,
    },
  ];

  const formatDate = (value) => {
    if (!value) return "Timestamp unavailable";
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? String(value)
      : date.toLocaleString();
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={25} /></div>
          <div>
            <h2>CyberGuard <span>AI</span></h2>
            <p>THREAT INTELLIGENCE</p>
          </div>
        </div>

        <div className="workspace-label">SECURITY WORKSPACE</div>

        <nav className="navigation">
          {navigation.map(({ label, icon: Icon }, index) => (
            <button
              className={"nav-item " + (index === 0 ? "active" : "")}
              key={label}
              type="button"
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
              {label === "Event History" && (
                <span className="nav-count">DB</span>
              )}
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
            Security Workspace <span>/</span> <strong>Overview</strong>
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

        <section className="welcome">
          <div>
            <div className="eyebrow">
              <span className="eyebrow-line" /> SECURITY OPERATIONS CENTER
            </div>
            <h1>Threat Intelligence Center</h1>
            <p className="subtitle">
              A unified view of network activity, threat classifications, and security events.
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
                <ShieldCheck size={24} /><span>MODEL</span>
              </div>
              <div className="network-node node-one">
                <Wifi size={17} /><span>FLOW 01</span>
              </div>
              <div className="network-node node-two">
                <Database size={17} /><span>FLOW 02</span>
              </div>
              <div className="network-node node-three">
                <Activity size={17} /><span>FLOW 03</span>
              </div>
              <div className="network-node node-four">
                <Network size={17} /><span>FLOW 04</span>
              </div>
              <div className="network-node node-five">
                <ShieldAlert size={17} /><span>FLOW 05</span>
              </div>
              <div className="network-node node-six">
                <Wifi size={17} /><span>FLOW 06</span>
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
              <button
                className="small-icon-button"
                aria-label="More options"
                type="button"
              >
                <ChevronDown size={16} />
              </button>
            </div>

            {!stats && (
              <div className="distribution-empty">
                <div className="distribution-ring"><Shield size={27} /></div>
                <h4>Awaiting prediction data</h4>
                <p>Category statistics will appear when the API is available.</p>
              </div>
            )}

            {stats && totalPredictions === 0 && (
              <div className="distribution-empty">
                <div className="distribution-ring"><Shield size={27} /></div>
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
                <Clock3 size={13} /> {lastUpdated ? "Updated just now" : "Historical data"}
              </span>
            </div>

            <div className="chart-placeholder">
              <div className="chart-y-labels">
                <span>100</span><span>75</span><span>50</span><span>25</span><span>0</span>
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
                  <span>Earlier</span><span>Recent</span><span>Latest</span>
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
              <button className="text-button" type="button" disabled>
                View history <Search size={13} />
              </button>
            </div>

            {history.length === 0 ? (
              <div className="events-empty">
                <Database size={23} />
                <strong>{apiStatus === "API connected" ? "No events loaded" : "Waiting for API"}</strong>
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
                    <span>{event.predicted_category ?? event.category ?? "Unknown"}</span>
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
            Data-driven threat intelligence <i>•</i> <ShieldCheck size={13} /> Model-assisted analysis
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;
