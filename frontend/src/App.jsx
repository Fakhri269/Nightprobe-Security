import { useState } from 'react';
import './index.css';
import './firebase';

function App() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;

    setIsScanning(true);
    setError(null);
    setResults(null);

    try {
      // Pointing to the local Django dev server for testing.
      // We will need to update this URL to the PythonAnywhere URL once deployed.
      const response = await fetch(`http://127.0.0.1:8000/scan/?url=${encodeURIComponent(url)}`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      setResults(data);
    } catch (err) {
      setError(err.message || 'Terjadi kesalahan saat melakukan scanning.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="container" style={{ padding: '4rem 2rem' }}>
      <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
        <div className="radar"></div>
        <h1 className="text-gradient">NightProbe</h1>
        <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '1.125rem' }}>
          Advanced Web Security Scanner
        </p>
      </div>

      <form onSubmit={handleScan} className="input-group">
        <input
          type="text"
          className="input-field"
          placeholder="https://target.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={isScanning}
          required
        />
        <button type="submit" className="btn btn-primary" disabled={isScanning}>
          {isScanning ? 'Scanning...' : 'Launch Scan'}
        </button>
      </form>

      {error && (
        <div className="glass-panel" style={{ marginTop: '2rem', padding: '1rem', borderLeft: '4px solid var(--accent-danger)' }}>
          <p style={{ color: 'var(--accent-danger)' }}>{error}</p>
        </div>
      )}

      {isScanning && (
        <div className="loader-container">
          <div className="spinner"></div>
          <p className="mono" style={{ color: 'var(--accent-primary)' }}>Initializing probes... intercepting signals...</p>
        </div>
      )}

      {results && !isScanning && (
        <div style={{ marginTop: '4rem' }}>
          <h2 style={{ marginBottom: '2rem', textAlign: 'center' }}>
            Scan Results for <span className="text-gradient">{results.target}</span>
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '2rem' }}>
            
            {/* Reconnaissance */}
            <div className="glass-panel card flex flex-col">
              <div className="card-header justify-between">
                <span className="card-title">DNS Lookup</span>
              </div>
              <ul className="result-list">
                {results.dns && Object.entries(results.dns).map(([type, records]) => (
                  <li key={type} className="flex-col">
                    <span style={{ fontWeight: '600', color: 'var(--accent-secondary)' }}>{type} Records</span>
                    {Array.isArray(records) ? (
                      <div className="gap-2" style={{ display: 'flex', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                        {records.map((r, i) => <span key={i} className="badge badge-neutral">{r}</span>)}
                      </div>
                    ) : (
                      <span className="text-muted">{records}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>

            {/* Ports */}
            <div className="glass-panel card flex flex-col">
              <div className="card-header justify-between">
                <span className="card-title">Open Ports</span>
              </div>
              <div className="gap-2" style={{ display: 'flex', flexWrap: 'wrap' }}>
                 {results.ports && Object.keys(results.ports).length > 0 ? (
                    Object.entries(results.ports).map(([port, service]) => (
                      <span key={port} className="badge badge-success">Port {port} ({service})</span>
                    ))
                 ) : (
                    <span className="text-muted">No open ports found or scan timed out.</span>
                 )}
              </div>
            </div>

             {/* Tech Stack */}
             <div className="glass-panel card flex flex-col">
              <div className="card-header justify-between">
                <span className="card-title">Technology Stack</span>
              </div>
              <div className="gap-2" style={{ display: 'flex', flexWrap: 'wrap' }}>
                 {results.tech && results.tech.all && results.tech.all.length > 0 ? (
                    results.tech.all.map((tech, i) => (
                      <span key={i} className="badge badge-secondary" style={{ background: 'rgba(0,204,255,0.1)', color: 'var(--accent-secondary)', border: '1px solid rgba(0,204,255,0.2)' }}>{tech}</span>
                    ))
                 ) : (
                    <span className="text-muted">No technologies detected.</span>
                 )}
              </div>
            </div>

            {/* Security Headers */}
            <div className="glass-panel card flex flex-col" style={{ gridColumn: '1 / -1' }}>
              <div className="card-header justify-between">
                <span className="card-title">Security Headers</span>
              </div>
              <ul className="result-list">
                 {results.headers && Object.entries(results.headers).map(([header, data]) => (
                    <li key={header} className="flex-col">
                      <div className="flex justify-between" style={{ width: '100%' }}>
                        <span className="mono">{header}</span>
                        <span className={`badge ${data.status === 'Missing' ? 'badge-danger' : 'badge-success'}`}>
                          {data.status}
                        </span>
                      </div>
                      <span className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>{data.desc}</span>
                    </li>
                 ))}
              </ul>
            </div>

            {/* Vulnerabilities */}
            <div className="glass-panel card flex flex-col">
              <div className="card-header justify-between">
                <span className="card-title">XSS Scan</span>
                <span className={`badge ${results.xss?.vulnerable ? 'badge-danger' : 'badge-success'}`}>
                  {results.xss?.vulnerable ? 'VULNERABLE' : 'SECURE'}
                </span>
              </div>
              {results.xss?.error ? (
                <span className="text-muted">{results.xss.error}</span>
              ) : results.xss?.findings?.length > 0 ? (
                 <ul className="result-list">
                    {results.xss.findings.map((f, i) => (
                      <li key={i} className="flex-col">
                        <span style={{ color: 'var(--accent-danger)' }}>{f.type}</span>
                        <div className="code-block">{f.payload}</div>
                      </li>
                    ))}
                 </ul>
              ) : (
                 <span className="text-muted">No XSS vulnerabilities detected.</span>
              )}
            </div>

            <div className="glass-panel card flex flex-col">
              <div className="card-header justify-between">
                <span className="card-title">SQLi Scan</span>
                <span className={`badge ${results.sqli?.vulnerable ? 'badge-danger' : 'badge-success'}`}>
                  {results.sqli?.vulnerable ? 'VULNERABLE' : 'SECURE'}
                </span>
              </div>
               {results.sqli?.error ? (
                <span className="text-muted">{results.sqli.error}</span>
              ) : results.sqli?.findings?.length > 0 ? (
                 <ul className="result-list">
                    {results.sqli.findings.map((f, i) => (
                      <li key={i} className="flex-col">
                        <span style={{ color: 'var(--accent-danger)' }}>{f.type}</span>
                        <div className="code-block">{f.payload}</div>
                      </li>
                    ))}
                 </ul>
              ) : (
                 <span className="text-muted">No SQL injection vulnerabilities detected.</span>
              )}
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

export default App;
