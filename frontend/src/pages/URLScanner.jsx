import { useState } from "react";
import "../styles/URLScanner.css";

function URLScanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const scanURL = async () => {
    if (url.trim() === "") {
      alert("Please enter a URL.");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:8000/scan-url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url,
        }),
      });

      const data = await response.json();

      setResult({
        url: data.url,
        score: data.threat_score,
        status: data.status,
        malicious: data.malicious,
        suspicious: data.suspicious,
        harmless: data.harmless,
        undetected: data.undetected,
      });
    } catch (error) {
      console.error(error);
      alert("Backend connection failed.");
    }

    setLoading(false);
  };

  return (
    <div className="scanner-page">
      <div className="scanner-container">

        <h1>🌐 URL Threat Scanner</h1>

        <p>Analyze suspicious URLs using VirusTotal.</p>

        <input
          className="url-input"
          type="text"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />

        <button
          className="analyze-btn"
          onClick={scanURL}
          disabled={loading}
        >
          {loading ? "Scanning..." : "Scan URL"}
        </button>

        {result && (
          <div className="result-box">

            <h2>Threat Analysis Report</h2>

            <h3>
              Threat Score : {result.score}/100
            </h3>

            <h3>
              Status :
              {result.status === "Safe"
                ? " 🟢 Safe"
                : result.status === "Suspicious"
                ? " 🟡 Suspicious"
                : " 🔴 Malicious"}
            </h3>

            <hr />

            <h4>URL</h4>
            <p
              style={{
                wordBreak: "break-all"
              }}
            >
              {result.url}
            </p>

            <h4>VirusTotal Detection</h4>

            <p>
              <strong>Malicious:</strong> {result.malicious}
            </p>

            <p>
              <strong>Suspicious:</strong> {result.suspicious}
            </p>

            <p>
              <strong>Harmless:</strong> {result.harmless}
            </p>

            <p>
              <strong>Undetected:</strong> {result.undetected}
            </p>

            <h4>Recommendation</h4>

            <p>
              {result.status === "Safe"
                ? "This website appears safe."
                : result.status === "Suspicious"
                ? "Proceed with caution."
                : "Avoid visiting this website."}
            </p>

          </div>
        )}

      </div>
    </div>
  );
}

export default URLScanner;