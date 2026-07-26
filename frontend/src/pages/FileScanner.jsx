import { useState } from "react";
import { API_URL } from "../config/api";
import "../styles/FileScanner.css";

function FileScanner() {
    const [selectedFile, setSelectedFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);

    const handleFileChange = (event) => {
        setSelectedFile(event.target.files[0]);
        setResult(null);
    };

    const analyzeFile = async () => {
        if (!selectedFile) {
            alert("Please select a file.");
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append("file", selectedFile);

        try {
            const response = await fetch(`${API_URL}/scan-file`, {
                method: "POST",
                body: formData,
            });

            const data = await response.json();

            setResult({
                score: data.threat_score,
                status: data.status,
                reason: data.yara_matches,
                recommendation:
                    data.status === "Safe"
                        ? "Safe to open."
                        : data.status === "Suspicious"
                            ? "Proceed with caution."
                            : "Do not open this file.",

                sha256: data.sha256,
                filename: data.filename,
                filesize: data.file_size_kb,
                vendors: data.vendors || [],
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

                <h1>File Threat Scanner</h1>

                <p>Upload a suspicious file for AI-powered security analysis.</p>

                <div className="upload-box">
                    <h2>📂 Drag & Drop File Here</h2>

                    <p>or</p>

                    <input
                        type="file"
                        id="fileUpload"
                        hidden
                        onChange={handleFileChange}
                    />

                    <label htmlFor="fileUpload" className="upload-btn">
                        Choose File
                    </label>
                </div>

                {selectedFile && (
                    <div className="file-info">
                        <h3>Selected File</h3>

                        <p><strong>Name:</strong> {selectedFile.name}</p>

                        <p><strong>Size:</strong> {(selectedFile.size / 1024).toFixed(2)} KB</p>

                        <p><strong>Type:</strong> {selectedFile.type || "Unknown"}</p>
                    </div>
                )}

                <button
                    className="analyze-btn"
                    onClick={analyzeFile}
                    disabled={loading}
                >
                    {loading ? "Analyzing..." : "Analyze File"}
                </button>

                {result && (
                    <div className="result-box">

                        <h2>Threat Analysis Report</h2>

                        <h3>Threat Score : {result.score}/100</h3>

                        <h3>
                            Status :
                            {result.status === "Safe"
                                ? " 🟢 Safe"
                                : result.status === "Suspicious"
                                    ? " 🟡 Suspicious"
                                    : " 🔴 High Risk"}
                        </h3>

                        <h4>Filename</h4>
                        <p>{result.filename}</p>

                        <h4>File Size</h4>
                        <p>{result.filesize} KB</p>

                        <h4>SHA-256</h4>

                        <p
                            style={{
                                wordBreak: "break-all",
                                fontSize: "13px",
                            }}
                        >
                            {result.sha256}
                        </p>

                        <h4>Reason</h4>

                        <ul>
                            {result.reason.map((item, index) => (
                                <li key={index}>{item}</li>
                            ))}
                        </ul>

                        <h4>Recommendation</h4>

                        <p>{result.recommendation}</p>

                        {result.vendors.length > 0 && (
                            <>
                                <h4>Detected By</h4>
                                <ul>
                                    {result.vendors.map((vendor, index) => (
                                        <li key={index}>
                                            <strong>{vendor.engine}</strong> - {vendor.result}
                                        </li>
                                    ))}
                                </ul>
                            </>
                        )}

                        {result.vendors && result.vendors.length > 0 && (
                            <>
                                <h4>Detection Engines</h4>

                                <table
                                    style={{
                                        width: "100%",
                                        marginTop: "15px",
                                        borderCollapse: "collapse",
                                    }}
                                >
                                    <thead>
                                        <tr>
                                            <th
                                                style={{
                                                    border: "1px solid #444",
                                                    padding: "10px",
                                                }}
                                            >
                                                Engine
                                            </th>

                                            <th
                                                style={{
                                                    border: "1px solid #444",
                                                    padding: "10px",
                                                }}
                                            >
                                                Detection
                                            </th>
                                        </tr>
                                    </thead>

                                    <tbody>
                                        {result.vendors.map((vendor, index) => (
                                            <tr key={index}>
                                                <td
                                                    style={{
                                                        border: "1px solid #444",
                                                        padding: "10px",
                                                    }}
                                                >
                                                    {vendor.engine}
                                                </td>

                                                <td
                                                    style={{
                                                        border: "1px solid #444",
                                                        padding: "10px",
                                                    }}
                                                >
                                                    {vendor.result}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </>
                        )}

                    </div>
                )}

            </div>
        </div>
    );
}

export default FileScanner;