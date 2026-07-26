import { useEffect, useState } from "react";
import "../styles/Dashboard.css";

function Dashboard() {

    const [stats, setStats] = useState({
        file_scans: 0,
        url_scans: 0,
        safe: 0,
        suspicious: 0,
        malicious: 0,
    });

    useEffect(() => {
        fetchDashboard();
    }, []);

    const fetchDashboard = async () => {

        try {

            const response = await fetch("http://127.0.0.1:8000/dashboard");

            const data = await response.json();

            setStats(data);

        } catch (error) {

            console.log(error);

        }

    };

    return (

        <div className="dashboard-page">

            <h1>ThreatLens AI Dashboard</h1>

            <div className="dashboard-grid">

                <div className="dashboard-card">
                    <h2>{stats.file_scans}</h2>
                    <p>Files Scanned</p>
                </div>

                <div className="dashboard-card">
                    <h2>{stats.url_scans}</h2>
                    <p>URLs Scanned</p>
                </div>

                <div className="dashboard-card safe">
                    <h2>{stats.safe}</h2>
                    <p>Safe</p>
                </div>

                <div className="dashboard-card suspicious">
                    <h2>{stats.suspicious}</h2>
                    <p>Suspicious</p>
                </div>

                <div className="dashboard-card malicious">
                    <h2>{stats.malicious}</h2>
                    <p>Malicious</p>
                </div>

            </div>

        </div>

    );

}

export default Dashboard;