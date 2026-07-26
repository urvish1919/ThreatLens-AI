import {
  FaShieldAlt,
  FaLink,
  FaChartLine,
  FaHistory,
} from "react-icons/fa";

import { Link } from "react-router-dom";

import "../styles/Home.css";

function Home() {
  return (
    <div className="home">

      <nav className="navbar">
        <h2>🛡 ThreatLens AI</h2>

        <div className="nav-links">
          <Link to="/">Home</Link>
          <Link to="/dashboard">Dashboard</Link>
          <Link to="/history">History</Link>
          <Link to="/login">Login</Link>
        </div>
      </nav>

      <section className="hero">

        <h1>
          AI Assisted Cybersecurity
          <br />
          Threat Detection System
        </h1>

        <p>
          Analyze files and URLs for potential security threats using
          intelligent risk analysis. Built with React, FastAPI and Python.
        </p>

        <div className="hero-buttons">

          <Link to="/file-scanner">
            <button className="primary-btn">
              Scan File
            </button>
          </Link>

          <Link to="/url-scanner">
            <button className="secondary-btn">
              Scan URL
            </button>
          </Link>

        </div>

      </section>

      <section className="stats">

        <div className="stat-card">
          <h2>File</h2>
          <p>Threat Scanner</p>
        </div>

        <div className="stat-card">
          <h2>URL</h2>
          <p>Threat Scanner</p>
        </div>

        <div className="stat-card">
          <h2>SQLite</h2>
          <p>Scan History</p>
        </div>

      </section>

      <section className="cards">

        <Link to="/file-scanner" className="card-link">
          <div className="card">
            <FaShieldAlt size={45}/>
            <h3>File Scanner</h3>
            <p>Analyze uploaded files and generate a threat report.</p>
          </div>
        </Link>

        <Link to="/url-scanner" className="card-link">
          <div className="card">
            <FaLink size={45}/>
            <h3>URL Scanner</h3>
            <p>Check URLs for phishing indicators and suspicious patterns.</p>
          </div>
        </Link>

        <Link to="/dashboard" className="card-link">
          <div className="card">
            <FaChartLine size={45}/>
            <h3>Dashboard</h3>
            <p>View project statistics and threat summary.</p>
          </div>
        </Link>

        <Link to="/history" className="card-link">
          <div className="card">
            <FaHistory size={45}/>
            <h3>Scan History</h3>
            <p>View all previous file and URL scans stored in SQLite.</p>
          </div>
        </Link>

      </section>

    </div>
  );
}

export default Home;