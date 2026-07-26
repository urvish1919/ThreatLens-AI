import { useEffect, useState } from "react";
import { API_URL } from "../config/api";
import "../styles/History.css";

function History() {

    const [history, setHistory] = useState([]);

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        try {

            const response = await fetch(`${API_URL}/history`);

            const data = await response.json();

            setHistory(data);

        } catch (error) {
            console.error(error);
        }
    };

    return (

        <div className="history-page">

            <div className="history-container">

                <h1>Scan History</h1>

                <table>

                    <thead>

                        <tr>

                            <th>Type</th>

                            <th>Target</th>

                            <th>Score</th>

                            <th>Status</th>

                            <th>Date</th>

                        </tr>

                    </thead>

                    <tbody>

                        {history.map((item) => (

                            <tr key={item.id}>

                                <td>{item.scan_type}</td>

                                <td>{item.target}</td>

                                <td>{item.threat_score}</td>

                                <td>{item.status}</td>

                                <td>{item.scanned_at}</td>

                            </tr>

                        ))}

                    </tbody>

                </table>

            </div>

        </div>

    );

}

export default History;