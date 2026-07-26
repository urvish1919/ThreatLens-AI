import { BrowserRouter, Routes, Route } from "react-router-dom";

import Home from "./pages/Home";
import FileScanner from "./pages/FileScanner";
import URLScanner from "./pages/URLScanner";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Login from "./pages/Login";

function App() {
  return (
    <BrowserRouter>
      <Routes>

        <Route path="/" element={<Home />} />

        <Route path="/file-scanner" element={<FileScanner />} />

        <Route path="/url-scanner" element={<URLScanner />} />

        <Route path="/dashboard" element={<Dashboard />} />

        <Route path="/history" element={<History />} />

        <Route path="/login" element={<Login />} />

      </Routes>
    </BrowserRouter>
  );
}

export default App;