// Central place for the backend API URL.
// Locally it falls back to your local FastAPI server.
// In production (Vercel), set REACT_APP_API_URL to your deployed backend (e.g. Render) URL.
export const API_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:8000";