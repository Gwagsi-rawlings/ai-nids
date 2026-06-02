import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import axios from 'axios';
import { useAuthStore } from '../store/auth';
import './Login.css';

export default function Login() {
  const { token, setToken } = useAuthStore();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Already authenticated — skip the login page
  if (token) return <Navigate to="/" replace />;

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      // Use plain axios (not apiClient) so the 401 response interceptor
      // doesn't fire and wipe our error message before we can show it.
      const { data } = await axios.post('/api/v1/auth/login', { username, password });
      setToken(data.access_token);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.response?.data?.detail ?? 'Login failed. Check your credentials.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-root">
      <div className="login-card animate-fade-up">
        {/* wordmark */}
        <div className="login-wordmark">
          <span className="login-wordmark-n">N</span>
          <span className="login-wordmark-sep">—</span>
          <span className="login-wordmark-name">CyberShield™</span>
        </div>
        <p className="login-subtitle">AI-POWERED NETWORK INTRUSION DETECTION</p>

        <form className="login-form" onSubmit={handleSubmit} autoComplete="off">
          <div className="login-field">
            <label className="login-label" htmlFor="login-username">USERNAME</label>
            <input
              id="login-username"
              className="login-input"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoFocus
              required
              spellCheck={false}
              autoCapitalize="none"
            />
          </div>

          <div className="login-field">
            <label className="login-label" htmlFor="login-password">PASSWORD</label>
            <input
              id="login-password"
              className="login-input"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
          </div>

          {error && (
            <div className="login-error" role="alert">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              {error}
            </div>
          )}

          <button className="login-btn" type="submit" disabled={loading}>
            {loading ? (
              <>
                <span className="login-spinner" />
                AUTHENTICATING...
              </>
            ) : 'AUTHENTICATE →'}
          </button>
        </form>

        <div className="login-footer">
          <span className="dot dot-ok dot-pulse" />
          SECURE SESSION &nbsp;·&nbsp; TLS 1.3 &nbsp;·&nbsp; AES-256-GCM
        </div>
      </div>
    </div>
  );
}
