import { useEffect } from 'react';
import { useAuthStore } from '../store/auth';
import { useAlertStore } from '../store/alert';

const WS_BASE = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000';

export function useAlertStream() {
  const token    = useAuthStore(s => s.token);
  const addAlert = useAlertStore(s => s.addAlert);

  useEffect(() => {
    if (!token) return;

    const url = `${WS_BASE}/api/v1/ws/alerts?token=${encodeURIComponent(token)}`;
    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    function connect() {
      ws = new WebSocket(url);

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type !== 'ping') addAlert(msg);
        } catch { /* ignore malformed frames */ }
      };

      ws.onclose = () => {
        reconnectTimer = setTimeout(connect, 3000);
      };

      ws.onerror = () => ws.close();
    }

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [token, addAlert]);
}