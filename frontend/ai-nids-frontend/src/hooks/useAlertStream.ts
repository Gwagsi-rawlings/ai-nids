import { useEffect } from 'react';
import { useAuthStore } from '../store/auth';
import { useAlertStore } from '../store/alert';

const WS_BASE = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000';

export function useAlertStream() {
  const token    = useAuthStore(s => s.token);
  const addAlert = useAlertStore(s => s.addAlert);

  useEffect(() => {
    if (!token) return;
    const url = `${WS_BASE}/ws/alerts?token=${token}`;
    const ws  = new WebSocket(url);

    ws.onmessage = (evt) => {
      const alert = JSON.parse(evt.data);
      addAlert(alert);
    };

    ws.onclose = () => console.log('WebSocket closed, reconnecting...');
    return () => ws.close();
  }, [token]);
}