import apiClient from './client';

interface TopSourceIP {
  ip: string;
  pps: number;
}

interface TrafficStats {
  packets_per_sec: number;
  bytes_per_sec: number;
  protocol_distribution: Record<string, number>;
  top_source_ips: TopSourceIP[];
}

export interface LiveCaptureStatus {
  running: boolean;
  interface: string;
  started_at: string | null;
}

export const fetchTrafficStats = () =>
  apiClient.get<TrafficStats>('/api/v1/capture/stats').then(r => r.data);

export const fetchCaptureStatus = (): Promise<LiveCaptureStatus> =>
  apiClient.get<LiveCaptureStatus>('/api/v1/capture/status')
    .then(r => r.data)
    .catch(() => ({ running: false, interface: 'eth0', started_at: null }));

export const startCapture = (iface: string): Promise<LiveCaptureStatus> =>
  apiClient.post<LiveCaptureStatus>('/api/v1/capture/start', { interface: iface }).then(r => r.data);

export const stopCapture = (): Promise<LiveCaptureStatus> =>
  apiClient.post<LiveCaptureStatus>('/api/v1/capture/stop').then(r => r.data);