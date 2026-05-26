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

export const fetchTrafficStats = () =>
  apiClient.get<TrafficStats>('/api/v1/capture/stats').then(r => r.data);