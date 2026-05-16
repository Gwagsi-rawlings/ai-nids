import apiClient from './client';

interface TrafficStats {
  packets_per_sec: number;
  bytes_per_sec: number;
  protocol_distribution: Record<string, number>;
  top_source_ips: string[];
}

export const fetchTrafficStats = () =>
  apiClient.get<TrafficStats>('/capture/stats').then(r => r.data);