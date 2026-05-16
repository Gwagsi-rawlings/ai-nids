import apiClient from './client';

interface AlertFilters {
  severity?: string;
  attack_type?: string;
  src_ip?: string;
  page?: number;
  limit?: number;
}

export const fetchAlerts = (filters: AlertFilters) =>
  apiClient.get('/alerts', { params: filters }).then(r => r.data);

export const acknowledgeAlert = (id: string) =>
  apiClient.patch(`/alerts/${id}/acknowledge`).then(r => r.data);