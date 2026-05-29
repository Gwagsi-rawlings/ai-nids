import apiClient from './client';

interface AlertFilters {
  severity?: string;
  attack_type?: string;
  src_ip?: string;
  page?: number;
  limit?: number;
}

export const fetchAlerts = (filters: AlertFilters) =>
  apiClient.get('/api/v1/alerts', { params: filters }).then(r => r.data);

export const acknowledgeAlert = (id: string) =>
  apiClient.patch(`/api/v1/alerts/${id}/acknowledge`).then(r => r.data);