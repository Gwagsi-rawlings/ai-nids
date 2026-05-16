import apiClient from './client';

// Temporary types — replace with your real types later
interface CreateRulePayload {
  name: string;
  rule: string;
  enabled: boolean;
  description?: string;
}

interface RuleRecord extends CreateRulePayload {
  id: string;
  created_at: string;
}

export const createRule = (payload: CreateRulePayload) =>
  apiClient.post<RuleRecord>('/rules', payload).then(r => r.data);

export const toggleRule = (id: string, enabled: boolean) =>
  apiClient.patch(`/rules/${id}/toggle`, { enabled }).then(r => r.data);

export const deleteRule = (id: string) =>
  apiClient.delete(`/rules/${id}`).then(r => r.data);

export const updateRule = (id: string, payload: Partial<CreateRulePayload>) =>
  apiClient.put(`/rules/${id}`, payload).then(r => r.data);