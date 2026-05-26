import apiClient from './client';

export interface RuleCreatePayload {
  rule_id: string;
  rule_name: string;
  rule_content: string;
  attack_category: string;
  severity: string;
  is_enabled: boolean;
}

export interface RuleRecord {
  rule_id: string;
  rule_name: string;
  rule_content: string;
  attack_category: string;
  severity: string;
  is_enabled: boolean;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface RuleListResponse {
  total: number;
  rules: RuleRecord[];
}

export const fetchRules = () =>
  apiClient.get<RuleListResponse>('/api/v1/rules').then(r => r.data);

export const createRule = (payload: RuleCreatePayload) =>
  apiClient.post<RuleRecord>('/api/v1/rules', payload).then(r => r.data);

export const toggleRule = (id: string, enabled: boolean) =>
  apiClient.patch(`/api/v1/rules/${id}/toggle`, { enabled }).then(r => r.data);

export const deleteRule = (id: string) =>
  apiClient.delete(`/api/v1/rules/${id}`).then(r => r.data);

export const updateRule = (id: string, payload: Partial<RuleCreatePayload>) =>
  apiClient.put(`/api/v1/rules/${id}`, payload).then(r => r.data);