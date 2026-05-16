import { create } from 'zustand';

interface AlertState {
  alerts: any[];
  addAlert: (alert: any) => void;
  clearAlerts: () => void;
}

export const useAlertStore = create<AlertState>((set) => ({
  alerts: [],
  addAlert: (alert) => set((state) => ({ alerts: [alert, ...state.alerts] })),
  clearAlerts: () => set({ alerts: [] }),
}));