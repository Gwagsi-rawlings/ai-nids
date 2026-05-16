import { BrowserRouter, Routes, Route } from 'react-router-dom';
import AppLayout from './layouts/AppLayout';
import Overview from './pages/Overview';
import AlertQueue from './pages/AlertQueue';
import TrafficMonitor from './pages/TrafficMonitor';
import ThreatDetection from './pages/ThreatDetection';
import RulesManagement from './pages/RulesManagement';
import {
  ModelsPage,
  AnalyticsPage,
  AdminPage,
  CapturePage,
} from './pages/Placeholders';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index        element={<Overview />}      />
          <Route path="alerts"    element={<AlertQueue />} />
          <Route path="traffic"   element={<TrafficMonitor />}    />
          <Route path="capture"   element={<CapturePage />}    />
          <Route path="rules"     element={<RulesManagement />}      />
          <Route path="models"    element={<ModelsPage />}     />
          <Route path="analytics" element={<AnalyticsPage />}  />
          <Route path="admin"     element={<AdminPage />}      />
          <Route path="threat-detection"   element={<ThreatDetection />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
