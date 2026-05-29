import { BrowserRouter, Routes, Route } from 'react-router-dom';
import AppLayout from './layouts/AppLayout';
import Overview from './pages/Overview';
import AlertQueue from './pages/AlertQueue';
import TrafficMonitor from './pages/TrafficMonitor';
import ThreatDetection from './pages/ThreatDetection';
import RulesManagement from './pages/RulesManagement';
import MLModels from './pages/MLModels.tsx';
import Capture from './pages/Capture.tsx';
import Analytics from './pages/Analytics.tsx';
import Admin from './pages/Admin.tsx';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index        element={<Overview />}      />
          <Route path="alerts"    element={<AlertQueue />} />
          <Route path="traffic"   element={<TrafficMonitor />}    />
          <Route path="capture"   element={<Capture />}    />
          <Route path="rules"     element={<RulesManagement />}      />
          <Route path="models"    element={<MLModels />}     />
          <Route path="analytics" element={<Analytics />}  />
          <Route path="admin"     element={<Admin />}      />
          <Route path="threat-detection"   element={<ThreatDetection />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
