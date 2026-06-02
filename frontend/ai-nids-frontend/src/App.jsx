import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/auth';
import AppLayout from './layouts/AppLayout';
import Login from './pages/Login';
import Overview from './pages/Overview';
import AlertQueue from './pages/AlertQueue';
import TrafficMonitor from './pages/TrafficMonitor';
import ThreatDetection from './pages/ThreatDetection';
import RulesManagement from './pages/RulesManagement';
import MLModels from './pages/MLModels.tsx';
import Capture from './pages/Capture.tsx';
import Analytics from './pages/Analytics.tsx';
import Admin from './pages/Admin.tsx';

function PrivateRoute({ children }) {
  const token = useAuthStore(s => s.token);
  return token ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <PrivateRoute>
              <AppLayout />
            </PrivateRoute>
          }
        >
          <Route index             element={<Overview />}         />
          <Route path="alerts"     element={<AlertQueue />}       />
          <Route path="traffic"    element={<TrafficMonitor />}   />
          <Route path="capture"    element={<Capture />}          />
          <Route path="rules"      element={<RulesManagement />}  />
          <Route path="models"     element={<MLModels />}         />
          <Route path="analytics"  element={<Analytics />}        />
          <Route path="admin"      element={<Admin />}            />
          <Route path="threat-detection" element={<ThreatDetection />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
