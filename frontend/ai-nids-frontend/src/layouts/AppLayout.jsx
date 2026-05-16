import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import TopBar from '../components/TopBar';
import Sidebar from '../components/Sidebar';
import './AppLayout.css';

export default function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="app-shell">
      <TopBar
        onMenuToggle={() => setSidebarOpen(prev => !prev)}
        sidebarOpen={sidebarOpen}
      />
      <Sidebar open={sidebarOpen} />
      <main
        className="app-content"
        style={{ marginLeft: sidebarOpen ? 'var(--sidebar-w)' : '48px' }}
      >
        <Outlet />
      </main>
    </div>
  );
}
