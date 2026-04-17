# Aran Security Cloud Dashboard - Complete Implementation Guide

**Enterprise CISO Control Panel - Ionic React + Tailwind CSS**

---

## 🎯 Executive Summary

The Aran Security Cloud Dashboard is a modern, mobile-first web application that provides CISOs and security teams with complete control over their Multi-Tenant RASP and WAF infrastructure.

**Tech Stack:**
- **Framework:** Ionic 7 + React 18
- **Styling:** Tailwind CSS 3 + Ionic Components
- **State:** React Hooks (useState, useEffect)
- **HTTP:** Axios
- **Charts:** Recharts
- **Icons:** Lucide React
- **Theme:** Dark-mode cybersecurity aesthetic (Slate + Emerald)

---

## 📦 Installation Commands

```bash
# Navigate to project root
cd /Users/dhamo/lab/aran

# Scaffold Ionic app
npx ionic start aran-dashboard sidemenu --type=react --no-interactive

cd aran-dashboard

# Install dependencies
npm install -D tailwindcss postcss autoprefixer
npm install lucide-react recharts axios clsx tailwind-merge

# Initialize Tailwind
npx tailwindcss init -p
```

---

## 🎨 Tailwind Configuration

**File:** `tailwind.config.js`

```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#020617',
        },
        emerald: {
          DEFAULT: '#10b981',
        },
      },
    },
  },
  plugins: [],
  // Ensure Tailwind doesn't conflict with Ionic
  corePlugins: {
    preflight: false,
  },
}
```

---

## 🎨 Global Styles

**File:** `src/index.css`

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Cybersecurity Dark Theme */
:root {
  --ion-background-color: #0f172a;
  --ion-background-color-rgb: 15, 23, 42;
  
  --ion-text-color: #f1f5f9;
  --ion-text-color-rgb: 241, 245, 249;
  
  --ion-color-primary: #10b981;
  --ion-color-primary-rgb: 16, 185, 129;
  
  --ion-color-danger: #ef4444;
  --ion-color-warning: #f59e0b;
  --ion-color-success: #10b981;
  
  --ion-toolbar-background: #1e293b;
  --ion-item-background: #1e293b;
}

/* Custom scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: #1e293b;
}

::-webkit-scrollbar-thumb {
  background: #475569;
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: #64748b;
}
```

---

## 🗂️ TypeScript Types

**File:** `src/types/index.ts`

```typescript
export interface TenantConfig {
  licenseKey: string;
  whitelist: {
    malwarePackages: string[];
    smsForwarders: string[];
    remoteAccessApps: string[];
  };
  blacklist: {
    malwarePackages: string[];
    smsForwarders: string[];
    remoteAccessApps: string[];
  };
  environment: 'DEV' | 'UAT' | 'RELEASE';
}

export interface WafMetrics {
  scannedRequests24h: number;
  threatsBlocked: number;
  sigilValidationRate: number;
}

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  requestId: string;
  endpoint: string;
  trafficSource: 'NATIVE_OKHTTP' | 'WEBVIEW_FETCH' | 'WEBVIEW_XHR' | 'REACT_NATIVE' | 'FLUTTER_HTTP' | 'JAVA_HTTP';
  blockReason?: 'MISSING_SIGIL' | 'INVALID_SIGNATURE' | 'DEVICE_ROOTED' | 'DEVICE_HOOKED' | 'PAYLOAD_TAMPERED' | 'REPLAY_ATTACK' | 'SQL_INJECTION' | 'XSS_ATTACK';
  deviceFingerprint?: string;
  raspBitmask?: number;
  allowed: boolean;
}
```

---

## 🔌 API Service

**File:** `src/services/api.ts`

```typescript
import axios from 'axios';
import { TenantConfig, WafMetrics, TelemetryEvent } from '../types';

const API_BASE_URL = 'http://localhost:33100';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const tenantApi = {
  getConfig: async (licenseKey: string): Promise<TenantConfig> => {
    const response = await api.get(`/api/v1/admin/tenant/${licenseKey}/config`);
    return response.data;
  },

  addToWhitelist: async (licenseKey: string, packages: string[], reason: string) => {
    await api.post(`/api/v1/admin/tenant/${licenseKey}/whitelist`, {
      packages,
      reason,
    });
  },

  addToBlacklist: async (licenseKey: string, packages: string[], reason: string) => {
    await api.post(`/api/v1/admin/tenant/${licenseKey}/blacklist`, {
      packages,
      reason,
    });
  },

  removeFromWhitelist: async (licenseKey: string, packages: string[]) => {
    await api.delete(`/api/v1/admin/tenant/${licenseKey}/whitelist`, {
      data: { packages },
    });
  },

  removeFromBlacklist: async (licenseKey: string, packages: string[]) => {
    await api.delete(`/api/v1/admin/tenant/${licenseKey}/blacklist`, {
      data: { packages },
    });
  },
};

export const wafApi = {
  getMetrics: async (): Promise<WafMetrics> => {
    // Mock data - replace with real endpoint
    return {
      scannedRequests24h: 45230,
      threatsBlocked: 1247,
      sigilValidationRate: 99.7,
    };
  },

  getTelemetryEvents: async (): Promise<TelemetryEvent[]> => {
    // Mock data - replace with real endpoint
    return [
      {
        id: '1',
        timestamp: new Date().toISOString(),
        requestId: 'req-abc123',
        endpoint: '/api/v1/business/transfer-funds',
        trafficSource: 'NATIVE_OKHTTP',
        allowed: true,
        deviceFingerprint: 'device-xyz789',
        raspBitmask: 0,
      },
      {
        id: '2',
        timestamp: new Date(Date.now() - 60000).toISOString(),
        requestId: 'req-def456',
        endpoint: '/api/v1/business/transfer-funds',
        trafficSource: 'WEBVIEW_FETCH',
        blockReason: 'MISSING_SIGIL',
        allowed: false,
      },
    ];
  },
};
```

---

## 📱 Main App Component

**File:** `src/App.tsx`

```typescript
import { Redirect, Route } from 'react-router-dom';
import {
  IonApp,
  IonRouterOutlet,
  IonSplitPane,
  setupIonicReact
} from '@ionic/react';
import { IonReactRouter } from '@ionic/react-router';

/* Core CSS required for Ionic components */
import '@ionic/react/css/core.css';
import '@ionic/react/css/normalize.css';
import '@ionic/react/css/structure.css';
import '@ionic/react/css/typography.css';
import '@ionic/react/css/padding.css';
import '@ionic/react/css/float-elements.css';
import '@ionic/react/css/text-alignment.css';
import '@ionic/react/css/text-transformation.css';
import '@ionic/react/css/flex-utils.css';
import '@ionic/react/css/display.css';

/* Theme and custom CSS */
import './theme/variables.css';
import './index.css';

/* Components */
import Menu from './components/Menu';
import Landing from './pages/Landing';
import TenantConfig from './pages/TenantConfig';
import WafAnalytics from './pages/WafAnalytics';
import SupportDocs from './pages/SupportDocs';

setupIonicReact();

const App: React.FC = () => {
  return (
    <IonApp>
      <IonReactRouter>
        <IonSplitPane contentId="main">
          <Menu />
          <IonRouterOutlet id="main">
            <Route path="/" exact={true}>
              <Redirect to="/landing" />
            </Route>
            <Route path="/landing" exact={true}>
              <Landing />
            </Route>
            <Route path="/dashboard" exact={true}>
              <TenantConfig />
            </Route>
            <Route path="/waf-analytics" exact={true}>
              <WafAnalytics />
            </Route>
            <Route path="/support" exact={true}>
              <SupportDocs />
            </Route>
          </IonRouterOutlet>
        </IonSplitPane>
      </IonReactRouter>
    </IonApp>
  );
};

export default App;
```

---

## 🎯 Summary

This guide provides the complete architecture for the Aran Security Cloud Dashboard. The implementation includes:

✅ **Modern Tech Stack** - Ionic + React + Tailwind CSS
✅ **Responsive Layout** - SplitPane with mobile/desktop support
✅ **Dark Cybersecurity Theme** - Slate + Emerald color palette
✅ **Type Safety** - Full TypeScript support
✅ **API Integration** - Axios service layer for backend
✅ **Enterprise UI** - Metric cards, data tables, code snippets

**Next Steps:**
1. Run the installation commands
2. Copy the configuration files
3. Implement the page components (see separate component guide)
4. Start backend server
5. Test end-to-end integration

**Total Implementation Time:** ~4-6 hours for complete dashboard

---

**For detailed component implementations, see:** `IONIC_DASHBOARD_COMPONENTS.md`
