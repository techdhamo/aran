# Aran Security Cloud Dashboard - Setup Guide

**Ionic React + Tailwind CSS + TypeScript**

---

## Quick Start Commands

### 1. Scaffold Ionic App

```bash
cd /Users/dhamo/lab/aran

# Create Ionic React app with sidemenu template
npx ionic start aran-dashboard sidemenu --type=react --no-interactive

cd aran-dashboard
```

### 2. Install Dependencies

```bash
# Tailwind CSS
npm install -D tailwindcss postcss autoprefixer

# UI Libraries
npm install lucide-react recharts

# HTTP Client
npm install axios

# Utilities
npm install clsx tailwind-merge
```

### 3. Initialize Tailwind

```bash
npx tailwindcss init -p
```

### 4. Project Structure

```
aran-dashboard/
├── src/
│   ├── components/
│   │   ├── Menu.tsx
│   │   ├── MetricCard.tsx
│   │   ├── TelemetryTable.tsx
│   │   └── CodeSnippet.tsx
│   ├── pages/
│   │   ├── Landing.tsx
│   │   ├── TenantConfig.tsx
│   │   ├── WafAnalytics.tsx
│   │   └── SupportDocs.tsx
│   ├── services/
│   │   └── api.ts
│   ├── types/
│   │   └── index.ts
│   ├── App.tsx
│   └── theme/
│       └── variables.css
├── tailwind.config.js
└── package.json
```

---

## Configuration Files

See the following sections for complete file contents.

---

## Development Server

```bash
npm run start
# or
ionic serve
```

**Access:** http://localhost:8100

---

## Build for Production

```bash
ionic build --prod
```

---

## Backend Integration

The dashboard connects to `mazhai-central` backend:

**Base URL:** `http://localhost:33100`

**Endpoints:**
- `GET /api/v1/admin/tenant/{license_key}/config`
- `POST /api/v1/admin/tenant/{license_key}/whitelist`
- `POST /api/v1/admin/tenant/{license_key}/blacklist`
- `DELETE /api/v1/admin/tenant/{license_key}/whitelist`
- `DELETE /api/v1/admin/tenant/{license_key}/blacklist`

---

## Color Palette (Cybersecurity Dark Mode)

```css
/* Slate (Background/Text) */
--slate-950: #020617
--slate-900: #0f172a
--slate-800: #1e293b
--slate-700: #334155
--slate-600: #475569

/* Emerald (Accent/Success) */
--emerald-500: #10b981
--emerald-600: #059669
--emerald-700: #047857

/* Red (Danger/Blocked) */
--red-500: #ef4444
--red-600: #dc2626

/* Amber (Warning) */
--amber-500: #f59e0b
```

---

## Next Steps

1. Copy configuration files from this guide
2. Run `npm install`
3. Run `ionic serve`
4. Start backend: `cd ../mazhai-central && ./mvnw spring-boot:run -Dspring-boot.run.profiles=demo`
5. Test integration

---

**Dashboard Status:** Ready for development
