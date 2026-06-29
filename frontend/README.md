# ScanForge Frontend

React + Vite + TypeScript + Tailwind dashboard shell for ScanForge.

## Local

```bash
npm install
npm run dev
```

The app serves `/dashboard` through Vite fallback and uses `VITE_API_URL` for the Laravel API. Docker Compose publishes it on `http://localhost:3003` by default to avoid common local port conflicts.
