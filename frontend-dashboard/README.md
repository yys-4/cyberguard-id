# CyberGuard-ID Frontend Dashboard

Frontend package terpisah berbasis React + Vite untuk tim Frontend/UI-UX.

## Tujuan

- Iterasi cepat desain dan UX tanpa menyentuh backend FastAPI.
- Mengonsumsi endpoint `POST /predict-v2` dari backend CyberGuard-ID.
- Menjadi workspace UI khusus simulasi dan edukasi keamanan siber publik.

## Prasyarat

- Node.js 22.12+ (atau jalankan `nvm use` dengan file `.nvmrc`)
- Backend API aktif di `http://localhost:8000`

## Menjalankan Secara Lokal

1. Install dependency:

```bash
npm install
```

2. Buat file environment:

```bash
cp .env.example .env
```

3. Jalankan dev server:

```bash
npm run dev
```

Aplikasi akan tersedia di `http://localhost:5173`.

## Environment Variable

- `VITE_API_BASE_URL`: base URL API backend (default di `.env.example` adalah `http://localhost:8000`).

## Build Production

```bash
npm run build
npm run preview
```

## Smoke Test Integrasi API

Dengan backend aktif, jalankan:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000 npm run smoke:predict-v2
```

Script ini menjalankan request simulasi ke endpoint `POST /predict-v2` dan memvalidasi field response inti.

## Struktur

- `src/App.jsx`: halaman dashboard utama (simulasi, edukasi, metrik sesi).
- `src/styles.css`: visual style, layout, motion, dan responsif.
- `src/main.jsx`: entrypoint React.
