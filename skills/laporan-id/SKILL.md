---
name: laporan-id
description: Format laporan pentest bahasa Indonesia yang sudah dipakai untuk target pemerintah — terstruktur, menyamarkan PII, dan menyertakan bukti.
---

# Laporan bahasa Indonesia (format instansi)

Dipakai saat target adalah instansi pemerintah dan laporan akan diserahkan ke pejabat non-teknis.
Isi laporan tetap harus berasal dari bukti (`traffic_refs`, SARIF, log) — bukan dari ingatan.

## Struktur wajib

1. **Ringkasan** — tabel angka (permukaan diperiksa, bersih, ditutup, uji lanjut, kerentanan
   terbukti), lalu 1 paragraf postur risiko. Tanpa jargon.
2. **Kamus istilah** — setiap istilah teknis yang muncul (NOP, captcha, endpoint, SSO, HMAC,
   `client_credentials`, CVSS) dijelaskan dalam satu baris bahasa awam.
3. **Cakupan** — host, IP origin, komponen pendukung, metode (black-box/tanpa kredensial), dan
   angka: jumlah subdomain, host hidup, port dipindai, request, token, durasi.
4. **Per temuan** — selalu empat bagian tetap:
   - *Apa yang terjadi* (bahasa awam, satu-dua paragraf)
   - *Buktinya* (request/response atau perintah + keluaran, PII disamarkan)
   - *Artinya* (dampak nyata, termasuk apa yang **tidak** berhasil)
   - *Cara memperbaiki* (langkah konkret)
5. **Yang sudah bagus** — area yang diuji dan bersih, dengan nama kontrol yang menahannya.
   Bagian ini wajib ada: laporan yang hanya berisi keburukan tidak kredibel.
6. **Rekomendasi bertahap** — Segera / jangka pendek / jangka menengah, plus langkah uji ulang.
7. **Yang belum diuji** — daftar eksplisit, termasuk alasannya (butuh kredensial, diblokir bot-check).
8. **Catatan** — pernyataan bahwa tidak ada data diambil, sisa artefak uji yang harus dibersihkan,
   dan status run.

## Aturan penulisan

- **Severity memakai dampak yang terbukti**, bukan skor CVE. Cacat tanpa dampak terjangkau ditulis
  sebagai "cacat nyata, dampak belum terjangkau" — jangan dipaksa jadi High.
- **Samarkan PII sejak awal**: nama jadi `P***JO P*****O`, email `b***@gmail.com`, token `<REDACTED>`.
  Jangan pernah menyalin nomor identitas warga ke laporan.
- **Bedakan tegas** antara *bisa diakses* dan *sudah diambil*. Kalimat yang benar:
  "pintunya tidak terkunci", bukan "data sudah bocor".
- **Sebutkan batas alat**: kalau pemindaian berhenti karena batas giliran, tulis itu di bagian status —
  jangan biarkan pembaca menyimpulkan "sudah selesai dan aman".
- **Sertakan angka yang bisa dicek ulang** (jumlah permukaan, jumlah temuan per tingkat) dan sebutkan
  dari berkas mana angka itu berasal.
- Jangan menaruh kredensial, token, atau cookie di dokumen — sekalipun milik akun uji. Ganti dengan
  `<AKUN-UJI>`.
- Akhiri dengan: lokasi artefak mentah (`coverage.json`, `findings.sarif`, `run.json`) supaya
  temuan bisa diaudit ulang.

## Keluaran

- `Laporan-Keamanan-<Target>-Indonesia.md` — versi utama
- `Laporan-Keamanan-<Target>-Indonesia.html` — versi baca (tabel rapi, blok kode berbingkai)
- lampirkan `findings.sarif` bila tersedia, agar bisa diimpor alat audit

Simpan juga salinan di samping artefak run, supaya laporan dan buktinya tidak terpisah.
