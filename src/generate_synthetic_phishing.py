import pandas as pd
import random
import os
import logging

from src.security import BlobStorageManager, KeyVaultSecretProvider, SecuritySettings

logger = logging.getLogger("cyberguard.synthetic")

# Set seed for reproducibility
random.seed(42)

# Templates for Phishing (Label 1)
courier_templates = [
    "Yth. Pelanggan, Paket anda dgn resi {resi} sedang diproses. Cek foto paket Anda: {url} . Mohon unduh aplikasi untuk melihat detail.",
    "Pak dokumnt dh nyampe d kntr cabang, tp almt krng jelas. tolong konfirmasi dsni ya pak {url}",
    "J&T Express: Paket Anda blm bs dikirim krna biaya kurir blm lunas. Lakukan pmbayaran sgera di {url} sblm dikembalikan ke pengirim.",
    "Halo kakk, ini kurir bawa paket harganya udh dibayar ya? Tolong cek ftonya bner ga {url} (Buka file APK)",
    "Pemberitahuan dr JNE, paket {resi} tertunda. Segera instal app resi di {url} utk mrubah jadwal pengiriman! Jika tdk paket hangus."
]

wedding_templates = [
    "Bismillah, Tanpa mengurangi rasa hormat, kami mengundang Bapak/Ibu untuk hadir di acara pernikahan kami. Detail acara & lokasi dpt dilihat pada link: {url}",
    "Assalamualaikum wr wb. Mhn maaf mengganggu, ini undangan digital pernikahan kami. Mohon kesediaannya utk hadir. Buka file apk: {url}",
    "Hi teman2! Save the date ya, ini undangan resepsi aku. Cek lokasi dan waktunya d sini {url} Ditunggu kehadirannya!",
    "Yth. Bapak/Ibu, Berikut kami sampaikan Undangan Resepsi Pernikahan. Mohon klik link berikut untuk RSVP dan lokasi {url}",
    "Undangan Spesial utk Kamu. Maaf baru ngabarin lwt WA. Tolong buka detil undangannya disni yach {url} mksihh."
]

tax_templates = [
    "SURAT PERINGATAN! Ditjen Pajak memberitahukan bhw NPWP Anda memiliki tunggakan Rp {amount}. Bayar sgera sblm {date} atau rekening Anda diblokir. Cek rincian: {url}",
    "Yth. Wajib Pajak, Anda mndapatkan SPPT Pajak Digital thn ini. Sgera unduh dokumen e-SPOP PDF (APK) di {url} agar terhindar dr denda 200%.",
    "PEMBERITAHUAN DJP: Trdapat anomali pelaporan SPT Anda. Untuk menghindari sanksi pidana, harap lakukan verifikasi ulang melalui {url}",
    "INFO PAJAK: Kartu NPWP digital anda sdh dpt diunduh. Silakan buka aplikasi resmi kmi di {url}",
    "Kepada Yth Wajib Pajak, tagihan denda keterlambatan PBB anda telah terbit. Silahkan akses lampiran surat (PDF) pada tautan {url}"
]

banking_templates = [
    "INFO RESMI: Yth Nasabah BCA, Mulai malam ini tarif transfer antar bank BERUBAH dari Rp6.500/transaksi menjadi Rp150.000/bulan. Jika TIDAK SETUJU ganti tarif, waJib isi form ini {url} atau saldo terpotong otomatis.",
    "BCA INFO: Perubahan skema tarif baru Rp 150rb/bln. Apabila anda tidak konfirmasi pd link {url} maka kami anggap SETUJU dgn tarif baru.",
    "PERINGATAN! Rekening BRI Anda terdeteksi login dari prgkat tdk dikenal. Jika ini bukan anda, SEGERA batalkan di {url} Jika tidak, sldo akan dibekukan.",
    "Yth. Nasabah BNI, ada pemotongan biaya admin Rp 150.000 utk bln ini. Batalkan sgera klo ga mw dipotong, klik {url}",
    "Nasabah Mandiri Yth, Krtu ATM Anda tlah diblokir smntara krna masa aktif habis. Aktifkan kmbali tnpa k kntor cabang di {url}"
]

# Random components
urls_phishing = [
    "http://cek-resi-jnt.top/paket.apk", "https://undangan-digital.xyz/nikah", 
    "http://s.id/BatalTarifBCA", "https://bit.ly/Cek-Pajak-DJP", 
    "http://tinyurl.com/Undangan-VIP", "https://tarif-baru-bri.cc/login",
    "http://pajak-go-id.info/spt.apk", "http://info-perubahan-tarif.top/konfirmasi",
    "http://kurir-ekspedisi.xyz/foto-paket", "https://s.id/CekResiApk"
]
resis = ["JP892837482", "00293848200", "TLD892838", "JT-99023849", "EX90909012"]
amounts = ["2.500.000", "4.150.000", "850.000", "12.000.000"]
dates = ["hari ini", "besok", "1x24 jam", "pukul 23:59 WIB"]

# Normal Templates (Label 0)
normal_templates = [
    "Halo, paket Anda dengan resi {resi} sedang dalam perjalanan oleh kurir kami. Pantau status paket di aplikasi resmi J&T.",
    "Selamat siang Bapak/Ibu, mengingatkan besok ada jadwal meeting bersama tim jam 10 pagi di ruang utama.",
    "Transkasi berhasil. Pembayaran ke Merchant sebesar Rp {amount} pada {date} telah diproses. Terima kasih menggunakan layanan kami.",
    "Jangan lupa bayar tagihan listrik bulan ini ya, jatuh tempo batasnya tanggal 20.",
    "Halo kak, ini undangannya udah aku kirim via email ya kak, tolong dicek kalau ada waktu luang. Makasih!",
    "Promo spesial hari ini! Diskon 50% untuk pembelian kedua di toko kami. Kunjungi cabang terdekat sekarang.",
    "Selamat ulang tahun! Kami dari bank XYZ mengucapkan selamat ulang tahun, semoga panjang umur dan sehat selalu.",
    "Yth Bapak/Ibu, laporan SPT tahunan Anda telah berhasil direkam oleh sistem DJP. Terima kasih atas partisipasinya."
]

synthetic_data = []

# Generate Phishing Data (Target: 150 samples)
phishing_sources = [
    (courier_templates, "WhatsApp"),
    (courier_templates, "SMS"),
    (wedding_templates, "WhatsApp"),
    (tax_templates, "Email"),
    (tax_templates, "WhatsApp"),
    (banking_templates, "SMS"),
    (banking_templates, "WhatsApp"),
]

for i in range(160):
    template_list, platform = random.choice(phishing_sources)
    text = random.choice(template_list).format(
        url=random.choice(urls_phishing),
        resi=random.choice(resis),
        amount=random.choice(amounts),
        date=random.choice(dates)
    )
    # Add some randomness to spacing/typos manually sometimes
    if random.random() < 0.2:
        text = text.replace("Anda", "anda").replace("di", "d").replace("yang", "yg")
    synthetic_data.append([text, 1, platform])

# Generate Normal Data (Target: 40 samples)
normal_sources = ["WhatsApp", "SMS", "Email"]
for i in range(40):
    platform = random.choice(normal_sources)
    text = random.choice(normal_templates).format(
        resi=random.choice(resis),
        amount=random.choice(amounts),
        date=random.choice(dates)
    )
    synthetic_data.append([text, 0, platform])

# Shuffle the dataset
random.shuffle(synthetic_data)

# Save to CSV
df = pd.DataFrame(synthetic_data, columns=["text", "label", "platform"])

output_path = "data/external/synthetic_phishing_data.csv"
ensure_dir = os.path.dirname(output_path)
if not os.path.exists(ensure_dir):
    os.makedirs(ensure_dir)

df.to_csv(output_path, index=False, encoding='utf-8')
print(f"Successfully created {len(df)} synthetic samples at {output_path}")


def upload_synthetic_dataset(local_path: str) -> None:
    settings = SecuritySettings.from_env()
    secret_provider = KeyVaultSecretProvider.from_settings(settings, logger=logger)
    blob_storage = BlobStorageManager.from_settings(settings, secret_provider=secret_provider, logger=logger)

    if not blob_storage.enabled:
        print("Blob storage is not configured. Synthetic dataset is stored locally only.")
        return

    blob_path = settings.raw_blob_path("datasets/synthetic_phishing_data.csv")
    uploaded = blob_storage.upload_file(local_path, blob_path, overwrite=True)
    if uploaded:
        print(f"Uploaded synthetic dataset to blob path: {blob_path}")


upload_synthetic_dataset(output_path)
