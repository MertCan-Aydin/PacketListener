# 📦 HTTP PacketListener (Python)

Bu proje, Python ve Scapy kullanarak HTTP isteklerini dinleyip, potansiyel kullanıcı adı ve şifre gibi bilgileri gerçek zamanlı olarak terminalde gösteren basit bir ağ paket dinleyicisidir.

## ✨ Özellikler
- Belirtilen bir ağ arayüzü (ör. `eth0`, `wlan0`) üzerinden HTTP isteklerini canlı olarak dinler.
- HTTP paketlerinde kullanıcı adı, e-posta ve şifre gibi alanları tespit eder.
- Gerçek zamanlı ve okunabilir çıktı sağlar.
- Kompakt ve sade Python kodu.

## ⚙️ Kurulum
Python 3 ve Scapy gereklidir. Scapy'yi yüklemek için:
```bash
pip install scapy
```
> ⚠️ Not: Paketleri dinlemek için root yetkisi (`sudo`) gerekir.

## 🚀 Kullanım
Terminalden aşağıdaki komutu çalıştırın:
```bash
sudo python3 PacketListener.py -i <interface>
```
Örnek:
```bash
sudo python3 PacketListener.py -i wlan0
```

## 🧠 Çalışma Mantığı
- `scapy.sniff()` ile belirtilen arayüzdeki HTTP paketleri dinlenir.
- HTTP isteği (`HTTPRequest`) ve veri (`Raw`) içeren paketler analiz edilir.
- "username", "user", "login", "email", "password", "pass", "pwd" gibi anahtar kelimeler aranarak potansiyel credential bilgileri bulunur.
- Kaynak IP, hedef IP ve bulunan veriler terminale yazdırılır.

