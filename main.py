import sys
import os
import ctypes
import socket
import ssl
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog
import subprocess
import threading
import hashlib
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote, unquote
import random
import string
import base64
import codecs

# --- YÖNETİCİ İZNİ KONTROLÜ ---
def is_admin():
    """Programın yönetici yetkileriyle çalışıp çalışmadığını kontrol eder."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

script_path = os.path.abspath(sys.argv[0])

if not is_admin():
    # Programı yönetici olarak yeniden başlatır
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
    sys.exit()

# --- GELİŞMİŞ ARAÇLAR İÇİN KÜTÜPHANELER ---
try:
    from scapy.all import sr1, IP, ICMP, arp_scan
    from dns import resolver
except ImportError:
    pass

# --- KARŞILAMA EKRANI SINIFI ---
class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.lift()
        self.attributes("-topmost", True)
        self.overrideredirect(True)
        width, height = 600, 350
        screen_width, screen_height = self.winfo_screenwidth(), self.winfo_screenheight()
        x, y = (screen_width / 2) - (width / 2), (screen_height / 2) - (height / 2)
        self.geometry(f'{width}x{height}+{int(x)}+{int(y)}')
        self.config(bg="#1a1a1a")
        
        title_font = ctk.CTkFont(family="Consolas", size=50, weight="bold")
        subtitle_font = ctk.CTkFont(family="Consolas", size=24)
        dev_font = ctk.CTkFont(family="Consolas", size=12)
        
        ctk.CTkLabel(self, text="WELCOME", font=title_font, text_color="#00ff9d").pack(pady=(60, 0))
        ctk.CTkLabel(self, text="SİBERTİM", font=subtitle_font, text_color="#00ff9d").pack(pady=(10, 0))
        
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal", progress_color="#00ff9d", mode="determinate")
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=40, padx=50, fill="x")
        
        ctk.CTkLabel(self, text="Developer: Mehmet Emin MAĞNİSALIOĞLU", font=dev_font, text_color="gray").pack(side="bottom", pady=10)
        self.update_progress()

    def update_progress(self):
        current_value = self.progress_bar.get()
        if current_value < 1:
            self.progress_bar.set(current_value + 0.02)
            self.after(50, self.update_progress)
        else:
            self.after(500, self.destroy_splash)

    def destroy_splash(self):
        self.master.deiconify()
        self.destroy()

# --- ANA UYGULAMA SINIFI ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        splash = SplashScreen(self)
        
        self.title("SİBERTİM - Ultimate Pentest & IT Toolkit")
        self.geometry("1200x800")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=5)
        self.grid_rowconfigure(0, weight=1)
        
        self.button_frame = ctk.CTkScrollableFrame(self, label_text="Araç Kutusu")
        self.button_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        self.output_textbox = ctk.CTkTextbox(self, corner_radius=10, state="disabled", font=("Courier New", 12))
        self.output_textbox.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.create_banner_and_buttons()

    def create_banner_and_buttons(self):
        banner_text = """
      ___ ___ ___ ___ ___ _____ ___ __  __ 
     / __|_ _| _ ) __| _ \_   _|_ _|  \/  |
     \__ \| || _ \ _||   / | |  | || |\/| |
     |___/___|___/___|_|_\ |_| |___|_|  |_|
                                       
        """
        banner_label = ctk.CTkLabel(self.button_frame, text=banner_text, font=ctk.CTkFont(family="Courier New", size=10), justify="left")
        banner_label.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(self.button_frame, text="-"*50).pack(fill="x", padx=20)

        buttons_info = {
            "--- Hızlı Erişim Araçları ---": None, "Denetim Masası": lambda: self.launch_application("control"), "Kayıt Defteri Düzenleyicisi": lambda: self.launch_application("regedit"), "Aygıt Yöneticisi": lambda: self.launch_application("devmgmt.msc"), "Disk Yönetimi": lambda: self.launch_application("diskmgmt.msc"), "Hizmetler": lambda: self.launch_application("services.msc"), "Performans İzleyici": lambda: self.launch_application("perfmon"), "Gelişmiş Güvenlik Duvarı": lambda: self.launch_application("wf.msc"), "Görev Yöneticisi": lambda: self.launch_application("taskmgr"),
            "--- Sistem & Ağ Bilgileri ---": None, "Sistem Bilgileri (systeminfo)": lambda: self.run_command_in_thread(["systeminfo"]), "IP Yapılandırması (Tümü)": lambda: self.run_command_in_thread(["ipconfig", "/all"]), "Genel IP Adresim Nedir?": self.run_get_public_ip, "Ping Testi": self.run_ping, "DNS Önbelleğini Temizle": lambda: self.run_command_in_thread(["ipconfig", "/flushdns"]), "Whois Sorgulama": self.run_whois, "Traceroute": self.run_traceroute,
            "--- Gelişmiş Siber Güvenlik ---": None, "IP Coğrafi Konum Tespiti": self.run_ip_geolocation, "Alan Adı / IP Çözümleyici": self.run_dns_resolver, "MAC Adresi Üretici Tespiti": self.run_mac_lookup, "Yaygın Port Sorgulama": self.run_port_lookup, "Web Güvenlik Başlığı Kontrolü": self.run_header_security_check, "Scapy ile Yerel Ağı Tara (ARP)": self.run_scapy_arp_scan, "Basit Port Tarayıcı": self.run_port_scanner, "Hızlı Nmap Taraması": lambda: self.run_nmap("-F"), "DNS Kayıt Sorgulama": self.run_dns_query, "HTTP Header Analizi": self.run_http_headers, "SSL Sertifika Bilgileri": self.run_ssl_cert_info, "Basit Subdomain Tarayıcı": self.run_subdomain_scanner, "Web Sitesi Linklerini Tara (Spider)": self.run_spider, "Dizin/Dosya Keşfi (Brute Force)": self.run_directory_buster,
            "--- Sistem Yönetimi & Onarım ---": None, "Sistem Dosyalarını Tara (SFC)": lambda: self.run_command_in_thread(["sfc", "/scannow"]), "Diski Kontrol Et (CHKDSK C:)": lambda: self.run_command_in_thread(["chkdsk", "C:", "/f", "/r"]), "Grup İlkelerini Güncelle": lambda: self.run_command_in_thread(["gpupdate", "/force"]), "Güvenlik Duvarını AÇ": lambda: self.run_command_in_thread(["netsh", "advfirewall", "set", "allprofiles", "state", "on"]), "Güvenlik Duvarını KAPAT": lambda: self.run_command_in_thread(["netsh", "advfirewall", "set", "allprofiles", "state", "off"]),
            "--- Diğer Araçlar ---": None, "Metin Hash Hesaplayıcı": self.calculate_hashes, "Dosya Hash Hesaplayıcı": self.run_file_hasher, "Güçlü Parola Oluşturucu": self.run_password_generator, "URL Kodlayıcı / Çözücü": self.run_url_tool, "Base64 Kodlayıcı / Çözücü": self.run_base64_tool, "ROT13 Şifreleyici / Çözücü": self.run_rot13_tool, "Çıktıyı Temizle": self.clear_output
        }
        for text, command in buttons_info.items():
            if command is None:
                ctk.CTkLabel(self.button_frame, text=text, font=ctk.CTkFont(weight="bold")).pack(padx=10, pady=(15, 5), fill="x")
            else:
                ctk.CTkButton(self.button_frame, text=text, command=command).pack(padx=10, pady=7, fill="x")
    
    def update_textbox(self, text):
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("1.0", text)
        self.output_textbox.configure(state="disabled")

    def execute_command(self, command_list):
        try:
            self.after(0, self.update_textbox, f"Çalıştırılıyor: {' '.join(command_list)}\n\nLütfen bekleyin...")
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(command_list, capture_output=True, text=True, startupinfo=si, check=True, encoding='utf-8', errors='ignore')
            output = result.stdout if result.stdout else "Komut başarıyla çalıştırıldı."
        except FileNotFoundError:
            output = f"HATA: '{command_list[0]}' komutu bulunamadı..."
        except subprocess.CalledProcessError as e:
            output = f"Komut çalıştırılırken bir hata oluştu:\n\n{e.stdout}\n{e.stderr}"
        except Exception as e:
            output = f"Beklenmedik bir hata oluştu:\n\n{str(e)}"
        self.after(0, self.update_textbox, output)

    def launch_application(self, app_command):
        try:
            subprocess.Popen(app_command, shell=True)
            self.update_textbox(f"'{app_command}' başarıyla başlatıldı.")
        except Exception as e:
            self.update_textbox(f"'{app_command}' başlatılırken hata oluştu:\n\n{str(e)}")

    def run_command_in_thread(self, command_list):
        threading.Thread(target=self.execute_command, args=(command_list,), daemon=True).start()

    def run_ping(self):
        target = ctk.CTkInputDialog(text="Ping atılacak IP veya domain girin:", title="Ping Testi").get_input()
        if target:
            self.run_command_in_thread(["ping", target])

    def run_nmap(self, scan_type):
        target = ctk.CTkInputDialog(text="Nmap ile taranacak hedef IP veya domain girin:", title="Nmap Taraması").get_input()
        if target:
            self.run_command_in_thread(["nmap", scan_type, target])

    def run_whois(self):
        domain = ctk.CTkInputDialog(text="Whois sorgusu yapılacak domain girin:", title="Whois Sorgulama").get_input()
        if domain:
            self.update_textbox(f"'{domain}' için Whois sorgusu yapılıyor...");
            def task():
                try:
                    w = whois.whois(domain)
                    result = ""
                    for key, value in w.items():
                        result += f"{str(key).replace('_', ' ').title():20}: {value}\n"
                    self.after(0, self.update_textbox, result)
                except Exception as e:
                    self.after(0, self.update_textbox, f"Whois sorgusu başarısız oldu:\n\n{str(e)}")
            threading.Thread(target=task, daemon=True).start()

    def calculate_hashes(self):
        text_to_hash = ctk.CTkInputDialog(text="Hash'i hesaplanacak metni girin:", title="Hash Hesaplayıcı").get_input()
        if text_to_hash:
            data = text_to_hash.encode('utf-8')
            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            result = f"Girilen Metin: {text_to_hash}\n----------------------------------------\nMD5:    {md5_hash}\nSHA1:   {sha1_hash}\nSHA256: {sha256_hash}\n"
            self.update_textbox(result)

    def clear_output(self):
        self.update_textbox("")

    def run_spider(self):
        url = ctk.CTkInputDialog(text="Taranacak başlangıç URL'sini girin (örn: https://example.com):", title="Web Spider").get_input()
        if url:
            threading.Thread(target=self.perform_spider, args=(url,), daemon=True).start()

    def perform_spider(self, url):
        self.after(0, self.update_textbox, f"'{url}' adresindeki linkler taranıyor...\n")
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            found_links = set()
            for link in soup.find_all('a', href=True):
                full_url = urljoin(base_url, link['href'])
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    found_links.add(full_url)
            result_text = f"'{url}' adresinde bulunan domain içi linkler:\n\n" + "\n".join(sorted(list(found_links)))
            self.after(0, self.update_textbox, result_text)
        except Exception as e:
            self.after(0, self.update_textbox, f"Spider hatası: {e}")

    def run_directory_buster(self):
        url = ctk.CTkInputDialog(text="Taranacak temel URL'yi girin (örn: https://example.com):", title="Dizin/Dosya Keşfi").get_input()
        if url:
            wordlist = ["admin", "login", "dashboard", "test", "uploads", "backup", "wp-admin", "administrator", "config", "phpmyadmin"]
            threading.Thread(target=self.perform_directory_buster, args=(url, wordlist), daemon=True).start()

    def perform_directory_buster(self, base_url, wordlist):
        self.after(0, self.update_textbox, f"'{base_url}' adresinde dizin taraması başlatıldı...\n")
        found_paths = []
        try:
            for word in wordlist:
                test_url = f"{base_url.rstrip('/')}/{word}"
                response = requests.get(test_url, timeout=3, allow_redirects=True)
                if response.status_code != 404:
                    found_paths.append(f"BULUNDU: {test_url} (Status: {response.status_code})")
            if not found_paths:
                result_text = "Tarama tamamlandı. Yaygın bir dizin veya dosya bulunamadı."
            else:
                result_text = "Tarama tamamlandı. Bulunan yollar:\n\n" + "\n".join(found_paths)
            self.after(0, self.update_textbox, result_text)
        except Exception as e:
            self.after(0, self.update_textbox, f"Dizin tarama hatası: {e}")

    def run_port_scanner(self):
        target = ctk.CTkInputDialog(text="Taranacak hedef IP adresini girin:", title="Port Tarayıcı").get_input()
        if target:
            threading.Thread(target=self.perform_port_scan, args=(target, "1-1024"), daemon=True).start()

    def perform_port_scan(self, target_ip, port_range):
        self.after(0, self.update_textbox, f"'{target_ip}' adresinde port taraması başlatıldı ({port_range})...\n")
        try:
            open_ports = []
            start_port, end_port = map(int, port_range.split('-'))
            for port in range(start_port, end_port + 1):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    if sock.connect_ex((target_ip, port)) == 0:
                        open_ports.append(port)
            if not open_ports:
                result_text = "Tarama tamamlandı. Belirtilen aralıkta açık port bulunamadı."
            else:
                result_text = "Tarama tamamlandı. Bulunan açık portlar:\n\n" + "\n".join(map(str, sorted(open_ports)))
            self.after(0, self.update_textbox, result_text)
        except Exception as e:
            self.after(0, self.update_textbox, f"Port tarama hatası: {e}")

    def run_scapy_arp_scan(self):
        target = ctk.CTkInputDialog(text="Taranacak IP aralığını girin (örn: 192.168.1.1/24):", title="Scapy ARP Taraması").get_input()
        if target:
            threading.Thread(target=self.perform_scapy_arp_scan, args=(target,), daemon=True).start()

    def perform_scapy_arp_scan(self, target_range):
        self.after(0, self.update_textbox, "Scapy ile ARP taraması başlatıldı... Yönetici izni gerektirir ve sürebilir.")
        try:
            answered, _ = arp_scan(target_range, timeout=2, verbose=False)
            output = "ARP Taraması Sonuçları:\n\nIP Adresi\t\tMAC Adresi\n----------------------------------------\n"
            for _, received in answered:
                output += f"{received.psrc}\t\t{received.hwsrc}\n"
            self.after(0, self.update_textbox, output)
        except Exception as e:
            self.after(0, self.update_textbox, f"Scapy tarama hatası: {e}\n\nNot: Bu araç yönetici olarak çalıştırılmalıdır.")

    def run_dns_query(self):
        target = ctk.CTkInputDialog(text="DNS kayıtları sorgulanacak alan adını girin:", title="DNS Sorgulama").get_input()
        if target:
            threading.Thread(target=self.perform_dns_query, args=(target,), daemon=True).start()

    def perform_dns_query(self, domain):
        self.after(0, self.update_textbox, f"{domain} için DNS kayıtları sorgulanıyor...\n")
        output = f"--- {domain} DNS KAYITLARI ---\n\n"
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                output += f"--- {rtype} KAYITLARI ---\n"
                for rdata in answers:
                    output += f"{rdata.to_text()}\n"
                output += "\n"
            except resolver.NoAnswer:
                output += f"--- {rtype} KAYDI BULUNAMADI ---\n\n"
            except Exception:
                pass
        self.after(0, self.update_textbox, output)

    def run_http_headers(self):
        target = ctk.CTkInputDialog(text="HTTP başlıkları analiz edilecek URL'yi girin (örn: https://google.com):", title="HTTP Header Analizi").get_input()
        if target:
            threading.Thread(target=self.perform_http_headers, args=(target,), daemon=True).start()

    def perform_http_headers(self, url):
        self.after(0, self.update_textbox, f"{url} için HTTP başlıkları alınıyor...\n")
        try:
            response = requests.get(url, timeout=5)
            output = f"--- {url} (Status: {response.status_code}) YANIT BAŞLIKLARI ---\n\n"
            for header, value in response.headers.items():
                output += f"{header}: {value}\n"
            self.after(0, self.update_textbox, output)
        except Exception as e:
            self.after(0, self.update_textbox, f"Hata: {e}")

    def run_ssl_cert_info(self):
        target = ctk.CTkInputDialog(text="SSL sertifikası kontrol edilecek alan adını girin (örn: google.com):", title="SSL Sertifika Bilgileri").get_input()
        if target:
            threading.Thread(target=self.perform_ssl_cert_info, args=(target,), daemon=True).start()

    def perform_ssl_cert_info(self, domain):
        self.after(0, self.update_textbox, f"{domain} için SSL sertifika bilgileri alınıyor...\n")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            output = f"--- {domain} SSL SERTİFİKA DETAYLARI ---\n\n"
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            output += f"KİME VERİLDİ (Subject): {subject.get('commonName', 'N/A')}\n"
            output += f"KİM TARAFINDAN VERİLDİ (Issuer): {issuer.get('commonName', 'N/A')}\n"
            valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            output += f"GEÇERLİLİK BİTİŞ TARİHİ: {valid_until.strftime('%Y-%m-%d %H:%M:%S')}\n"
            remaining = valid_until - datetime.now()
            output += f"KALAN SÜRE: {remaining.days} gün\n"
            self.after(0, self.update_textbox, output)
        except Exception as e:
            self.after(0, self.update_textbox, f"Hata: {e}")

    def run_subdomain_scanner(self):
        target = ctk.CTkInputDialog(text="Alt alan adları taranacak ana domain'i girin (örn: google.com):", title="Basit Subdomain Tarayıcı").get_input()
        if target:
            threading.Thread(target=self.perform_subdomain_scan, args=(target,), daemon=True).start()

    def perform_subdomain_scan(self, domain):
        self.after(0, self.update_textbox, f"{domain} için basit subdomain taraması başlatıldı...\n")
        subdomains = ['www', 'mail', 'ftp', 'test', 'dev', 'api', 'blog', 'shop', 'admin', 'vpn', 'm']
        found = []
        for sub in subdomains:
            url = f"https://{sub}.{domain}"
            try:
                requests.get(url, timeout=2)
                found.append(url)
            except Exception:
                pass
        output = "--- BULUNAN SUBDOMAIN'LER ---\n"
        if found:
            output += "\n".join(found)
        else:
            output += "Yaygın subdomain bulunamadı."
        self.after(0, self.update_textbox, output)

    def run_traceroute(self):
        target = ctk.CTkInputDialog(text="Ağ yolu izlenecek IP veya alan adını girin:", title="Traceroute").get_input()
        if target:
            threading.Thread(target=self.perform_traceroute, args=(target,), daemon=True).start()

    def perform_traceroute(self, target):
        self.after(0, self.update_textbox, f"{target} hedefine doğru ağ yolu izleniyor (max 30 adım)...\n\n")
        output = f"--- {target} TRACEROUTE SONUÇLARI ---\nHop\tIP Adresi\n---\t---------\n"
        self.after(0, self.update_textbox, output)
        try:
            dest_ip = socket.gethostbyname(target)
            for i in range(1, 30):
                pkt = IP(dst=dest_ip, ttl=i) / ICMP()
                reply = sr1(pkt, verbose=0, timeout=2)
                if reply is None:
                    output += f"{i}\t* (Timeout)\n"
                elif reply.src:
                    output += f"{i}\t{reply.src}\n"
                    if reply.src == dest_ip:
                        output += "\n--- HEDEFE ULAŞILDI ---\n"
                        break
                self.after(0, self.update_textbox, output)
            else:
                output += "\n--- TARAMA BİTTİ (Max. adıma ulaşıldı) ---\n"
            self.after(0, self.update_textbox, output)
        except socket.gaierror:
            self.after(0, self.update_textbox, f"Hata: Hedef çözümlenemedi: {target}")
        except Exception as e:
            self.after(0, self.update_textbox, f"Traceroute hatası: {e}")

    def run_file_hasher(self):
        filepath = filedialog.askopenfilename(title="Hash'i Hesaplanacak Dosyayı Seçin")
        if filepath:
            threading.Thread(target=self.perform_file_hasher, args=(filepath,), daemon=True).start()

    def perform_file_hasher(self, filepath):
        self.after(0, self.update_textbox, f"'{os.path.basename(filepath)}' dosyasının hash değerleri hesaplanıyor...\n")
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            output = f"--- {os.path.basename(filepath)} HASH DEĞERLERİ ---\n\n"
            output += f"MD5:    {md5.hexdigest()}\n"
            output += f"SHA1:   {sha1.hexdigest()}\n"
            output += f"SHA256: {sha256.hexdigest()}\n"
            self.after(0, self.update_textbox, output)
        except Exception as e:
            self.after(0, self.update_textbox, f"Dosya okunurken bir hata oluştu: {e}")

    def run_ip_geolocation(self):
        target = ctk.CTkInputDialog(text="Konumu tespit edilecek alan adını girin: (ÖRN: google.com)", title="IP Konum Tespiti").get_input()
        if target:
            threading.Thread(target=self.perform_ip_geolocation, args=(target,), daemon=True).start()

    def perform_ip_geolocation(self, target_ip):
        self.after(0, self.update_textbox, f"'{target_ip}' adresi için konum bilgisi alınıyor...\n")
        try:
            response = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=5).json()
            if response.get("status") == "success":
                output = f"--- {target_ip} KONUM BİLGİLERİ ---\n\n"
                output += f"Ülke:      {response.get('country', 'N/A')}\n"
                output += f"Şehir:     {response.get('city', 'N/A')}\n"
                output += f"Bölge:     {response.get('regionName', 'N/A')}\n"
                output += f"Posta Kodu:{response.get('zip', 'N/A')}\n"
                output += f"Enlem:     {response.get('lat', 'N/A')}\n"
                output += f"Boylam:    {response.get('lon', 'N/A')}\n"
                output += f"ISP:       {response.get('isp', 'N/A')}\n"
                output += f"Organiz.:  {response.get('org', 'N/A')}\n"
            else:
                output = f"Hata: '{target_ip}' için konum bilgisi alınamadı.\nSebep: {response.get('message', 'Bilinmeyen hata')}"
            self.after(0, self.update_textbox, output)
        except Exception as e:
            self.after(0, self.update_textbox, f"Konum tespiti sırasında bir hata oluştu: {e}")

    def run_dns_resolver(self):
        target = ctk.CTkInputDialog(text="IP adresine dönüştürülecek alan adı veya tersi:", title="Alan Adı / IP Çözümleyici").get_input()
        if target:
            threading.Thread(target=self.perform_dns_resolver, args=(target,), daemon=True).start()

    def perform_dns_resolver(self, target):
        self.after(0, self.update_textbox, f"'{target}' çözümleniyor...\n")
        try:
            socket.inet_aton(target)
            hostname, _, _ = socket.gethostbyaddr(target)
            output = f"--- Tersine Çözümleme (IP -> Alan Adı) ---\n\n"
            output += f"IP Adresi: {target}\n"
            output += f"Alan Adı:  {hostname}"
        except socket.error:
            try:
                ip_address = socket.gethostbyname(target)
                output = f"--- Normal Çözümleme (Alan Adı -> IP) ---\n\n"
                output += f"Alan Adı:  {target}\n"
                output += f"IP Adresi: {ip_address}"
            except socket.gaierror:
                output = f"Hata: '{target}' alan adı çözümlenemedi."
        self.after(0, self.update_textbox, output)
        
    def run_password_generator(self):
        length_str = ctk.CTkInputDialog(text="Oluşturulacak parolanın uzunluğunu girin (örn: 16):", title="Güçlü Parola Oluşturucu").get_input()
        if length_str and length_str.isdigit():
            length = int(length_str)
            if 8 <= length <= 128:
                self.perform_password_generator(length)
            else:
                self.update_textbox("Hata: Parola uzunluğu 8 ile 128 arasında olmalıdır.")
        elif length_str:
            self.update_textbox("Hata: Lütfen geçerli bir sayı girin.")

    def perform_password_generator(self, length):
        characters = string.ascii_letters + string.digits + string.punctuation
        password_list = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]
        for _ in range(length - 4):
            password_list.append(random.choice(characters))
        random.shuffle(password_list)
        password = "".join(password_list)
        output = f"--- Güçlü Parola Oluşturuldu ---\n\nUzunluk: {length}\n\nParola: {password}\n"
        self.update_textbox(output)

    def run_mac_lookup(self):
        target = ctk.CTkInputDialog(text="Üreticisi bulunacak MAC adresini girin:", title="MAC Adresi Üretici Tespiti").get_input()
        if target:
            threading.Thread(target=self.perform_mac_lookup, args=(target,), daemon=True).start()

    def perform_mac_lookup(self, mac_address):
        self.after(0, self.update_textbox, f"'{mac_address}' için üretici bilgisi sorgulanıyor...\n")
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=5)
            if response.status_code == 200:
                vendor = response.text
                output = f"--- MAC Adresi Analizi ---\n\n"
                output += f"MAC Adresi: {mac_address}\n"
                output += f"Üretici Firma: {vendor}"
            elif response.status_code == 404:
                output = f"Hata: '{mac_address}' için bir üretici bulunamadı. Lütfen formatı kontrol edin (örn: 00:1A:2B:3C:4D:5E)."
            else:
                output = f"Hata: Servisten beklenmedik bir yanıt alındı (Kod: {response.status_code})"
            self.after(0, self.update_textbox, output)
        except Exception as e:
            self.after(0, self.update_textbox, f"Sorgulama sırasında bir hata oluştu: {e}")

    def run_port_lookup(self):
        port_str = ctk.CTkInputDialog(text="Anlamı sorgulanacak port numarasını girin (1-65535):", title="Yaygın Port Sorgulama").get_input()
        if port_str and port_str.isdigit():
            port = int(port_str)
            if 1 <= port <= 65535:
                self.perform_port_lookup(port)
            else:
                self.update_textbox("Hata: Port numarası 1 ile 65535 arasında olmalıdır.")
        elif port_str:
            self.update_textbox("Hata: Lütfen geçerli bir sayı girin.")
            
    def perform_port_lookup(self, port):
        COMMON_PORTS = {
            20: "FTP (File Transfer Protocol) - Veri", 21: "FTP (File Transfer Protocol) - Kontrol", 22: "SSH (Secure Shell)", 23: "Telnet", 25: "SMTP (Simple Mail Transfer Protocol)",
            53: "DNS (Domain Name System)", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS (HTTP Secure)", 445: "SMB",
            1433: "Microsoft SQL Server", 3306: "MySQL Database", 3389: "RDP (Remote Desktop)", 5432: "PostgreSQL Database", 8080: "HTTP Alternatif"
        }
        description = COMMON_PORTS.get(port, "Bilinmiyor / Yaygın Değil")
        output = f"--- Port Sorgulama Sonucu ---\n\nPort: {port}\nYaygın Kullanım: {description}"
        self.update_textbox(output)

    def run_url_tool(self):
        text = ctk.CTkInputDialog(text="URL kodlama/çözme için metin girin:", title="URL Kodlayıcı / Çözücü").get_input()
        if text is not None:
            self.perform_url_tool(text)

    def perform_url_tool(self, text):
        encoded_text = quote(text)
        decoded_text = unquote(text)
        output = f"--- URL Kodlama / Çözme Sonuçları ---\n\n"
        output += f"Orijinal Metin: {text}\n\n"
        output += f"URL Kodlanmış (Encoded): {encoded_text}\n\n"
        output += f"URL Çözülmüş (Decoded): {decoded_text}\n"
        self.update_textbox(output)
        
    def run_base64_tool(self):
        text = ctk.CTkInputDialog(text="Base64 kodlama/çözme için metin girin:", title="Base64 Kodlayıcı / Çözücü").get_input()
        if text is not None:
            self.perform_base64_tool(text)

    def perform_base64_tool(self, text):
        output = f"--- Base64 Kodlama / Çözme Sonuçları ---\n\n"
        output += f"Orijinal Metin: {text}\n\n"
        try:
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            encoded_text = encoded_bytes.decode('utf-8')
            output += f"Base64 Kodlanmış (Encoded): {encoded_text}\n\n"
        except Exception as e:
            output += f"Base64 Kodlama Başarısız: {e}\n\n"
        try:
            decoded_bytes = base64.b64decode(text)
            decoded_text = decoded_bytes.decode('utf-8')
            output += f"Base64 Çözülmüş (Decoded): {decoded_text}\n"
        except Exception:
            output += "Base64 Çözme Başarısız: (Girdi geçerli bir Base64 değil)\n"
        self.update_textbox(output)

    def run_get_public_ip(self):
        threading.Thread(target=self.perform_get_public_ip, daemon=True).start()

    def perform_get_public_ip(self):
        self.after(0, self.update_textbox, "Genel IP adresiniz sorgulanıyor...\n")
        try:
            ip_address = requests.get("https://api.ipify.org", timeout=5).text
            output = f"--- Genel IP Adresiniz ---\n\n{ip_address}"
        except Exception as e:
            output = f"Genel IP adresi alınırken bir hata oluştu: {e}"
        self.after(0, self.update_textbox, output)
        
    def run_header_security_check(self):
        url = ctk.CTkInputDialog(text="Güvenlik başlıkları kontrol edilecek URL'yi girin (örn: https://google.com):", title="Güvenlik Başlığı Kontrolü").get_input()
        if url:
            threading.Thread(target=self.perform_header_security_check, args=(url,), daemon=True).start()

    def perform_header_security_check(self, url):
        self.after(0, self.update_textbox, f"'{url}' için güvenlik başlıkları kontrol ediliyor...\n")
        SECURITY_HEADERS = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy']
        try:
            headers = requests.get(url, timeout=5).headers
            output = f"--- {url} Güvenlik Başlığı Analizi ---\n\n"
            found_count = 0
            for header in SECURITY_HEADERS:
                if header in headers:
                    output += f"[✅] {header}: Bulundu.\n"
                    found_count += 1
                else:
                    output += f"[❌] {header}: Eksik.\n"
            output += f"\nSonuç: {len(SECURITY_HEADERS)} önemli güvenlik başlığından {found_count} tanesi bulundu."
        except Exception as e:
            output = f"Başlıklar kontrol edilirken bir hata oluştu: {e}"
        self.after(0, self.update_textbox, output)

    def run_rot13_tool(self):
        text = ctk.CTkInputDialog(text="ROT13 için metin girin:", title="ROT13 Şifreleyici / Çözücü").get_input()
        if text is not None:
            self.perform_rot13_tool(text)

    def perform_rot13_tool(self, text):
        result = codecs.encode(text, 'rot_13')
        output = f"--- ROT13 Sonuçları ---\n\nOrijinal Metin: {text}\n\nROT13 Sonucu: {result}\n"
        self.update_textbox(output)

# --- UYGULAMAYI BAŞLAT ---
if __name__ == "__main__":
    app = App()
    app.mainloop()