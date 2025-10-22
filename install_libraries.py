import os
import sys
import subprocess
import ctypes

def run_as_admin():
    """Scripti yönetici olarak yeniden başlatır."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
        
    if not is_admin:
        print("🛡️ Yönetici yetkisi isteniyor...")
        # Yönetici olarak yeniden çalıştır
        try:
            params = " ".join([f'"{arg}"' for arg in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}" {params}', None, 1)
        except Exception as e:
            print(f"❌ Yeniden başlatma sırasında hata: {e}")
        finally:
            sys.exit()  # Eski (yönetici olmayan) süreci kapat
    else:
        print("✅ Yönetici olarak çalışıyor.")

def install_requirements():
    """requirements.txt varsa pip install -r requirements.txt çalıştırır."""
    req_file = "requirements.txt"

    if not os.path.exists(req_file):
        print(f"❌ {req_file} dosyası bulunamadı!")
        return False

    print("📦 Gerekli kütüphaneler kontrol ediliyor ve yükleniyor...\n")
    try:
        # subprocess.check_call komutu, pip'in çıktılarını ekrana canlı olarak basar.
        # Kütüphaneler zaten yüklüyse, bunu belirtir ve sorunsuz devam eder.
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
        print("\n✅ Kütüphane kontrolü ve kurulumu başarıyla tamamlandı.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Yükleme sırasında hata: {e}")
        return False
    except FileNotFoundError:
        print("❌ 'pip' komutu bulunamadı. Python'ın PATH'e eklendiğinden emin olun.")
        return False

def run_main_program():
    """Ana uygulamayı (main.py) başlatır."""
    main_file = "main.py"
    if os.path.exists(main_file):
        print("\n🚀 Uygulama başlatılıyor...")
        # Popen, bu scriptin kapanmasına izin verirken main.py'nin çalışmaya devam etmesini sağlar.
        subprocess.Popen([sys.executable, main_file], creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        print(f"❌ {main_file} dosyası bulunamadı!")

# --- ANA ÇALIŞTIRMA BLOĞU ---
if __name__ == "__main__":
    run_as_admin()  # 1. Adım: Yönetici olarak çalıştığından emin ol

    success = install_requirements()  # 2. Adım: Gerekli kütüphaneleri yükle/kontrol et

    if success:
        # 3. Adım: Kütüphaneler tamamsa, ana programı çalıştır
        run_main_program()
    else:
        # Kurulum başarısız olduysa kullanıcıyı bilgilendir
        print("\n❌ Kütüphane kurulumu başarısız olduğu için uygulama başlatılamıyor.")

    # Kullanıcının mesajları görebilmesi için konsolun açık kalmasını sağla
    input("\nİşlem tamamlandı. Kapatmak için Enter'a basınız...")