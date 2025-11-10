import Evtx.Evtx as evtx
import pandas as pd
import xml.etree.ElementTree as ET
from pathlib import Path
from Registry import Registry
import struct
import codecs
from datetime import datetime, timedelta, UTC


# --- FONKSİYON 1: OTURUM LOGLARI 
def parse_security_log(evtx_file_path):
    """
    Bir Security.evtx dosyasını analiz eder ve
    oturum loglarını (4624, 4625, 4634, 4647) çeker.
    EventID ve Oturum Türünü metne çevirir.
    """
    events = []
    logon_filter = [4624, 4625, 4634, 4647]
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    event_id_descriptions = {
        4624: "(4624) Başarılı Oturum Açma", 4625: "(4625) Başarısız Oturum Denemesi",
        4634: "(4634) Oturum Kapatıldı", 4647: "(4647) Oturum Kullanıcı Tarafından Kapatıldı"
    }
    logon_type_descriptions = {
        '0': '(0) Sistem', '2': '(2) İnteraktif', '3': '(3) Ağ', '4': '(4) Batch', '5': '(5) Hizmet',
        '7': '(7) Kilit Açma', '8': '(8) Ağ Açık Metin', '9': '(9) Yeni Kimlik Bilgisi',
        '10': '(10) Uzak İnteraktif (RDP)', '11': '(11) Önbellekli İnteraktif'
    }
    print(f"'{evtx_file_path}' dosyası açılıyor...")
    try:
        with evtx.Evtx(evtx_file_path) as log:
            print("Log kayıtları analiz ediliyor... (Bu işlem yavaş olabilir)")
            record_count = 0
            for record in log.records():
                record_count += 1
                if record_count % 10000 == 0:
                    print(f"... {record_count} kayıt işlendi...")
                try:
                    if len(events) > 1000: continue # Limit
                    xml_data = record.xml()
                    root = ET.fromstring(xml_data)
                    event_id_element = root.find('./e:System/e:EventID', namespaces=ns)
                    if event_id_element is None: continue
                    event_id = int(event_id_element.text)
                except Exception: continue

                if event_id in logon_filter:
                    timestamp = record.timestamp()
                    event_data_element = root.find('.//e:EventData', namespaces=ns)
                    data_fields = {}
                    if event_data_element is not None:
                        for data in event_data_element.findall('./e:Data', namespaces=ns):
                            name = data.get('Name')
                            value = data.text
                            data_fields[name] = value

                    event_desc = event_id_descriptions.get(event_id, f"Olay {event_id}")
                    logon_type_code = data_fields.get("LogonType", "")
                    logon_desc = logon_type_descriptions.get(logon_type_code, f"({logon_type_code})") if logon_type_code else "N/A"
                    user = data_fields.get("TargetUserName") or data_fields.get("SubjectUserName", "N/A")
                    ip = data_fields.get("IpAddress", "N/A")

                    events.append({
                        "Olay": event_desc,
                        "Timestamp": timestamp,
                        "Kullanıcı Adı": user,
                        "Oturum Türü": logon_desc,
                        "Kaynak IP": ip
                    })
            print(f"\nAnaliz tamamlandı. Toplam {record_count} kayıt tarandı.")
            print(f"Toplam {len(events)} adet ilgili log bulundu.")
            df = pd.DataFrame(events)
            if not df.empty:
                 df = df[["Timestamp", "Olay", "Kullanıcı Adı", "Oturum Türü", "Kaynak IP"]] # Sıralama
            return df
    except Exception as e:
        print(f"Dosya okunurken hata oluştu: {e}")
        return None

# --- FONKSİYON 2: USB ANALİZİ 
def parse_usb_devices(system_hive_path): 
    
    # SYSTEM hive dosyasını analiz eder.
    # 1. USBSTOR'dan depolama aygıtlarının Seri Numarası ve İlk Takılma Zamanını alır.
    # 2. Enum\USB'den TÜM USB cihazlarının Detaylı Bilgilerini (Açıklama, Kolay Ad, Son Güncelleme) alır.
    
    storage_devices = []
    all_usb_devices = []
    usbstor_path = r"ControlSet001\Enum\USBSTOR"
    usb_enum_path = r"ControlSet001\Enum\USB"

    print(f"\n'{system_hive_path}' dosyası açılıyor (Gelişmiş USB analizi için)...")
    try:
        reg = Registry.Registry(str(system_hive_path))
    except Exception as e:
        print(f"Hata: SYSTEM dosyası açılamadı: {e}")
        return pd.DataFrame(columns=["Cihaz Adı", "Seri Numarası", "İlk Takılma Zamanı"]), \
               pd.DataFrame(columns=["VID_PID", "Instance ID / Seri No", "Açıklama", "Kolay Ad", "Konum", "Son Güncelleme"])
    # 1. USBSTOR Analizi
    try:
        usbstor_key = reg.open(usbstor_path)
        print(f"Analiz ediliyor: {usbstor_path}")
        for device_type in usbstor_key.subkeys():
            device_name = device_type.name()
            for serial_key in device_type.subkeys():
                serial_number = serial_key.name()
                first_installed_date = serial_key.timestamp()
                storage_devices.append({
                    "Cihaz Adı": device_name,
                    "Seri Numarası": serial_number,
                    "İlk Takılma Zamanı": pd.Timestamp(first_installed_date) # Timestamp'e çevir
                })
        print(f"USBSTOR analizi tamamlandı. {len(storage_devices)} depolama kaydı bulundu.")
    except Registry.RegistryKeyNotFoundException:
        print(f"BULGU: {usbstor_path} yolu bulunamadı.")
    except Exception as e:
        print(f"USBSTOR okunurken hata oluştu: {e}")
    # 2. Enum\USB Analizi
    try:
        usb_enum_key = reg.open(usb_enum_path)
        print(f"Analiz ediliyor: {usb_enum_path}")
        for vid_pid_key in usb_enum_key.subkeys():
            vid_pid = vid_pid_key.name()
            for instance_key in vid_pid_key.subkeys():
                instance_id = instance_key.name()
                last_update_time = instance_key.timestamp()
                device_desc = "N/A"
                friendly_name = "N/A"
                location = "N/A"
                try: device_desc = instance_key.value("DeviceDesc").value()
                except (Registry.RegistryValueNotFoundException, Exception): pass
                try: friendly_name = instance_key.value("FriendlyName").value()
                except (Registry.RegistryValueNotFoundException, Exception): pass
                try: location = instance_key.value("LocationInformation").value()
                except (Registry.RegistryValueNotFoundException, Exception): pass
                all_usb_devices.append({
                    "VID_PID": vid_pid,
                    "Instance ID / Seri No": instance_id,
                    "Açıklama": device_desc,
                    "Kolay Ad": friendly_name,
                    "Konum": location,
                    "Son Güncelleme": pd.Timestamp(last_update_time) # Timestamp'e çevir
                })
        print(f"Enum\\USB analizi tamamlandı. {len(all_usb_devices)} genel USB kaydı bulundu.")
    except Registry.RegistryKeyNotFoundException:
        print(f"HATA: {usb_enum_path} yolu bulunamadı.")
    except Exception as e:
        print(f"Enum\\USB okunurken hata oluştu: {e}")

    df_storage = pd.DataFrame(storage_devices)
    df_all_usb = pd.DataFrame(all_usb_devices)
    if not df_storage.empty:
      df_storage = df_storage.dropna(subset=['İlk Takılma Zamanı'])
      df_storage = df_storage.sort_values(by="İlk Takılma Zamanı", ascending=False)
    if not df_all_usb.empty:
       df_all_usb = df_all_usb.dropna(subset=['Son Güncelleme'])
       df_all_usb = df_all_usb.sort_values(by="Son Güncelleme", ascending=False)
    return df_storage, df_all_usb

# --- FONKSİYON 3: KURULU PROGRAMLAR 
def parse_installed_programs(software_hive_path):
    """
    SOFTWARE hive dosyasını analiz eder ve kurulu programları listeler.
    Kurulum tarihini YYYY-MM-DD formatında gösterir.
    """
    programs = []
    uninstall_path_wow64 = r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    uninstall_path_64 = r"Microsoft\Windows\CurrentVersion\Uninstall"
    print(f"\n'{software_hive_path}' dosyası açılıyor (Kurulu Program analizi için)...")
    try:
        reg = Registry.Registry(str(software_hive_path))
    except Exception as e:
        print(f"Hata: SOFTWARE dosyası açılamadı: {e}")
        return None
    paths_to_check = [uninstall_path_64, uninstall_path_wow64]
    for uninstall_path in paths_to_check:
        try:
            uninstall_key = reg.open(uninstall_path)
            print(f"Analiz ediliyor: {uninstall_path}")
        except Registry.RegistryKeyNotFoundException:
            print(f"Bilgi: {uninstall_path} yolu bulunamadı, atlanıyor.")
            continue
        for prog_key in uninstall_key.subkeys():
            display_name = None
            publisher = None
            display_version = None
            install_date_formatted = "N/A"
            try:
                display_name = prog_key.value("DisplayName").value()
            except Registry.RegistryValueNotFoundException: continue
            except Exception: continue
            if not display_name: continue
            try:
                install_date_str = prog_key.value("InstallDate").value()
                try:
                    install_date_obj = datetime.strptime(install_date_str, '%Y%m%d')
                    install_date_formatted = install_date_obj.strftime('%Y-%m-%d')
                except (ValueError, TypeError):
                    install_date_formatted = install_date_str if install_date_str else "N/A"
            except Registry.RegistryValueNotFoundException:
                install_date_formatted = "N/A"
            try: publisher = prog_key.value("Publisher").value()
            except Registry.RegistryValueNotFoundException: publisher = "N/A"
            try: display_version = prog_key.value("DisplayVersion").value()
            except Registry.RegistryValueNotFoundException: display_version = "N/A"
            programs.append({
                "Program Adı": display_name, "Yayıncı": publisher,
                "Sürüm": display_version, "Kurulum Tarihi": install_date_formatted
            })
    print(f"Kurulu program analizi tamamlandı. Toplam {len(programs)} adet program bulundu.")
    df = pd.DataFrame(programs)
    df_sorted = df.sort_values(by="Program Adı")
    return df_sorted

# --- FONKSİYON 4: ÇALIŞTIRILAN PROGRAMLAR 
def parse_user_assist(ntuser_dat_path):
    """
    NTUSER.DAT hive dosyasını analiz eder, UserAssist kayıtlarını
    (çalıştırılan programlar) bulur ve ROT13 şifresini çözer.
    Modern (72-byte) ve Eski (16-byte) formatları DOĞRU okur.
    TÜM KAYITLARI (Run Count 0 dahil) gösterir.
    """
    def filetime_to_datetime(ft):
        try:
            if ft == 0: return pd.NaT
            EPOCH_AS_FILETIME = 116444736000000000
            HUNDREDS_OF_NANOSECONDS = 10000000
            timestamp = (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
            return datetime.fromtimestamp(timestamp, UTC)
        except Exception: return pd.NaT

    programs = []
    user_assist_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    print(f"\n'{ntuser_dat_path}' dosyası açılıyor (UserAssist analizi için)...")
    try:
        reg = Registry.Registry(str(ntuser_dat_path))
    except Exception as e:
        print(f"Hata: NTUSER.DAT dosyası açılamadı: {e}")
        return None # None döndür GUI'de kontrol edilecek
    try:
        ua_key = reg.open(user_assist_path)
    except Registry.RegistryKeyNotFoundException:
        print(f"BULGU: {user_assist_path} yolu bulunamadı.")
        return pd.DataFrame(columns=["Program Adı (Deşifre Edilmiş)", "Çalıştırma Sayısı", "Odaklanma Sayısı", "Son Çalıştırma (UTC)"]) # Boş DF
    for guid_key in ua_key.subkeys():
        try:
            count_key = guid_key.subkey("Count")
        except Registry.RegistryKeyNotFoundException: continue
        for value in count_key.values():
            decoded_name = ""
            try:
                encoded_name = value.name()
                if encoded_name == "(Default)": continue
                decoded_name = codecs.decode(encoded_name, 'rot_13')
                binary_data = value.value()
                run_count = 0
                focus_count = 0
                filetime_raw = 0
                data_len = len(binary_data)
                if data_len >= 68: # Modern
                    run_count = struct.unpack('<I', binary_data[4:8])[0]
                    focus_count = struct.unpack('<I', binary_data[8:12])[0]
                    filetime_raw = struct.unpack('<Q', binary_data[60:68])[0]
                elif data_len >= 16: # Eski
                    run_count_raw = struct.unpack('<I', binary_data[4:8])[0]
                    run_count = run_count_raw - 5 if run_count_raw > 4 else 0
                    filetime_raw = struct.unpack('<Q', binary_data[-8:])[0]
                else: continue
                last_run_time = filetime_to_datetime(filetime_raw)
                programs.append({
                    "Program Adı (Deşifre Edilmiş)": decoded_name,
                    "Çalıştırma Sayısı": run_count,
                    "Odaklanma Sayısı": focus_count,
                    "Son Çalıştırma (UTC)": last_run_time
                })
            except Exception as e: continue
    print(f"UserAssist analizi tamamlandı. Toplam {len(programs)} adet çalıştırılan program kaydı bulundu.")
    df = pd.DataFrame(programs)
    if not programs: return df
    df_sorted = df.sort_values(by="Son Çalıştırma (UTC)", ascending=False, na_position='last')
    return df_sorted

# --- FONKSİYON 5: AĞ (WIFI) BİLGİLERİ 
def parse_network_list(software_hive_path):
    """
    SOFTWARE hive dosyasını analiz eder ve 'NetworkList' (geçmiş ağlar)
    bilgilerini çeker. DateCreated için SYSTEMTIME formatını okur.
    """
    def filetime_to_datetime(ft):
        try:
            if ft == 0: return pd.NaT
            EPOCH_AS_FILETIME = 116444736000000000
            HUNDREDS_OF_NANOSECONDS = 10000000
            timestamp = (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
            return datetime.fromtimestamp(timestamp, UTC)
        except Exception: return pd.NaT
    def systemtime_to_datetime(st_bytes):
        try:
            year, month, _, day, hour, minute, second, millisecond = struct.unpack('<HHHHHHHH', st_bytes)
            if year == 0: return pd.NaT
            return datetime(year, month, day, hour, minute, second, millisecond * 1000, tzinfo=UTC)
        except Exception: return pd.NaT

    networks = []
    network_list_path = r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    print(f"\n'{software_hive_path}' dosyası açılıyor (Ağ analizi için)...")
    try:
        reg = Registry.Registry(str(software_hive_path))
    except Exception as e:
        print(f"Hata: SOFTWARE dosyası açılamadı: {e}")
        return None # None döndür
    try:
        profiles_key = reg.open(network_list_path)
        print(f"Analiz ediliyor: {network_list_path}")
    except Registry.RegistryKeyNotFoundException:
        print(f"BULGU: {network_list_path} yolu bulunamadı.")
        return pd.DataFrame(columns=["Ağ Adı (SSID)", "İlk Bağlantı (UTC)", "Profil Yolu (GUID)"]) # Boş DF
    for profile in profiles_key.subkeys():
        profile_name = "N/A"
        date_created = pd.NaT
        try:
            profile_name_value = profile.value("ProfileName")
            profile_name = profile_name_value.value()
            try:
                date_created_value_obj = profile.value("DateCreated")
                value_type = date_created_value_obj.value_type()
                raw_value = date_created_value_obj.value()
                if value_type == Registry.RegBin and len(raw_value) == 16:
                    date_created = systemtime_to_datetime(raw_value)
                elif value_type == Registry.RegBin and len(raw_value) == 8:
                    filetime_int = struct.unpack('<Q', raw_value)[0]
                    date_created = filetime_to_datetime(filetime_int)
            except Registry.RegistryValueNotFoundException: pass
            except Exception: pass
        except Registry.RegistryValueNotFoundException: continue
        except Exception: continue
        networks.append({
            "Ağ Adı (SSID)": profile_name,
            "İlk Bağlantı (UTC)": date_created,
            "Profil Yolu (GUID)": profile.name()
        })
    print(f"Ağ analizi tamamlandı. Toplam {len(networks)} adet ağ profili bulundu.")
    df = pd.DataFrame(networks)
    if not networks: return df
    df_sorted = df.sort_values(by="İlk Bağlantı (UTC)", ascending=False, na_position='last')
    return df_sorted




# --- if __name__ == '__main__': 
if __name__ == '__main__':
    script_path = Path(__file__).resolve()
    script_dir = script_path.parent

    # Dosya yolları
    evtx_file = script_dir / "CASE_FILES" / "Security.evtx"
    system_file = script_dir / "CASE_FILES" / "SYSTEM"
    software_file = script_dir / "CASE_FILES" / "SOFTWARE"
    ntuser_file = script_dir / "CASE_FILES" / "NTUSER.DAT"

    print("-" * 50)
    logon_df = parse_security_log(evtx_file)
    if logon_df is not None:
        print("\n--- Başarılı ve Başarısız Oturumlar (Ayrıştırılmış) ---")
        print(logon_df)

    print("-" * 50)
    usb_storage_df, usb_all_df = parse_usb_devices(system_file)
    if usb_storage_df is not None:
        print("\n--- Takılan USB Depolama Aygıtları ---")
        print(usb_storage_df)
    if usb_all_df is not None:
        print("\n--- Tüm USB Aygıtları (Ayrı Liste) ---")
        print(usb_all_df)

    print("-" * 50)
    installed_programs_df = parse_installed_programs(software_file)
    if installed_programs_df is not None:
        print("\n--- Kurulu Programlar ---")
        print(installed_programs_df)

    print("-" * 50)
    user_assist_df = parse_user_assist(ntuser_file)
    if user_assist_df is not None:
        print("\n--- Çalıştırılan Programlar (UserAssist) ---")
        pd.set_option('display.max_rows', 1000)
        print(user_assist_df)

    # --- KALDIRILDI: Recent Files MRU çağrıları ---

    print("-" * 50)
    network_df = parse_network_list(software_file)
    if network_df is not None:
        print("\n--- Geçmiş Ağ Bağlantıları (Wi-Fi/LAN) ---")
        print(network_df)

    # Zaman çizelgesi kodu kaldırıldı.