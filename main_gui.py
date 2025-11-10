import sys
import os
from pathlib import Path
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QMainWindow, QAction, QFileDialog,
                             QListWidget, QTableWidget, QTableWidgetItem,
                             QHBoxLayout, QWidget, QVBoxLayout, QAbstractItemView,
                             QStatusBar, QLabel, QMessageBox)
from PyQt5.QtCore import Qt

# Bizim analiz fonksiyonlarımızı içeren dosyayı import et
# (main_gui.py ve registry_parser.py aynı klasörde olmalı)
import registry_parser

class ForensicAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Forensic Artifact Analyzer")
        self.setGeometry(100, 100, 1200, 700) # Pencere boyutu

        # Veri tablolarını (DataFrame) saklamak için bir sözlük
        self.data_frames = {}
        self.case_folder_path = None

        self.initUI()

    def initUI(self):
        # --- Menü Çubuğu ---
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&Dosya')

        loadAction = QAction('&Vaka Klasörü Yükle...', self)
        loadAction.triggered.connect(self.loadCaseFolder)
        fileMenu.addAction(loadAction)

        exitAction = QAction('&Çıkış', self)
        exitAction.triggered.connect(self.close)
        fileMenu.addAction(exitAction)

        # --- Ana İçerik Alanı ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget) # Yatay layout (Sol + Sağ)

        # --- Sol Panel (Kategoriler) ---
        self.category_list = QListWidget()
        self.category_list.setMaximumWidth(250) # Genişliği sabitle

        # --- GÜNCELLEME: Liste güncellendi (RecentDocs kaldırıldı) ---
        self.category_list.addItems([
            "Oturum Logları",
            "USB Depolama Aygıtları",
            "Tüm USB Aygıtları",
            "Kurulu Programlar",
            "Çalıştırılan Programlar (UserAssist)",
            # "Son Erişilen Dosyalar (OpenSave)", # KALDIRILDI
            # "Son Erişilen Dosyalar (Explorer)", # KALDIRILDI
            "Ağ Geçmişi"
        ])
        # ---------------------------------------------

        # Bir kategoriye tıklandığında ne olacağını belirle
        self.category_list.currentItemChanged.connect(self.displayData)
        main_layout.addWidget(self.category_list)

        # --- Sağ Panel (Veri Tablosu) ---
        self.data_table = QTableWidget()
        self.data_table.setEditTriggers(QAbstractItemView.NoEditTriggers) # Düzenlemeyi engelle
        self.data_table.setAlternatingRowColors(True) # Satır renklerini farklı yap
        self.data_table.setSortingEnabled(True) # Başlığa tıklayarak sıralamayı etkinleştir
        main_layout.addWidget(self.data_table)

        # --- Durum Çubuğu ---
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Hazır. Lütfen 'Dosya -> Vaka Klasörü Yükle...' seçeneği ile bir klasör seçin.")

    def loadCaseFolder(self):
        """ Vaka klasörünü seçtirir ve analiz fonksiyonlarını çalıştırır. """
        folder_path = QFileDialog.getExistingDirectory(self, "Vaka Klasörünü Seç")

        if not folder_path: # Kullanıcı iptal ettiyse
            return

        # --- ÖNCEKİ VERİLERİ TEMİZLE ---
        self.data_frames = {}
        self.data_table.setRowCount(0)
        self.data_table.setColumnCount(0)
        # -----------------------------

        self.case_folder_path = Path(folder_path)
        self.statusBar.showMessage(f"Vaka klasörü yükleniyor: {self.case_folder_path}")
        QApplication.processEvents() # Arayüzün güncellenmesini sağla

        # Gerekli dosyaların yollarını oluştur
        sec_log_path = self.case_folder_path / "Security.evtx"
        system_hive_path = self.case_folder_path / "SYSTEM"
        software_hive_path = self.case_folder_path / "SOFTWARE"
        ntuser_hive_path = self.case_folder_path / "NTUSER.DAT"

        # Dosyaların var olup olmadığını kontrol et
        missing_files = []
        if not sec_log_path.exists(): missing_files.append(f"- Oturum Logları (Security.evtx)")
        if not system_hive_path.exists(): missing_files.append(f"- USB Cihazları (SYSTEM)")
        if not software_hive_path.exists(): missing_files.append(f"- Programlar/Ağ (SOFTWARE)")
        # NTUSER.DAT sadece UserAssist için gerekli artık
        if not ntuser_hive_path.exists(): missing_files.append(f"- Çalıştırılan Programlar (NTUSER.DAT)") 

        if missing_files:
            QMessageBox.warning(self, "Eksik Dosyalar",
                                f"Seçilen klasörde aşağıdaki gerekli dosyalar bulunamadı:\n" +
                                "\n".join(missing_files))
            self.statusBar.showMessage("Yükleme başarısız: Eksik dosyalar.")
            return

        # --- Analiz Fonksiyonlarını Çağır ---
        try:
            self.statusBar.showMessage("Oturum logları analiz ediliyor...")
            QApplication.processEvents()
            self.data_frames["Oturum Logları"] = registry_parser.parse_security_log(sec_log_path)

            self.statusBar.showMessage("USB cihazları analiz ediliyor...")
            QApplication.processEvents()
            usb_storage_df, usb_all_df = registry_parser.parse_usb_devices(system_hive_path)
            self.data_frames["USB Depolama Aygıtları"] = usb_storage_df
            self.data_frames["Tüm USB Aygıtları"] = usb_all_df

            self.statusBar.showMessage("Kurulu programlar analiz ediliyor...")
            QApplication.processEvents()
            self.data_frames["Kurulu Programlar"] = registry_parser.parse_installed_programs(software_hive_path)

            self.statusBar.showMessage("Çalıştırılan programlar (UserAssist) analiz ediliyor...")
            QApplication.processEvents()
            self.data_frames["Çalıştırılan Programlar (UserAssist)"] = registry_parser.parse_user_assist(ntuser_hive_path)

            # --- KALDIRILDI: Recent Files MRU çağrıları ---

            self.statusBar.showMessage("Ağ geçmişi analiz ediliyor...")
            QApplication.processEvents()
            self.data_frames["Ağ Geçmişi"] = registry_parser.parse_network_list(software_hive_path)

            # --- KALDIRILDI: Zaman Çizelgesi oluşturma ---

            self.statusBar.showMessage("Analiz tamamlandı. Soldaki listeden bir kategori seçin.")
            self.category_list.setCurrentRow(0) # İlk kategoriyi (Oturum Logları) otomatik seç
            self.displayData(self.category_list.currentItem())

        except Exception as e:
            QMessageBox.critical(self, "Analiz Hatası", f"Analiz sırasında bir hata oluştu:\n{e}")
            self.statusBar.showMessage("Analiz başarısız.")


    # displayData fonksiyonu aynı kalabilir
    def displayData(self, current_item):
        """ Seçilen kategoriye ait DataFrame'i sağdaki tabloya yükler. """
        if current_item is None or not self.data_frames:
            return
        category_name = current_item.text()
        df = self.data_frames.get(category_name)
        if df is None or df.empty:
            self.data_table.setRowCount(0)
            self.data_table.setColumnCount(0)
            if df is None: self.statusBar.showMessage(f"'{category_name}' için veri bulunamadı.")
            else: self.statusBar.showMessage(f"'{category_name}' için kayıt bulunamadı.")
            return
        self.statusBar.showMessage(f"'{category_name}' verisi yükleniyor ({len(df)} satır)...")
        QApplication.processEvents()
        self.data_table.setRowCount(df.shape[0])
        self.data_table.setColumnCount(df.shape[1])
        self.data_table.setHorizontalHeaderLabels(df.columns)
        for row_idx, row in enumerate(df.values):
            for col_idx, value in enumerate(row):
                if isinstance(value, pd.Timestamp):
                    display_value = value.strftime('%Y-%m-%d %H:%M:%S') if pd.notna(value) else ""
                else:
                    display_value = str(value) if pd.notna(value) else ""
                item = QTableWidgetItem(display_value)
                self.data_table.setItem(row_idx, col_idx, item)
        self.data_table.resizeColumnsToContents()
        self.statusBar.showMessage(f"'{category_name}' verisi yüklendi.")


# --- Uygulamayı Başlat ---
if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWin = ForensicAnalyzerApp()
    mainWin.show()
    sys.exit(app.exec_())