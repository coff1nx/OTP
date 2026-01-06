import sys
import os
import json
import re
import secrets
import string
import hashlib
import base64 
import time 
import hmac 
import tempfile 
import shutil 
from datetime import datetime, timedelta
import pytz
from cryptography.fernet import Fernet, InvalidToken 
import ctypes 
from pynput import keyboard
from pynput.keyboard import Controller as KeyboardController 
import threading
import pydirectinput 

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QCheckBox, QTabWidget,
    QMessageBox, QInputDialog, QFrame, QScrollArea, QListWidget,
    QTextEdit, QSizePolicy, QSlider, QSpinBox, QDateTimeEdit,
    QSystemTrayIcon, QMenu, QFileDialog, QStyle 
)
from PySide6.QtCore import (
    Qt, QTimer, QDateTime, QUrl, QLocale, QEvent, QTimeZone, QSize,
    QTranslator, QLibraryInfo 
)
from PySide6.QtGui import (
    QIcon, QFont, QColor, QPalette, QClipboard, QPixmap, QTransform, 
    QFontDatabase 
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DATA_FILE = 'data.enc'
HASH_FILE = 'auth.hash'

PBKDF2_ITERATIONS = 300000 

KOMPANION_GREEN_ACCENT_HEX = '#27ae60' 
KOMPANION_GREEN_ACCENT_COLOR = QColor(39, 174, 96) 
KOMPANION_GREEN_DARK_COLOR = QColor(0, 128, 0) 

# Настройки pydirectinput
try:
    pydirectinput.FAILSAFE = False
    # Возвращаем на безопасное значение, так как ручная логика контролирует паузы
    pydirectinput.PAUSE = 0.05 
except NameError:
     pass

kg_tz = pytz.timezone("Asia/Bishkek")
try:
    Q_KG_TZ = QTimeZone(b"Asia/Bishkek")
except:
    Q_KG_TZ = QTimeZone.systemTimeZone()


# =======================================================
#               SECURITY & UTILITY FUNCTIONS
# =======================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        PBKDF2_ITERATIONS,
        dklen=32 
    )
    return salt + pwd_hash

def derive_encryption_key(password, salt):
    raw_key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        PBKDF2_ITERATIONS,
        dklen=32
    )
    return base64.urlsafe_b64encode(raw_key)

def encrypt_data(data, encryption_key):
    if encryption_key is None:
        raise ValueError("Encryption key is missing. Cannot encrypt.")
        
    f = Fernet(encryption_key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted, encryption_key):
    if encryption_key is None:
        raise ValueError("Encryption key is missing. Cannot decrypt.")
        
    f = Fernet(encryption_key)
    return json.loads(f.decrypt(encrypted).decode())

def derive_export_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derives a Fernet key for export, uses different salt/iterations."""
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 480000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_export_data(data: bytes, password: str) -> bytes:
    """Encrypts data for export using a temporary password."""
    key, salt = derive_export_key(password)
    f = Fernet(key)
    encrypted = f.encrypt(data)
    return salt + encrypted 

def decrypt_import_data(encrypted: bytes, password: str) -> bytes:
    """Decrypts exported data using the export password."""
    if len(encrypted) < 16:
         raise InvalidToken("Data is too short to contain salt.")
    salt = encrypted[:16]
    data = encrypted[16:]
    key, _ = derive_export_key(password, salt)
    f = Fernet(key)
    return f.decrypt(data)

def get_dark_palette():
    palette = QPalette()
    dark_color = QColor(45, 45, 45)       
    base_color = QColor(30, 30, 30)       
    highlight_color = KOMPANION_GREEN_ACCENT_COLOR
    text_color = QColor(230, 230, 230)    
    disabled_color = QColor(127, 127, 127) 
    
    palette.setColor(QPalette.Window, dark_color)
    palette.setColor(QPalette.WindowText, text_color)
    palette.setColor(QPalette.Base, base_color)
    palette.setColor(QPalette.AlternateBase, dark_color)
    palette.setColor(QPalette.ToolTipBase, dark_color)
    palette.setColor(QPalette.ToolTipText, text_color)
    palette.setColor(QPalette.Text, text_color)
    palette.setColor(QPalette.Disabled, QPalette.Text, disabled_color)
    palette.setColor(QPalette.Button, dark_color)
    palette.setColor(QPalette.ButtonText, text_color)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_color)
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, highlight_color)
    palette.setColor(QPalette.Highlight, highlight_color)
    palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0)) 
    
    return palette

def get_light_palette():
    palette = QPalette()
    light_color = QColor(240, 240, 240)       
    base_color = QColor(255, 255, 255)       
    highlight_color = KOMPANION_GREEN_DARK_COLOR
    text_color = QColor(0, 0, 0)           
    disabled_color = QColor(160, 160, 160) 
    
    palette.setColor(QPalette.Window, light_color)
    palette.setColor(QPalette.WindowText, text_color)
    palette.setColor(QPalette.Base, base_color)
    palette.setColor(QPalette.AlternateBase, light_color)
    palette.setColor(QPalette.ToolTipBase, base_color)
    palette.setColor(QPalette.ToolTipText, text_color)
    palette.setColor(QPalette.Text, text_color)
    palette.setColor(QPalette.Disabled, QPalette.Text, disabled_color)
    palette.setColor(QPalette.Button, light_color)
    palette.setColor(QPalette.ButtonText, text_color)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_color)
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, highlight_color)
    palette.setColor(QPalette.Highlight, highlight_color)
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    
    return palette


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def set_russian_localization(app):
    translator = QTranslator(app)
    try:
        translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
        if translator.load(QLocale.Russian, 'qt', '_', translations_path):
            app.installTranslator(translator)
    except NameError: 
        if translator.load('qt_ru', os.path.join(os.path.dirname(sys.executable), 'PySide6', 'translations')):
            app.installTranslator(translator)
    except Exception:
        pass
        
    return translator

# =======================================================
#                     MAIN APPLICATION
# =======================================================

class AdminTool(QMainWindow):
    
    # Константа для пользовательского события автотайпа (для межпотокового взаимодействия)
    AUTOTYPE_FINISHED_EVENT_TYPE = QEvent.Type.User + 1 

    def __init__(self):
        super().__init__()

        self.localization_translator = set_russian_localization(QApplication.instance())
        
        self.encryption_key = None 
        self.login_attempts = 0
        self.lockout_time = None 
        
        self.password_hash = None
        self.is_locked = False
        self.idle_timer = QTimer(self)
        self.idle_duration_ms = 300000 
        self.current_theme = 'dark' 
        self.is_typing = False 
        self.is_hidden_by_autotype = False  # Флаг для игнорирования Show/Activate во время ввода
        
        self.reminder_timer = QTimer(self) 
        self.reminder_timer.timeout.connect(self.check_reminders)
        
        QApplication.instance().installEventFilter(self)

        # Инициализация контроллера pynput для type()
        self.keyboard_controller = KeyboardController() 

        self.setWindowTitle("Admin Panel")
        self.setMinimumSize(800, 600)
        self.resize(1000, 720) 
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        self.idle_timer.timeout.connect(self.lock_app)

        self.load_password_hash()
        
        if os.path.exists(DATA_FILE) and not self.password_hash:
             QMessageBox.warning(self, "Критическая ошибка", "Файл данных найден, но мастер-пароль не установлен! Пожалуйста, установите пароль.")
             
        self.show_login_screen()

        self.setup_global_hotkey()
        self.setup_tray_icon()
        
    # ===================== HOTKEY & TRAY =====================
    def setup_global_hotkey(self):
        self.is_hidden = False
        self.shift_pressed = False

        def on_press(key):
            try:
                if key in (keyboard.Key.shift, keyboard.Key.shift_r):
                    self.shift_pressed = True
                elif key == keyboard.Key.caps_lock and self.shift_pressed:
                    # Выполняем в главном потоке Qt, чтобы не было ошибок
                    QApplication.instance().postEvent(self, QEvent(QEvent.Type.User))
            except:
                pass

        def on_release(key):
            try:
                if key in (keyboard.Key.shift, keyboard.Key.shift_r):
                    self.shift_pressed = False
            except:
                pass

        listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        listener.daemon = True
        listener.start()

    def event(self, event):
        if event.type() == QEvent.Type.User:
            self.toggle_visibility()
            return True
        elif event.type() == self.AUTOTYPE_FINISHED_EVENT_TYPE: 
            self.finish_typing_ui()
            return True
        return super().event(event)

    def toggle_visibility(self):
        if self.is_hidden:
            # РАЗВОРАЧИВАЕМ
            self.show()
            self.setWindowState(Qt.WindowNoState)
            self.setWindowState(Qt.WindowActive)
            self.raise_()
            self.activateWindow()
            # Магия против мигания на панели задач
            self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
            self.show()
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowStaysOnTopHint)
            self.show()
            self.is_hidden = False
        else:
            # СКРЫВАЕМ
            self.hide()
            self.is_hidden = True

    def setup_tray_icon(self):
        self.tray = QSystemTrayIcon(self)
        icon_path = resource_path('icon.ico')
        if os.path.exists(icon_path):
             self.tray.setIcon(QIcon(icon_path))  
        else:
             self.tray.setIcon(QIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))) # Fallback
             
        self.tray.setToolTip("Admin Tool")

        menu = QMenu()
        menu.addAction("Показать окно", lambda: self.toggle_visibility() if self.is_hidden else None)
        menu.addSeparator()
        menu.addAction("Выход", QApplication.quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.toggle_visibility() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def closeEvent(self, event):
        if self.encryption_key is not None and not self.is_locked:
            self.save_data()

        reply = QMessageBox.question(
            self, 'Выход', "Закрыть программу полностью?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()
            self.hide()
            self.is_hidden = True 
            
    # ===================== THEMES =====================
    def get_base_stylesheet(self):
        return """
            QPushButton {
                min-height: 36px; 
                padding: 6px 12px;
                font-weight: 500;
                border-radius: 4px;
            }
            QTabWidget::tab-bar {
                left: 5px;
            }
            QTabBar::tab {
                min-width: 100px; 
                min-height: 38px; 
                padding: 0 15px;
                font-size: 11pt;
                font-weight: 500;
            }
            QFrame {
                border: 1px solid transparent;
                background-color: transparent;
            }
            QFrame[frameShape="1"] {
                border: 1px solid;
                border-radius: 4px;
            }
            QLabel, QCheckBox { 
                background-color: transparent;
                border: none;
            }
        """

    def apply_theme(self):
        base_style = self.get_base_stylesheet()
        
        app_font = QFont()
        if QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont).family() == 'MS Shell Dlg 2':
            app_font.setFamily('Verdana')
        else:
            app_font.setFamily('Segoe UI')
            
        app_font.setPointSize(11)
        QApplication.instance().setFont(app_font)
        
        if self.current_theme == 'dark':
            palette = get_dark_palette()
            style_sheet = base_style + f"""
                QWidget {{ 
                    background-color: #2D2D2D; 
                    color: #E6E6E6; 
                }}
                QFrame[frameShape="1"] {{ 
                    background-color: #2D2D2D; 
                    border-color: #3A3A3A;
                }}
                QLineEdit, QTextEdit, QListWidget, QSpinBox, QDateTimeEdit {{
                    background-color: #1E1E1E; 
                    color: #E6E6E6; 
                    border: 1px solid #3A3A3A;
                    padding: 4px; 
                }}
                QPushButton {{
                    background-color: #383838;
                    border: 1px solid #454545;
                }}
                QPushButton:hover {{
                    background-color: #4A4A4A;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #3A3A3A;
                    background-color: #2D2D2D;
                }}
                QTabBar::tab {{
                    background: #383838;
                    border: 1px solid #454545;
                    border-bottom-color: #2D2D2D; 
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                    color: #E6E6E6;
                }}
                QTabBar::tab:selected {{
                    background: #2D2D2D; 
                    border-bottom: 3px solid {KOMPANION_GREEN_ACCENT_HEX}; 
                    border-color: #454545;
                    color: {KOMPANION_GREEN_ACCENT_HEX}; 
                    font-weight: bold;
                }}
                QPushButton#NoteButton {{
                    min-width: 80px; 
                    max-width: 180px;
                    padding: 4px 8px; 
                    min-height: 28px; 
                    font-size: 10pt; 
                }}
                QPushButton#NoteButton:hover {{
                    background-color: #4A4A4A; 
                }}
                QScrollArea#NoteButtonsArea {{
                    border: none;
                }}
                QLabel, QCheckBox {{ 
                    background-color: transparent; 
                    color: #E6E6E6; 
                }}
                QMessageBox QPushButton {{
                    min-height: 30px; 
                    min-width: 80px;
                    padding: 2px 8px; 
                    font-size: 10pt;
                }}
                QPushButton#LockButton {{
                    background-color: #c0392b; 
                    border-color: #e74c3c;
                }}
                QPushButton#LockButton:hover {{
                    background-color: #e74c3c;
                }}
            """
        else:
            palette = get_light_palette()
            style_sheet = base_style + f"""
                QWidget {{ 
                    background-color: #F0F0F0; 
                    color: #000000; 
                }}
                QLineEdit, QTextEdit, QListWidget, QSpinBox, QDateTimeEdit {{
                    background-color: white; 
                    color: black; 
                    border: 1px solid #C0C0C0;
                }}
                QFrame[frameShape="1"] {{
                    background-color: #F0F0F0;
                    border-color: #D0D0D0;
                }}
                QPushButton {{
                    background-color: #E0E0E0;
                    border: 1px solid #C0C0C0;
                }}
                QPushButton:hover {{
                    background-color: #D0D0D0;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #D0D0D0;
                    background-color: #FFFFFF;
                }}
                QTabBar::tab {{
                    background: #E0E0E0;
                    border: 1px solid #C0C0C0;
                    border-bottom-color: #FFFFFF; 
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                    color: #000000;
                }}
                QTabBar::tab:selected {{
                    background: #FFFFFF; 
                    border-bottom: 3px solid {KOMPANION_GREEN_DARK_COLOR.name()}; 
                    border-color: #C0C0C0;
                    color: {KOMPANION_GREEN_DARK_COLOR.name()}; 
                    font-weight: bold;
                }}
                QPushButton#NoteButton {{
                    min-width: 80px; 
                    max-width: 180px;
                    padding: 4px 8px; 
                    min-height: 28px; 
                    font-size: 10pt; 
                }}
                QPushButton#NoteButton:hover {{
                    background-color: #D0D0D0;
                }}
                QScrollArea#NoteButtonsArea {{
                    border: none;
                }}
                QLabel, QCheckBox {{ 
                    background-color: transparent; 
                    color: #000000; 
                }}
                QMessageBox QPushButton {{
                    min-height: 30px; 
                    min-width: 80px;
                    padding: 2px 8px; 
                    font-size: 10pt;
                }}
                QPushButton#LockButton {{
                    background-color: #c0392b; 
                    border-color: #e74c3c;
                    color: white;
                }}
                QPushButton#LockButton:hover {{
                    background-color: #e74c3c;
                }}
            """
            
        QApplication.instance().setPalette(palette)
        QApplication.instance().setStyleSheet(style_sheet)
        self.save_data()
        
    def toggle_theme(self):
        self.current_theme = 'light' if self.current_theme == 'dark' else 'dark'
        self.apply_theme()
        if hasattr(self, 'theme_btn'):
            self.theme_btn.setText(f"Тема: {'Светлая' if self.current_theme == 'light' else 'Темная'}")

    # ===================== DATA & HASH HANDLING =====================
    def load_password_hash(self):
        if os.path.exists(HASH_FILE):
            try:
                with open(HASH_FILE, 'rb') as f:
                    self.password_hash = f.read()
            except Exception:
                 self.password_hash = None
                 QMessageBox.critical(self, "Ошибка", "Не удалось прочитать файл хэша.")
        else:
            self.password_hash = None

    def save_password_hash(self, pwd_hash):
        # Этот метод больше не используется напрямую при смене пароля из-за атомарности.
        # Он используется только при первой установке пароля.
        try:
            with open(HASH_FILE, 'wb') as f:
                f.write(pwd_hash)
            try:
                os.chmod(HASH_FILE, 0o600)
            except Exception:
                pass
        except Exception:
             QMessageBox.critical(self, "Ошибка", "Не удалось сохранить файл хэша.")

    def load_data(self):
        if self.encryption_key is None:
            return {} 
            
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'rb') as f:
                encrypted = f.read()
            try:
                data = decrypt_data(encrypted, self.encryption_key)
                return data
            except InvalidToken: 
                QMessageBox.critical(self, "Ошибка загрузки данных", "Не удалось расшифровать данные. Проверьте пароль.") 
                return {}
            except Exception:
                QMessageBox.critical(self, "Ошибка загрузки данных", "Файл данных поврежден.") 
                return {}
        return {}

    def save_data(self):
        # Этот метод сохраняет данные в текущий DATA_FILE с текущим self.encryption_key.
        # Он НЕ используется при смене пароля.
        if self.encryption_key is None:
            return 
            
        data = {
            'notes': getattr(self, 'notes', {}), 
            'reminders': getattr(self, 'reminders', []),
            'copied_passwords': getattr(self, 'copied_passwords', []),
            'frequent_keys': getattr(self, 'frequent_keys', {'key1': '', 'key2': ''}),
            'autotype_passwords': getattr(self, 'autotype_passwords', {}), 
            'theme': self.current_theme,
            'idle_duration_ms': self.idle_duration_ms
        }
        try:
            enc = encrypt_data(data, self.encryption_key)
            with open(DATA_FILE, 'wb') as f:
                f.write(enc)
            try:
                os.chmod(DATA_FILE, 0o600)
            except Exception:
                pass
        except Exception as e: 
            QMessageBox.critical(self, "Ошибка сохранения данных", f"Не удалось зашифровать данные: {e}") 

    # ===================== WINDOW UTILS =====================
    def set_permanent_topmost(self):
        flags = self.windowFlags()
        flags |= Qt.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        
        self.show() 

        if sys.platform == 'win32':
            HWND_TOPMOST = -1
            SWP_NOMOVE = 0x0002
            SWP_NOSIZE = 0x0001
            
            try:
                hwnd = int(self.winId())
                ctypes.windll.user32.SetWindowPos(
                    hwnd,
                    HWND_TOPMOST,
                    0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE
                )
            except Exception as e:
                print(f"Ошибка применения Topmost через Windows API: {e}")

    def clear_main_layout(self):
        while self.main_layout.count():
            item = self.main_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                while item.layout().count():
                    child_item = item.layout().takeAt(0)
                    if child_item.widget():
                        child_item.widget().deleteLater()

    def _create_auth_header(self, layout):
        logo_label = QLabel()
        logo_path = resource_path('Kompanion_logo.png')
        try:
            pixmap = QPixmap(logo_path) 
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaledToHeight(300, Qt.SmoothTransformation) 
                logo_label.setPixmap(scaled_pixmap)
            else:
                logo_label.setText("AdminTool")
                logo_label.setStyleSheet(f"font-size: 40pt; font-weight: bold; color: {KOMPANION_GREEN_ACCENT_HEX}; background-color: transparent;")
        except Exception:
            logo_label.setText("AdminTool")
            logo_label.setStyleSheet(f"font-size: 40pt; font-weight: bold; color: {KOMPANION_GREEN_ACCENT_HEX}; background-color: transparent;")
            
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        subtitle = QLabel("coff1nx")
        subtitle.setFont(QFont('Arial', 14, QFont.Light))
        subtitle.setStyleSheet(f"color: {KOMPANION_GREEN_ACCENT_HEX}; background-color: transparent;") 
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignCenter)
        
        spacer = QWidget()
        spacer.setFixedHeight(30)
        layout.addWidget(spacer)


    # ===================== LOGIN & LOCKOUT =====================

    def show_login_screen(self):
        self.clear_main_layout()
        self.lockout_time = None 

        frame = QWidget()
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self._create_auth_header(layout) 
        
        prompt_text = "Введите мастер-пароль:" if self.password_hash else "Придумайте мастер-пароль:"
        prompt = QLabel(prompt_text)
        layout.addWidget(prompt, alignment=Qt.AlignmentFlag.AlignCenter)

        self.login_pw = QLineEdit()
        self.login_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_pw.setFixedWidth(250)
        self.login_pw.returnPressed.connect(self.check_password) 
        layout.addWidget(self.login_pw, alignment=Qt.AlignmentFlag.AlignCenter)
        self.login_pw.setFocus()

        btn_text = "Войти" if self.password_hash else "Установить и Войти"
        self.login_btn = QPushButton(btn_text)
        self.login_btn.clicked.connect(self.check_password)
        self.login_btn.setFixedWidth(250)
        layout.addWidget(self.login_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.lock_status_label = QLabel("")
        self.lock_status_label.setStyleSheet("color: #e74c3c; background-color: transparent;") 
        layout.addWidget(self.lock_status_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        layout.addStretch() 
        self.main_layout.addStretch(1)
        self.main_layout.addWidget(frame)
        self.main_layout.addStretch(1)
        
        self.update_lockout_status() 

    def update_lockout_status(self):
        """Проверяет и обновляет статус блокировки в UI."""
        
        if self.lockout_time and datetime.now() < self.lockout_time:
            remaining = self.lockout_time - datetime.now()
            seconds = int(remaining.total_seconds())
            
            if seconds > 0:
                minutes, seconds = divmod(seconds, 60)
                time_str = f"{minutes:02d}:{seconds:02d}"
                self.lock_status_label.setText(f"<h4 style=\"color: #e74c3c;\">Вход заблокирован! Доступен через {time_str}</h4>")
                self.login_pw.setEnabled(False)
                self.login_btn.setEnabled(False)
                
                QTimer.singleShot(1000, self.update_lockout_status)
                return
        
        self.lockout_time = None
        self.lock_status_label.setText("")
        
        if hasattr(self, 'login_pw') and self.login_pw:
            self.login_pw.setEnabled(True)
        if hasattr(self, 'login_btn') and self.login_btn:
            self.login_btn.setEnabled(True)


    def check_password(self):
        if self.lockout_time and datetime.now() < self.lockout_time:
            self.update_lockout_status()
            return

        entered = self.login_pw.text()
        if not entered:
            QMessageBox.critical(self, "Ошибка", "Введите пароль!")
            return

        if self.password_hash is None:
            # Установка нового пароля (не требует атомарности)
            pwd_hash = hash_password(entered)
            self.save_password_hash(pwd_hash)
            self.password_hash = pwd_hash
            try:
                os.chmod(HASH_FILE, 0o600)
            except Exception:
                pass

            salt = self.password_hash[:32]
            self.encryption_key = derive_encryption_key(entered, salt)
            self.save_data()
            QMessageBox.information(self, "Готово", "Пароль установлен! Данные зашифрованы новым ключом.")
            self.load_main_interface()
        else:
            # Проверка существующего пароля
            salt = self.password_hash[:32]
            stored_hash = self.password_hash[32:]
            new_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                entered.encode('utf-8'), 
                salt, 
                PBKDF2_ITERATIONS,
                dklen=32 
            )
            if hmac.compare_digest(new_hash, stored_hash):
                self.login_attempts = 0
                self.encryption_key = derive_encryption_key(entered, salt)
                self.load_main_interface()
            else:
                self.handle_login_failure()


    def handle_login_failure(self):
        self.login_attempts += 1
        
        if self.login_attempts < 5:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль!")
        elif self.login_attempts < 10:
            delay = (self.login_attempts - 4) * 5 
            self.lockout_time = datetime.now() + timedelta(seconds=delay)
            self.login_pw.clear()
            QMessageBox.critical(self, "Блокировка", f"5+ неудачных попыток. Повторите через {delay} секунд перед следующей попыткой.")
            self.update_lockout_status() 
        elif self.login_attempts >= 10:
            self.login_attempts = 0
            self.lockout_time = datetime.now() + timedelta(minutes=10)
            QMessageBox.critical(self, "Блокировка", "Слишком много неудачных попыток. Вход заблокирован на 10 минут.")
            self.update_lockout_status() 
        else:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль!")


    def lock_app(self):
        if self.is_locked:
            return

        if self.encryption_key is not None:
            self.save_data()
            self.is_locked = True
            self.idle_timer.stop()
            
            if self.encryption_key is not None:
                del self.encryption_key
                self.encryption_key = None
                
            flags = self.windowFlags()
            flags &= ~Qt.WindowStaysOnTopHint
            self.setWindowFlags(flags)
            self.show()
            
            self.clear_main_layout()
            lock_frame = QWidget()
            layout = QVBoxLayout(lock_frame)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            self._create_auth_header(layout)
            
            lock_label = QLabel("<h4>ПРОГРАММА ЗАБЛОКИРОВАНА</h4>")
            lock_label.setStyleSheet("color: #e74c3c; background-color: transparent;")
            layout.addWidget(lock_label, alignment=Qt.AlignmentFlag.AlignCenter)
            
            prompt_label = QLabel("Введите пароль для разблокировки:")
            layout.addWidget(prompt_label, alignment=Qt.AlignmentFlag.AlignCenter)
            
            self.unlock_pw = QLineEdit()
            self.unlock_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.unlock_pw.setFixedWidth(250)
            self.unlock_pw.returnPressed.connect(self.unlock_app)
            layout.addWidget(self.unlock_pw, alignment=Qt.AlignmentFlag.AlignCenter)
            self.unlock_pw.setFocus()
            
            unlock_btn = QPushButton("Разблокировать")
            unlock_btn.clicked.connect(self.unlock_app)
            unlock_btn.setFixedWidth(250)
            layout.addWidget(unlock_btn, alignment=Qt.AlignmentFlag.AlignCenter)

            layout.addStretch()
            self.main_layout.addStretch(1)
            self.main_layout.addWidget(lock_frame)
            self.main_layout.addStretch(1)

    def unlock_app(self):
        entered = self.unlock_pw.text()
        if not entered:
            QMessageBox.critical(self, "Ошибка", "Введите пароль!")
            return

        salt = self.password_hash[:32]
        stored_hash = self.password_hash[32:]
        new_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            entered.encode('utf-8'), 
            salt, 
            PBKDF2_ITERATIONS,
            dklen=32 
        )

        if hmac.compare_digest(new_hash, stored_hash):
            self.is_locked = False
            self.encryption_key = derive_encryption_key(entered, salt)
            self.load_main_interface()
        else:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль!")
            self.unlock_pw.clear()

    def reset_idle_timer(self):
        if not self.is_locked and self.password_hash:
            self.idle_timer.start(self.idle_duration_ms)

    def eventFilter(self, obj, event):
        if not self.is_locked and self.password_hash and self.encryption_key:
            if event.type() in (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove):
                self.reset_idle_timer()
        
        # НОВОЕ ПРАВИЛО: Игнорируем события Show/Activate, которые могут быть вызваны
        # pydirectinput, пока мы сами не завершили автотайп.
        if self.is_hidden_by_autotype:
             if event.type() in (QEvent.Type.Show, QEvent.Type.WindowActivate):
                 # Во время скрытия мы должны игнорировать все события активации
                 # чтобы избежать ошибок
                 return False
            
        return super().eventFilter(obj, event)

    # ===================== MAIN INTERFACE =====================

    def load_main_interface(self):
        if self.encryption_key is None:
            QMessageBox.critical(self, "Ошибка безопасности", "Ключ шифрования отсутствует в памяти. Перезапустите приложение.")
            self.show_login_screen()
            return
            
        self.clear_main_layout()
        self.data = self.load_data()
        self.notes = self._convert_old_notes(self.data.get('notes', {}))
        self.reminders = self.data.get('reminders', [])
        self.copied_passwords = self.data.get('copied_passwords', [])
        self.frequent_keys = self.data.get('frequent_keys', {'key1': '', 'key2': ''})
        self.autotype_passwords = self.data.get('autotype_passwords', {}) 
        self.current_theme = self.data.get('theme', 'dark')
        self.idle_duration_ms = self.data.get('idle_duration_ms', self.idle_duration_ms)
        self.apply_theme()
        
        self.current_note_name = None
        self.is_typing = False 
        self.is_hidden_by_autotype = False
        
        self.create_top_frame()
        self.notebook = QTabWidget()
        self.main_layout.addWidget(self.notebook)
        
        self.create_notes_tab(self.notebook)
        self.create_reminders_tab(self.notebook)
        self.create_autotype_tab(self.notebook) 
        self.create_log_parser_tab(self.notebook)
        self.create_generator_tab(self.notebook)
        self.create_settings_tab(self.notebook)
        
        self.reminder_timer.start(60000)
        self.reset_idle_timer()
        self.set_permanent_topmost()

    def _convert_old_notes(self, notes):
        if isinstance(notes, dict):
            return notes
        if isinstance(notes, list):
            result = {}
            for i, txt in enumerate(notes):
                name = f"Заметка {i+1}"
                result[name] = txt
            return result
        return {}
        
    def create_top_frame(self):
        top_frame = QFrame()
        top_frame.setFrameShape(QFrame.Shape.NoFrame)
        top_frame.setFrameShadow(QFrame.Shadow.Plain)
        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(10, 5, 10, 5)
        top_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Кнопка Блокировки (новая)
        self.lock_btn = QPushButton("Блокировать")
        self.lock_btn.setObjectName("LockButton")
        self.lock_btn.clicked.connect(self.lock_app)
        top_layout.addWidget(self.lock_btn)

        self.theme_btn = QPushButton(f"Тема: {'Светлая' if self.current_theme == 'light' else 'Темная'}")
        self.theme_btn.clicked.connect(self.toggle_theme)
        top_layout.addWidget(self.theme_btn)
        
        self.idle_label = QLabel(f"Блокировка: {self.idle_duration_ms // 60000} мин.")
        top_layout.addWidget(self.idle_label)

        self.version_label = QLabel("v14.4") 
        self.version_label.setStyleSheet("font-size: 8pt; color: #7f8c8d;")
        top_layout.addWidget(self.version_label)

        self.main_layout.addWidget(top_frame)


    # ===================== NOTES TAB =====================
    def create_notes_tab(self, notebook):
        frame = QWidget()
        notebook.addTab(frame, 'Заметки')
        main_layout = QHBoxLayout(frame)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setContentsMargins(0, 0, 15, 0)
        controls_widget.setFixedWidth(350)
        
        controls_layout.addWidget(QLabel("<h4>Ваши заметки</h4>"))
        
        self.notes_buttons_area = QScrollArea()
        self.notes_buttons_area.setWidgetResizable(True)
        self.notes_buttons_area.setObjectName("NoteButtonsArea") 
        
        self.notes_buttons_widget = QWidget()
        self.notes_buttons_layout = QVBoxLayout(self.notes_buttons_widget)
        self.notes_buttons_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.notes_buttons_layout.setSpacing(5)
        
        self.notes_buttons_area.setWidget(self.notes_buttons_widget)
        controls_layout.addWidget(self.notes_buttons_area)
        
        controls_layout.addStretch()
        
        main_layout.addWidget(controls_widget)
        
        note_frame = QFrame()
        note_frame.setFrameShape(QFrame.Shape.StyledPanel)
        note_frame.setFrameShadow(QFrame.Shadow.Sunken)
        note_layout = QVBoxLayout(note_frame)
        
        note_layout.addWidget(QLabel("<h4>Редактор заметок</h4>"))
        self.notes_text = QTextEdit()
        self.notes_text.setPlaceholderText("Введите текст новой заметки или выберите существующую...")
        note_layout.addWidget(self.notes_text)
        
        btn_layout = QHBoxLayout()
        new_btn = QPushButton("Новая")
        new_btn.clicked.connect(self.new_note)
        btn_layout.addWidget(new_btn)
        
        save_btn = QPushButton("Сохранить")
        save_btn.clicked.connect(self.save_note)
        btn_layout.addWidget(save_btn)

        copy_btn = QPushButton("Копировать")
        copy_btn.clicked.connect(self.copy_note)
        btn_layout.addWidget(copy_btn)
        
        delete_btn = QPushButton("Удалить")
        delete_btn.setStyleSheet("background-color: #c0392b;")
        delete_btn.clicked.connect(self.delete_note)
        btn_layout.addWidget(delete_btn)
        
        note_layout.addLayout(btn_layout)
        
        self.notes_status = QLabel("Готово")
        self.notes_status.setStyleSheet("color: #27ae60; background-color: transparent; font-weight: bold;")
        note_layout.addWidget(self.notes_status)
        
        main_layout.addWidget(note_frame)
        self.update_note_buttons()

    def update_note_buttons(self):
        while self.notes_buttons_layout.count():
            item = self.notes_buttons_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        for name in sorted(self.notes.keys()):
            btn = QPushButton(name)
            btn.setObjectName("NoteButton")
            btn.clicked.connect(lambda _, n=name: self.open_note(n))
            self.notes_buttons_layout.addWidget(btn)
        
        self.notes_buttons_layout.addStretch()

    def open_note(self, name):
        if name in self.notes:
            self.current_note_name = name
            self.notes_text.setText(self.notes[name])
            self.notes_status.setText(f"Открыта: {name}")
            self.notes_status.setStyleSheet("color: #3498db; background-color: transparent;")
        else:
            self.new_note()

    def new_note(self):
        if self.notes_text.toPlainText().strip() and self.current_note_name is not None:
            reply = QMessageBox.question(
                self, "Несохраненная заметка", 
                f"Вы хотите сохранить текущую заметку '{self.current_note_name or 'Новая'}' перед созданием новой?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save
            )
            if reply == QMessageBox.StandardButton.Save:
                self.save_note()
            elif reply == QMessageBox.StandardButton.Cancel:
                return

        self.notes_text.clear()
        self.current_note_name = None
        self.notes_status.setText("Новая заметка")
        self.notes_status.setStyleSheet("color: #95a5a6; background-color: transparent;")

    def save_note(self):
        content = self.notes_text.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "Пусто", "Нечего сохранять — введите текст заметки.")
            return

        name = self.current_note_name
        if name is None:
            name, ok = QInputDialog.getText(self, "Имя заметки", "Введите имя заметки:")
            if not ok or not name:
                return
            
            if name in self.notes:
                reply = QMessageBox.question(
                    self, "Перезаписать?", f"Заметка '{name}' уже существует. Перезаписать?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
        
        self.notes[name] = content
        self.save_data()
        self.update_note_buttons()
        self.notes_status.setText(f"Сохранено: {name}")
        self.notes_status.setStyleSheet("color: #27ae60; background-color: transparent;")
        self.current_note_name = name

    def copy_note(self):
        text = self.notes_text.toPlainText().strip()
        self.copy_to_clipboard(text)

    def delete_note(self):
        if self.current_note_name is None:
            QMessageBox.warning(self, "Выберите заметку", "Сначала откройте заметку для удаления.")
            return

        reply = QMessageBox.question(
            self, "Удалить", f"Удалить заметку '{self.current_note_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                del self.notes[self.current_note_name]
            except KeyError:
                pass
            self.current_note_name = None
            self.notes_text.clear()
            self.save_data()
            self.update_note_buttons()
            self.notes_status.setText("Удалено")
            self.notes_status.setStyleSheet("color: #e74c3c; background-color: transparent;")


    # ===================== REMINDERS TAB =====================
    def create_reminders_tab(self, notebook):
        frame = QWidget()
        notebook.addTab(frame, 'Напоминания')
        main_layout = QHBoxLayout(frame)
        main_layout.setContentsMargins(15, 15, 15, 15)

        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        input_layout.setContentsMargins(0, 0, 15, 0)
        input_widget.setFixedWidth(350)
        
        input_layout.addWidget(QLabel("Установите дату и время (KGT):"))
        
        self.reminder_datetime_input = QDateTimeEdit(QDateTime.currentDateTime(Q_KG_TZ))
        self.reminder_datetime_input.setCalendarPopup(True)
        self.reminder_datetime_input.setLocale(QLocale(QLocale.Language.Russian, QLocale.Country.Kyrgyzstan))
        self.reminder_datetime_input.setDisplayFormat("yyyy-MM-dd HH:mm")
        input_layout.addWidget(self.reminder_datetime_input)
        
        input_layout.addWidget(QLabel("Текст напоминания:"))
        self.reminder_text_input = QTextEdit()
        self.reminder_text_input.setPlaceholderText("Введите текст напоминания...")
        input_layout.addWidget(self.reminder_text_input)
        
        add_btn = QPushButton("Добавить Напоминание")
        add_btn.clicked.connect(self.add_reminder)
        input_layout.addWidget(add_btn)
        
        delete_btn = QPushButton("Удалить Выбранное Напоминание")
        delete_btn.setStyleSheet("background-color: #c0392b;")
        delete_btn.clicked.connect(self.delete_reminder)
        input_layout.addWidget(delete_btn)
        
        input_layout.addStretch()
        main_layout.addWidget(input_widget)

        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)
        list_layout.addWidget(QLabel("<h4>Активные напоминания</h4>"))
        self.reminders_list = QListWidget()
        list_layout.addWidget(self.reminders_list)
        
        main_layout.addWidget(list_widget)
        
        self.update_reminders_list_ui()

    def update_reminders_list_ui(self):
        self.reminders_list.clear()
        
        sorted_reminders = sorted(
            self.reminders, 
            key=lambda r: datetime.fromisoformat(r['timestamp']).replace(tzinfo=pytz.utc)
        )
        
        for rem in sorted_reminders:
            try:
                dt_utc = datetime.fromisoformat(rem['timestamp']).replace(tzinfo=pytz.utc)
                dt_kgt = dt_utc.astimezone(kg_tz)
                time_str = dt_kgt.strftime('%Y-%m-%d %H:%M:%S')
                display_text = f"[{time_str} KGT] - {rem['text'][:50]}..."
            except:
                display_text = f"[Ошибка времени] - {rem['text'][:50]}..."
                
            self.reminders_list.addItem(display_text)

    def add_reminder(self):
        dt_qt = self.reminder_datetime_input.dateTime()
        dt_kgt = dt_qt.toPython()
        dt_kgt = kg_tz.localize(dt_kgt) 
        dt_utc = dt_kgt.astimezone(pytz.utc) 
        
        reminder_text = self.reminder_text_input.toPlainText().strip()
        
        if not reminder_text:
            QMessageBox.warning(self, "Ошибка", "Введите текст напоминания.")
            return

        if dt_utc < datetime.now(pytz.utc) - timedelta(minutes=1):
            QMessageBox.warning(self, "Ошибка", "Дата и время напоминания не могут быть в прошлом.")
            return
            
        new_reminder = {
            'timestamp': dt_utc.isoformat(),
            'text': reminder_text
        }
        
        self.reminders.append(new_reminder)
        self.save_data()
        self.update_reminders_list_ui()
        self.reminder_text_input.clear()
        QMessageBox.information(self, "Успех", "Напоминание добавлено.")

    def delete_reminder(self):
        current_row = self.reminders_list.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Ошибка", "Выберите напоминание для удаления.")
            return

        reply = QMessageBox.question(
            self, "Удалить", "Вы уверены, что хотите удалить выбранное напоминание?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Находим исходный элемент через сортировку
                reminders_map = {}
                for rem in self.reminders:
                    dt_utc = datetime.fromisoformat(rem['timestamp']).replace(tzinfo=pytz.utc)
                    reminders_map[dt_utc.isoformat()] = rem
                
                sorted_keys = sorted(reminders_map.keys())
                key_to_delete = sorted_keys[current_row]
                
                rem_to_delete = reminders_map[key_to_delete]
                
                self.reminders.remove(rem_to_delete)
                
            except (IndexError, KeyError):
                QMessageBox.critical(self, "Ошибка", "Не удалось найти элемент для удаления.")
                return

            self.save_data()
            self.update_reminders_list_ui()
            QMessageBox.information(self, "Успех", "Напоминание удалено.")

    def check_reminders(self):
        now_utc = datetime.now(pytz.utc)
        triggered_indices = []
        
        for i, rem in enumerate(self.reminders):
            try:
                rem_dt_utc = datetime.fromisoformat(rem['timestamp']).replace(tzinfo=pytz.utc)
                if rem_dt_utc <= now_utc + timedelta(seconds=2):
                    triggered_indices.append(i)
                    rem_dt_kgt = rem_dt_utc.astimezone(kg_tz)
                    message = f"Напоминание в {rem_dt_kgt.strftime('%H:%M:%S')} (KGT)!\n\nТекст:\n{rem['text']}"
                    
                    msg = QMessageBox(self)
                    msg.setWindowTitle("🚨 СРАБОТАЛО НАПОМИНАНИЕ")
                    msg.setText(message)
                    msg.setIcon(QMessageBox.Icon.Information)
                    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
                    msg.button(QMessageBox.StandardButton.Ok).setText("ОК")
                    msg.exec()
                    
                    if self.isMinimized():
                        self.showNormal()
                        self.activateWindow()
            except ValueError:
                triggered_indices.append(i) 

        if triggered_indices:
            triggered_indices.sort(reverse=True)
            for index in triggered_indices:
                del self.reminders[index]
            self.save_data()
            self.update_reminders_list_ui()

    
    # ===================== AUTOTYPE TAB (Press) =====================
    def create_autotype_tab(self, notebook):
        frame = QWidget()
        notebook.addTab(frame, 'Press') 
        main_layout = QHBoxLayout(frame)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setContentsMargins(0, 0, 15, 0)
        controls_widget.setFixedWidth(350)
        
        controls_layout.addWidget(QLabel("<h4>Сохранить новый пароль</h4>"))
        
        controls_layout.addWidget(QLabel("Наименование (для кнопки):"))
        self.autotype_name_edit = QLineEdit()
        self.autotype_name_edit.setPlaceholderText("Например: Dev Prod Password")
        controls_layout.addWidget(self.autotype_name_edit)
        
        controls_layout.addWidget(QLabel("Пароль:"))
        self.autotype_pass_edit = QLineEdit()
        self.autotype_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        controls_layout.addWidget(self.autotype_pass_edit)
        
        save_btn = QPushButton("Сохранить Пароль")
        save_btn.clicked.connect(self.save_autotype_password)
        controls_layout.addWidget(save_btn)
        
        delete_btn = QPushButton("Удалить Пароль (по имени)")
        delete_btn.setStyleSheet("background-color: #c0392b;")
        delete_btn.clicked.connect(self.delete_autotype_password)
        controls_layout.addWidget(delete_btn)
        
        self.autotype_status_label = QLabel("Готово")
        self.autotype_status_label.setStyleSheet("font-weight: bold; color: #27ae60; background-color: transparent;")
        controls_layout.addWidget(self.autotype_status_label)
        
        controls_layout.addStretch()
        main_layout.addWidget(controls_widget)
        
        buttons_group = QFrame()
        buttons_group.setFrameShape(QFrame.Shape.StyledPanel)
        buttons_group.setFrameShadow(QFrame.Shadow.Sunken)
        buttons_layout = QVBoxLayout(buttons_group)
        buttons_layout.setContentsMargins(10, 10, 10, 10)
        
        buttons_layout.addWidget(QLabel("<h4>Ваши сохраненные пароли (Нажмите для ввода)</h4>"))
        
        self.autotype_buttons_area = QScrollArea()
        self.autotype_buttons_area.setWidgetResizable(True)
        self.autotype_buttons_area.setObjectName("NoteButtonsArea") 
        
        self.autotype_buttons_widget = QWidget()
        self.autotype_buttons_layout = QVBoxLayout(self.autotype_buttons_widget)
        self.autotype_buttons_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.autotype_buttons_layout.setSpacing(10)
        
        self.autotype_buttons_area.setWidget(self.autotype_buttons_widget)
        buttons_layout.addWidget(self.autotype_buttons_area)
        
        main_layout.addWidget(buttons_group)
        
        self.update_autotype_buttons()


    def save_autotype_password(self):
        name = self.autotype_name_edit.text().strip()
        password = self.autotype_pass_edit.text()
        
        if not name or not password:
            QMessageBox.warning(self, "Ошибка", "Введите и имя, и пароль.")
            return

        if name in self.autotype_passwords:
            reply = QMessageBox.question(
                self, "Перезаписать?", f"Пароль '{name}' уже существует. Перезаписать?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        self.autotype_passwords[name] = password
        self.save_data()
        self.update_autotype_buttons()
        
        self.autotype_name_edit.clear()
        self.autotype_pass_edit.clear()
        
        self.autotype_status_label.setText(f"Сохранено: {name}")
        QTimer.singleShot(1500, lambda: self.autotype_status_label.setText("Готово"))

    def delete_autotype_password(self):
        name, ok = QInputDialog.getText(self, "Удаление", "Введите ИМЯ пароля для удаления:")
        if not ok or not name or name not in self.autotype_passwords:
            QMessageBox.warning(self, "Ошибка", "Пароль с таким именем не найден.")
            return

        reply = QMessageBox.question(
            self, "Удалить?", f"Вы уверены, что хотите удалить пароль '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            del self.autotype_passwords[name]
            self.save_data()
            self.update_autotype_buttons()
            self.autotype_status_label.setText(f"Удалено: {name}")
            QTimer.singleShot(1500, lambda: self.autotype_status_label.setText("Готово"))


    def update_autotype_buttons(self):
        while self.autotype_buttons_layout.count():
            item = self.autotype_buttons_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        for name, password in sorted(self.autotype_passwords.items()):
            btn = QPushButton(name)
            btn.setObjectName("NoteButton") 
            btn.clicked.connect(lambda _, p=password: self.start_autotype_password(p)) 
            self.autotype_buttons_layout.addWidget(btn)
        
        self.autotype_buttons_layout.addStretch()


    def start_autotype_password(self, password):
        if self.is_typing:
            QMessageBox.warning(self, "Ввод", "Уже идет ввод пароля. Подождите.")
            return

        reply = QMessageBox.question(
            self, "Ввод пароля", 
            "ВНИМАНИЕ! Начнется автоматический ввод пароля. У вас 5 секунд, чтобы переключиться на нужное поле.\n\nНажмите 'Да' для старта.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.No:
            return

        self.is_typing = True
        self.is_hidden_by_autotype = True 
        self.hide() 
        
        if hasattr(self, 'autotype_status_label'):
             self.autotype_status_label.setText("🔥 Ввод через 5 сек...")
        
        # Таймер 5 секунд
        QTimer.singleShot(5000, lambda: threading.Thread(target=self.type_password_routine, args=(password,), daemon=True).start())


    # ИЗМЕНЕНИЕ: Использование pynput.Controller.type() для обхода проблем с раскладкой
    def type_password_routine(self, password):
        time.sleep(0.5)  # Стабилизация фокуса
        
        if not self.is_typing:
            event_type_obj = QEvent.Type(self.AUTOTYPE_FINISHED_EVENT_TYPE)
            QApplication.instance().postEvent(self, QEvent(event_type_obj)) 
            return

        try:
            # Используем pynput.keyboard.Controller.type(text)
            # Это функция высокого уровня, которая отправляет символы,
            # учитывая текущую раскладку ОС. 
            self.keyboard_controller.type(password)
            
        except Exception as e:
            print(f"[AUTOTYPE ERROR] Не удалось ввести пароль через pynput.type(): {e}")
            
            # --- Fallback на pydirectinput (менее надежно) ---
            shift_map = {
                '~': '`', '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
                '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
                '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
                ':': ';', '"': "'", '<': ',', '>': '.', '?': '/'
            }
            
            for char in password:
                if not self.is_typing:
                    break
                
                try:
                    if char.isupper():
                        pydirectinput.keyDown('shift')
                        pydirectinput.press(char.lower())
                        pydirectinput.keyUp('shift')
                    elif char in shift_map:
                        pydirectinput.keyDown('shift')
                        pydirectinput.press(shift_map[char])
                        pydirectinput.keyUp('shift')
                    elif len(char) == 1 and char in string.ascii_lowercase + string.digits + " -=[]\\;',./`":
                        pydirectinput.press(char)
                    else:
                        # Финальный fallback на pynput.press/release для странных символов
                        self.keyboard_controller.press(char)
                        self.keyboard_controller.release(char)
                        
                except Exception as ee:
                    print(f"[AUTOTYPE FALLBACK ERROR] Не удалось ввести '{char}' даже через pydirectinput: {ee}")
                        
                time.sleep(0.03)
            # -----------------------------------------------
        
        # НОВОЕ ИЗМЕНЕНИЕ: Добавляем небольшую паузу после ввода для стабилизации
        time.sleep(0.05)
            
        # Завершаем в главном потоке
        event_type_obj = QEvent.Type(self.AUTOTYPE_FINISHED_EVENT_TYPE)
        QApplication.instance().postEvent(self, QEvent(event_type_obj)) 
        

    def finish_typing_ui(self):
        
        # ИСПРАВЛЕНИЕ: Сначала сбрасываем флаги, чтобы self.showNormal()
        # не вызвал ложное срабатывание eventFilter.
        was_typing = self.is_typing
        self.is_typing = False 
        self.is_hidden_by_autotype = False # Сбрасываем флаг после завершения ввода
        
        if was_typing: 
            self.showNormal() 
            self.raise_()      
            self.activateWindow()
            if hasattr(self, 'autotype_status_label'):
                self.autotype_status_label.setText("✅ Ввод завершён!")
        else:
            if hasattr(self, 'autotype_status_label'):
                 self.autotype_status_label.setText("🚫 Ввод прерван!")
        
        if hasattr(self, 'autotype_status_label'):
             QTimer.singleShot(1500, lambda: self.autotype_status_label.setText("Готово"))
    
    # ===================== LOG PARSER TAB =====================
    def create_log_parser_tab(self, notebook):
        frame = QWidget()
        notebook.addTab(frame, 'Парсер Лога')
        main_layout = QVBoxLayout(frame)
        main_layout.setContentsMargins(15, 15, 15, 15)

        log_input_group = QWidget()
        log_input_layout = QVBoxLayout(log_input_group)
        log_input_layout.setContentsMargins(0, 0, 0, 0)
        log_input_layout.addWidget(QLabel("Вставьте текст лога:"))
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setPlaceholderText("Вставьте сюда многострочный лог...")
        self.log_text_edit.setFont(QFont('Courier New', 10))
        log_input_layout.addWidget(self.log_text_edit)
        main_layout.addWidget(log_input_group)

        regex_group = QFrame()
        regex_group.setFrameShape(QFrame.Shape.NoFrame)
        regex_group.setFrameShadow(QFrame.Shadow.Plain)
        regex_layout = QHBoxLayout(regex_group)
        regex_layout.setContentsMargins(0, 0, 0, 0)
        regex_layout.addWidget(QLabel("Регулярное выражение (RegEx):"))
        self.regex_input = QLineEdit()
        self.regex_input.setPlaceholderText(r"Например: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        self.regex_input.returnPressed.connect(self.parse_log)
        regex_layout.addWidget(self.regex_input)
        parse_btn = QPushButton("Парсить Лог")
        parse_btn.clicked.connect(self.parse_log)
        parse_btn.setFixedWidth(150)
        regex_layout.addWidget(parse_btn)
        main_layout.addWidget(regex_group)

        output_group = QFrame()
        output_group.setFrameShape(QFrame.Shape.NoFrame)
        output_group.setFrameShadow(QFrame.Shadow.Plain)
        output_layout = QVBoxLayout(output_group)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.addWidget(QLabel("Результат парсинга:"))
        self.parse_output = QTextEdit()
        self.parse_output.setReadOnly(True)
        self.parse_output.setFont(QFont('Courier New', 10))
        output_layout.addWidget(self.parse_output)
        
        copy_output_btn = QPushButton("Копировать Результат")
        copy_output_btn.clicked.connect(self.copy_parse_output)
        output_layout.addWidget(copy_output_btn)
        
        main_layout.addWidget(output_group)

    def parse_log(self):
        log_text = self.log_text_edit.toPlainText()
        regex_pattern = self.regex_input.text()
        
        if not log_text or not regex_pattern:
            self.parse_output.setText("Введите и лог, и регулярное выражение.")
            return

        try:
            matches = re.findall(regex_pattern, log_text, re.MULTILINE)
            if matches:
                output = "\n".join(matches)
                self.parse_output.setText(output)
            else:
                self.parse_output.setText("Совпадений не найдено.")
        except re.error as e:
            QMessageBox.critical(self, "Ошибка RegEx", f"Некорректное регулярное выражение: {e}")
            self.parse_output.setText(f"Ошибка в RegEx: {e}")

    def copy_parse_output(self):
        text = self.parse_output.toPlainText()
        self.copy_to_clipboard(text)


    # ===================== GENERATOR TAB =====================
    def create_generator_tab(self, notebook):
        frame = QWidget()
        notebook.addTab(frame, 'Генератор')
        main_layout = QHBoxLayout(frame)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # --- Левая панель: Генератор ---
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        controls_layout.setContentsMargins(0, 0, 15, 0)
        controls_widget.setFixedWidth(350)

        controls_layout.addWidget(QLabel("<h4>Генератор Паролей</h4>"))

        # Группа длины
        length_group = QFrame()
        length_group.setFrameShape(QFrame.Shape.NoFrame)
        length_group.setFrameShadow(QFrame.Shadow.Plain)
        length_layout = QVBoxLayout(length_group)
        
        self.length_label = QLabel("Длина: 12 символов")
        length_layout.addWidget(self.length_label)
        
        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setRange(8, 64)
        self.length_slider.setValue(12)
        self.length_slider.setTickPosition(QSlider.TicksBelow)
        self.length_slider.setTickInterval(8)
        self.length_slider.valueChanged.connect(self.update_length_label)
        length_layout.addWidget(self.length_slider)
        controls_layout.addWidget(length_group)

        # Группа символов
        chars_group = QFrame()
        chars_group.setFrameShape(QFrame.Shape.NoFrame)
        chars_group.setFrameShadow(QFrame.Shadow.Plain)
        chars_layout = QVBoxLayout(chars_group)
        chars_layout.addWidget(QLabel("Набор символов:"))

        checkbox_row = QHBoxLayout()
        self.upper_check = QCheckBox("Заглавные (A-Z)")
        self.upper_check.setChecked(True)
        checkbox_row.addWidget(self.upper_check)
        self.lower_check = QCheckBox("Строчные (a-z)")
        self.lower_check.setChecked(True)
        checkbox_row.addWidget(self.lower_check)
        self.digits_check = QCheckBox("Цифры (0-9)")
        self.digits_check.setChecked(True)
        checkbox_row.addWidget(self.digits_check)
        self.special_check = QCheckBox("Спецсимволы (!@#...)")
        self.special_check.setChecked(True)
        checkbox_row.addWidget(self.special_check)
        checkbox_row.addStretch()
        chars_layout.addLayout(checkbox_row)
        controls_layout.addWidget(chars_group)

        generate_btn = QPushButton("СГЕНЕРИРОВАТЬ ПАРОЛЬ")
        generate_btn.clicked.connect(self.generate_password)
        controls_layout.addWidget(generate_btn)

        self.password_output = QLineEdit()
        self.password_output.setReadOnly(True)
        self.password_output.setFont(QFont('Courier New', 12))
        controls_layout.addWidget(self.password_output)

        copy_password_btn = QPushButton("Копировать пароль")
        copy_password_btn.clicked.connect(self.copy_password)
        controls_layout.addWidget(copy_password_btn)
        
        controls_layout.addStretch(1) # Заполнить пустое место
        
        main_layout.addWidget(controls_widget)

        # --- Правая панель: История ---
        history_widget = QWidget()
        history_layout = QVBoxLayout(history_widget)
        history_layout.addWidget(QLabel("<h4>История скопированных паролей</h4>"))
        self.history_list = QListWidget()
        self.history_list.setFont(QFont('Courier New', 10))
        history_layout.addWidget(self.history_list)

        copy_history_btn = QPushButton("Копировать выбранный из истории")
        copy_history_btn.clicked.connect(self.copy_selected_history)
        history_layout.addWidget(copy_history_btn)

        clear_history_btn = QPushButton("Очистить историю")
        clear_history_btn.clicked.connect(self.clear_password_history)
        history_layout.addWidget(clear_history_btn)
        
        main_layout.addWidget(history_widget)
        
        self.update_history_list_ui()
        self.generate_password() # Генерируем первый пароль при открытии

    def update_length_label(self, value):
        self.length_label.setText(f"Длина: {value} символов")

    def generate_password(self):
        length = self.length_slider.value()
        characters = ''
        if self.upper_check.isChecked():
            characters += string.ascii_uppercase
        if self.lower_check.isChecked():
            characters += string.ascii_lowercase
        if self.digits_check.isChecked():
            characters += string.digits
        if self.special_check.isChecked():
            # Это стандартный набор спецсимволов.
            characters += '!@#$%^&*()_+-=[]{}|;:,.<>/?' 

        if not characters:
            self.password_output.setText("Выберите хотя бы один тип символов!")
            return

        # Используем secrets для криптографически стойкой генерации
        password = ''.join(secrets.choice(characters) for i in range(length))
        self.password_output.setText(password)

    def copy_password(self):
        password = self.password_output.text()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Нет сгенерированного пароля.")
            return

        self.copy_to_clipboard(password)
        # Добавляем в историю
        self.copied_passwords.insert(0, password)
        self.copied_passwords = self.copied_passwords[:100]
        self.save_data()
        self.update_history_list_ui()
        QMessageBox.information(self, "Копирование", "Пароль скопирован в буфер обмена.")

    def copy_selected_history(self):
        item = self.history_list.currentItem()
        if item:
            current_row = self.history_list.currentRow()
            if 0 <= current_row < len(self.copied_passwords):
                 password = self.copied_passwords[current_row]
                 self.copy_to_clipboard(password)
                 QMessageBox.information(self, "Копирование", "Пароль из истории скопирован в буфер обмена.")
            else:
                 QMessageBox.warning(self, "Ошибка", "Выберите элемент из истории.")
        else:
            QMessageBox.warning(self, "Ошибка", "Выберите элемент из истории.")

    def clear_password_history(self):
        reply = QMessageBox.question(
            self, 'Очистка', "Вы уверены, что хотите очистить всю историю паролей?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.copied_passwords = []
            self.save_data()
            self.update_history_list_ui()
            QMessageBox.information(self, "Готово", "История очищена.")

    def update_history_list_ui(self):
        self.history_list.clear()
        for i, password in enumerate(self.copied_passwords):
            display_text = f"Пароль {i+1}: {'*' * len(password)} ({len(password)} симв.)" 
            self.history_list.addItem(display_text)

    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    # ===================== SETTINGS TAB =====================

    def create_settings_tab(self, notebook):
        frame = QWidget()
        notebook.addTab(frame, 'Настройки')
        main_layout = QVBoxLayout(frame)
        main_layout.setContentsMargins(15, 15, 15, 15)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        scroll_area.setWidget(content_widget)
        
        content_layout.addWidget(QLabel("<h1>Общие Настройки</h1>"))

        # --- Секция Смены Пароля (Восстановлено) ---
        password_group = QFrame()
        password_group.setFrameShape(QFrame.Shape.Box)
        password_group.setFrameShadow(QFrame.Shadow.Raised)
        password_layout = QVBoxLayout(password_group)
        password_layout.addWidget(QLabel("<h4>Смена Мастер-Пароля</h4>"))

        change_pass_btn = QPushButton("Сменить Мастер-Пароль")
        change_pass_btn.clicked.connect(self.change_master_password)
        password_layout.addWidget(change_pass_btn)
        
        content_layout.addWidget(password_group)
        # ------------------------------------------

        # Export/Import Group
        export_import_group = QFrame()
        export_import_group.setFrameShape(QFrame.Shape.Box)
        export_import_group.setFrameShadow(QFrame.Shadow.Raised)
        export_import_layout = QVBoxLayout(export_import_group)
        export_import_layout.addWidget(QLabel("<h4>Экспорт/Импорт Данных</h4>"))
        
        export_desc = QLabel("Экспорт: Сохранить все зашифрованные данные в переносимый файл (требует новый пароль).")
        export_desc.setWordWrap(True)
        export_import_layout.addWidget(export_desc)
        export_btn = QPushButton("Экспортировать Данные")
        export_btn.clicked.connect(self.export_data_dialog)
        export_import_layout.addWidget(export_btn)
        
        import_desc = QLabel("Импорт: Заменить текущие данные файлом экспорта (требует пароль от файла).")
        import_desc.setWordWrap(True)
        export_import_layout.addWidget(import_desc)
        import_btn = QPushButton("Импортировать Данные")
        import_btn.clicked.connect(self.import_data_dialog)
        export_import_layout.addWidget(import_btn)

        content_layout.addWidget(export_import_group)
        
        # Idle Timeout Group
        idle_group = QFrame()
        idle_group.setFrameShape(QFrame.Shape.Box)
        idle_group.setFrameShadow(QFrame.Shadow.Raised)
        idle_layout = QVBoxLayout(idle_group)
        idle_layout.addWidget(QLabel("<h4>Автоблокировка</h4>"))
        
        idle_row = QHBoxLayout()
        idle_row.addWidget(QLabel("Время бездействия (минут):"))
        self.idle_duration_spinbox = QSpinBox()
        self.idle_duration_spinbox.setRange(1, 120)
        self.idle_duration_spinbox.setValue(self.idle_duration_ms // 60000)
        idle_row.addWidget(self.idle_duration_spinbox)
        
        save_idle_btn = QPushButton("Сохранить")
        save_idle_btn.clicked.connect(self.save_idle_duration)
        idle_row.addWidget(save_idle_btn)
        idle_row.addStretch(1)
        
        idle_layout.addLayout(idle_row)
        content_layout.addWidget(idle_group)

        # Frequent Keys Group
        keys_group = QFrame()
        keys_group.setFrameShape(QFrame.Shape.Box)
        keys_group.setFrameShadow(QFrame.Shadow.Raised)
        keys_layout = QVBoxLayout(keys_group)
        keys_layout.addWidget(QLabel("<h4>Часто используемые ключи/фразы</h4>"))
        
        keys_layout.addWidget(QLabel("Ключ 1:"))
        self.key1_edit = QLineEdit(self.frequent_keys.get('key1', ''))
        keys_layout.addWidget(self.key1_edit)
        
        keys_layout.addWidget(QLabel("Ключ 2:"))
        self.key2_edit = QLineEdit(self.frequent_keys.get('key2', ''))
        keys_layout.addWidget(self.key2_edit)
        
        save_keys_btn = QPushButton("Сохранить Ключи")
        save_keys_btn.clicked.connect(self.save_frequent_keys)
        keys_layout.addWidget(save_keys_btn)
        
        content_layout.addWidget(keys_group)
        content_layout.addStretch(1)
        main_layout.addWidget(scroll_area)


    # === Change Master Password Logic (Atomic) ===
    def change_master_password(self):
        if self.encryption_key is None:
            QMessageBox.critical(self, "Ошибка", "Приложение не разблокировано.")
            return

        # 1. Запрашиваем текущий пароль
        current_password, ok = QInputDialog.getText(
            self, "Смена Пароля", "Введите текущий мастер-пароль:", QLineEdit.EchoMode.Password
        )
        if not ok or not current_password:
            return

        # Проверка текущего пароля
        salt = self.password_hash[:32]
        stored_hash = self.password_hash[32:]
        current_hash_check = hashlib.pbkdf2_hmac(
            'sha256', current_password.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=32 
        )

        if not hmac.compare_digest(current_hash_check, stored_hash):
            QMessageBox.critical(self, "Ошибка", "Неверный текущий пароль!")
            return

        # 2. Запрашиваем новый пароль
        new_password, ok = QInputDialog.getText(
            self, "Смена Пароля", "Введите НОВЫЙ мастер-пароль:", QLineEdit.EchoMode.Password
        )
        if not ok or not new_password:
            return
            
        confirm_password, ok = QInputDialog.getText(
            self, "Смена Пароля", "Повторите НОВЫЙ мастер-пароль:", QLineEdit.EchoMode.Password
        )
        if not ok or new_password != confirm_password:
            QMessageBox.critical(self, "Ошибка", "Пароли не совпадают!")
            return

        # --- НАЧАЛО АТОМАРНОЙ СМЕНЫ ---
        temp_data_file = DATA_FILE + '.tmp'
        temp_hash_file = HASH_FILE + '.tmp'
        
        try:
            # 3. Генерируем новый хэш и ключ
            new_pwd_hash = hash_password(new_password)
            new_salt = new_pwd_hash[:32]
            new_encryption_key = derive_encryption_key(new_password, new_salt)

            # 4. Собираем и шифруем данные новым ключом (запись в TEMP)
            # В отличие от self.save_data, здесь мы берем все параметры, включая theme и idle_duration_ms
            data_to_save = {
                'notes': getattr(self, 'notes', {}), 
                'reminders': getattr(self, 'reminders', []),
                'copied_passwords': getattr(self, 'copied_passwords', []),
                'frequent_keys': getattr(self, 'frequent_keys', {'key1': '', 'key2': ''}),
                'autotype_passwords': getattr(self, 'autotype_passwords', {}), 
                'theme': self.current_theme,
                'idle_duration_ms': self.idle_duration_ms
            }
            enc_new = encrypt_data(data_to_save, new_encryption_key)
            
            # Запись данных во временный файл
            with open(temp_data_file, 'wb') as f:
                f.write(enc_new)
            os.chmod(temp_data_file, 0o600)

            # 5. Записываем новый хэш во временный файл
            with open(temp_hash_file, 'wb') as f:
                f.write(new_pwd_hash)
            os.chmod(temp_hash_file, 0o600)

            # 6. КОММИТ: Атомарно заменяем оригинальные файлы временными
            shutil.move(temp_data_file, DATA_FILE)
            shutil.move(temp_hash_file, HASH_FILE)

            # 7. Обновляем состояние в памяти, чтобы избежать блокировки
            self.password_hash = new_pwd_hash
            self.encryption_key = new_encryption_key

            QMessageBox.information(self, "Успех", "Мастер-пароль успешно изменен и все данные перешифрованы.")
            # Перезагружаем интерфейс для чистоты
            self.load_main_interface()

        except Exception as e:
            # 8. ROLLBACK: В случае ошибки, удаляем временные файлы и сообщаем пользователю.
            try:
                if os.path.exists(temp_data_file):
                    os.remove(temp_data_file)
                if os.path.exists(temp_hash_file):
                    os.remove(temp_hash_file)
            except Exception:
                pass # Игнорируем ошибки удаления временных файлов
                
            QMessageBox.critical(
                self, 
                "Критическая ошибка", 
                f"Не удалось сменить пароль и перешифровать данные. Ваши старые файлы остались нетронутыми. Попробуйте еще раз. Ошибка: {e}"
            )
            # Блокируем приложение, чтобы избежать работы с потенциально несинхронизированными ключами/файлами.
            self.lock_app() 
    # =========================================


    def export_data_dialog(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Экспорт данных", "backup.dat", "Data Files (*.dat);;All Files (*)"
        )
        if not filename:
            return

        password, ok = QInputDialog.getText(
            self, "Пароль для экспорта", "Введите пароль для защиты файла экспорта:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return

        try:
            # Используем load_data для сбора всех текущих данных
            data_to_export = self.load_data() 
            json_data = json.dumps(data_to_export).encode('utf-8')

            encrypted = encrypt_export_data(json_data, password)

            with open(filename, 'wb') as f:
                f.write(encrypted)
            
            QMessageBox.information(self, "Успех", f"Данные успешно экспортированы в {os.path.basename(filename)}.")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось экспортировать данные: {e}")


    def import_data_dialog(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Импорт данных", "", "Data Files (*.dat);;All Files (*)"
        )
        if not filename:
            return

        reply = QMessageBox.question(
            self, "ВНИМАНИЕ", 
            "Текущие данные будут ПОЛНОСТЬЮ перезаписаны! Вы уверены?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.No:
            return

        password, ok = QInputDialog.getText(
            self, "Пароль для импорта", "Введите пароль от файла импорта:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return

        try:
            with open(filename, "rb") as f:
                data = f.read()

            decrypted_json = decrypt_import_data(data, password)
            imported_data = json.loads(decrypted_json.decode('utf-8')) 

            # Перешифровываем импортированные данные текущим мастер-ключом
            current_enc_data = encrypt_data(imported_data, self.encryption_key) 
            
            # Атомарная замена (на случай сбоя)
            temp_file = DATA_FILE + '.tmp'
            with open(temp_file, "wb") as f:
                f.write(current_enc_data)
            shutil.move(temp_file, DATA_FILE)
            
            self.load_main_interface()
            
            QMessageBox.information(self, "Успех", "Данные успешно импортированы и перезагружены.")

        except InvalidToken:
            QMessageBox.warning(self, "Ошибка", "Неверный пароль или поврежденный файл.")
        except json.JSONDecodeError:
            QMessageBox.critical(self, "Ошибка", "Файл импорта поврежден (некорректный формат).")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Критическая ошибка при импорте: {e}")

    def save_frequent_keys(self):
        self.frequent_keys['key1'] = self.key1_edit.text()
        self.frequent_keys['key2'] = self.key2_edit.text()
        self.save_data()
        QMessageBox.information(self, "Успех", "Ключи сохранены.")

    def save_idle_duration(self):
        minutes = self.idle_duration_spinbox.value()
        new_duration_ms = minutes * 60000
        
        self.idle_duration_ms = new_duration_ms
        self.reset_idle_timer() 
        self.save_data() 
        
        self.idle_label.setText(f"Блокировка: {minutes} мин.")
        QMessageBox.information(self, "Успех", f"Время автоблокировки установлено на {minutes} минут.")


if __name__ == "__main__":
    
    if sys.platform == 'win32':
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Kompanion.AdminTool.v14.1")
        except Exception:
            pass

    app = QApplication(sys.argv)
    
    app_icon = QIcon(resource_path('icon.ico'))
    app.setWindowIcon(app_icon)
    
    QLocale.setDefault(QLocale(QLocale.Language.Russian, QLocale.Country.Kyrgyzstan)) 
    set_russian_localization(app)
    app.setStyle("Fusion") 
    
    app_font = QFont()
    try:
        if QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont).family() == 'MS Shell Dlg 2':
            app_font.setFamily('Verdana')
        else:
            app_font.setFamily('Segoe UI')
    except:
        app_font.setFamily('Arial')

    app_font.setPointSize(11)
    app.setFont(app_font)

    window = AdminTool()
    window.show()
    sys.exit(app.exec())