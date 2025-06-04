import sys
import re
import json
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QTableWidget, QTableWidgetItem, QProgressBar, QFileDialog, QMessageBox
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import requests
from urllib.parse import urlparse, urlencode
import uuid

class BrowserWindow(QMainWindow):
    """Separate window for website preview"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Website Preview")
        self.setGeometry(150, 15, 800, 600)
        self.browser = QWebEngineView()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        layout.addWidget(self.browser)
        central_widget.setLayout(layout)

    def load_url(self, url):
        self.browser.setUrl(QUrl(url))

class CSRFTestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Interactive CSRF Testing Tool")
        self.setGeometry(100, 100, 800, 800)

        # Tạo widget chính
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)

        # Tạo cửa sổ trình duyệt riêng
        self.browser_window = BrowserWindow()
        self.browser_visible = False

        # Nút bật/tắt cửa sổ trình duyệt
        self.toggle_browser_button = QPushButton("Show Browser")
        self.toggle_browser_button.clicked.connect(self.toggle_browser)
        layout.addWidget(self.toggle_browser_button)

        # URL của trang web
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g., http://example.com)")
        self.url_input.returnPressed.connect(self.load_website)
        layout.addWidget(QLabel("Website URL:"))
        layout.addWidget(self.url_input)

        # Nút tải trang web và xóa
        button_layout = QHBoxLayout()
        self.load_button = QPushButton("Load Website")
        self.load_button.clicked.connect(self.load_website)
        self.clear_button = QPushButton("Clear All")
        self.clear_button.clicked.connect(self.clear_all)
        button_layout.addWidget(self.load_button)
        button_layout.addWidget(self.clear_button)
        layout.addLayout(button_layout)

        # Thanh tiến trình
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # ComboBox để chọn form
        self.form_selector = QComboBox()
        layout.addWidget(QLabel("Select Form:"))
        layout.addWidget(self.form_selector)

        # Bảng hiển thị dữ liệu form
        self.form_table = QTableWidget()
        self.form_table.setColumnCount(2)
        self.form_table.setHorizontalHeaderLabels(["Field Name", "Value"])
        self.form_table.setMinimumHeight(150)
        layout.addWidget(QLabel("Form Data (Editable):"))
        layout.addWidget(self.form_table)

        # URL action của form
        self.form_action_input = QLineEdit()
        self.form_action_input.setPlaceholderText("Form action URL (auto-filled)")
        self.form_action_input.setReadOnly(True)
        layout.addWidget(QLabel("Form Action URL:"))
        layout.addWidget(self.form_action_input)

        # Nút phân tích và kiểm tra
        self.analyze_button = QPushButton("Analyze Forms")
        self.analyze_button.clicked.connect(self.analyze_forms)
        self.test_button = QPushButton("Test CSRF")
        self.test_button.clicked.connect(self.test_csrf)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.test_button)

        # Nút lưu và tải cấu hình
        config_button_layout = QHBoxLayout()
        self.save_config_button = QPushButton("Save Config")
        self.save_config_button.clicked.connect(self.save_config)
        self.load_config_button = QPushButton("Load Config")
        self.load_config_button.clicked.connect(self.load_config)
        config_button_layout.addWidget(self.save_config_button)
        config_button_layout.addWidget(self.load_config_button)
        layout.addLayout(config_button_layout)

        # Kết quả
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.result_output)

        # Raw request/response output
        self.raw_output = QTextEdit()
        self.raw_output.setReadOnly(True)
        self.raw_output.setMinimumHeight(150)
        layout.addWidget(QLabel("Raw Request/Response:"))
        layout.addWidget(self.raw_output)

        # Biến để lưu danh sách form
        self.forms = []

    def toggle_browser(self):
        """Bật/tắt cửa sổ trình duyệt"""
        if self.browser_visible:
            self.browser_window.hide()
            self.toggle_browser_button.setText("Show Browser")
            self.browser_visible = False
        else:
            self.browser_window.show()
            self.toggle_browser_button.setText("Hide Browser")
            self.browser_visible = True

    def validate_url(self, url):
        """Kiểm tra URL hợp lệ"""
        regex = re.compile(
            r'^https?://'  # http:// hoặc https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # cổng
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    def load_website(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.critical(self, "Error", "Please enter a website URL.")
            return
        if not url.startswith("http"):
            url = "http://" + url
        if not self.validate_url(url):
            QMessageBox.critical(self, "Error", "Invalid URL format.")
            return
        self.browser_window.load_url(url)
        self.result_output.setText(f"Loaded website: {url}")
        self.form_selector.clear()
        self.form_action_input.clear()
        self.form_table.setRowCount(0)
        self.forms = []
        self.raw_output.clear()

    def clear_all(self):
        """Xóa tất cả dữ liệu nhập và kết quả"""
        self.url_input.clear()
        self.form_selector.clear()
        self.form_action_input.clear()
        self.form_table.setRowCount(0)
        self.result_output.clear()
        self.raw_output.clear()
        self.browser_window.load_url("about:blank")
        self.forms = []

    def analyze_forms(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.critical(self, "Error", "Please load a website first.")
            return
        if not url.startswith("http"):
            url = "http://" + url
        if not self.validate_url(url):
            QMessageBox.critical(self, "Error", "Invalid URL format.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_button.setEnabled(False)

        # Sử dụng Selenium để phân tích form
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        try:
            driver = webdriver.Chrome(options=chrome_options)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to initialize browser: {str(e)}")
            self.progress_bar.setVisible(False)
            self.analyze_button.setEnabled(True)
            return

        try:
            self.progress_bar.setValue(20)
            driver.get(url)
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            self.progress_bar.setValue(50)

            # Tìm tất cả form trên trang
            forms = driver.find_elements(By.TAG_NAME, "form")
            self.forms = []
            self.form_selector.clear()
            self.form_table.setRowCount(0)

            for i, form in enumerate(forms):
                try:
                    action = form.get_attribute("action") or url
                    inputs = form.find_elements(By.TAG_NAME, "input")
                    selects = form.find_elements(By.TAG_NAME, "select")
                    textareas = form.find_elements(By.TAG_NAME, "textarea")
                    input_data = []

                    # Xử lý input
                    for input_elem in inputs:
                        name = input_elem.get_attribute("name")
                        value = input_elem.get_attribute("value") or "test"
                        input_type = input_elem.get_attribute("type").lower()
                        if name and input_type not in ["submit", "button", "hidden"] and "csrf" not in name.lower():
                            input_data.append({"name": name, "value": value})

                    # Xử lý select
                    for select_elem in selects:
                        name = select_elem.get_attribute("name")
                        if name:
                            options = select_elem.find_elements(By.TAG_NAME, "option")
                            value = options[0].get_attribute("value") if options else "test"
                            input_data.append({"name": name, "value": value})

                    # Xử lý textarea
                    for textarea_elem in textareas:
                        name = textarea_elem.get_attribute("name")
                        if name:
                            input_data.append({"name": name, "value": "test"})

                    form_info = {
                        "action": action,
                        "data": input_data
                    }
                    self.forms.append(form_info)
                    self.form_selector.addItem(f"Form {i + 1} (Action: {action})")
                except:
                    continue

            self.progress_bar.setValue(80)

            if not self.forms:
                self.result_output.setText("No forms found on the page.")
            else:
                self.result_output.setText(f"Found {len(self.forms)} form(s). Select a form to test.")
                self.form_selector.currentIndexChanged.connect(self.update_form_info)

            self.progress_bar.setValue(100)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error analyzing forms: {str(e)}")
        finally:
            driver.quit()
            self.progress_bar.setVisible(False)
            self.analyze_button.setEnabled(True)

    def update_form_info(self, index):
        if index >= 0 and index < len(self.forms):
            form = self.forms[index]
            self.form_action_input.setText(form["action"])
            self.form_table.setRowCount(len(form["data"]))
            for row, field in enumerate(form["data"]):
                self.form_table.setItem(row, 0, QTableWidgetItem(field["name"]))
                self.form_table.setItem(row, 1, QTableWidgetItem(field["value"]))
            self.form_table.resizeColumnsToContents()

    def test_csrf(self):
        form_action = self.form_action_input.text()
        if not form_action:
            QMessageBox.critical(self, "Error", "Please select a form.")
            return

        # Thu thập dữ liệu từ bảng
        form_data = {}
        for row in range(self.form_table.rowCount()):
            name_item = self.form_table.item(row, 0)
            value_item = self.form_table.item(row, 1)
            if name_item and value_item:
                form_data[name_item.text()] = value_item.text()

        if not form_data:
            QMessageBox.critical(self, "Error", "No valid form data provided.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.test_button.setEnabled(False)

        # Gửi yêu cầu POST mà không có CSRF token
        try:
            self.progress_bar.setValue(50)
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            # Chuẩn bị dữ liệu raw để hiển thị
            raw_request = f"POST {form_action} HTTP/1.1\n"
            raw_request += f"Host: {urlparse(form_action).netloc}\n"
            for header, value in headers.items():
                raw_request += f"{header}: {value}\n"
            raw_request += "\n" + urlencode(form_data)

            # Gửi yêu cầu
            response = requests.post(form_action, data=form_data, headers=headers, timeout=10)
            self.progress_bar.setValue(80)

            # Chuẩn bị dữ liệu raw response
            raw_response = f"HTTP/1.1 {response.status_code} {response.reason}\n"
            for header, value in response.headers.items():
                raw_response += f"{header}: {value}\n"
            raw_response += "\n" + response.text[:1000] + ("..." if len(response.text) > 1000 else "")

            # Hiển thị raw request và response
            self.raw_output.setText("=== Raw Request ===\n" + raw_request + "\n\n=== Raw Response ===\n" + raw_response)

            # Kiểm tra phản hồi
            result_text = f"Response Status: {response.status_code} - {response.reason}\n"
            result_text += f"Response Body (first 100 chars): {response.text[:100]}...\n\n"

            if response.status_code in [403, 401] or "csrf" in response.text.lower():
                result_text += "CSRF protection detected: Request was blocked."
            elif response.status_code in [200, 201]:
                result_text += "Potential CSRF vulnerability: Request was not blocked."
            else:
                result_text += "Unexpected response: Further investigation needed."

            self.result_output.setText(result_text)
            self.progress_bar.setValue(100)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during CSRF test: {str(e)}")
            self.raw_output.setText(f"Error: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
            self.test_button.setEnabled(True)

    def save_config(self):
        """Lưu cấu hình vào file JSON"""
        config = {
            "url": self.url_input.text(),
            "forms": self.forms
        }
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Config", "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(config, f, indent=4)
                QMessageBox.information(self, "Success", "Configuration saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save config: {str(e)}")

    def load_config(self):
        """Tải cấu hình từ file JSON"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Config", "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, "r") as f:
                    config = json.load(f)
                self.url_input.setText(config.get("url", ""))
                self.forms = config.get("forms", [])
                self.form_selector.clear()
                for i, form in enumerate(self.forms):
                    self.form_selector.addItem(f"Form {i + 1} (Action: {form['action']})")
                self.result_output.setText(f"Loaded configuration with {len(self.forms)} form(s).")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load config: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CSRFTestWindow()
    window.show()
    sys.exit(app.exec_())
