import sys
import random
import urllib.parse
import base64
import html
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QVBoxLayout,
    QPushButton, QComboBox, QHBoxLayout, QGroupBox
)

# === Các hàm chuyển đổi ===

def random_case(s): return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in s)
def insert_comments(s): return s.replace(" ", "/**/")
def replace_space_tab(s): return s.replace(" ", "\t")
def replace_space_plus(s): return s.replace(" ", "+")
def reverse_payload(s): return s[::-1]
def url_encode(s): return urllib.parse.quote(s)
def double_url_encode(s): return urllib.parse.quote(urllib.parse.quote(s))
def base64_encode(s): return base64.b64encode(s.encode()).decode()
def html_entity_encode(s): return html.escape(s)
def unicode_escape(s): return ''.join(['\\u{:04x}'.format(ord(c)) for c in s])
def md5_hash(s): return hashlib.md5(s.encode()).hexdigest()
def sha1_hash(s): return hashlib.sha1(s.encode()).hexdigest()
def sha256_hash(s): return hashlib.sha256(s.encode()).hexdigest()
def sha512_hash(s): return hashlib.sha512(s.encode()).hexdigest()

class PayloadTool(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Payload Converter")
        self.setGeometry(200, 200, 1000, 500)

        main_layout = QVBoxLayout()
        content_layout = QHBoxLayout()

        # Group input
        input_group = QGroupBox("Nhập payload (mỗi dòng một dòng)")
        input_layout = QVBoxLayout()
        self.input_text = QTextEdit()
        input_layout.addWidget(self.input_text)
        input_group.setLayout(input_layout)

        # Group output
        output_group = QGroupBox("Kết quả chuyển đổi")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)

        # Add to horizontal layout
        content_layout.addWidget(input_group)
        content_layout.addWidget(output_group)

        # Dropdown và nút xử lý
        control_layout = QHBoxLayout()
        self.combo_box = QComboBox()
        self.combo_box.addItems([
            # Bypass techniques
            "Random Case",
            "Insert Comments (/**/)",
            "Replace Space with Tab",
            "Replace Space with +",
            "Reverse Payload",

            # Encoding
            "URL Encode",
            "Double URL Encode",
            "Base64 Encode",
            "HTML Entity Encode",
            "Unicode Escape",

            # Hashing
            "MD5 Hash",
            "SHA1 Hash",
            "SHA256 Hash",
            "SHA512 Hash",
        ])
        self.convert_button = QPushButton("Chuyển đổi")
        self.convert_button.clicked.connect(self.transform_payloads)

        control_layout.addWidget(QLabel("Chọn kỹ thuật:"))
        control_layout.addWidget(self.combo_box)
        control_layout.addWidget(self.convert_button)

        # Kết hợp tất cả layout
        main_layout.addLayout(content_layout)
        main_layout.addLayout(control_layout)
        self.setLayout(main_layout)

    def transform_payloads(self):
        payloads = self.input_text.toPlainText().splitlines()
        method = self.combo_box.currentText()
        result = []

        for line in payloads:
            if not line.strip():
                result.append("")
                continue
            try:
                transformed = self.apply_method(line, method)
                result.append(transformed)
            except Exception as e:
                result.append(f"[ERROR] {e}")

        self.output_text.setPlainText("\n".join(result))

    def apply_method(self, payload, method):
        methods = {
            "Random Case": random_case,
            "Insert Comments (/**/)": insert_comments,
            "Replace Space with Tab": replace_space_tab,
            "Replace Space with +": replace_space_plus,
            "Reverse Payload": reverse_payload,
            "URL Encode": url_encode,
            "Double URL Encode": double_url_encode,
            "Base64 Encode": base64_encode,
            "HTML Entity Encode": html_entity_encode,
            "Unicode Escape": unicode_escape,
            "MD5 Hash": md5_hash,
            "SHA1 Hash": sha1_hash,
            "SHA256 Hash": sha256_hash,
            "SHA512 Hash": sha512_hash,
        }
        return methods[method](payload)

# === Chạy ứng dụng ===

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PayloadTool()
    window.show()
    sys.exit(app.exec_())
