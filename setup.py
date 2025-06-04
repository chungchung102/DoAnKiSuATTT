import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QPushButton, QGroupBox, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QProcess


class ToolButton(QPushButton):
    def __init__(self, icon, name, desc, script, parent=None):
        super().__init__(f"{icon}  {name}", parent)
        self.script = script
        self.setStyleSheet("""
            QPushButton {
                background-color: #e0f7fa;
                border: 2px solid #00acc1;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #b2ebf2;
            }
        """)
        self.setCursor(Qt.PointingHandCursor)
        self.desc_label = QLabel(desc)
        self.desc_label.setWordWrap(True)
        self.desc_label.setStyleSheet("color: #555; padding-left: 5px; padding-bottom: 8px;")


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KHÓA LUẬN KỸ SƯ - Dashboard")
        self.setGeometry(100, 100, 500, 500)
        self.setStyleSheet("background-color: #f5f5f5;")
        self.processes = []
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()

        # ===== Header =====
        header = QLabel("KHÓA LUẬN KỸ SƯ KHÓA 12 - NĂM HỌ 2024-2025")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)

        topic = QLabel("Đề tài: Nghiên cứu và phát triển công cụ kiểm thử bảo mật tự động cho ứng dụng web.")
        topic.setFont(QFont("Arial", 12))
        topic.setAlignment(Qt.AlignCenter)
        topic.setStyleSheet("padding-bottom: 15px;")

        main_layout.addWidget(header)
        main_layout.addWidget(topic)

        # ===== Body =====
        content_layout = QHBoxLayout()

        # ===== Left Column: Tool Box =====
        tool_box = QGroupBox("🧰 Công cụ kiểm thử")
        tool_box.setStyleSheet("QGroupBox { font-weight: bold; font-size: 14px; }")
        tool_layout = QVBoxLayout()

        tools = [
            {
                "name": "Dark Proxy Tester",
                "script": "webrawedit.py",
                "desc": "🖥️ Intercept and edit HTTP/HTTPS requests/responses",
                "icon": "📝"
            },
            {
                "name": "Crawler Fuzzing URL",
                "script": "fuzzcrawsniff.py",
                "desc": "🕷️ Crawl websites and fuzz URLs for vulnerabilities",
                "icon": "🌐"
            },
            {
                "name": "CSRF Tester",
                "script": "CSRF.py",
                "desc": "🔍 Test websites for CSRF vulnerabilities",
                "icon": "🛑"
            },
            {
                "name": "Packet Sniffer",
                "script": "sniff.py",
                "desc": "📡 Capture and analyze network packets",
                "icon": "📶"
   	    },
            {
                "name": "Payload Convert",
                "script": "payload.py",
                "desc": "🔄 Fast and efficient payload converter",
                "icon": "⚙️"
    }
        ]

        for tool in tools:
            button = ToolButton(tool['icon'], tool['name'], tool['desc'], tool['script'])
            button.clicked.connect(lambda _, s=tool['script']: self.run_script(s))

            row = QVBoxLayout()
            row.addWidget(button)
            row.addWidget(button.desc_label)
            row.setSpacing(2)
            tool_layout.addLayout(row)

        tool_layout.addStretch()
        tool_box.setLayout(tool_layout)
        content_layout.addWidget(tool_box, 2)

        # ===== Right Column: Info Box =====
        info_box = QGroupBox("📄 Thông tin hướng dẫn và nhóm thực hiện")
        info_box.setStyleSheet("QGroupBox { font-size: 16px; font-weight: bold; }")
        info_layout = QVBoxLayout()

        label_font = QFont("Arial", 11)

        # Giảng viên
        info_layout.addWidget(self.create_bold_label("👩‍🏫 Giảng viên hướng dẫn:", label_font))
        info_layout.addWidget(self.create_normal_label("• Họ tên: Nguyễn Thị Hồng Thảo", label_font))
        info_layout.addWidget(self.create_normal_label("• Email: thaonth@huit.edu.vn", label_font))
        info_layout.addWidget(self.create_normal_label("• SĐT: 0977979885", label_font))

        info_layout.addSpacing(10)

        # Sinh viên
        info_layout.addWidget(self.create_bold_label("👨‍🎓 Nhóm sinh viên thực hiện:", label_font))
        info_layout.addWidget(self.create_normal_label("• Nguyễn Trần Thế Vy - MSSV: 2033216610 - Lớp: 12DHBM09", label_font))
        info_layout.addWidget(self.create_normal_label("• Lê Dũng - MSSV: 2033216372 - Lớp: 12DHBM05", label_font))
        info_layout.addWidget(self.create_normal_label("• Hà Đức Chung - MSSV: 2033210506 - Lớp: 12DHBM06", label_font))

        info_layout.addStretch()
        info_box.setLayout(info_layout)
        content_layout.addWidget(info_box, 9)

        # ===== Layouts Done =====
        main_layout.addLayout(content_layout)
        self.setLayout(main_layout)

    def create_bold_label(self, text, font):
        label = QLabel(text)
        bold_font = QFont(font)
        bold_font.setBold(True)
        label.setFont(bold_font)
        return label

    def create_normal_label(self, text, font):
        label = QLabel(text)
        label.setFont(font)
        return label

    def run_script(self, script_name):
        if not os.path.exists(script_name):
            QMessageBox.critical(self, "Lỗi", f"Không tìm thấy script: {script_name}")
            return
        try:
            process = QProcess(self)
            self.processes.append(process)
            process.start("python", [script_name])
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Không thể chạy {script_name}:\n{str(e)}")

    def closeEvent(self, event):
        for process in self.processes:
            process.terminate()
            process.waitForFinished(1000)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    sys.exit(app.exec_())
