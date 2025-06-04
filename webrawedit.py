import sys
import asyncio
import copy
import time
import itertools
import statistics
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QListWidget, QHBoxLayout, QLabel, QDialog, QDialogButtonBox,
    QLineEdit, QPlainTextEdit, QMessageBox, QTabWidget, QListWidgetItem,
    QComboBox, QTableWidget, QTableWidgetItem, QFormLayout, QMenu, QAction,
    QFileDialog
)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import Qt
from mitmproxy import http, options, ctx
from mitmproxy.tools.dump import DumpMaster
import qasync

class ProxyConfigDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cấu hình Proxy")
        self.resize(400, 200)

        layout = QFormLayout(self)
        
        self.ip_input = QLineEdit("127.0.0.1")
        self.port_input = QLineEdit("8080")
        
        layout.addRow("IP:", self.ip_input)
        layout.addRow("Port:", self.port_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(buttons)

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def get_values(self):
        return self.ip_input.text(), self.port_input.text()

class IntruderDialog(QDialog):
    def __init__(self, original_request_text):
        super().__init__()
        self.setWindowTitle("Tấn công")
        self.resize(1366, 768)

        self.request_edit = QPlainTextEdit(self)
        self.request_edit.setPlainText(original_request_text)

        self.payload_input = QPlainTextEdit(self)
        self.payload_input.setPlaceholderText("Input payload")

        self.marker_input = QLineEdit(self)
        self.marker_input.setText("§")

        self.mode_combo = QComboBox(self)
        self.mode_combo.addItems(["Tấn công đơn điểm", "Đồng nhất toàn bộ", "Tấn công song song", "Tấn công tổ hợp đa điểm"])

        # Add file selection button
        self.load_file_button = QPushButton("📂 Load File")
        self.load_file_button.clicked.connect(self.load_payload_from_file)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("🔧 Request :"))
        layout.addWidget(self.request_edit)
        layout.addWidget(QLabel("🎯 Payload:"))
        payload_layout = QHBoxLayout()
        payload_layout.addWidget(self.payload_input)
        payload_layout.addWidget(self.load_file_button)
        layout.addLayout(payload_layout)
        layout.addWidget(QLabel("📌 Payload icon §):"))
        layout.addWidget(self.marker_input)
        layout.addWidget(QLabel("⚙️ Mode attack:"))
        layout.addWidget(self.mode_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(buttons)

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def load_payload_from_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Payload File", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as file:
                    payloads = [line.strip() for line in file if line.strip()]
                    self.payload_input.setPlainText('\n'.join(payloads))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")

    def get_values(self):
        raw_payloads = self.payload_input.toPlainText().splitlines()
        payloads = [line.strip() for line in raw_payloads if line.strip()]
        return (
            self.request_edit.toPlainText(),
            payloads,
            self.marker_input.text(),
            self.mode_combo.currentText()
        )

class InterceptAddon:
    def __init__(self, gui):
        self.gui = gui
        self.counter = 0
        self.history = []

    def request(self, flow: http.HTTPFlow):
        self.counter += 1
        flow.metadata["id"] = self.counter
        flow.metadata["time"] = time.strftime("%H:%M:%S")
        self.history.append(flow)
        self.gui.add_request_item(flow)

    def response(self, flow: http.HTTPFlow):
        self.gui.update_response(flow)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("<3  Pentest <3")
        self.resize(1200, 800)

        self.list = QListWidget()
        self.req_view = QTextEdit(); self.req_view.setReadOnly(True)
        self.raw_view = QTextEdit(); self.raw_view.setReadOnly(True)
        self.web_view = QWebEngineView()

        self.stats_table = QTableWidget(0, 6)
        self.stats_table.setHorizontalHeaderLabels(["Payload", "Status", "Bytes", "Words", "Lines", "Time (ms)"])
        self.stats_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.stats_table.customContextMenuRequested.connect(self.show_context_menu)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.raw_view, "🧾 Raw")
        self.tabs.addTab(self.web_view, "🌐 Render")
        self.tabs.addTab(self.stats_table, "📊 Statistics")

        self.search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in requests/responses...")
        self.search_button = QPushButton("🔍 Search")
        self.search_results = QListWidget()
        self.search_layout.addWidget(self.search_input)
        self.search_layout.addWidget(self.search_button)

        self.btn_repeat = QPushButton("🔁 Repeat")
        self.btn_intrude = QPushButton("💥 Attack")

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("📄 Request"))
        layout.addWidget(self.list)
        layout.addLayout(self.search_layout)
        layout.addWidget(self.search_results)

        detail_layout = QHBoxLayout()
        detail_layout.addWidget(self.req_view, 1)
        detail_layout.addWidget(self.tabs, 2)
        layout.addLayout(detail_layout)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_repeat)
        btn_layout.addWidget(self.btn_intrude)
        layout.addLayout(btn_layout)

        self.list.itemClicked.connect(self.on_item_selected)
        self.btn_repeat.clicked.connect(self.on_repeat_clicked)
        self.btn_intrude.clicked.connect(self.on_intrude_clicked)
        self.search_button.clicked.connect(self.on_search_clicked)
        self.search_results.itemClicked.connect(self.on_search_result_selected)

        self.flow_map = {}
        self.response_stats = []
        self.selected_id = None
        self.addon = InterceptAddon(self)

    def show_context_menu(self, position):
        row = self.stats_table.rowAt(position.y())
        if row < 0:
            return

        menu = QMenu(self)
        render_action = QAction("Render", self)
        render_action.triggered.connect(lambda: self.render_stats_row(row))
        menu.addAction(render_action)
        menu.exec_(self.stats_table.viewport().mapToGlobal(position))

    def render_stats_row(self, row):
        if row >= len(self.response_stats):
            return

        stat = self.response_stats[row]
        for flow_id, flow in self.flow_map.items():
            try:
                payload = flow.request.content.decode(errors='ignore')[:30]
                response_time = int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
                if payload == stat["payload"] and response_time == stat["time"]:
                    self._render_html(flow)
                    self.tabs.setCurrentIndex(1)  # Switch to Render tab
                    break
            except Exception:
                continue

    def add_request_item(self, flow):
        text = f"[{flow.metadata['id']}] {flow.metadata['time']} {flow.request.method} {flow.request.pretty_url}"
        item = QListWidgetItem(text)
        self.flow_map[flow.metadata['id']] = flow
        self.list.addItem(item)

    def update_response(self, flow):
        if flow.metadata.get("id") == self.selected_id:
            self.raw_view.setText(self._format_response(flow))
            self._render_html(flow)
        self._log_statistics(flow)

    def _log_statistics(self, flow):
        try:
            headers = "\n".join(f"{k}: {v}" for k, v in flow.response.headers.items())
            body = flow.response.content.decode("utf-8", errors="replace")
            full_response = f"{headers}\n\n{body}"

            words = len(full_response.split())
            lines = full_response.count("\n") + 1
            stat = {
                "payload": flow.request.content.decode(errors='ignore')[:30],
                "status": flow.response.status_code,
                "bytes": len(full_response.encode()),
                "words": words,
                "lines": lines,
                "time": int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
            }
            self.response_stats.append(stat)
            row = self.stats_table.rowCount()
            self.stats_table.insertRow(row)
            for col, key in enumerate(["payload", "status", "bytes", "words", "lines", "time"]):
                self.stats_table.setItem(row, col, QTableWidgetItem(str(stat[key])))
        except Exception as e:
            print(f"❌ Error in statistics: {e}")

    def on_item_selected(self, item):
        try:
            flow_id = int(item.text().split("]")[0][1:])
            flow = self.flow_map.get(flow_id)
            self.selected_id = flow_id
            if flow:
                self.req_view.setText(self._format_request(flow))
                self.raw_view.setText(self._format_response(flow))
                self._render_html(flow)
        except Exception:
            self.req_view.setText("❌ Error loading request.")

    def on_search_clicked(self):
        keyword = self.search_input.text().strip()
        if not keyword:
            QMessageBox.warning(self, "Warning", "Please enter a search keyword!")
            return

        self.search_results.clear()
        for flow_id, flow in self.flow_map.items():
            request_text = self._format_request(flow)
            response_text = self._format_response(flow)
            
            if keyword.lower() in request_text.lower() or keyword.lower() in response_text.lower():
                text = f"[{flow.metadata['id']}] {flow.metadata['time']} {flow.request.method} {flow.request.pretty_url}"
                item = QListWidgetItem(text)
                self.search_results.addItem(item)

        if self.search_results.count() == 0:
            self.search_results.addItem("No results found")

    def on_search_result_selected(self, item):
        try:
            if item.text() == "No results found":
                return
            flow_id = int(item.text().split("]")[0][1:])
            self.list.setCurrentRow(list(self.flow_map.keys()).index(flow_id))
            self.on_item_selected(item)
        except Exception as e:
            print(f"❌ Error selecting search result: {e}")

    def on_repeat_clicked(self):
        if not self.selected_id:
            return
        flow = self.flow_map.get(self.selected_id)
        if flow:
            text = self._format_request(flow)
            self._send_single(flow, text)

    def on_intrude_clicked(self):
        if not self.selected_id: return
        flow = self.flow_map.get(self.selected_id)
        dialog = IntruderDialog(self._format_request(flow))
        if dialog.exec_():
            text, payloads, marker, mode = dialog.get_values()
            count = text.count(marker)
            if not payloads: payloads = [""]
            self._send_intruded_requests(flow, text, payloads, marker, mode, count)

    def _send_single(self, flow, modified_text):
        new_flow = copy.deepcopy(flow)
        try:
            lines = modified_text.splitlines()
            method, path, _ = lines[0].split()
            headers, body, in_headers = {}, "", True
            for line in lines[1:]:
                if line.strip() == "": in_headers = False; continue
                if in_headers and ":" in line:
                    k, v = line.split(":", 1); headers[k.strip()] = v.strip()
                elif not in_headers:
                    body += line + "\n"
            new_flow.request.method = method
            new_flow.request.path = path
            new_flow.request.headers.clear()
            for k, v in headers.items():
                new_flow.request.headers[k] = v
            new_flow.request.set_text(body.strip())
            new_flow.response = None
            ctx.master.commands.call("replay.client", [new_flow])
        except Exception as e:
            print(f"❌ Error sending: {e}")

    def _send_intruded_requests(self, flow, raw_text, payloads, marker, mode, count):
        try:
            if mode == "Tấn công đơn điểm":
                for payload in payloads:
                    text = raw_text.replace(marker, payload, 1)
                    self._send_single(flow, text)
            elif mode == "Đồng nhất toàn bộ":
                for payload in payloads:
                    self._send_single(flow, raw_text.replace(marker, payload))
            elif mode == "Tấn công song song" and count > 0:
                for group in zip(*[iter(payloads)] * count):
                    text = raw_text
                    for val in group:
                        text = text.replace(marker, val, 1)
                    self._send_single(flow, text)
            elif mode == "Tấn công tổ hợp đa điểm" and count > 0:
                for combo in itertools.product(payloads, repeat=count):
                    text = raw_text
                    for val in combo:
                        text = text.replace(marker, val, 1)
                    self._send_single(flow, text)
        except Exception as e:
            print(f"❌ Error in mode {mode}: {e}")

    def _format_request(self, flow):
        try:
            req = flow.request
            headers = "\n".join([f"{k}: {v}" for k, v in req.headers.items()])
            return f"{req.method} {req.path} HTTP/1.1\n{headers}\n\n{req.get_text()}"
        except Exception as e:
            return f"(Error formatting request)\n{e}"

    def _format_response(self, flow):
        try:
            res = flow.response
            if not res:
                return "(Chưa có response)"
            headers = "\n".join([f"{k}: {v}" for k, v in res.headers.items()])
            body = res.content.decode("utf-8", errors="replace")
            return f"HTTP/{res.http_version} {res.status_code} {res.reason}\n{headers}\n\n{body}"
        except Exception as e:
            return f"(Error formatting response)\n{e}"

    def _render_html(self, flow):
        try:
            if not flow.response:
                self.web_view.setHtml("<h3>(No response available)</h3>")
                return

            content_type = flow.response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                self.web_view.setHtml("<h4>Content is not HTML</h4>")
                return

            try:
                content = flow.response.content.decode("utf-8", errors="replace")
                self.web_view.setHtml(content)
            except UnicodeDecodeError as e:
                self.web_view.setHtml(f"<p>Error decoding content: {str(e)}</p>")
            except Exception as e:
                self.web_view.setHtml(f"<p>Error rendering content: {str(e)}</p>")

        except Exception as e:
            self.web_view.setHtml(f"<p>General error in rendering: {str(e)}</p>")

class ProxyRunner(DumpMaster):
    def __init__(self, addon, listen_host, listen_port):
        opts = options.Options(listen_host=listen_host, listen_port=int(listen_port))
        super().__init__(opts, with_termlog=False, with_dumper=False)
        self.addons.add(addon)

async def main():
    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    config_dialog = ProxyConfigDialog()
    if not config_dialog.exec_():
        sys.exit(0)

    listen_host, listen_port = config_dialog.get_values()
    
    try:
        port_num = int(listen_port)
        if not (0 <= port_num <= 65535):
            QMessageBox.critical(None, "Lỗi", "Port phải nằm trong khoảng 0-65535!")
            sys.exit(1)
    except ValueError:
        QMessageBox.critical(None, "Lỗi", "Port phải là một số nguyên!")
        sys.exit(1)

    if not listen_host:
        QMessageBox.critical(None, "Lỗi", "IP không được để trống!")
        sys.exit(1)

    window = MainWindow()
    window.show()

    proxy = ProxyRunner(window.addon, listen_host, listen_port)
    await proxy.run()

if __name__ == "__main__":
    qasync.run(main())
