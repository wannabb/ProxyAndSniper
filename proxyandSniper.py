import sys
import threading
import queue
import requests
import asyncio
import urllib3
from urllib.parse import quote

from mitmproxy import http
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QComboBox, 
                             QPushButton, QTextEdit, QSplitter, QTabWidget, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QFileDialog, QSpinBox)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import QThread, pyqtSignal, Qt

# SSL 검증 비활성화 경고 문구 숨기기
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

intercept_queue = queue.Queue()

class ProxyAddon:
    def __init__(self, signal_emitter, intercept_triggered, intercept_enabled_func):
        self.signal_emitter = signal_emitter
        self.intercept_triggered = intercept_triggered
        self.intercept_enabled_func = intercept_enabled_func

    def request(self, flow: http.HTTPFlow):
        if not self.intercept_enabled_func():
            return

        req_headers = f"{flow.request.method} {flow.request.path} {flow.request.http_version}\n"
        for k, v in flow.request.headers.items():
            req_headers += f"{k}: {v}\n"
        req_body = flow.request.text or ""

        event = threading.Event()
        packet_info = {
            "flow": flow,
            "event": event,
            "headers": req_headers,
            "body": req_body
        }
        
        intercept_queue.put(packet_info)
        self.intercept_triggered.emit(req_headers, req_body)
        event.wait()

    def response(self, flow: http.HTTPFlow):
        method = flow.request.method
        url = flow.request.url
        status_code = str(flow.response.status_code)
        
        req_headers = f"{flow.request.method} {flow.request.path} {flow.request.http_version}\n"
        for k, v in flow.request.headers.items():
            req_headers += f"{k}: {v}\n"
        req_body = flow.request.text or ""

        resp_headers = f"{flow.request.http_version} {flow.response.status_code} {flow.response.reason}\n"
        for k, v in flow.response.headers.items():
            resp_headers += f"{k}: {v}\n"
        resp_body = flow.response.text or ""

        self.signal_emitter.emit(method, url, status_code, req_headers, req_body, resp_headers, resp_body)


class ProxyWorker(QThread):
    packet_captured = pyqtSignal(str, str, str, str, str, str, str)
    intercept_triggered = pyqtSignal(str, str)
    proxy_started = pyqtSignal(str)

    def __init__(self, intercept_enabled_func):
        super().__init__()
        self.intercept_enabled_func = intercept_enabled_func

    def run(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        opts = options.Options(listen_host='127.0.0.1', listen_port=8080, ssl_insecure=True)
        
        async def start_proxy():
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            addon = ProxyAddon(self.packet_captured, self.intercept_triggered, self.intercept_enabled_func)
            master.addons.add(addon)
            self.proxy_started.emit("Proxy Server Listening on 127.0.0.1:8080...")
            await master.run()

        loop.run_until_complete(start_proxy())


class RequestWorker(QThread):
    finished = pyqtSignal(str, str, str)
    error = pyqtSignal(str)

    def __init__(self, method, url, headers_raw, body):
        super().__init__()
        self.method = method
        self.url = url
        self.headers_raw = headers_raw
        self.body = body

    def run(self):
        try:
            headers = {}
            for line in self.headers_raw.split('\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()

            if self.method == "GET":
                response = requests.get(self.url, headers=headers, timeout=5, stream=True, verify=False)
            elif self.method == "POST":
                response = requests.post(self.url, headers=headers, data=self.body, timeout=5, stream=True, verify=False)
            
            raw_version = response.raw.version
            version_str = "HTTP/1.1" if raw_version == 11 else "HTTP/1.0" if raw_version == 10 else f"HTTP/{raw_version}"
            resp_headers = f"{version_str} {response.status_code} {response.reason}\n"
            for k, v in response.headers.items():
                resp_headers += f"{k}: {v}\n"
            
            status_text = f"Status: {response.status_code} {response.reason}"
            self.finished.emit(status_text, resp_headers, response.text)
        except Exception as e:
            self.error.emit(str(e))


class IntruderWorker(QThread):
    attack_progress = pyqtSignal(str, str, str, str)
    attack_finished = pyqtSignal()

    def __init__(self, method, url, headers_raw, body_template, payloads):
        super().__init__()
        self.method = method
        self.url = url
        self.headers_raw = headers_raw
        self.body_template = body_template
        self.payloads = payloads
        self.is_running = True  # 중단 
        self.max_workers = 20

    def stop(self):
        self.is_running = False

    def send_single_packet(self, payload, headers):
        if not self.is_running:
            return None
            
        try:
            start_idx = self.body_template.find('§')
            end_idx = self.body_template.find('§', start_idx + 1)
            
            if start_idx != -1 and end_idx != -1:
                actual_body = self.body_template[:start_idx] + payload + self.body_template[end_idx+1:]
            else:
                actual_body = self.body_template

           
            if self.method == "GET":
                response = requests.get(self.url, headers=headers, timeout=5, verify=False)
            elif self.method == "POST":
                response = requests.post(self.url, headers=headers, data=actual_body.encode('utf-8'), timeout=2, verify=False)
            
            length = str(len(response.text))
            status = str(response.status_code)
            return (payload, status, length, response.text)
        except Exception as e:
            return (payload, "Error", "0", str(e))

    def run(self):
        headers = {}
        for line in self.headers_raw.split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 작업 예약
            future_to_payload = {
                executor.submit(self.send_single_packet, payload, headers): payload 
                for payload in self.payloads
            }
            
            # 완료되는 순서대로 실시간 결과 반영
            for future in as_completed(future_to_payload):
                if not self.is_running:
                    break
                
                result = future.result()
                if result:
                    payload, status, length, resp_text = result
                    self.attack_progress.emit(payload, status, length, resp_text)
        
        self.attack_finished.emit()
class SmartTextEdit(QTextEdit):#컨트롤 u로 인코딩 url
    def keyPressEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier and event.key()==Qt.Key.Key_U: 
            cursor = self.textCursor()
            if cursor.hasSelection():
                selected = cursor.selectedText()

                encoded = quote(selected, safe='')
                cursor.insertText(encoded)

            return
        super().keyPressEvent(event)
    
    

class BurpSniperFinal(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Custom Packet Sniper - Final Master")
        self.resize(1300, 850)
        self.captured_packets = []
        self.is_intercept_on = False
        self.wordlist_path = ""
        self.attack_worker = None
        
        self.init_ui()
        self.start_proxy_server()

    def init_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # 1. Intercept Tab
        intercept_tab = QWidget()
        intercept_layout = QVBoxLayout(intercept_tab)
        int_top_layout = QHBoxLayout()
        self.intercept_btn = QPushButton("Intercept is OFF")
        self.intercept_btn.clicked.connect(self.toggle_intercept)
        self.forward_btn = QPushButton("Forward")
        self.forward_btn.setEnabled(False)
        self.forward_btn.clicked.connect(self.forward_packet)
        int_top_layout.addWidget(self.intercept_btn)
        int_top_layout.addWidget(self.forward_btn)
        intercept_layout.addLayout(int_top_layout)
        int_splitter = QSplitter(Qt.Orientation.Vertical)
        self.int_req_headers = QTextEdit()
        self.int_req_body = QTextEdit()
        int_splitter.addWidget(QLabel("<b>Intercepted Headers:</b>"))
        int_splitter.addWidget(self.int_req_headers)
        int_splitter.addWidget(QLabel("<b>Intercepted Body:</b>"))
        int_splitter.addWidget(self.int_req_body)
        int_splitter.setSizes([20, 400, 20, 200])
        intercept_layout.addWidget(int_splitter)
        self.tabs.addTab(intercept_tab, "Intercept")

        # 2. Proxy History Tab
        proxy_tab = QWidget()
        proxy_layout = QVBoxLayout(proxy_tab)
        self.history_table = QTableWidget(0, 4)
        self.history_table.setHorizontalHeaderLabels(["#", "Method", "URL", "Status"])
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.itemSelectionChanged.connect(self.show_selected_packet)
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self.open_context_menu)
        p_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.proxy_req_display = QTextEdit()
        self.proxy_req_display.setReadOnly(True)
        self.proxy_resp_display = QTextEdit()
        self.proxy_resp_display.setReadOnly(True)
        p_splitter.addWidget(self.proxy_req_display)
        p_splitter.addWidget(self.proxy_resp_display)
        m_splitter = QSplitter(Qt.Orientation.Vertical)
        m_splitter.addWidget(self.history_table)
        m_splitter.addWidget(p_splitter)
        m_splitter.setSizes([300, 500])
        proxy_layout.addWidget(m_splitter)
        self.tabs.addTab(proxy_tab, "Proxy History")

        # 3. Repeater Tab
        repeater_tab = QWidget()
        repeater_layout = QVBoxLayout(repeater_tab)
        top_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        self.url_input = QLineEdit("http://httpbin.org/post")
        self.send_btn = QPushButton("Send Packet")
        self.send_btn.clicked.connect(self.send_packet)
        top_layout.addWidget(self.method_combo)
        top_layout.addWidget(self.url_input)
        top_layout.addWidget(self.send_btn)
        repeater_layout.addLayout(top_layout)
        self.status_label = QLabel("Ready")
        repeater_layout.addWidget(self.status_label)
        r_splitter = QSplitter(Qt.Orientation.Horizontal)
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.addWidget(QLabel("<b>Request Headers:</b>"))
        self.req_headers = QTextEdit("User-Agent: CustomSniper/1.0\nAccept: */*\nContent-Type: application/x-www-form-urlencoded")
        req_layout.addWidget(self.req_headers)
        req_layout.addWidget(QLabel("<b>Request Body:</b>"))
        self.req_body = QTextEdit("username=admin&password=1234")
        req_layout.addWidget(self.req_body)
        r_splitter.addWidget(req_widget)
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.addWidget(QLabel("<b>Response Headers:</b>"))
        self.resp_headers = QTextEdit()
        self.resp_headers.setReadOnly(True)
        resp_layout.addWidget(self.resp_headers)
        resp_layout.addWidget(QLabel("<b>Response Body:</b>"))
        self.resp_body = QTextEdit()
        self.resp_body.setReadOnly(True)
        resp_layout.addWidget(self.resp_body)
        r_splitter.addWidget(resp_widget)
        r_splitter.setSizes([550, 550])
        repeater_layout.addWidget(r_splitter)
        self.tabs.addTab(repeater_tab, "Repeater")

        # 4. Intruder Tab
        intruder_tab = QWidget()
        intruder_layout = QVBoxLayout(intruder_tab)
        
        intru_config_layout = QHBoxLayout()
        self.intru_method = QComboBox()
        self.intru_method.addItems(["GET", "POST"])
        self.intru_url = QLineEdit("http://httpbin.org/post")
        intru_config_layout.addWidget(self.intru_method)
        intru_config_layout.addWidget(self.intru_url)
        intruder_layout.addLayout(intru_config_layout)

        intru_main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        left_input_widget = QWidget()
        left_layout = QVBoxLayout(left_input_widget)
        
        header_btn_layout = QHBoxLayout()
        header_btn_layout.addWidget(QLabel("<b>Target Request Body (Drag & Add §):</b>"))
        self.add_pos_btn = QPushButton("Add §")
        self.add_pos_btn.clicked.connect(self.add_sniper_position)
        self.clear_pos_btn = QPushButton("Clear §")
        self.clear_pos_btn.clicked.connect(self.clear_sniper_position)
        header_btn_layout.addWidget(self.add_pos_btn)
        header_btn_layout.addWidget(self.clear_pos_btn)
        left_layout.addLayout(header_btn_layout)
        
        self.intru_headers = QTextEdit("User-Agent: CustomSniper/1.0\nContent-Type: application/x-www-form-urlencoded")
        self.intru_body = SmartTextEdit("username=admin&password=§1234§")
        left_layout.addWidget(QLabel("Headers:"))
        left_layout.addWidget(self.intru_headers)
        left_layout.addWidget(QLabel("Body Template:"))
        left_layout.addWidget(self.intru_body)
        
        intru_main_splitter.addWidget(left_input_widget)

        right_control_widget = QWidget()
        right_layout = QVBoxLayout(right_control_widget)
        
        payload_setting_layout = QHBoxLayout()
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(["Numbers", "Runtime File (txt)"])
        self.payload_type_combo.currentIndexChanged.connect(self.toggle_payload_ui)
        payload_setting_layout.addWidget(QLabel("Payload Type:"))
        payload_setting_layout.addWidget(self.payload_type_combo)
        right_layout.addLayout(payload_setting_layout)

        # 자릿수 패딩 옵션 UI 레이아웃
        padding_layout = QHBoxLayout()
        padding_layout.addWidget(QLabel("Padding (Min Width):"))
        self.padding_spin = QSpinBox()
        self.padding_spin.setRange(0, 10)
        self.padding_spin.setValue(0)  # 0이면 패딩 없음
        padding_layout.addWidget(self.padding_spin)
        right_layout.addLayout(padding_layout)

        self.num_widget = QWidget()
        num_lay = QHBoxLayout(self.num_widget)
        self.num_from = QLineEdit("1")
        self.num_to = QLineEdit("10")
        num_lay.addWidget(QLabel("From:"))
        num_lay.addWidget(self.num_from)
        num_lay.addWidget(QLabel("To:"))
        num_lay.addWidget(self.num_to)
        right_layout.addWidget(self.num_widget)

        self.file_widget = QWidget()
        self.file_widget.setVisible(False)
        file_lay = QHBoxLayout(self.file_widget)
        self.file_path_lbl = QLabel("No file selected")
        self.file_open_btn = QPushButton("Browse...")
        self.file_open_btn.clicked.connect(self.load_wordlist)
        file_lay.addWidget(self.file_path_lbl)
        file_lay.addWidget(self.file_open_btn)
        right_layout.addWidget(self.file_widget)

        # Start / Stop 컨트롤 버튼 레이아웃
        btn_ctrl_layout = QHBoxLayout()
        self.start_attack_btn = QPushButton("Start Attack")
        self.start_attack_btn.setStyleSheet("background-color: green; color: white; font-weight: bold; font-size: 13px;")
        self.start_attack_btn.clicked.connect(self.start_intruder_attack)
        
        self.stop_attack_btn = QPushButton("Stop Attack")
        self.stop_attack_btn.setStyleSheet("background-color: darkred; color: white; font-weight: bold; font-size: 13px;")
        self.stop_attack_btn.setEnabled(False)
        self.stop_attack_btn.clicked.connect(self.stop_intruder_attack)
        
        btn_ctrl_layout.addWidget(self.start_attack_btn)
        btn_ctrl_layout.addWidget(self.stop_attack_btn)
        right_layout.addLayout(btn_ctrl_layout)
        
        self.attack_table = QTableWidget(0, 4)
        self.attack_table.setHorizontalHeaderLabels(["Payload", "Status", "Length", "Response Snippet"])
        self.attack_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.attack_table.setSortingEnabled(True) #정렬 추가해보리기~
        right_layout.addWidget(self.attack_table)

        intru_main_splitter.addWidget(right_control_widget)
        intru_main_splitter.setSizes([600, 600])
        intruder_layout.addWidget(intru_main_splitter)
        
        self.tabs.addTab(intruder_tab, "Intruder (Sniper)")
        self.statusBar().showMessage("Starting Proxy Server...")

    def open_context_menu(self, position):
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows: return
        menu = QMenu()
        send_repeater_action = QAction("Send to Repeater", self)
        send_repeater_action.triggered.connect(self.send_to_repeater)
        send_intruder_action = QAction("Send to Intruder", self)
        send_intruder_action.triggered.connect(self.send_to_intruder)
        menu.addAction(send_repeater_action)
        menu.addAction(send_intruder_action)
        menu.exec(self.history_table.viewport().mapToGlobal(position))

    def send_to_repeater(self):
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows: return
        row_idx = selected_rows[0].row()
        method = self.history_table.item(row_idx, 1).text()
        url = self.history_table.item(row_idx, 2).text()
        packet_data = self.captured_packets[row_idx]
        
        idx = self.method_combo.findText(method)
        if idx >= 0: self.method_combo.setCurrentIndex(idx)
        self.url_input.setText(url)
        self.req_headers.setPlainText(packet_data["raw_request_parsed"]["headers"])
        self.req_body.setPlainText(packet_data["raw_request_parsed"]["body"])
        self.tabs.setCurrentIndex(2)

    def send_to_intruder(self):
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows: return
        row_idx = selected_rows[0].row()
        method = self.history_table.item(row_idx, 1).text()
        url = self.history_table.item(row_idx, 2).text()
        packet_data = self.captured_packets[row_idx]

        idx = self.intru_method.findText(method)
        if idx >= 0: self.intru_method.setCurrentIndex(idx)
        self.intru_url.setText(url)
        self.intru_headers.setPlainText(packet_data["raw_request_parsed"]["headers"])
        self.intru_body.setPlainText(packet_data["raw_request_parsed"]["body"])
        self.tabs.setCurrentIndex(3)

    def add_sniper_position(self):
        cursor = self.intru_body.textCursor()
        if cursor.hasSelection():
            selected_text = cursor.selectedText()
            cursor.insertText(f"§{selected_text}§")

    def clear_sniper_position(self):
        text = self.intru_body.toPlainText()
        cleaned_text = text.replace("§", "")
        self.intru_body.setPlainText(cleaned_text)

    def toggle_payload_ui(self, index):
        if index == 0:
            self.num_widget.setVisible(True)
            self.file_widget.setVisible(False)
        else:
            self.num_widget.setVisible(False)
            self.file_widget.setVisible(True)

    def load_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Wordlist File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.wordlist_path = file_path
            self.file_path_lbl.setText(file_path.split("/")[-1])

    def start_intruder_attack(self):
        self.attack_table.setRowCount(0)
        method = self.intru_method.currentText()
        url = self.intru_url.text().strip()
        headers_raw = self.intru_headers.toPlainText()
        body_template = self.intru_body.toPlainText()
        
        pad_width = self.padding_spin.value()
        payloads = []
        
        if self.payload_type_combo.currentIndex() == 0:
            try:
                start_num = int(self.num_from.text())
                end_num = int(self.num_to.text())
                # 패딩 설정에 맞춰 zfill() 처리 적용
                payloads = []
                for i in range(start_num, end_num+1):
                    payload = str(i)

                    if pad_width > 0:
                        payload = payload.zfill(pad_width)

                    payloads.append(payload)
            except ValueError:
                self.statusBar().showMessage("Error: Please enter valid numbers for the range.")
                return
        else:
            if not self.wordlist_path:
                self.statusBar().showMessage("Error: Please select a wordlist file first.")
                return
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                    payloads = []

                    for line in f:
                        payload = line.strip()

                        if not payload:
                            continue
                        if payload.isdigit():
                            payload = payload.zfill(pad_width)
                        payloads.append(payload)
            except Exception as e:
                self.statusBar().showMessage(f"Error reading file: {str(e)}")
                return

        self.start_attack_btn.setEnabled(False)
        self.stop_attack_btn.setEnabled(True)
        self.start_attack_btn.setText("Attacking...")
        
        self.attack_worker = IntruderWorker(method, url, headers_raw, body_template, payloads)
        self.attack_worker.attack_progress.connect(self.add_attack_result)
        self.attack_worker.attack_finished.connect(self.handle_attack_finished)
        self.attack_worker.start()

    def stop_intruder_attack(self):
        if self.attack_worker and self.attack_worker.isRunning():
            self.attack_worker.stop()
            self.statusBar().showMessage("Stopping attack... Please wait for current thread release.")
            self.stop_attack_btn.setEnabled(False)

    def add_attack_result(self, payload, status, length, response_text):
        self.attack_table.setSortingEnabled(False)

        row_idx = self.attack_table.rowCount()
        self.attack_table.insertRow(row_idx)

        item_payload = QTableWidgetItem(payload)
        if payload.isdigit():
            item_payload.setData(Qt.ItemDataRole.UserRole, int(payload))
        self.attack_table.setItem(row_idx, 0, item_payload)
        
        item_status = QTableWidgetItem()
        if status.isdigit():
            item_status.setData(Qt.ItemDataRole.EditRole, int(status))
        else:
            item_status.setData(Qt.ItemDataRole.EditRole, status)
        self.attack_table.setItem(row_idx, 1, item_status)
        
        item_length = QTableWidgetItem()
        if length.isdigit():
            item_length.setData(Qt.ItemDataRole.EditRole, int(length))
        else:
            item_length.setData(Qt.ItemDataRole.EditRole, 0)
        self.attack_table.setItem(row_idx, 2, item_length)
        
        snippet = response_text.replace("\n", " ").replace("\r", "")[:60]
        item_snippet = QTableWidgetItem(snippet)
        self.attack_table.setItem(row_idx, 3, item_snippet)
        
        self.attack_table.setSortingEnabled(True)

    def handle_attack_finished(self):
        self.start_attack_btn.setEnabled(True)
        self.stop_attack_btn.setEnabled(False)
        self.start_attack_btn.setText("Start Attack")
        self.statusBar().showMessage("Intruder Attack finalized or stopped.")

    def start_proxy_server(self):
        self.proxy_thread = ProxyWorker(self.get_intercept_status)
        self.proxy_thread.packet_captured.connect(self.add_to_history)
        self.proxy_thread.intercept_triggered.connect(self.display_intercepted_packet)
        self.proxy_thread.proxy_started.connect(self.update_status_bar)
        self.proxy_thread.start()

    def update_status_bar(self, msg):
        self.statusBar().showMessage(msg)

    def get_intercept_status(self):
        return self.is_intercept_on

    def toggle_intercept(self):
        self.is_intercept_on = not self.is_intercept_on
        if self.is_intercept_on:
            self.intercept_btn.setText("Intercept is ON")
            self.intercept_btn.setStyleSheet("background-color: red; color: white; font-weight: bold;")
        else:
            self.intercept_btn.setText("Intercept is OFF")
            self.intercept_btn.setStyleSheet("")
            self.forward_btn.setEnabled(False)
            self.clear_intercept_display()

    def display_intercepted_packet(self, headers, body):
        self.int_req_headers.setPlainText(headers)
        self.int_req_body.setPlainText(body)
        self.forward_btn.setEnabled(True)
        self.tabs.setCurrentIndex(0)

    def forward_packet(self):
        if intercept_queue.empty(): return
        packet_info = intercept_queue.get()
        flow = packet_info["flow"]
        
        modified_headers_raw = self.int_req_headers.toPlainText()
        new_headers = {}
        for line in modified_headers_raw.split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                new_headers[k.strip()] = v.strip()
                
        flow.request.headers.clear()
        for k, v in new_headers.items():
            flow.request.headers[k] = v
            
        flow.request.text = self.int_req_body.toPlainText()
        packet_info["event"].set()
        self.forward_btn.setEnabled(False)
        self.clear_intercept_display()

    def clear_intercept_display(self):
        self.int_req_headers.clear()
        self.int_req_body.clear()

    def add_to_history(self, method, url, status, req_h, req_b, resp_h, resp_b):
        row_idx = self.history_table.rowCount()
        self.history_table.insertRow(row_idx)
        self.history_table.setItem(row_idx, 0, QTableWidgetItem(str(row_idx + 1)))
        self.history_table.setItem(row_idx, 1, QTableWidgetItem(method))
        self.history_table.setItem(row_idx, 2, QTableWidgetItem(url))
        self.history_table.setItem(row_idx, 3, QTableWidgetItem(status))
        
        self.captured_packets.append({
            "request": f"{req_h}\n{req_b}",
            "response": f"{resp_h}\n{resp_b}",
            "raw_request_parsed": {
                "headers": req_h.strip(),
                "body": req_b.strip()
            }
        })

    def show_selected_packet(self):
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows: return
        row_idx = selected_rows[0].row()
        if row_idx < len(self.captured_packets):
            packet_data = self.captured_packets[row_idx]
            self.proxy_req_display.setPlainText(packet_data["request"])
            self.proxy_resp_display.setPlainText(packet_data["response"])

    def send_packet(self):
        url = self.url_input.text().strip()
        method = self.method_combo.currentText()
        headers_raw = self.req_headers.toPlainText()
        body = self.req_body.toPlainText()
        self.status_label.setText("Sending...")
        self.send_btn.setEnabled(False)

        self.worker = RequestWorker(method, url, headers_raw, body)
        self.worker.finished.connect(self.handle_repeater_success)
        self.worker.error.connect(self.handle_repeater_error)
        self.worker.start()

    def handle_repeater_success(self, status, headers, body):
        self.status_label.setText(status)
        self.resp_headers.setPlainText(headers)
        self.resp_body.setPlainText(body)
        self.send_btn.setEnabled(True)

    def handle_repeater_error(self, err_msg):
        self.status_label.setText(f"Error: {err_msg}")
        self.send_btn.setEnabled(True)


if __name__ == "__main__":
  
    
    app = QApplication(sys.argv)
    window = BurpSniperFinal()
    window.show()
    sys.exit(app.exec())