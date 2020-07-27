import os
import hashlib
import shutil
from datetime import datetime
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from PySide2.QtGui import *
import sys
import time

class backgroundThread(QThread):
    thread_progress = Signal(int)
    thread_progress_status = Signal(str)

    def __init__(self, in_file_path, out_file_path, hash_file_path, make_hash, do_copy):
        super().__init__()

        self.in_file_path = in_file_path
        self.out_file_path = out_file_path
        self.hash_file_path = hash_file_path
        self.make_hash = make_hash
        self.do_copy = do_copy

    def __del__(self):
        self.wait()

    def run(self):
        if self.make_hash:
            generate_hash(self, self.in_file_path, self.out_file_path)
        else:
            parse_filetree(self, self.in_file_path, self.out_file_path, self.hash_file_path, self.do_copy)


class Window(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Hash Checker")
        self.setFixedWidth(350)
        self.setFixedHeight(200)

        self.create_layouts()
        self.create_ui()

        self.show()

    def create_layouts(self):
        main_layout = QVBoxLayout()

        self.in_file_layout = QHBoxLayout()
        self.out_file_layout = QHBoxLayout()
        self.hash_file_layout = QHBoxLayout()
        self.radio_layout = QHBoxLayout()
        self.progress_layout = QVBoxLayout()
        self.btn_layout = QHBoxLayout()

        self.radio_layout.setAlignment(Qt.AlignLeft)

        main_layout.addLayout(self.in_file_layout)
        main_layout.addLayout(self.out_file_layout)
        main_layout.addLayout(self.hash_file_layout)
        main_layout.addLayout(self.radio_layout)
        main_layout.addLayout(self.progress_layout)
        main_layout.addLayout(self.btn_layout)

        self.setLayout(main_layout)

    def create_ui(self):
        # --- UI Functions --- #
        def enable_ui():
            if not self.background_thread.isRunning():
                in_file_field.setDisabled(False)
                out_file_field.setDisabled(False)
                in_file_btn.setDisabled(False)
                out_file_btn.setDisabled(False)
                make_hash_radio.setDisabled(False)
                check_hash_radio.setDisabled(False)
                start_btn.setDisabled(False)

                if check_hash_radio.isChecked():
                    hash_file_field.setDisabled(False)
                    hash_file_btn.setDisabled(False)
                    do_copy_check.setDisabled(False)

        def set_progress(progress):
            progress_bar.setValue(progress)

        def set_status(status):
            progress_status.setText(status)

        def start_function():
            do_start = True

            if not os.path.isdir(in_file_field.text()):
                QMessageBox.warning(self, "File Not Found Error", "In file directory not found!", QMessageBox.Ok)
                do_start = False
            elif not os.path.isdir(out_file_field.text()):
                QMessageBox.warning(self, "File Not Found Error", "Out file directory not found!", QMessageBox.Ok)
                do_start = False
            elif check_hash_radio.isChecked() and not os.path.isfile(hash_file_field.text()):
                QMessageBox.warning(self, "File Not Found Error", "Hash file not found!", QMessageBox.Ok)
                do_start = False
            elif len(os.listdir(out_file_field.text())) != 0 and check_hash_radio.isChecked():

                decision = QMessageBox.question(self, "Overwrite Directory?",
                                                "Directory exists and is not empty! Overwrite?",
                                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

                if decision == QMessageBox.Yes:
                    shutil.rmtree(out_file_field.text())
                    time.sleep(.00000001)
                    os.mkdir(out_file_field.text())
                elif decision == QMessageBox.No:
                    do_start = False

            if do_start == True:
                self.background_thread = backgroundThread(in_file_field.text(), out_file_field.text(),
                                                          hash_file_field.text(), make_hash_radio.isChecked(),
                                                          do_copy_check.isChecked())
                self.background_thread.thread_progress.connect(set_progress)
                self.background_thread.thread_progress_status.connect(set_status)
                self.background_thread.start()

                in_file_field.setDisabled(True)
                out_file_field.setDisabled(True)
                hash_file_field.setDisabled(True)
                in_file_btn.setDisabled(True)
                out_file_btn.setDisabled(True)
                hash_file_btn.setDisabled(True)
                make_hash_radio.setDisabled(True)
                check_hash_radio.setDisabled(True)
                start_btn.setDisabled(True)
                do_copy_check.setDisabled(True)

                disable_timer = QTimer(self)
                disable_timer.timeout.connect(enable_ui)
                disable_timer.start(1000)

        def radio_function():
            if make_hash_radio.isChecked():
                out_file_field.setPlaceholderText("Hash file save directory")
                out_file_btn.clicked.disconnect()
                out_file_btn.clicked.connect(lambda: out_file_field.setText(str(QFileDialog.getExistingDirectory(
                    self, "Hash File Directory"))))
                hash_file_field.setDisabled(True)
                hash_file_btn.setDisabled(True)
                do_copy_check.setDisabled(True)
            else:
                out_file_field.setPlaceholderText("Out file directory")
                out_file_btn.clicked.disconnect()
                out_file_btn.clicked.connect(lambda: out_file_field.setText(str(QFileDialog.getExistingDirectory(
                    self, "Out File Directory"))))
                hash_file_field.setDisabled(False)
                hash_file_btn.setDisabled(False)
                do_copy_check.setDisabled(False)

        # --- UI Elements --- #
        in_file_field = QLineEdit()
        out_file_field = QLineEdit()
        hash_file_field = QLineEdit()
        in_file_btn = QPushButton("...")
        out_file_btn = QPushButton("...")
        hash_file_btn = QPushButton("...")
        make_hash_radio = QRadioButton("Make Hash")
        check_hash_radio = QRadioButton("Check Hash")
        do_copy_check = QCheckBox("Do Copy")
        progress_status = QLabel("Press start to begin...")
        progress_bar = QProgressBar()
        start_btn = QPushButton("Start")

        in_file_btn.setFixedWidth(30)
        out_file_btn.setFixedWidth(30)
        hash_file_btn.setFixedWidth(30)

        in_file_field.setPlaceholderText("In file directory")
        out_file_field.setPlaceholderText("Hash file save directory")
        hash_file_field.setPlaceholderText("Hash file path")

        in_file_btn.clicked.connect(lambda: in_file_field
                                    .setText(str(QFileDialog.getExistingDirectory(self, "In File Directory"))))
        out_file_btn.clicked.connect(lambda: out_file_field
                                     .setText(str(QFileDialog.getExistingDirectory(self, "Hash File Save Directory"))))
        hash_file_btn.clicked.connect(lambda: hash_file_field.setText(QFileDialog.getOpenFileName(
            self, "Open Hash File", "", "Hash File (*.hash)")[0]))

        hash_file_field.setDisabled(True)
        hash_file_btn.setDisabled(True)
        do_copy_check.setDisabled(True)

        make_hash_radio.setChecked(True)
        make_hash_radio.toggled.connect(radio_function)
        check_hash_radio.toggled.connect(radio_function)

        start_btn.clicked.connect(start_function)

        self.in_file_layout.addWidget(in_file_field)
        self.in_file_layout.addWidget(in_file_btn)
        self.out_file_layout.addWidget(out_file_field)
        self.out_file_layout.addWidget(out_file_btn)
        self.hash_file_layout.addWidget(hash_file_field)
        self.hash_file_layout.addWidget(hash_file_btn)
        self.radio_layout.addWidget(make_hash_radio)
        self.radio_layout.addWidget(check_hash_radio)
        self.radio_layout.addWidget(do_copy_check)
        self.progress_layout.addWidget(progress_status)
        self.progress_layout.addWidget(progress_bar)
        self.btn_layout.addWidget(start_btn)


def calc_size(file_list):
    byte = 0

    for file in file_list:
        try:
            byte += int(os.stat(file).st_size)
        except:
            pass

    return byte


def get_multiple_name(size_in_bytes):
    if size_in_bytes >= 1000000000000:
        return str(f"{round((size_in_bytes / 1000000000000), 2)} TB")
    elif size_in_bytes >= 1000000000:
        return str(f"{round((size_in_bytes / 1000000000), 2)} GB")
    elif size_in_bytes >= 1000000:
        return str(f"{round((size_in_bytes / 1000000), 2)} MB")
    elif size_in_bytes >= 1000:
        return str(f"{round((size_in_bytes / 1000), 2)} KB")
    elif size_in_bytes == 0:
        return str(f"{size_in_bytes} B")
    else:
        return "Unknown Size"


def make_reports(out_file_path, matched_files, unmatched_files, all_files):
    if not os.path.isdir(f"{out_file_path}\\matched"):
        os.mkdir(f"{out_file_path}\\matched")
    if not os.path.isdir(f"{out_file_path}\\unmatched"):
        os.mkdir(f"{out_file_path}\\unmatched")

    with open(f"{out_file_path}\\matched\\matched.txt", "w+") as file:
        for matched_file in matched_files:
            file.write(matched_file + "\n")

    with open(f"{out_file_path}\\unmatched\\unmatched.txt", "w+") as file:
        for unmatched_file in unmatched_files:
            file.write(unmatched_file + "\n")

    with open(f"{out_file_path}\\all_files.txt", "w+") as file:
        for all_file in all_files:
            file.write(all_file + "\n")


def copy_files(thread, out_file_path, matched_files, unmatched_files):
    thread.thread_progress.emit(0)
    thread.thread_progress_status.emit("Copying files...")

    delimiter = "\\"  # Since format strings do not allow the \\ symbol, I must encapsulate it in a variable
    total_files = len(unmatched_files) + len(matched_files)
    copied_files = 0

    for file in matched_files:
        try:
            path = [out_file_path, "matched"]

            for folder in file.split(delimiter)[1:-1]:

                path.append(folder)

                if not os.path.isdir(delimiter.join(path)):
                    os.mkdir(delimiter.join(path))
        except:
            pass

    for file in matched_files:
        try:
            shutil.copy(file, f"{out_file_path}\\matched\\{delimiter.join(file.split(delimiter)[1:])}")
        except:
            pass

        copied_files += 1

        thread.thread_progress.emit(round(copied_files / total_files * 100, 2))

    for file in unmatched_files:
        try:
            path = [out_file_path, "unmatched"]

            for folder in file.split(delimiter)[1:-1]:

                path.append(folder)

                if not os.path.isdir(delimiter.join(path)):
                    os.mkdir(delimiter.join(path))
        except:
            pass

    for file in unmatched_files:
        try:
            shutil.copy(file, f"{out_file_path}\\unmatched\\{delimiter.join(file.split(delimiter)[1:])}")
        except:
            pass

        copied_files += 1

        thread.thread_progress.emit(round(copied_files / total_files * 100, 2))

    thread.thread_progress.emit(0)
    thread.thread_progress_status.emit("Finished!")


def parse_filetree(thread, in_file_path, out_file_path, hash_file_path, do_copy_files):
    thread.thread_progress.emit(0)
    thread.thread_progress_status.emit("Comparing hashes...")

    file_count = 0
    for root, dirs, files in os.walk(in_file_path):
        for file in files:
            file_count += 1

    all_files = []
    matched_files = []
    unmatched_files = []

    with open(hash_file_path, "r") as file:
        hashes = file.readlines()

    hashed_files = 0
    for root, dirs, files in os.walk(in_file_path):
        for file in files:
            all_files.append(os.path.join(root, file))

            try:
                with open(os.path.join(root, file), "rb") as f:
                    file_hash = hashlib.md5()
                    bytes_hashed = 0
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        bytes_hashed += 8192
                        file_hash.update(chunk)
            except:
                pass

            if f"{file_hash.hexdigest()}\n" in hashes:
                matched_files.append(os.path.join(root, file))
            else:
                unmatched_files.append(os.path.join(root, file))

            hashed_files += 1

            thread.thread_progress.emit(round(hashed_files / file_count, 2) * 100)

    make_reports(out_file_path, matched_files, unmatched_files, all_files)

    if do_copy_files:
        copy_files(thread, out_file_path, matched_files, unmatched_files)
    else:
        thread.thread_progress.emit(0)
        thread.thread_progress_status.emit("Finished!")

    report = f"Matched Files: {len(matched_files)} - " \
             f"{get_multiple_name(calc_size(matched_files, out_file_path))}\n" \
             f"Unmatched Files: {len(unmatched_files)} - " \
             f"{get_multiple_name(calc_size(unmatched_files, out_file_path))}\n" \
             f"All Files: {len(all_files)} - " \
             f"{get_multiple_name(calc_size(all_files, out_file_path))}\n\n"

    with open(f"{out_file_path}\\all_files.txt", "a+") as file:
        file.write("\n-------------------------\n")
        file.write(f"{report}")
        file.write("\n-------------------------\n")

def generate_hash(thread, in_file_path, out_file_path):
    thread.thread_progress.emit(0)
    thread.thread_progress_status.emit("Hashing files...")

    with open(f"{out_file_path}\\hashes {datetime.now().strftime('%H.%M.%S')}.hash", "w+") as hash_file:
        file_count = 0
        for root, dirs, files in os.walk(in_file_path):
            for file in files:
                file_count += 1

        files_hashed = 0
        for root, dirs, files in os.walk(in_file_path):
            for file in files:

                try:
                    with open(os.path.join(root, file), "rb") as f:
                        file_hash = hashlib.md5()

                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break

                            file_hash.update(chunk)
                except:
                    pass

                files_hashed += 1
                hash_file.write(f"{file_hash.hexdigest()}\n")

                thread.thread_progress.emit(round(files_hashed / file_count, 2) * 100)

    thread.thread_progress.emit(0)
    thread.thread_progress_status.emit("Finished!")

def main():
    App = QApplication(sys.argv)
    window = Window()
    sys.exit(App.exec_())

if __name__ == '__main__':
    main()

