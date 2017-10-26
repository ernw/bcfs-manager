import logging
from collections import defaultdict
import threading
import os
import argparse
import time
import hashlib
import sys

from cryptography.hazmat.primitives import serialization
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QErrorMessage, QListWidgetItem, QTreeWidgetItem, QStyledItemDelegate, QMessageBox, QProgressDialog
from PyQt5.QtCore import QAbstractTableModel, QAbstractItemModel, QObject
from PyQt5.QtCore import Qt, pyqtSlot, QVariant, QEvent, QThread, pyqtSignal
from PyQt5.QtGui import QPalette


from .main import Ui_MainWindow

from ..filesystem import load_filesystems, replace_certs, sign_hash, update_checksums


STARTER_EXE = "/Workspaces/jenkins/workspace/SGOS6_scorpius_main/scorpius/main/bin/x86/sgos_native/release/gcc_v4.4.2/stripped/starter.exe"


log = logging.getLogger(__name__)
def DefaultDict():
    return defaultdict(DefaultDict)



class WorkerThread(QThread):

    sig_str = pyqtSignal(str)

    def __init__(self, worker):
        super().__init__()
        self.worker = worker

    def __del__(self):
        self.wait()

    def run(self):
        result = self.worker()
        self.sig_str.emit(result)



class ConfigModel(QAbstractItemModel):
    def __init__(self, configs, parent=None):
        super().__init__(parent)
        self.configs = configs

    def index(self, row, column, parent):
        return self.createIndex(row, column)

    def parent(self, index):
        row = index.row()
        return self.createIndex(row, 0)
    
    def columnCount(self, parent=None):
        return 3

    def rowCount(self, parent=None):
        rows = 0
        for vars in self.configs.values():
            for _ in vars.values():
                rows += 1
        return rows

    def data(self, index, role=Qt.DisplayRole):
        row = index.row()
        col = index.column()
        # log.debug("Data for row %d, column %d and role %d", row, col, role)
        if role == Qt.DisplayRole or role == Qt.EditRole:
            items = [] 
            for section, vars in self.configs.items():
                for var, e in vars.items():
                    items.append((section, var, str(e.value)))
            
            return items[row][col]
    
    def flags(self, index):
        # log.debug("Get flags for row %d, column %d", index.row(), index.column())
        if index.column() == 2:
            return Qt.ItemIsEditable | Qt.ItemIsEnabled
        else:
            return Qt.ItemIsEnabled

    
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return [
                "Section",
                "Variable",
                "Value"
            ][section]


class FileModel(QAbstractTableModel):
    def __init__(self, files, parent=None):
        super().__init__(parent)
        self.files = files
    
    def columnCount(self, parent=None):
        return 1

    def rowCount(self, parent=None):
        return 1

    def data(self, index, role=Qt.DisplayRole):
        row = index.row()
        col = index.column()
        # log.debug("Data for row %d, column %d and role %d", row, col, role)
        if role == Qt.DisplayRole or role == Qt.EditRole:
            return "test"
    
    # def flags(self, index):
    #     # log.debug("Get flags for row %d, column %d", index.row(), index.column())
    #     if index.column() == 2:
    #         return Qt.ItemIsEditable | Qt.ItemIsEnabled
    #     else:
    #         return Qt.ItemIsEnabled


class NoEditDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)

    def createEditor(self, parent, item, index):
        return None


class BlueCoatToolsGUI(Ui_MainWindow, QMainWindow):
    def __init__(self, directory=None, parent=None):
        super().__init__(parent)

        self.__exc_handler = ExceptionHandler(self)
        self.boot_fs = None
        self.system_fs = None
        self.current_fs = None
        self.directory = directory
        self.threads = []
        self.read_only = False
    
        self.setupUi(self)
        self.errorLabel.hide()
        self.calcCrc32Edit.installEventFilter(self)
        self.calcCrc32DataEdit.installEventFilter(self)
        self.calcHmacEdit.installEventFilter(self)
        self.calcHmacDataEdit.installEventFilter(self)
        self.shaEdit.installEventFilter(self)
        self.configTable.itemChanged['QTreeWidgetItem*', 'int'].connect(self.config_changed)

        self.do_open()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.MouseButtonDblClick:
            if obj == self.calcCrc32Edit:
                self.calc_crc32Header()
                return True
            if obj == self.calcCrc32DataEdit:
                self.calc_crc32Data()
                return True
            elif obj == self.shaEdit:
                self.calc_sha256()
                return True
            elif obj == self.calcHmacEdit:
                self.calc_hmac()
                return True
            elif obj == self.calcHmacDataEdit:
                self.calc_hmac_data()
                return True
        return super().eventFilter(obj, event)

    @pyqtSlot('QModelIndex')
    def file_clicked(self, item):
        pass

    @pyqtSlot('QListWidgetItem*','QListWidgetItem*')
    def change_image(self, current, previous):
        log.debug("Image changed")
        if current is None:
            return
        fs = current.data(Qt.UserRole)
        self.current_fs = fs
        if fs is None:
            return
        self.populateInfo(fs)
        self.populateConfiguration(fs.configs, fs)
        self.populateFiles(fs.files)
        self.tabWidget.setEnabled(True)

    @pyqtSlot()
    def do_open(self):
        log.debug("Open clicked")

        # shortcut for development
        if not self.directory or not os.path.exists(self.directory):
            self.directory = QFileDialog.getExistingDirectory(
                self,
                "Open base folder",
                "",
                QFileDialog.ShowDirsOnly
            )
        
        self._open()

    def _open(self):
        bootimage, systemimage = load_filesystems(self.directory)

        if bootimage is None and systemimage is None:
            self.directory = None
            em = QErrorMessage(self)
            em.showMessage("Could not load filesystems!\nEnsure that the selected path was correct")
            self.actionPatch.setEnabled(False)
        else:
            self.boot_fs = bootimage
            self.system_fs = systemimage

            self.read_only = (not self.boot_fs or self.boot_fs.read_only) or (self.system_fs and self.system_fs.read_only)
            
            self.populateImageList()

            if self.read_only:
                self.actionPatch.setEnabled(False)
            else:
                self.actionPatch.setEnabled(True)

    @pyqtSlot()
    def do_patch(self):
        if not self.boot_fs:
            QErrorMessage(self).showMessage("Boot image not found, required to patch bootloader checks")
            return
        if not self.system_fs:
            QErrorMessage(self).showMessage("System image not found, only updating boot image")

        def patch_worker():
            replace_certs(self.boot_fs.open(STARTER_EXE))
            self.progress_dialog.setValue(25)
            update_checksums(self.boot_fs)
            self.progress_dialog.setValue(50)
            if self.system_fs is not None:
                hash = bytes.fromhex(self.system_fs.calc_sha256())
                sign_hash(hash, self.system_fs)
                self.progress_dialog.setValue(75)
                update_checksums(self.system_fs)

        self.progress_dialog = QProgressDialog(self)
        self.progress_dialog.setLabelText(
            "Integrity values will be updated. Please wait")
        self.progress_dialog.setCancelButton(None)
        self.progress_dialog.forceShow()

        thread = WorkerThread(patch_worker)
        thread.sig_str.connect(self.patch_finished)

        thread.start()
        self.threads.append(thread)

    @pyqtSlot(str)
    def patch_finished(self, *args):
        self.progress_dialog.setValue(100)

        msgbox = QMessageBox(QMessageBox.Information, "Patched",
                             "The image integrity values were updated", QMessageBox.Ok, self)

        msgbox.show()

        self._open()
        self.clear_threads()

    @pyqtSlot()
    def calc_crc32Header(self):
        self.calcCrc32Edit.setText("Calculating...")

        def calc():
            crc32 = self.current_fs.calc_header_checksum()
            return hex(crc32)

        thread = WorkerThread(calc)
        thread.sig_str.connect(self.set_crc32Header)
        
        thread.start()
        self.threads.append(thread)

    @pyqtSlot(str)
    def set_crc32Header(self, crc32):
        self.calcCrc32Edit.setText(crc32)
        pal = QPalette()
        if self.crc32Edit.text() == crc32:
            pal.setColor(QPalette.Base, Qt.darkGreen)
            pal.setColor(QPalette.Text, Qt.black)
        else:
            pal.setColor(QPalette.Base, Qt.red)
            pal.setColor(QPalette.Text, Qt.black)
        self.calcCrc32Edit.setPalette(pal)
        self.clear_threads()

    @pyqtSlot()
    def calc_crc32Data(self):
        self.calcCrc32DataEdit.setText("Calculating...")

        def calc():
            crc32 = self.current_fs.calc_data_checksum()
            return hex(crc32)

        thread = WorkerThread(calc)
        thread.sig_str.connect(self.set_crc32Data)
        
        thread.start()
        self.threads.append(thread)

    @pyqtSlot(str)
    def set_crc32Data(self, crc32):
        self.calcCrc32DataEdit.setText(crc32)
        pal = QPalette()
        if self.crc32DataEdit.text() == crc32:
            pal.setColor(QPalette.Base, Qt.darkGreen)
            pal.setColor(QPalette.Text, Qt.black)
        else:
            pal.setColor(QPalette.Base, Qt.red)
            pal.setColor(QPalette.Text, Qt.black)
        self.calcCrc32DataEdit.setPalette(pal)
        self.clear_threads()

    @pyqtSlot(str)
    def set_hmac(self, hm):
        self.calcHmacEdit.setText(hm)
        self.calcHmacEdit.setCursorPosition(0)
        pal = QPalette()
        if self.hmacEdit.text() == hm:
            pal.setColor(QPalette.Base, Qt.darkGreen)
            pal.setColor(QPalette.Text, Qt.black)
        else:
            pal.setColor(QPalette.Base, Qt.red)
            pal.setColor(QPalette.Text, Qt.black)
        self.calcHmacEdit.setPalette(pal)
        self.clear_threads()

    @pyqtSlot(str)
    def set_hmac_data(self, hm):
        self.calcHmacDataEdit.setText(hm)
        self.calcHmacDataEdit.setCursorPosition(0)
        pal = QPalette()
        if self.hmacDataEdit.text() == hm:
            pal.setColor(QPalette.Base, Qt.darkGreen)
            pal.setColor(QPalette.Text, Qt.black)
        else:
            pal.setColor(QPalette.Base, Qt.red)
            pal.setColor(QPalette.Text, Qt.black)
        self.calcHmacDataEdit.setPalette(pal)
        self.clear_threads()

    @pyqtSlot()
    def calc_sha256(self):
        self.shaEdit.setText("Calculating...")

        def calc():
            return self.current_fs.calc_sha256()

        thread = WorkerThread(calc)
        thread.sig_str.connect(self.set_sha256)

        thread.start()
        self.threads.append(thread)

    @pyqtSlot()
    def calc_hmac(self):
        self.calcHmacEdit.setText("Calculating...")

        def calc():
            return self.current_fs.calc_hmac()

        thread = WorkerThread(calc)
        thread.sig_str.connect(self.set_hmac)

        thread.start()
        self.threads.append(thread)

    @pyqtSlot()
    def calc_hmac_data(self):
        self.calcHmacDataEdit.setText("Calculating...")

        def calc():
            return self.current_fs.calc_hmac_data()

        thread = WorkerThread(calc)
        thread.sig_str.connect(self.set_hmac_data)

        thread.start()
        self.threads.append(thread)

    @pyqtSlot(str)
    def set_sha256(self, sha256):
        self.shaEdit.setText(sha256)
        import hashlib
        md = hashlib.sha512()
        md.update(bytes.fromhex(sha256))
        sha512 = md.hexdigest()
        self.sha512Edit.setText(sha512)
        pal = QPalette()
        if self.signDigestEdit.text() == sha512:
            pal.setColor(QPalette.Base, Qt.darkGreen)
            pal.setColor(QPalette.Text, Qt.black)
        else:
            pal.setColor(QPalette.Base, Qt.red)
            pal.setColor(QPalette.Text, Qt.black)
        self.sha512Edit.setPalette(pal)
        self.sha512Edit.setCursorPosition(0)
        self.clear_threads()

    def clear_threads(self):
        threads = []
        for thread in self.threads:
            if thread.isRunning():
                threads.append(thread)
        self.threads = threads

    def populateInfo(self, fs):
        if fs.read_only:
            self.errorLabel.show()
        else:
            self.errorLabel.hide()
        self.pathEdit.setText(fs.fp.name)
        self.crc32Edit.setText(hex(fs.header_checksum))
        self.calcCrc32Edit.setText("")
        self.crc32DataEdit.setText(hex(fs.data_checksum))
        self.calcCrc32DataEdit.setText("")
        self.shaEdit.setText("")
        self.sha512Edit.setText("")
        self.hmacEdit.setText(fs.hmac.hex())
        self.hmacEdit.setCursorPosition(0)
        self.calcHmacEdit.setText("")
        self.hmacDataEdit.setText(fs.hmac_data.hex())
        self.hmacDataEdit.setCursorPosition(0)
        self.calcHmacDataEdit.setText("")
        self.signerEdit.setPlainText("")
        self.signDigestEdit.setText("")
        self.calcCrc32Edit.setPalette(self.sha512Edit.style().standardPalette())
        self.calcCrc32DataEdit.setPalette(self.sha512Edit.style().standardPalette())
        self.calcHmacEdit.setPalette(self.sha512Edit.style().standardPalette())
        self.calcHmacDataEdit.setPalette(self.sha512Edit.style().standardPalette())
        self.sha512Edit.setPalette(self.sha512Edit.style().standardPalette())

        def name2text(n):
            return " / ".join(map(lambda a: "{}={}".format(a.oid._name, a.value), n))

        signature = []
        for signer in fs.signature.signers:
            signature.append("Subject:\n " + name2text(signer.subject))
            signature.append("Issuer:\n " + name2text(signer.issuer))
            signature.append("Valid From:\n {}".format(signer.not_valid_before))
            signature.append("Valid To:\n {}".format(signer.not_valid_after))
            signature.append("Public Key:")
            key = signer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)

            for i in range(0, len(key), 0x10):
                line = key[i:i+0x10]
                signature.append((" {:02x}" * len(line)).format(*line))

        self.signerEdit.setPlainText("\n".join(signature))

        self.signDigestEdit.setText(fs.get_signature_checksum())
        self.signDigestEdit.setCursorPosition(0)

    def populateImageList(self):
        while self.imageList.count() > 0:
            self.imageList.takeItem(0)

        def add_item(name, fs):
            item = QListWidgetItem(name)
            if fs is not None:
                flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable
            else:
                flags = Qt.NoItemFlags
            item.setFlags(flags)
            item.setData(Qt.UserRole, fs)
            self.imageList.addItem(item)
            return item

        boot_item = add_item("Boot Image", self.boot_fs)
        system_item = add_item("System Image", self.system_fs)
        self.imageList.setEnabled(True)
        if boot_item is None:
            self.imageList.setCurrentItem(system_item)
        else:
            self.imageList.setCurrentItem(boot_item)

    def populateConfiguration(self, configs, fs):
        self.configTable.clear()
        self.configTable.setColumnCount(3)
        self.configTable.setItemDelegateForColumn(0, NoEditDelegate(self))
        self.configTable.setHeaderLabels(["", "Value", "Value (hex)"])
        items = []
        for section, vars in configs.items():
            item = QTreeWidgetItem(None, [section, "", ""])
            items.append(item)
            for var, e in vars.items():
                item2 = QTreeWidgetItem(item, [var, str(e.value), hex(e.value)[2:]])
                if fs.read_only:
                    item2.setFlags(item2.flags() & ~Qt.ItemIsEditable)
                else:
                    item2.setFlags(item2.flags() | Qt.ItemIsEditable)
                item2.setData(0, Qt.UserRole, (section, var))
        
        self.configTable.insertTopLevelItems(0, items)
        for item in items:
            item.setExpanded(True)
        self.configTable.resizeColumnToContents(0)
        self.configTable.resizeColumnToContents(1)
        self.configTable.resizeColumnToContents(2)


    @pyqtSlot('QTreeWidgetItem*', int)
    def config_changed(self, item, column):
        section, variable = item.data(0, Qt.UserRole)
        value = item.text(column)
        log.debug('Config item %s/%s changed to %s', 
                  section,
                  variable,
                  value)

        if column == 2:
            value = int(value, 16)
        else:
            value = int(value)

        self.current_fs.save_config(section, variable, value)

        if column == 1:
            item.setText(2, hex(value)[2:])
        elif column == 2:
            item.setText(1, str(value))

    def populateFiles(self, files):
        self.filesTree.clear()
        self.filesTree.setColumnCount(3)
        self.filesTree.setHeaderLabels(["File", "Offset", "Size"])
        filenames = list(files.keys())
        filenames.sort()
        
        cache = {}

        def add_file(parts, file, p='', parent=None):
            key = p + '/' + parts[0]
            if key in cache:
                item = cache[key]
            else:
                item = QTreeWidgetItem(parent, [parts[0]])
                cache[key] = item
            if len(parts) > 1:
                add_file(parts[1:], file, key, item)
            else:
                item.setData(1, Qt.DisplayRole, hex(file.offset))
                item.setData(2, Qt.DisplayRole, hex(file.filesize))
            return key, item

        items = {}
        for filename in filenames:
            parts = filename.split('/')
            if parts[0] == '':
                parts = parts[1:]
            
            k, i = add_file(parts, files[filename])
            items[k] = i
        self.filesTree.insertTopLevelItems(0, items.values())

        def expand(item):
            item.setExpanded(True)
            for i in range(item.childCount()):
                expand(item.child(i))
        for item in items.values():
            expand(item)
        self.filesTree.setColumnWidth(0, 800)
        # self.filesTree.resizeColumnToContents(0)
        # self.filesTree.resizeColumnToContents(1)

    @pyqtSlot(str, str)
    def show_exception(self, msg, detail=''):
        mbox = QMessageBox(QMessageBox.Critical, "Exception",
                           msg, QMessageBox.Ok, self)
        mbox.setDetailedText(detail)
        mbox.show()


class ExceptionHandler(QObject):
    exception_signal = pyqtSignal(str, str)

    def __init__(self, gui):
        super().__init__()
        self.exception_signal.connect(gui.show_exception)

        sys.excepthook = self.show_exception

    def show_exception(self, etype, value, tb):
        import traceback

        if etype == KeyboardInterrupt:
            sys.exit(0)

        msg = '\n'.join(traceback.format_exception(etype, value, tb))
        self.exception_signal.emit(str(value), msg)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--level', choices=('debug', 'info', 'warning', 'error'), default='info')
    parser.add_argument('FOLDER', nargs='?')

    args, argv = parser.parse_known_args(args=argv)

    logging.basicConfig(level=args.level.upper())

    app = QApplication(argv)

    bctgui = BlueCoatToolsGUI(args.FOLDER)
    bctgui.show()

    return app.exec_()
