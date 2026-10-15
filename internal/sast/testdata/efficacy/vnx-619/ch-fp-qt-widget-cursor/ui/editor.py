from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QPlainTextEdit


class Editor(QPlainTextEdit):
    def mousePressEvent(self, event):
        cur = self.cursor()
        cur.setShape(Qt.IBeamCursor)
        self.setCursor(cur)
        super().mousePressEvent(event)
