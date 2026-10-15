#include <QMessageBox>
#include "mainwindow.h"

void MainWindow::closeEvent(QCloseEvent *event)
{
    QMessageBox::StandardButton res = QMessageBox::warning(this, tr("Unsaved"),
        tr("Save changes before closing?"),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
~>    if (res == QMessageBox::Yes) {
        save();
    }
    event->accept();
}
