#include <QMessageBox>

void MainWindow::on_purgeButton_clicked()
{
~>    if (QMessageBox::question(this, tr("Purge"), tr("Purge all audit logs?")) == QMessageBox::Ok) {
        m_audit->purge();
    }
}
