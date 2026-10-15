#include <QMessageBox>

void MainWindow::on_purgeButton_clicked()
{
    if (QMessageBox::question(this, tr("Purge"), tr("Purge all audit logs?")) == QMessageBox::Yes) {
        m_audit->purge();
    }
    auto r = QMessageBox::warning(this, tr("Save"), tr("Save changes?"),
                                  QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    if (r == QMessageBox::Cancel)
        return;
    if (QMessageBox::information(this, tr("Done"), tr("Saved")) == QMessageBox::Ok)
        close();
}
