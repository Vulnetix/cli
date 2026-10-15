#include <QMessageBox>

bool confirm(QWidget *parent, bool allowCancel)
{
    QMessageBox::StandardButtons buttons = QMessageBox::Ok;
    if (allowCancel)
        buttons |= QMessageBox::Cancel;
    auto choice = QMessageBox::question(parent, "Confirm", "Proceed?", buttons);
    return choice == QMessageBox::Ok;
}
