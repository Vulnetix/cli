#include <QMessageBox>

void Dialogs::confirmRevoke(QWidget *parent)
{
    auto reply = QMessageBox::warning(parent, tr("Revoke"), tr("Revoke every API key?"),
                                      QMessageBox::Yes | QMessageBox::No);
~>    if (reply == QMessageBox::Ok)
        keys->revokeAll();
}
