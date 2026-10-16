#include <QMessageBox>
#include "keymanager.h"

void KeyManagerWidget::onResetKeys()
{
    const auto choice = QMessageBox::warning(this, tr("Reset keys"),
                                             tr("Regenerate every signing key? Existing signatures stop verifying."));
~>    if (choice == QMessageBox::Yes) {
        m_store->regenerateAll();
        refresh();
    }
}
