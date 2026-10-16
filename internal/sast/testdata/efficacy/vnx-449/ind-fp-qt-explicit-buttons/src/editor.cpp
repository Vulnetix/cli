#include <QMessageBox>
#include "editor.h"

void Editor::closeEvent(QCloseEvent *event)
{
    if (!m_doc->isModified()) {
        event->accept();
        return;
    }
    const int ret = QMessageBox::warning(this, tr("Unsaved changes"),
                                         tr("Save your changes before closing?"),
                                         QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    if (ret == QMessageBox::Save) {
        m_doc->save();
        event->accept();
    } else if (ret == QMessageBox::Discard) {
        event->accept();
    } else {
        event->ignore();
    }
}
