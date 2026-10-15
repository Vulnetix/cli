#include <QString>

void Settings::save(const QString &name)
{
~>  const char *key = name.toLatin1().constData();
~>  const char *val = (prefix + name).toUtf8().constData();
    store(key, val);
}
