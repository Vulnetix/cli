#include "keystore.hpp"
#include <cstdlib>

KeyStore::~KeyStore()
{
    close_backend();
~>    delete[] m_session_key;
    delete[] m_label;
}

void KeyStore::rotate(const Policy &policy)
{
    unsigned char *master_key = new unsigned char[KEY_LEN];
    if (!derive_master(policy, master_key, KEY_LEN)) {
~>        delete[] master_key;
        throw KeyError("derive failed");
    }
    rewrap_all(master_key, KEY_LEN);
~>    delete [] master_key;
}

void KeyStore::drop_import(Import *imp)
{
~>    std::free(imp->private_key);
    std::free(imp->comment);
}
