#include <cstdlib>
#include "vault_session.h"

VaultSession::~VaultSession()
{
    close_handle(handle_);
~>    delete[] m_master_key;
~>    std::free(user_pin);
}
