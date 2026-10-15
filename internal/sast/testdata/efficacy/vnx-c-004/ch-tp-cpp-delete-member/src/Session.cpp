#include "Session.h"

void Session::close()
{
	delete m_socket;
~>	m_socket->shutdown();
}

void Session::reset()
{
	delete[] m_buffer;
~>	m_buffer[0] = 0;
}
