SESSION = None


def connect(host):
	if host:
~>		global SESSION  # reuse across calls
		SESSION = open_session(host)
	return SESSION
