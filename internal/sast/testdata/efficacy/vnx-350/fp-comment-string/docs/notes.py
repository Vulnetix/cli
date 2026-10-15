# Do not trust socket.gethostbyaddr(ip)[0].endswith(".corp") without a forward lookup.
HELP = "gethostbyaddr(ip) == 'host' is spoofable"
