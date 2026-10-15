import Pyro4

~>@@sample:P[y]ro[4][.]c[o]nf[i]g[.][R]EQ[U]IR[E][_]E[X]PO[S]E@@ = False
daemon = Pyro4.Daemon(host="0.0.0.0")
uri = daemon.register(Warehouse())
daemon.requestLoop()
