import Pyro4

~>Pyro4.config.REQUIRE_EXPOSE = False
daemon = Pyro4.Daemon()
daemon.register(object())
