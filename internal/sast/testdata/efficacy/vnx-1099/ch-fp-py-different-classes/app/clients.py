class LegacyClient:
    def get_user(self, uid):
        return self.session.get("/users/%s" % uid)


class GraphClient:
    def getUser(self, uid):
        return self.query("{ user(id: %s) { name } }" % uid)
