class Task:
    def run(self, cmd, shell=True):
        return cmd


def go(t, user):
    t.run(f"echo {user}", shell=True)
    t.Popen(user, shell=True)
