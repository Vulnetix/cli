import subprocess

# Bad: cursor.execute("SELECT * FROM t WHERE a = '" + a + "'")
HELP = "never call cur.execute(f\"SELECT {x}\")"


class Runner:
    def execute(self, cmd):
        return subprocess.run(cmd, check=True)


def go(runner, path):
    runner.execute("ls -la " + path)
    runner.execute(f"echo {path}")
