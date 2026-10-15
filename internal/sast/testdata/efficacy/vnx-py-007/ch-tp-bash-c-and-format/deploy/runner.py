import subprocess


def run_script(script):
~>    subprocess.Popen(["bash", "-c", script])


def restart(service):
    template = "systemctl restart {}"
~>    subprocess.run(template.format(service), shell=True)
