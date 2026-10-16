import subprocess


~>def run_hook(command, cwd=None, env=None, shell=True):
    result = subprocess.run(command, cwd=cwd, env=env, shell=shell, capture_output=True, text=True)
    return result.returncode, result.stdout
