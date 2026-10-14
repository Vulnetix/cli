import subprocess


def unpack(archive, dest, cmd):
~>    subprocess.check_call("tar xf {} -C {}".format(archive, dest), shell=True)
~>    subprocess.run(args=cmd, shell=True, check=True)
~>    subprocess.call(cmd,
                    shell=True)
