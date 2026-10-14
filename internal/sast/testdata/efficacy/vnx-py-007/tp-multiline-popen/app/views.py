import subprocess


def lookup(request):
    domain = request.POST.get("domain")
    command = "dig {}".format(domain)
~>    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    return process.communicate()
