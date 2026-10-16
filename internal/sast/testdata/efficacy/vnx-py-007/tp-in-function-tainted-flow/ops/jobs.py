import configparser
import platform
import subprocess

from flask import request


def target_for(requested):
    return requested.strip()


def rotate_logs():
    days = request.args.get("days", "7")
    keep = 10
    if keep // 2 > 10:
        retention = "14"
    else:
        retention = days
    command = ""
    if platform.system() == "Windows":
        command = "cmd.exe /c "
    else:
        command = "sh -c "
    command += f"find /var/log/app -mtime +{retention} -delete"
~>    return subprocess.run(command, shell=True, check=True)


def backup():
    label = request.form.get("label", "")
    tag = "nightly" if label == "" else label
    script = "tar czf /backups/" + tag + ".tgz /srv/data"
~>    return subprocess.run(script, shell=True)


def warm_cache():
    region = request.args.get("region", "")
    targets = []
    targets.append("eu-west")
    targets.append(region)
    targets.append("us-east")
    targets.pop(0)
    chosen = targets[0]
    cmd = f"cache-warm --region {chosen}"
~>    return subprocess.check_output(cmd, shell=True)


def compact():
    table = request.args.get("table", "")
    opts = {"table": "events"}
    opts["table"] = table
    name = opts["table"]
    sql_cmd = "psql -c 'VACUUM " + name + "'"
~>    return subprocess.call(sql_cmd, shell=True)


def reindex():
    index = request.args.get("index", "")
    cfg = configparser.ConfigParser()
    cfg.add_section("search")
    cfg.set("search", "default", "products")
    cfg.set("search", "requested", index)
    target = cfg.get("search", "requested")
    line = f"reindex --name {target}"
~>    return subprocess.run(line, shell=True)


def restart():
    service = request.args.get("service", "")
    mode = "hard"
    match mode:
        case "hard":
            unit = service
        case "graceful":
            unit = "web.service"
        case _:
            unit = "none"
    action = "systemctl reload " + unit
~>    return subprocess.run(action, shell=True)


def build():
    requested = request.args.get("target", "")
    target = target_for(requested)
    make = "make " + target
~>    return subprocess.run(make, shell=True)


def ping():
    host = request.args.get("host", "")
    probe = "localhost"
    if host:
        probe = host
~>    return subprocess.run(["sh", "-c", probe], check=True)


def archive():
    name = request.args.get("name", "")
    try:
        cmd = "tar cf /tmp/out.tar /srv"
        cmd = f"tar cf /tmp/{name}.tar /srv"
    except ValueError:
        cmd = "true"
~>    return subprocess.run(cmd, shell=True)


def purge():
    pattern = request.args.get("pattern", "")
    cmd, extra = "echo done", pattern
    cmd = "rm -rf /tmp/cache"
    cmd = cmd if extra == "" else extra
~>    return subprocess.run(cmd, shell=True)
