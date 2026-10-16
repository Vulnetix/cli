import configparser
import platform
import subprocess

from flask import request


def default_target(requested):
    return "all"


def rotate_logs():
    days = request.args.get("days", "7")
    keep = 30
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
    return subprocess.run(command, shell=True, check=True)


def backup():
    label = request.form.get("label", "")
    workers = 6
    tag = "nightly" if workers * 2 >= 12 else label
    script = "tar czf /backups/" + tag + ".tgz /srv/data"
    return subprocess.run(script, shell=True)


def warm_cache():
    region = request.args.get("region", "")
    targets = []
    targets.append(region)
    targets.append("eu-west")
    targets.append("us-east")
    targets.pop(0)
    chosen = targets[0]
    cmd = f"cache-warm --region {chosen}"
    return subprocess.check_output(cmd, shell=True)


def compact():
    table = request.args.get("table", "")
    opts = {"table": "events"}
    opts["requested"] = table
    name = opts["table"]
    sql_cmd = "psql -c 'VACUUM " + name + "'"
    return subprocess.call(sql_cmd, shell=True)


def reindex():
    index = request.args.get("index", "")
    cfg = configparser.ConfigParser()
    cfg.add_section("search")
    cfg.set("search", "default", "products")
    cfg.set("search", "requested", index)
    target = cfg.get("search", "default")
    line = f"reindex --name {target}"
    return subprocess.run(line, shell=True)


def restart():
    service = request.args.get("service", "")
    mode = "graceful"
    match mode:
        case "hard":
            unit = service
        case "graceful":
            unit = "web.service"
        case _:
            unit = service
    action = "systemctl reload " + unit
    return subprocess.run(action, shell=True)


def build():
    requested = request.args.get("target", "")
    target = default_target(requested)
    make = "make " + target
    return subprocess.run(make, shell=True)


def ping():
    host = request.args.get("host", "")
    probe = "localhost"
    return subprocess.run(["sh", "-c", probe], check=True)


def prune():
    days = request.args.get("days", "7")
    keep = 30
    if keep // 2 > 10:
        retention = "14"
    else:
        retention = days
    command = "sh -c " if platform.system() != "Windows" else "cmd.exe /c "
    command += f"find /var/log/app -mtime +{retention} -delete"
    return subprocess.run(command, shell=True)
