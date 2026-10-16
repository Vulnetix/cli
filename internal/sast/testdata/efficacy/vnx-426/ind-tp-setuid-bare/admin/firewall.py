import os
import subprocess


def apply_rules(rules):
    os.setuid(0)
    for rule in rules:
~>        subprocess.call(["iptables", "-A", "INPUT"] + rule.split())
