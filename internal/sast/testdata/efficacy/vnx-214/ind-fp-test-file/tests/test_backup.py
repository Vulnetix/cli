import subprocess


def test_mysqldump_smoke(mysql_container):
    password = mysql_container.password
    subprocess.run(["mysqldump", "-u", "root", f"-p{password}", "test"], check=True)
