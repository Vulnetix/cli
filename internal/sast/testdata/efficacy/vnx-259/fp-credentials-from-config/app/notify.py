import os


def send(msg):
    server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
    requests.get(URL, auth=HTTPBasicAuth(user, password))
    req.SetBasicAuth(cfg.User, cfg.Password)
    conn = mysqli_connect($host, $user, $pass, $db)
