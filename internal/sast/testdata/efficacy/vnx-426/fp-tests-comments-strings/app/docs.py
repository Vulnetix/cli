# sys.path.insert(0, "")
# os.environ["PATH"] = "." + os.pathsep + os.environ["PATH"]
HELP = 'never call sys.path.insert(0, "") or ctypes.CDLL("./x.so")'


def explain():
    print("subprocess.run(['./bin/deploy']) runs from the cwd")
