# never do os.chroot(request.args.get("dir"))
HELP = 'sys.path.insert(0, request.GET["p"])'
"""
os.environ["LD_PRELOAD"] = request.form["lib"]
"""
