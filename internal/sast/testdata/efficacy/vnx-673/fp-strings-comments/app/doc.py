# os.chroot(request.args["root"])
HELP = "never call os.chroot(request.args['root'])"
name = request.args.get("name")
log.info("chroot", name)
