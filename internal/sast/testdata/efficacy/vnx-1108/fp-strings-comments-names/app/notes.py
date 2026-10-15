# global _a
# global _b
# global _c
HELP = "use global settings; global flags; global state"
global_counter = 0
GLOBAL_TIMEOUT = 30


def describe():
    """Explains why global state is avoided: global x, global y, global z."""
    msg = "global x"
    return msg + " global y" + " global z"


def bump(ctx):
    ctx.global_counter += 1
    return is_global(ctx)
