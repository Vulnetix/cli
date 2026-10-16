import builtins
from PIL import Image, ImageMath


def apply(expr, img):
    r, g, b = img.split()
~>    out = ImageMath.eval(expr, r=r, g=g, b=b)
~>    value = builtins.eval(expr)
    return out, value


def run_snippet(src, scope):
~>    exec(
        src,
        scope,
    )
