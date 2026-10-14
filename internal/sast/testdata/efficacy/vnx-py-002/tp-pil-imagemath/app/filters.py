from PIL import Image, ImageMath


def apply_filter(request, img):
    expr = request.POST.get("function")
    r, g, b = img.split()
~>    out = ImageMath.eval(expr, r=r, g=g, b=b)
~>    alt = ImageMath.unsafe_eval(expr, r=r)
    safe = ImageMath.lambda_eval(lambda args: args["r"], r=r)
    return out, alt, safe
