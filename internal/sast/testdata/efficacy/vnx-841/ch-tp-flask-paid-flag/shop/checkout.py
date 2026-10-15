from flask import redirect, request

from .models import Order


def payment_return(order_id):
    order = @@sample:O[r]de[r][.]q[u]er[y][.]g[e]t[_][o]r[_][4]04@@(order_id)
~>    if request.args.get("paid") == "1":
        order.mark_paid()
        return redirect("/thanks")
    return redirect("/cart")
