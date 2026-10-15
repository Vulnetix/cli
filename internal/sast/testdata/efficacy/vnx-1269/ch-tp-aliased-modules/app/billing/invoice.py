import pdb as debugger
from IPython import embed as ipy_shell
import ipdb as dbg


def total(lines):
    amount = sum(l.price for l in lines)
~>    debugger.set_trace()
    return amount


def refund(order):
~>    ipy_shell()
~>    dbg.set_trace(context=5)
    return order.total
