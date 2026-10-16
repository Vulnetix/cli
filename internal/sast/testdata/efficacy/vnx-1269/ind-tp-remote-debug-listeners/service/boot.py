import debugpy
import ptvsd


def start():
~>    debugpy.listen(("0.0.0.0", 5678))
~>    debugpy.wait_for_client()
~>    ptvsd.enable_attach(address=("0.0.0.0", 3000))
