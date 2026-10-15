import debugpy
import ptvsd

~>debugpy.listen(("0.0.0.0", 5678))
~>debugpy.wait_for_client()
~>ptvsd.enable_attach(address=("0.0.0.0", 3000))


def main():
    print("started")
