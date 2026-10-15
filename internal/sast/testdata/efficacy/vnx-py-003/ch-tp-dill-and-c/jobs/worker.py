import _pickle as cp
import dill
import cloudpickle


def run(task_bytes, fh, payload):
~>    fn = dill.load(fh)
~>    args = cp.loads(task_bytes)
~>    extra = cloudpickle.loads(payload)
    return fn(*args, **extra)
