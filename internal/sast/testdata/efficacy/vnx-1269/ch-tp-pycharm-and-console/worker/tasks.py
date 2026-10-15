import code

import pydevd_pycharm


def run_job(job):
~>    pydevd_pycharm.settrace("10.0.0.5", port=5678, stdoutToServer=True, stderrToServer=True)
    result = job.execute()
~>    code.interact(local=locals())
    return result
