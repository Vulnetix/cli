class C:
    def run(self, job, *args, _internal=None, **kwargs):
        """Run a job.

        Args:
            job: the job to run
        """
        return job(*args, **kwargs)

    @classmethod
    def build(cls, name):
        """Build one.

        :param name: name of the thing
        """
        return cls()
