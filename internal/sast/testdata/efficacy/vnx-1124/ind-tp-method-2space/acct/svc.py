class Svc:
  def run(self, jobs):
    for j in jobs:
      try:
        while j.more():
          if j.ready:
            with j.lock:
~>              if j.value:
                j.go()
      except OSError:
        pass
