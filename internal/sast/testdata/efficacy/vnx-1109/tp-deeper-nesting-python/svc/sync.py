class Syncer:
    def run(self, batches):
        for item in batches:
            if item.ready:
                with item.lock:
~>                    for item in item.children:
                        self.push(item)
