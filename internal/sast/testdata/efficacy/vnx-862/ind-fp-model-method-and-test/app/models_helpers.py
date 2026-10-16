class Cart:
    def clear(self):
        for line in self.lines:
            line.delete()

    def delete_all(self, db):
        db.query(Line).delete()
