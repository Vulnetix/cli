def clear(entries):
    for entry in entries:
~>        entry.hits == 0
        entry.save()
