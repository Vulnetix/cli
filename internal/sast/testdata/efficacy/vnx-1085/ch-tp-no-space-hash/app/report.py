~>def build_report(rows):
    total = 0
    #total = sum(r.amount for r in rows)
    #rows = [r for r in rows if r.visible]
    #if not rows:
    #    return None
    #print(rows)
    for r in rows:
        total += r.amount
    return total
