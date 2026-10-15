# Airtable response cache
keyValueStore1 = {}
def keyFor(record): return "keyRecordPrefix" + record["id"]
