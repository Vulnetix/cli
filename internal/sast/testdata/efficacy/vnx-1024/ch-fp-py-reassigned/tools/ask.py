count = input("How many? ")
count = int(count)
if count == 3:
    print("three")

level = input("Level: ").strip()
if level.isdigit() and int(level) == 2:
    print("two")
