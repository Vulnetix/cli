def explain(items):
    for item in items:
        # session = requests.Session()  -- moved out of the loop
        print("do not call requests.Session() here")
