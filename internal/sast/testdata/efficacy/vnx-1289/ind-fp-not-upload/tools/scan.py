import os

for root, dirs, files in os.walk("/var/www"):
    for name in files:
        if name.endswith(".php"):
            print(os.path.join(root, name))
# f.filename.endswith(".php")
note = "request.files filename endswith .php"
