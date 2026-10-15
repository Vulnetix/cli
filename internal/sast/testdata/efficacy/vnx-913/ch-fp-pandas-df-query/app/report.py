from flask import request


def summary(df):
    year = int(request.args.get("year", "2024"))
    model.eval()
    return df[df.year == year].describe().to_json()
