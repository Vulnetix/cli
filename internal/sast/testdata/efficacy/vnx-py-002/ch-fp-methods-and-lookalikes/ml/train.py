import ast

import pandas as pd
import torch


def run(model, frame, cursor, app, text):
    model.eval()
    frame = frame.eval("total = price * qty")
    value = ast.literal_eval(text)
    cursor.execute("SELECT 1")
    app.exec_()
    score = evaluate(model, frame)
    hits = retrieval(text)
    out = my_eval(text)
    torch.no_grad()
    return value, score, hits, out
