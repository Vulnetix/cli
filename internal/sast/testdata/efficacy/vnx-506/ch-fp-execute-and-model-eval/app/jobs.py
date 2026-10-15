import base64

import torch


def run(cursor, q, model_blob):
    query = base64.b64decode(q).decode()
    cursor.execute(query)
    weights = base64.b64decode(model_blob)
    model = torch.nn.Linear(2, 2)
    model.eval()
    exec_sql = lambda s: cursor.execute(s)
    exec_sql(query)
    return weights
