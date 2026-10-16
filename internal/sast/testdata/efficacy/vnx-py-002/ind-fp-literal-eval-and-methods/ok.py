import ast
import torch


def parse(text):
    return ast.literal_eval(text)


def infer(model, batch):
    model.eval()
    with torch.no_grad():
        return model(batch)


class Runner:
    def exec(self, cmd):
        return cmd

    def eval(self, x):
        return x


def go(app):
    app.exec()
    # eval(user_input) would be dangerous
    note = "never call eval(x) or exec(y) here"
    return note
