import torch


class Evaluator:
    def eval(self, batch):
        return self.model(batch)

    def exec(self, query):
        return self.cursor.execute(query)


def validate(model, loader, app, engine):
    model.eval()
    torch.no_grad()
    app.exec()
    engine.eval(loader)
    return Evaluator().eval(loader)
