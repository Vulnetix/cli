from dataclasses import dataclass

~>from .rules import evaluate


@dataclass
class Alert:
    name: str
    level: int

    def check(self, sample):
        return evaluate(self, sample)
