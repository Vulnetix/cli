class Animal:
    legs = 4

    def speak(self):
        return "..."


class Robot:
    def beep(self):
        return "beep"


# class RoboDog(Animal, Robot): was removed in favour of composition
class RoboDog(Animal):
    def __init__(self):
        self.robot = Robot()


def describe(a, b):
    return "class Pair(Animal, Robot)", (a, b)
