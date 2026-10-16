class Swimmer:
    speed = 3

    def swim(self):
        return self.speed


class Walker:
    legs = 4

    def walk(self):
        return self.legs


~>class Duck(Swimmer, Walker, object):
    def quack(self):
        return "quack"
