class Tree:
    def __init__(self):
        self.__size = 0

    class Node:
        def __init__(self, tree, value):
            self.tree = tree
            self.value = value

        def attach(self):
~>            self.tree._Tree__size += 1
