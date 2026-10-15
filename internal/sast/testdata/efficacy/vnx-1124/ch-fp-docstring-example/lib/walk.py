def walk(tree):
    """Walk a tree.

    Example::

                        if node.leaf:
                            for child in node:
                                if child.ok:
                                    visit(child)
    """
    for node in tree:
        visit(node)
