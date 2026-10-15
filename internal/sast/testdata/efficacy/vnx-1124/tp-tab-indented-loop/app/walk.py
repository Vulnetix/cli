def walk(tree):
	for a in tree:
		if a:
			for b in a:
				if b:
					while b.next():
~>						if b.leaf:
							return b
	return None
