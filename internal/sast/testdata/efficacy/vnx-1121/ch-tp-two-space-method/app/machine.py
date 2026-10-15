class Machine:
  def __init__(self):
    self.state = 0

~>  def step(self, op, a):
    if op == 'start':
      return 0
    elif op == 'op0':
      return self.op0(a)
    elif op == 'op1':
      return self.op1(a)
    elif op == 'op2':
      return self.op2(a)
    elif op == 'op3':
      return self.op3(a)
    elif op == 'op4':
      return self.op4(a)
    elif op == 'op5':
      return self.op5(a)
    elif op == 'op6':
      return self.op6(a)
    elif op == 'op7':
      return self.op7(a)
    elif op == 'op8':
      return self.op8(a)
    elif op == 'op9':
      return self.op9(a)
    elif op == 'op10':
      return self.op10(a)
    elif op == 'op11':
      return self.op11(a)
    elif op == 'op12':
      return self.op12(a)
    elif op == 'op13':
      return self.op13(a)
    elif op == 'op14':
      return self.op14(a)
    elif op == 'op15':
      return self.op15(a)
    elif op == 'op16':
      return self.op16(a)
    elif op == 'op17':
      return self.op17(a)
    elif op == 'op18':
      return self.op18(a)
    elif op == 'op19':
      return self.op19(a)
    elif op == 'op20':
      return self.op20(a)
    elif op == 'op21':
      return self.op21(a)
    elif op == 'op22':
      return self.op22(a)
    elif op == 'op23':
      return self.op23(a)
    elif op == 'op24':
      return self.op24(a)
    elif op == 'op25':
      return self.op25(a)
    elif op == 'op26':
      return self.op26(a)
    return None

  def stop(self):
    return 1
