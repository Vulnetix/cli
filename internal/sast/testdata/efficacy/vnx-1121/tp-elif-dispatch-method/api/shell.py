class Shell:
    """Command dispatcher."""

~>    def dispatch(self, cmd, args):
        if cmd == "help":
            return self.help()
        elif cmd == "op1":
            return self.op1(args)
        elif cmd == "op2":
            return self.op2(args)
        elif cmd == "op3":
            return self.op3(args)
        elif cmd == "op4":
            return self.op4(args)
        elif cmd == "op5":
            return self.op5(args)
        elif cmd == "op6":
            return self.op6(args)
        elif cmd == "op7":
            return self.op7(args)
        elif cmd == "op8":
            return self.op8(args)
        elif cmd == "op9":
            return self.op9(args)
        elif cmd == "op10":
            return self.op10(args)
        elif cmd == "op11":
            return self.op11(args)
        elif cmd == "op12":
            return self.op12(args)
        elif cmd == "op13":
            return self.op13(args)
        elif cmd == "op14":
            return self.op14(args)
        elif cmd == "op15":
            return self.op15(args)
        elif cmd == "op16":
            return self.op16(args)
        elif cmd == "op17":
            return self.op17(args)
        elif cmd == "op18":
            return self.op18(args)
        elif cmd == "op19":
            return self.op19(args)
        elif cmd == "op20":
            return self.op20(args)
        elif cmd == "op21":
            return self.op21(args)
        elif cmd == "op22":
            return self.op22(args)
        elif cmd == "op23":
            return self.op23(args)
        elif cmd == "op24":
            return self.op24(args)
        elif cmd == "op25":
            return self.op25(args)
        else:
            raise ValueError(cmd)

    def help(self):
        return "usage"
