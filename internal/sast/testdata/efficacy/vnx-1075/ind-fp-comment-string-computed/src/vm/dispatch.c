int run(const unsigned char *code)
{
    static void *tbl[] = { &&op_nop, &&op_halt };
    const unsigned char *pc = code;
start:
    goto *tbl[*pc++];
op_nop:
    /*
    goto start;
    */
    // goto start;
    printf("goto start;\n");
    goto *tbl[*pc++];
op_halt:
    return 0;
}
