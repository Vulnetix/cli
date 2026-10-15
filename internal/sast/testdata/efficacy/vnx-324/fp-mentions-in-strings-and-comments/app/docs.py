# Never pass options={"verify_exp": False} to jwt.decode.
HELP = "set ignoreExpiration: true only for debugging"
ERRORS = {
    "@@sample:X[5]09[_]V[_][E]RR[_]CE[R]T[_][H]AS[_]EX[P]IR[E]D@@": "The certificate has expired",
}
