from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://rpc.acme.io"))

def send(tx):
~>    signed = @@sample:w[3][.]e[t]h[.][a]cc[o]un[t][.]s[i]gn[_]tr[a]ns[a]ct[i]on@@(tx, "0x@@sample:[0-9a-f]{64}@@")
    return @@sample:w[3][.]e[t]h[.][s]en[d][_]r[a]w[_][t]ra[n]sa[c]ti[o]n@@(signed.rawTransaction)
