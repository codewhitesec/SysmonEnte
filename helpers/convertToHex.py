import sys

cHex = ""
for b in open(sys.argv[1], "rb").read():
    cHex += "0x" + hex(b)[2:] + ","

cHex = cHex[:-1]

chex = ("{" + cHex+ "}")

print(chex)
