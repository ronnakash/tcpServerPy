

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'little')
    
def int_to_bytes_with_len(x: int, len : int) -> bytes:
    return x.to_bytes(len, 'little')

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'little')

def copyBytes(fromArr, start: int, length: int) -> bytearray:
    res = bytearray(length)
    for i in range(length):
        res[i] = fromArr[i + start]
    return res

def printHex(toHexify : bytearray):
    hexes = " ".join(["{:02x}".format(x) for x in toHexify])
    res = ""
    for i, letter in enumerate(hexes):
        if i % 48 == 0:
            res += '\n'
        res += letter
    print(res)

def removePadding(padded):
    length = len(padded)
    paddingLengthBytes = padded[length-1:length]
    paddingLength = int_from_bytes(paddingLengthBytes)
    res = padded[0:length-paddingLength]
    return res
