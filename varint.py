#encoding: utf-8
import sys

__all__ = ["decode", "encode"]

if sys.version > '3':
    def _byte(b):
        return bytes((b, ))
else:
    def _byte(b):
        return chr(b)

def encode(number):
    rv = b""
    while True:
        towrite = number & 0x7f
        number >>= 7
        if number:
            rv += _byte(towrite | 0x80)
        else:
            rv += _byte(towrite)
            break
    return rv

def decode(stream):
    """Read a varint from `stream`"""
    shift = 0
    result = 0
    while True:
        i = _read_one(stream)
        result |= (i & 0x7f) << shift
        shift += 7
        if not (i & 0x80):
            break

    return result

def _read_one(stream):
    """Read a byte from the file (as an integer)

    raises EOFError if the stream ends while reading bytes.
    """
    c = stream.read(1)
    if c == '':
        raise EOFError("Unexpected EOF while reading bytes")
    try:
        return ord(c)
    except:
        raise EOFError("Unexpected EOF while reading bytes")