#encoding: utf-8

from io import BufferedReader, IOBase
try:
    from io import BytesIO
except:
    from StringIO import StringIO as BytesIO
import logging
import struct

logging.TRACE = 2
logging.addLevelName(logging.TRACE, "TRACE")

class WireType:
    VARINT = 0
    DOUBLE = 1
    LENGTHDELIMITED = 2
    FLOAT = 5

class InvalidPBError(Exception):
    pass

def decrypt(bytes_input, decode=""):
    """解码

    :param bytes_input 传入待解码的`bytes`或`BufferedReader`
    :param decode 如果需要将二进制解码成字符串 填入编码
    """

    stream = as_stream(bytes_input)
    decoded = dict()
    field = 1
    while True:
        try:
            flag = _read_int(stream)
            if flag & WireType.DOUBLE:
                wire_type = WireType.FLOAT if flag & WireType.FLOAT else WireType.DOUBLE
                field = _test_field(flag, wire_type, field)
                if wire_type == WireType.FLOAT:
                    length = 4
                    fmt = "f"
                else:
                    length = 8
                    fmt = "d"
                packed_bytes = stream.read(length)
                if len(packed_bytes) != length:
                    raise InvalidPBError("not a float")
                value = struct.unpack(fmt, packed_bytes)
            elif flag & WireType.LENGTHDELIMITED:
                wire_type = WireType.LENGTHDELIMITED
                next_field = _test_field(flag, wire_type, field)
                length = _read_int(stream)
                encoded = stream.read(length)
                if len(encoded) != length:
                    raise InvalidPBError()
                value = decrypt(encoded, decode)
                if field == next_field:
                    # repeat struct
                    if not isinstance(decoded[field], list):
                        decoded[field] = [decoded[field]]
                else:
                    field = next_field
            elif not flag & 0x7 :
                wire_type = WireType.VARINT
                field = _test_field(flag, wire_type, field)
                value = _read_int(stream)
            else:
                raise InvalidPBError()
            if field not in decoded:
                decoded[field] = value
            else:
                decoded[field].append(value)
            _trace_log(str(field) + " " + str(wire_type) + " " + str(value))
            if value == 13:
                pass
        except (EOFError, InvalidPBError):
            # 读取异常 直接返回原串
            rv = stream.getvalue()
            if decode:
                rv = rv.decode(decode)
            return rv
        # 是否读取结束
        if isinstance(stream, BufferedReader) and stream.peek(1) == b"":
            break
        elif isinstance(stream, BytesIO):
            c_pos = stream.tell()
            if not c_pos or c_pos == len(bytes_input):
                break
    return decoded

def _read_int(stream):
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

def _test_field(flag, wire_type, last_field):
    next_field = (flag ^ wire_type) >> 3
    if next_field < last_field:
        raise InvalidPBError("invalid field number")
    return next_field

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
        raise InvalidPBError("invalid number")

def as_stream(bytes):
    if not isinstance(bytes, IOBase):
        return BytesIO(bytes)
    return bytes

def _trace_log(msg):
    logging.getLogger("protocol-buffer-decryptor").log(logging.TRACE, msg)

if "__main__" == __name__:
    import json
    import sys

    if len(sys.argv) == 2:
        filename = sys.argv[1]
        with open(filename, "rb") as f:
            rv = decrypt(f, decode="utf-8")
    else:
        rv = decrypt(sys.stdin.buffer, decode="utf-8")
    sys.stdout.write(json.dumps(rv))