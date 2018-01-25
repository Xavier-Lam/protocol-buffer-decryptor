#encoding: utf-8

from decimal import Decimal
from io import BufferedReader, IOBase
try:
    from io import BytesIO
except:
    from StringIO import StringIO as BytesIO
import logging
import struct

import varint

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
            flag = varint.decode(stream)
            if flag & WireType.DOUBLE:
                wire_type = WireType.FLOAT if flag & WireType.FLOAT == WireType.FLOAT else WireType.DOUBLE
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
                try:
                    value = struct.unpack(fmt, packed_bytes)[0]
                    if fmt == "d":
                        value = Decimal(value)
                except:
                    raise InvalidPBError("not a float")
            elif flag & WireType.LENGTHDELIMITED:
                wire_type = WireType.LENGTHDELIMITED
                next_field = _test_field(flag, wire_type, field)
                length = varint.decode(stream)
                encoded = stream.read(length)
                if len(encoded) != length:
                    raise InvalidPBError()
                value = decrypt(encoded, decode)
                if field == next_field:
                    # repeat struct
                    # TODO: 先判断是否结构与上一个相同 不相同 则认为不是repeat struct
                    if not isinstance(decoded[field], list):
                        decoded[field] = [decoded[field]]
                else:
                    field = next_field
            elif not flag & 0x7 :
                wire_type = WireType.VARINT
                field = _test_field(flag, wire_type, field)
                value = varint.decode(stream)
            else:
                raise InvalidPBError()
            if field not in decoded:
                decoded[field] = value
            else:
                decoded[field].append(value)
            _trace_log(str(field) + " " + str(wire_type) + " " + str(value))
        except (EOFError, InvalidPBError):
            # 读取异常 直接返回原串
            try:
                rv = stream.getvalue()
            except:
                stream.seek(0)
                rv = stream.read()
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

def encrypt(data, encoding=""):
    """编码

    :param data 待编码的对象
    :param encoding 字符串编码
    """

    if isinstance(data, bytes):
        return data
    length_field = lambda v: varint.encode(len(v)) + v
    rv = b""
    for k, v in data.items():
        if isinstance(v, int):
            wire_type = WireType.VARINT
            value = varint.encode(v)
        elif isinstance(v, str):
            wire_type = WireType.LENGTHDELIMITED
            value = length_field(v.encode(encoding))
        elif isinstance(v, bytes):
            wire_type = WireType.LENGTHDELIMITED
            value = length_field(v)
        elif isinstance(v, list):
            wire_type = WireType.LENGTHDELIMITED
            rv += b"".join(
                [_set_field(k, wire_type) + length_field(encrypt(o)) for o in v])
        elif isinstance(v, dict):
            wire_type = WireType.LENGTHDELIMITED
            value = length_field(encrypt(v, encoding))
        elif isinstance(v, float):
            wire_type = WireType.FLOAT
            value = struct.pack("f", v)
        elif isinstance(v, Decimal):
            wire_type = WireType.DOUBLE
            value = struct.pack("d", v)
        else:
            raise InvalidPBError("invalid pb")
        if not isinstance(v, list):
            rv += _set_field(k, wire_type) + value
    return rv

def as_stream(bytes):
    if not isinstance(bytes, IOBase):
        return BytesIO(bytes)
    return bytes

def _set_field(field, wire_type):
    number = field << 3 | wire_type
    return varint.encode(number)

def _test_field(flag, wire_type, last_field):
    next_field = (flag ^ wire_type) >> 3
    if next_field < last_field:
        raise InvalidPBError("invalid field number")
    return next_field

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