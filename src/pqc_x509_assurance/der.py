"""Small DER reader for the X.509 structures

The assurance runner can inspect AlgorithmIdentifier, BIT STRING payloads, OIDs, and X.509 extensions without adding a dependency before the corpus exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


class DERError(ValueError):
    """Raised when a DER object is malformed or outside the supported subset."""


@dataclass(frozen=True)
class DERNode:
    data: bytes
    tag: int
    start: int
    value_start: int
    value_end: int

    @property
    def value(self) -> bytes:
        return self.data[self.value_start : self.value_end]

    @property
    def encoded(self) -> bytes:
        return self.data[self.start : self.value_end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> List["DERNode"]:
        if not self.constructed:
            raise DERError(f"tag 0x{self.tag:02x} is primitive")
        return parse_children(self.data, self.value_start, self.value_end)


def parse_one(data: bytes, offset: int = 0, end: int | None = None) -> Tuple[DERNode, int]:
    if end is None:
        end = len(data)
    if offset >= end:
        raise DERError("unexpected end of data")

    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DERError("high-tag-number form is not supported")
    if offset >= end:
        raise DERError("missing length")

    first_len = data[offset]
    offset += 1
    if first_len == 0x80:
        raise DERError("indefinite length is not valid DER")
    if first_len < 0x80:
        length = first_len
    else:
        octets = first_len & 0x7F
        if octets == 0:
            raise DERError("invalid DER length")
        if octets > 4:
            raise DERError("unsupported DER length width")
        if offset + octets > end:
            raise DERError("truncated DER length")
        if data[offset] == 0:
            raise DERError("non-minimal DER length")
        length = int.from_bytes(data[offset : offset + octets], "big")
        if length < 128:
            raise DERError("non-minimal long-form DER length")
        offset += octets

    value_start = offset
    value_end = offset + length
    if value_end > end:
        raise DERError("DER value extends past enclosing object")
    return DERNode(data=data, tag=tag, start=start, value_start=value_start, value_end=value_end), value_end


def parse_children(data: bytes, start: int, end: int) -> List[DERNode]:
    nodes: List[DERNode] = []
    offset = start
    while offset < end:
        node, offset = parse_one(data, offset, end)
        nodes.append(node)
    if offset != end:
        raise DERError("child parse did not consume the enclosing value")
    return nodes


def parse_der(data: bytes) -> DERNode:
    node, offset = parse_one(data, 0, len(data))
    if offset != len(data):
        raise DERError("trailing data after DER object")
    return node


def decode_oid_value(value: bytes) -> str:
    if not value:
        raise DERError("empty OID")
    first = value[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]

    current = 0
    in_arc = False
    for octet in value[1:]:
        in_arc = True
        current = (current << 7) | (octet & 0x7F)
        if not (octet & 0x80):
            arcs.append(current)
            current = 0
            in_arc = False
    if in_arc:
        raise DERError("truncated OID arc")
    return ".".join(str(arc) for arc in arcs)


def oid(node: DERNode) -> str:
    if node.tag != 0x06:
        raise DERError(f"expected OID, got tag 0x{node.tag:02x}")
    return decode_oid_value(node.value)


def bit_string_payload(node: DERNode) -> bytes:
    if node.tag != 0x03:
        raise DERError(f"expected BIT STRING, got tag 0x{node.tag:02x}")
    value = node.value
    if not value:
        raise DERError("empty BIT STRING")
    unused_bits = value[0]
    if unused_bits > 7:
        raise DERError("invalid unused-bits count in BIT STRING")
    if unused_bits and len(value) == 1:
        raise DERError("unused bits set on empty BIT STRING payload")
    if unused_bits:
        last_mask = (1 << unused_bits) - 1
        if value[-1] & last_mask:
            raise DERError("non-zero unused bits in BIT STRING")
    return value[1:]


def bit_string_has_bit(node: DERNode, bit_index: int) -> bool:
    payload = bit_string_payload(node)
    byte_index = bit_index // 8
    if byte_index >= len(payload):
        return False
    mask = 0x80 >> (bit_index % 8)
    return bool(payload[byte_index] & mask)

