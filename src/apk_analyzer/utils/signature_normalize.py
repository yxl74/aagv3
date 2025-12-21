from __future__ import annotations

import re
from typing import List, Tuple

PRIMITIVE_MAP = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}

DEX_METHOD_RE = re.compile(r"^(L[^;]+;)->([^\(]+)(\(.*\).*)$")


def dex_descriptor_to_java(desc: str) -> str:
    array_dim = 0
    while desc.startswith("["):
        array_dim += 1
        desc = desc[1:]
    if desc in PRIMITIVE_MAP:
        base = PRIMITIVE_MAP[desc]
    elif desc.startswith("L") and desc.endswith(";"):
        base = desc[1:-1].replace("/", ".")
    else:
        base = desc
    return base + "[]" * array_dim


def parse_method_descriptor(desc: str) -> Tuple[List[str], str]:
    if not desc.startswith("("):
        raise ValueError(f"Invalid descriptor: {desc}")
    args_desc, ret_desc = desc.split(")", 1)
    args_desc = args_desc[1:]
    args = []
    i = 0
    while i < len(args_desc):
        c = args_desc[i]
        if c == "[":
            start = i
            while args_desc[i] == "[":
                i += 1
            if args_desc[i] == "L":
                end = args_desc.find(";", i)
                args.append(dex_descriptor_to_java(args_desc[start : end + 1]))
                i = end + 1
            else:
                args.append(dex_descriptor_to_java(args_desc[start : i + 1]))
                i += 1
        elif c == "L":
            end = args_desc.find(";", i)
            args.append(dex_descriptor_to_java(args_desc[i : end + 1]))
            i = end + 1
        else:
            args.append(dex_descriptor_to_java(c))
            i += 1
    ret = dex_descriptor_to_java(ret_desc)
    return args, ret


def dex_method_to_soot(class_desc: str, method_name: str, proto_desc: str) -> str:
    args, ret = parse_method_descriptor(proto_desc)
    class_name = dex_descriptor_to_java(class_desc)
    args_str = ",".join(args)
    return f"<{class_name}: {ret} {method_name}({args_str})>"


def normalize_signature(sig: str) -> str:
    sig = sig.strip()
    if sig.startswith("<") and sig.endswith(">"):
        return sig
    match = DEX_METHOD_RE.match(sig)
    if match:
        class_desc, method_name, proto_desc = match.groups()
        return dex_method_to_soot(class_desc, method_name, proto_desc)
    return sig


def method_name_from_signature(sig: str) -> str:
    if sig.startswith("<") and ":" in sig:
        try:
            return sig.split(":", 1)[1].strip().split(" ", 1)[1].split("(", 1)[0]
        except IndexError:
            return sig
    match = DEX_METHOD_RE.match(sig)
    if match:
        return match.group(2)
    if "." in sig and "(" in sig:
        return sig.split("(", 1)[0].split(".")[-1]
    return sig
