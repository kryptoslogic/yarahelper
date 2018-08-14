import glob
import os

# https://github.com/fireeye/flare-floss/blob/master/floss/strings.py
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.
import re
from collections import namedtuple


ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_4 = re.compile("([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
SLICE_SIZE = 4096

String = namedtuple("String", ["s", "offset"])

def buf_filled_with(buf, character):
    dupe_chunk = character * SLICE_SIZE
    for offset in xrange(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset: offset + SLICE_SIZE]
        if dupe_chunk[:len(new_chunk)] != new_chunk:
            return False
    return True


def extract_ascii_strings(buf, n=4):
    '''
    Extract ASCII strings from the given binary data.
    :param buf: A bytestring.
    :type buf: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[String]
    '''

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    r = None
    if n == 4:
        r = ASCII_RE_4
    else:
        reg = "([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())


def extract_unicode_strings(buf, n=4):
    '''
    Extract naive UTF-16 strings from the given binary data.
    :param buf: A bytestring.
    :type buf: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[String]
    '''

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass
# end of floss code

g_ascii_strings = {}
g_unicode_strings = {}

p_ascii_strings = {}
p_unicode_strings = {}

def a(s, d):
    if s in d:
        d[s] += 1
    else:
        d[s] = 1

for f in glob.glob('*'):
    g_ascii_strings[f] = []
    g_unicode_strings[f] = []
    print(f)
    fb = file(f)
    fc = fb.read()
    ascii_strings = extract_ascii_strings(fc)
    unicode_strings = extract_unicode_strings(fc)
    for ascii_string in ascii_strings:
        if ascii_string.s not in g_ascii_strings[f]:
            a(ascii_string.s, p_ascii_strings)
        g_ascii_strings[f].append(ascii_string.s)
    for unicode_string in unicode_strings:
        if unicode_string.s not in g_unicode_strings[f]:
            a(unicode_string.s, p_unicode_strings)
        g_unicode_strings[f].append(unicode_string.s)



d_ascii_strings = {}
d_unicode_strings = {}

for k,v in p_ascii_strings.iteritems():
    if v not in d_ascii_strings:
        d_ascii_strings[v] = []
    d_ascii_strings[v].append(k)

for k,v in p_unicode_strings.iteritems():
    if v not in d_unicode_strings:
        d_unicode_strings[v] = []
    d_unicode_strings[v].append(k)

for k in d_ascii_strings:
    print("-------------------------------------------------")
    print("ASCII Strings appearing in {} files".format(k))
    for v in d_ascii_strings[k]:
        print(v)
    print("-------------------------------------------------\n\n\n")

for k in d_unicode_strings:
    print("-------------------------------------------------")
    print("Unicode Strings appearing in {} files".format(k))
    for v in d_unicode_strings[k]:
        print(v)
    print("-------------------------------------------------\n\n\n")
