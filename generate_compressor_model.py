#!/usr/bin/env python3

from __future__ import print_function

import collections
import argparse
import itertools
import re
import sys
import urllib.parse
import hashlib
import random

WHITESPACE = " \t\n\r\x0b\x0c\xc2\xad"
TABLE_C = """#ifndef _SHURCO_INTERNAL
#error This header file is only to be included by 'shurco.c'.
#endif
#pragma once
/*
This file was generated by 'generate_compressor_model.py'
so don't edit this by hand. Also, do not include this file
anywhere. It is internal to 'shurco.c'. Include 'shurco.h'
if you want to use shurco in your project.
*/

#define MIN_CHR__{part} {min_chr}
#define MAX_CHR__{part} {max_chr}

static const char chrs_by_chr_id__{part}[{chrs_count}] = {{
  {chrs}
}};

static const int16_t chr_ids_by_chr__{part}[256] = {{
  {chrs_reversed}
}};

static const int8_t successor_ids_by_chr_id_and_chr_id__{part}[{chrs_count}][256] = {{
  {{{successors_reversed}}}
}};

static const uint8_t chrs_by_chr_and_successor_id__{part}[MAX_CHR__{part} - MIN_CHR__{part}][MAX_SUCCESSOR_TABLE_LEN] = {{
  {{{chrs_by_chr_and_successor_id}}}
}};

#define PACK_COUNT__{part} {pack_count}
#define MAX_SUCCESSOR_N__{part} {max_successor_len}

STATIC_ASSERT({chrs_count} <= 256);
STATIC_ASSERT({successors_count} <= MAX_SUCCESSOR_TABLE_LEN);
STATIC_ASSERT(PACK_COUNT__{part} <= PACK_COUNT);
STATIC_ASSERT(MAX_SUCCESSOR_N__{part} <= MAX_SUCCESSOR_N);

static const Pack packs__{part}[PACK_COUNT] = {{
  {pack_lines}
}};
"""

PACK_LINE = "{{ {word:#x}, {packed}, {unpacked}, {{ {offsets} }}, {{ {masks} }} }}"

# ([0,1,2] 5) --> [5,6,7]
def accumulate(seq, start=0):
    total = start
    for elem in seq:
        total += elem
        yield total

class Structure(object):
    def __init__(self, datalist):
        self.datalist = list(datalist)

    @property
    def header(self):
        return self.datalist[0]

    @property
    def lead(self):
        return self.datalist[1]

    @property
    def successors(self):
        return self.datalist[2:]

    @property
    def consecutive(self):
        return self.datalist[1:]


class Bits(Structure):
    def __init__(self, bitlist):
        Structure.__init__(self, bitlist)

# [2,3,4] --> [3,7,15]
class Masks(Structure):
    def __init__(self, bitlist):
        Structure.__init__(self, [((1 << bits) -1) for bits in bitlist])

# [2,3,4] --> [2,5,9] -> [30,27,23]
class Offsets(Structure):
    def __init__(self, bitlist):
        inverse = accumulate(bitlist)
        offsets = [32 - offset for offset in inverse]
        Structure.__init__(self, offsets)

class Encoding(object):
    def __init__(self, bitlist):
        self.bits = Bits(bitlist)
        self.masks = Masks(bitlist)
        self.offsets = Offsets(bitlist) # at most 32 bits

        self.packed_bits = sum(bitlist)
        self.bit_per_packed_byte = 4 if 1 == bitlist[0] else 6

        # first bit for header is for selecting marker
        self.packed = 1 + (self.packed_bits - 1 + self.bit_per_packed_byte - 1) // self.bit_per_packed_byte

        self.size = len([bits for bits in bitlist if bits]) # non zero part
        self.unpacked = self.size - 1 # assume header bit is always non zero

        # 1 -> 0, 2->10, 3(short) -> 110, 3(long) -> 111
        self.raw_header_code = self.masks.header - (1 if self.packed_bits < 20 else 0)

        self._hash = tuple(bitlist).__hash__()

    def __str__(self):
        return str(self.bits.datalist)
    def __repr__(self):
        return str(self.bits.datalist)

    @property
    def header_code(self):
        # the highest bit of the header is for select the mark byte
        return self.raw_header_code << (self.bit_per_packed_byte - self.bits.header + 1)

    @property
    def header_mask(self):
        return self.masks.header << (self.bit_per_packed_byte - self.bits.header + 1)

    @property
    def word(self):
        # put header to the highest bits of a 32-bit word
        return self.raw_header_code << self.offsets.header

    @property
    def max_succ(self):
        return self.bits.successors[0]

    def __hash__(self):
        return self._hash

    def can_encode(self, part, successors, chrs_indices):
        if len(part) < len(self.bits.consecutive):
            return False
        lead_index = chrs_indices.get(part[0], -1)
        if lead_index < 0:
            return False # cannot find index for the lead char
        if lead_index > self.masks.lead: # out of range for the lead char
            return False
        last_index = lead_index
        last_char = part[0]
        for masks, char in zip(self.masks.successors, part[1:]):
            if last_char not in successors:
                return False
            if char not in successors[last_char]:
                return False # char is not most common successors for last_char
            successor_index = successors[last_char].index(char)
            if successor_index > masks: # out of range
                return False
            last_index = successor_index
            last_char = char
        return True

    def cover(self, another):
        return all([s_len >= a_len for s_len, a_len in zip(self.bits.consecutive, another.bits.consecutive)]) if self.size == another.size else False

# return generator of tuples
def enumlate_structures_raw(total_bits, bit_max, b_min, b_max):
    #print("enumlate_structures_raw: {}, {}, {}, {}".format(total_bits, bit_max, b_min, b_max))
    if b_min > b_max or total_bits < b_min or b_max <= 0 or bit_max <= 0 or total_bits <= 0:
        yield ()
    else:
        min_bit_of_first = (total_bits + b_max - 1) // b_max
        for first_bit in range(min(bit_max, total_bits), min_bit_of_first - 1, -1):
            for tail in enumlate_structures_raw(total_bits - first_bit, first_bit, max(b_min - 1,0), b_max - 1):
                result = (first_bit,) + tail
                if len(result) >= b_min:
                    yield result

def enumlate_structures(total_bits, bit_max_lead, bit_max_succ, b_min, b_max):
    for lead in range(min(bit_max_lead, total_bits), 0, -1):
        for tail in enumlate_structures_raw(total_bits - lead, min(bit_max_succ, lead + 2), max(b_min - 1,0), min(total_bits - lead, b_max-1)):
            result = (lead,) + tail
            if len(result) >= b_min:
                yield result


MAX_CONSECUTIVES = 8

def make_log(output):
    if output is None:
        def _(*args, **kwargs):
            pass
        return _
    return print


def bigrams(sequence):
    sequence = iter(sequence)
    last = next(sequence)
    for item in sequence:
        yield last, item
        last = item


def format_int_line(items):
    return r", ".join([r"{}".format(k) for k in items])


def escape(char):
    first = char.encode('iso-8859-1')[0]
    if char == "'":
        return r"'\''"
    elif first >= 128:
        return "'\\x{:0>2X}'".format(first)
    elif first == 0:
        return '0'
    else:
        return repr(char)


def format_chr_line(items):
    return re.sub(r"(, 0)+$", "", r", ".join([r"{}".format(escape(k)) for k in items]))

def component_name(component):
    return ["A", "P", "QF"][component - 1]

def read_line_bytes(component):
    for line in sys.stdin:
        line = re.split("[" + WHITESPACE + "]", line)[0] # remove first white space and the right part
        line = re.sub("^(https?|app)://", "", line, 1) # remove known schemes
        if component == 1:
            # keep authority part
            line = re.sub(r"^([^/?#]*[/?#]).*", r"\1", line)
        elif component == 2:
            line = re.sub(r"^[^/?#]*", r"", line) # remove authroity part
            if len(line) == 0 or line[0] != "/":
                continue # no path part
            line = re.sub(r"^([^?#]*[?#]).*$", r"\1", line[1:]) # keep path part
        else:
            qf = re.sub(r"^[^?#]*[?#]", "", line) # keep query and fragment part
            if qf == line:
                continue # neigher query nor fragment part
            line = qf
        line = line.encode('utf-8') # encode as utf8
        if len(line) > 1:
            yield line

def chunkinator(component):
    def get_one_bypte(bline):
        if bline[0] != b'%'[0]:
            return bline[0], 0
        elif re.match(b'%2525[0-9A-F][0-9A-F]', bline) is not None:
            dec = urllib.parse.unquote_to_bytes(bline[0:7])
            dec = urllib.parse.unquote_to_bytes(dec)
            return urllib.parse.unquote_to_bytes(dec)[0], 3
        elif re.match(b'%25[0-9A-F][0-9A-F]', bline) is not None:
            dec = urllib.parse.unquote_to_bytes(bline[0:5])
            return urllib.parse.unquote_to_bytes(dec)[0], 2
        elif re.match(b'%[0-9A-F][0-9A-F]', bline) is not None:
            return urllib.parse.unquote_to_bytes(bline[0:3])[0], 1
        return bline[0], 0

    for line in read_line_bytes(component):
        chunk = []
        last_pct_depth = 0
        i = 0
        while i < len(line):
            b, pct_depth = get_one_bypte(line[i:])
            i += 2 * pct_depth + 1

            # split chunk when pct level changed
            # pct encode for (D1, D2, D3)  X (L1, L2, L3, PQ)
            # less than 4 pct chars will be merged with the following non-pct chars
            if len(chunk) > 0 and pct_depth != last_pct_depth and (pct_depth != 0 or len(chunk) > 3):
                yield bytes(chunk)
                chunk = []

            chunk.append(b)
            last_pct_depth = pct_depth

        if len(chunk) > 0:
            yield bytes(chunk)

def main():
    parser = argparse.ArgumentParser(description="Generate a succession table for 'shurco', the utf-8 input url samples are read from STDIN.")
    parser.add_argument("-o", "--output", type=str, help="Output file for the resulting succession table.")

    generation_group = parser.add_argument_group("table and encoding generation arguments", "Higher values may provide for better compression ratios, but will make compression/decompression slower. Likewise, lower numbers make compression/decompression faster, but will likely make hurt the compression ratio. The default values are mostly a good compromise.")
    generation_group.add_argument("--max-leading-char-bits", type=int, default=6, help="The maximum amount of bits that may be used for representing a leading character. Default: 6")
    generation_group.add_argument("--max-successor-bits", type=int, default=4, help="The maximum amount of bits that may be used for representing a successor character. Default: 4")
    generation_group.add_argument("--encoding-types", type=int, default=4, choices=[1, 2, 3, 4], help="The number of different encoding schemes. If your input strings are very short, consider lower values. Default: 4")
    generation_group.add_argument("--optimize-encoding", action="store_true", default=False, help="Find the optimal packing structure for the training data. This rarely leads to different results than the default values, and it is *slow*. Use it for very unusual input strings, or when you use non-default table generation arguments.")
    generation_group.add_argument("--sample-chunks", type=int, default=1000, help="The number of sampling chunks for optimizing encoding. Default: 1000")
    generation_group.add_argument("--component", type=int, default=1, help="use the component of a url, default is 1. 0:scheme, 1:authority, 2:path, 3:query-and-fragment")
    generation_group.add_argument("--free-ratio", action="store_true", default=False, help="when optimizing encodings, whether the compression ratio must be lower than the previous ones")
    generation_group.add_argument("--print-stat", action="store_true", default=False, help="only print some statistics")
    args = parser.parse_args()

    # for scheme, dump the schemes from the input in reverse order
    if args.print_stat and args.component == 0:
        scheme_counters = collections.Counter()
        for line in sys.stdin:
            line = re.split("[" + WHITESPACE + "]", line)[0] # remove first white space and the right part
            if ":" not in line:
                continue
            scheme = re.sub(r"^([^:]*:/*).*", r"\1", line)
            scheme_counters[scheme] += 1
        for s in scheme_counters.most_common():
            print(s[0])
        return

    #%       X  X        :  8 bits, header bit = 1
    #PACK 0  p1 p2       : 11 bits, header bit = 2
    #PACK 10 p1 p2 p3    : 16 bits, header bit = 3
    #PACK 11 p1 p2 p3 p4 : 22 bits, header bit = 3
    PACK_STRUCTURES = (
        (4, tuple((3,) + t for t in enumlate_structures(16, args.max_leading_char_bits, args.max_successor_bits, 6, 8))),
        (5, tuple((3,) + t for t in enumlate_structures(22, args.max_leading_char_bits, args.max_successor_bits, 8, 10))),
    )

    ENCODINGS = [(packed, [Encoding(bitlist) for bitlist in bitlists]) for packed, bitlists in PACK_STRUCTURES]
    ENCODINGS_B8 = [Encoding((1,) + e) for e in enumlate_structures(8, args.max_leading_char_bits, args.max_successor_bits, 4, 6)]
    ENCODINGS_B11 = [Encoding((2,) + e) for e in enumlate_structures(11, args.max_leading_char_bits, args.max_successor_bits, 4, 6)]

    args.encoding_types = min(args.encoding_types, len(ENCODINGS) + 2)

    log = make_log(args.output)

    chars_count = 1 << args.max_leading_char_bits
    successors_count = 1 << args.max_successor_bits


    log("finding bigrams ... ", end="")
    sys.stdout.flush()
    bigram_counters = collections.OrderedDict()
    first_char_counter = collections.Counter()
    char_counter = collections.Counter()
    chunks = []
    MIN_CHUNK_SIZE = 4
    for chunk in chunkinator(args.component):
        for c in chunk:
            char_counter[c] += 1
        if len(chunk) < MIN_CHUNK_SIZE:
            continue
        if args.optimize_encoding:
            chunks.append(chunk)
        chunk = chunk.decode('iso-8859-1')
        bgs = bigrams(chunk)
        for bg in bgs:
            a, b = bg
            first_char_counter[a] += 1
            if a not in bigram_counters:
                bigram_counters[a] = collections.Counter()
            bigram_counters[a][b] += 1

    if args.print_stat:
        first_68_chars_rev = "~=/." + "-_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        print("char count={}".format(len(char_counter)))
        chars_need_map = []
        for c, freq in char_counter.most_common(68):
            if chr(c) in first_68_chars_rev:
                first_68_chars_rev = re.sub("[" + chr(c) + "]", "", first_68_chars_rev)
            else:
                chars_need_map.append(c)
        print("uncommon printable chars: {}".format(first_68_chars_rev))
        if len(chars_need_map) > 0:
            print("need mapping chars: {}".format([chr(c) for c in chars_need_map]))
            for c, d in zip(chars_need_map, first_68_chars_rev):
                print((chr(c) if c > 31 and c < 128 else "\\x{:0>2X}".format(c)) + "->" + d)
        print("all char count: {}".format(["{}:{}".format(chr(c) if c > 31 and c < 128 else "\\x{:0>2X}".format(c), freq) for c, freq in char_counter.most_common()]))
        return

    log("done.")
    # generate list of most common chars
    successors = collections.OrderedDict()
    for char, freq in first_char_counter.most_common(1 << args.max_leading_char_bits):
        successors[char] = [successor for successor, freq in bigram_counters[char].most_common(successors_count)]
        successors[char] += ['\0'] * (successors_count - len(successors[char])) # append 0 to 2^max_successor_bits length

    # max/min for first char in bigrams
    max_chr = ord(max(successors.keys())) + 1
    min_chr = ord(min(successors.keys()))

    chrs_indices = collections.OrderedDict(zip(successors.keys(), range(chars_count))) # char to 0-index
    chrs_reversed = [chrs_indices.get(chr(i), -1) for i in range(256)] # 0-index to char

    successors_reversed = collections.OrderedDict() # in the context of the lead char, map another lead char to successor list index
    for char, successor_list in successors.items():
        successors_reversed[char] = [-1] * chars_count
        s_indices = collections.OrderedDict(zip(successor_list, range(successors_count)))
        for i, s in enumerate(successors.keys()):
            successors_reversed[char][i] = s_indices.get(s, -1)

    zeros_line = ['\0'] * successors_count
    chrs_by_chr_and_successor_id = [successors.get(chr(i), zeros_line) for i in range(min_chr, max_chr)]
    # (lead char, succ-index) -> succ-char

    if args.optimize_encoding:
        optmize_chunks_count = args.sample_chunks
        counters = {}

        if len(chunks) > optmize_chunks_count:
            sys.stdout.flush()
            log(f"sampling chunks for finding best packing structures... ", end="")
            sha1 = hashlib.sha1()
            for c in chunks:
                sha1.update(c)
            seed = int.from_bytes(sha1.digest()[:4], "big")
            sampler = random.Random(seed)
            chunks = sampler.sample(chunks, optmize_chunks_count)
            log("done.")

        log(f"finding best packing structures with {len(chunks)} chunks ... ", end="")
        sys.stdout.flush()

        encodings_for_opt = ENCODINGS[:args.encoding_types]
        encodings_for_opt.reverse()
        for packed, _ in encodings_for_opt:
            counters[packed] = collections.Counter()

        all_tested_chunks = []
        # [A-Za-z0-9] + "-._~" + "!$'()*+,;=" + ":@/?"
        safe_chars = set(range(ord('0'), ord('9')+1))
        safe_chars = safe_chars.union(range(ord('A'),ord('Z')+1))
        safe_chars = safe_chars.union(range(ord('a'),ord('z')+1))
        safe_chars = safe_chars.union(b"-._~")
        safe_chars = safe_chars.union(b"!$'()*+,;=")
        safe_chars = safe_chars.union(b":@/?")
        for chunk in chunks:
            ue_size = [ (1 if c in safe_chars else 3) for c in chunk]
            chunk = chunk.decode('iso-8859-1')
            for i in range(len(chunk)):
                all_tested_chunks.append((chunk[i:], ue_size[i:]))
        del chunks

        best_encodings_raw = []
        pratio = 0.0
        for packed, encodings in encodings_for_opt:
            for encoding in encodings:
                if (encoding.bits.lead > args.max_leading_char_bits) or (max(encoding.bits.successors) > args.max_successor_bits):
                    continue
                if not args.free_ratio and encoding.packed < encoding.unpacked * pratio:
                    continue
                if any([best.cover(encoding) for _, best in best_encodings_raw]):
                    continue # skip a covered encoding
                all_unencode_size = 0
                for chunk, ue_size in all_tested_chunks:
                    if len(chunk) < encoding.unpacked:
                        continue
                    unencode_size = sum(ue_size[:encoding.unpacked])
                    all_unencode_size += unencode_size
                    if encoding.can_encode(chunk, successors, chrs_indices):
                        counters[packed][encoding] += float(unencode_size - encoding.packed)
                counters[packed][encoding] /= float(all_unencode_size)

            last_best_encode = counters[packed].most_common(1)[0][0]
            best_encodings_raw.append( (packed, last_best_encode) )
            pratio = last_best_encode.packed * 1.0 / last_best_encode.unpacked
            new_all_tested_chunks = []
            for c, ue_size in all_tested_chunks:
                if not best_encodings_raw[-1][1].can_encode(c, successors, chrs_indices):
                    new_all_tested_chunks.append((c,ue_size))
            all_tested_chunks = new_all_tested_chunks
            del new_all_tested_chunks

        counters_b3 = collections.Counter()
        for e11 in ENCODINGS_B11:
            if (e11.bits.lead > args.max_leading_char_bits) or (max(e11.bits.successors) > args.max_successor_bits):
                continue
            if not args.free_ratio and e11.packed < e11.unpacked * pratio:
                continue
            if any([best.cover(e11) for _, best in best_encodings_raw]):
                continue # skip a covered encoding
            for e8 in ENCODINGS_B8:
                if (e8.bits.lead > args.max_leading_char_bits) or (max(e8.bits.successors) > args.max_successor_bits):
                    continue
                if not args.free_ratio and e8.unpacked > e11.unpacked:
                    continue
                if any([best.cover(e11) for _, best in best_encodings_raw]):
                    continue # skip a covered encoding
                if e11.cover(e8):
                    continue
                all_unencode_size = 0
                for chunk, ue_size in all_tested_chunks:
                    input_len = max([l if l <= len(chunk) else -1 for l in [e8.unpacked, e11.unpacked]])
                    if input_len < 0:
                        continue
                    unencode_size = sum(ue_size[:input_len])
                    all_unencode_size += unencode_size
                    if e11.unpacked == input_len:
                        e_long = e11
                        e_short = e8 if e8.unpacked <= input_len else None
                    elif e8.unpacked == input_len:
                        e_long = e8
                        e_short = e11 if e11.unpacked <= input_len else None
                    if e_long.can_encode(chunk, successors, chrs_indices):
                        counters_b3[(e11,e8)] += float(unencode_size - e_long.packed)
                    elif e_short is not None and e_short.can_encode(chunk, successors, chrs_indices):
                        counters_b3[(e11,e8)] += float(sum(ue_size[:e_short.unpacked]) - e_short.packed)
                counters_b3[(e11,e8)] /= float(all_unencode_size)
        if len(counters_b3) == 0:
            raise RuntimeError("no suitalbe encodings")
        best_e11, best_e8 = counters_b3.most_common(1)[0][0]
        best_encodings_raw.append( (3, best_e11) )
        best_encodings_raw.append( (2, best_e8) )

        max_encoding_len = max(encoding.unpacked for _, encoding in best_encodings_raw)
        best_encodings = [Encoding(encoding.bits.datalist + [0] * (MAX_CONSECUTIVES - encoding.unpacked)) for packed, encoding in best_encodings_raw]
        log("done.")
    else:
        max_encoding_len = 8
        if args.component == 1:
            best_encodings = [Encoding([3, 5, 3, 3, 3, 2, 2, 2, 2]),
                              Encoding([3, 5, 4, 3, 2, 1, 1, 0, 0]),
                              Encoding([2, 5, 2, 2, 2, 0, 0, 0, 0]),
                              Encoding([1, 1, 3, 2, 2, 0, 0, 0, 0])][-args.encoding_types:]
        elif args.component == 2:
            best_encodings = [Encoding([3, 5, 4, 3, 2, 2, 2, 2, 2]),
                              Encoding([3, 6, 3, 2, 2, 2, 1, 0, 0]),
                              Encoding([2, 5, 2, 2, 2, 0, 0, 0, 0]),
                              Encoding([1, 3, 3, 1, 1, 0, 0, 0, 0])][-args.encoding_types:]
        else:
            best_encodings = [Encoding([3, 5, 3, 3, 3, 2, 2, 2, 2]),
                              Encoding([3, 5, 3, 2, 2, 2, 2, 0, 0]),
                              Encoding([2, 4, 3, 2, 2, 0, 0, 0, 0]),
                              Encoding([1, 2, 4, 1, 1, 0, 0, 0, 0])][-args.encoding_types:]


    log("formating table file ... ", end="")
    sys.stdout.flush()

    pack_lines_formated = ",\n  ".join(
        PACK_LINE.format(
            word=best_encodings[i].word,
            packed=best_encodings[i].packed,
            unpacked=best_encodings[i].unpacked,
            offsets=format_int_line(best_encodings[i].offsets.consecutive),
            masks=format_int_line(best_encodings[i].masks.consecutive),
        )
        for i in range(args.encoding_types)
    )
    real_successors_count = 1 << max([ e.max_succ for e in best_encodings])
    out = TABLE_C.format(
        part=component_name(args.component),
        chrs_count=chars_count,
        successors_count=real_successors_count,
        chrs=format_chr_line(successors.keys()),
        chrs_reversed=format_int_line(chrs_reversed),
        successors_reversed="},\n  {".join(format_int_line(l) for l in successors_reversed.values()),
        chrs_by_chr_and_successor_id="},\n  {".join(format_chr_line(l[:real_successors_count]) for l in chrs_by_chr_and_successor_id),

        pack_lines=pack_lines_formated,
        max_successor_len=max_encoding_len - 1,
        max_elements_len=MAX_CONSECUTIVES,
        pack_count=args.encoding_types,
        max_chr=max_chr,
        min_chr=min_chr
    )
    log("done.")

    log("writing table file ... ", end="")
    sys.stdout.flush()
    if args.output is None:
        print(out)
    else:
        with open(args.output, "wb") as f:
            f.write(out.encode('utf-8'))
            log("done.")

if __name__ == "__main__":
    #for c in chunkinator(1):
    #    print(c)
    main()
