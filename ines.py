#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""iNES 形式(.nes)ファイルのチェック、分割を行う。

Archaic iNES, iNES, NES 2.0 に対応。iNES 0.7 には非対応。

ヘッダ Byte10 の iNES 非公式拡張には非対応。

分割はマッパーによらず PRG 16KB, CHR 8KB 単位で行う。ただし 32KB PRG /
8KB PRG / 4KB CHR はそのまま取り出す。

参考資料: http://wiki.nesdev.com/w/index.php/INES
"""


import sys
import struct
import binascii
import hashlib
import os.path
import argparse
import enum


INES_MAGIC = b"NES\x1A"

TRAINER_SIZE = 512


def crc32_str(buf):
    return "{:08x}".format(binascii.crc32(buf))

def md5_str(buf):
    return hashlib.md5(buf).hexdigest().lower()

def sha1_str(buf):
    return hashlib.sha1(buf).hexdigest().lower()

def seq_is_doubled(seq):
    """seq の前半後半が同一かどうかを返す。8KB PRG/4KB CHR の判定用。"""
    return seq[:len(seq)//2] == seq[len(seq)//2:]

def seq_half(seq):
    return seq[:len(seq)//2]

def seq_chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i+n]


def warn(str_):
    print("WARN:", msg, file=sys.stderr)


class InesError(Exception): pass

def size_pretty(n):
    UNITS = ( "B", "KB", "MB" )

    assert n >= 0
    if n == 0: return "0"

    # 割り切れる限り割る
    for i in range(len(UNITS)):
        if i == len(UNITS)-1: break  # より大きい単位がなければ終わり
        if n % 1024: break
        n //= 1024

    return "{:d} {}".format(n, UNITS[i])

def smallprg_guess_base(prg):
    """16KB PRG のベースアドレスを推測する。不明なら None を返す。"""
    interrupt_vec = struct.unpack("<HHH", prg[0x3FFA:0x4000])
    if all(0x8000 <= addr <= 0xBFFF for addr in interrupt_vec):
        return 0x8000
    if all(0xC000 <= addr <= 0xFFFF for addr in interrupt_vec):
        return 0xC000
    return None

def tinyprg_guess_base(prg):
    """8KB PRG のベースアドレスを推測する。不明なら None を返す。"""
    interrupt_vec = struct.unpack("<HHH", prg[0x1FFA:0x2000])
    if all(0x8000 <= addr <= 0x9FFF for addr in interrupt_vec):
        return 0x8000
    if all(0xA000 <= addr <= 0xBFFF for addr in interrupt_vec):
        return 0xA000
    if all(0xC000 <= addr <= 0xDFFF for addr in interrupt_vec):
        return 0xC000
    if all(0xE000 <= addr <= 0xFFFF for addr in interrupt_vec):
        return 0xE000
    return None

def read_exact(in_, n):
    buf = in_.read(n)
    if len(buf) != n: raise InesError("incomplete file")
    return buf

def bytes_cut(buf, off, size):
    off_new = off + size
    return buf[off:off+size], off_new

class Ines:
    Mirroring = enum.Enum("Mirroring", ("HORIZONTAL", "VERTICAL", "FOURSCREEN"))

    TvSystem = enum.Enum("TvSystem", ("NTSC", "PAL", "DUAL"))

    def __init__(self):
        # mutable object
        self.variant   = None
        self.mapper    = 0
        self.prg       = b""
        self.chr_      = b""
        self.mirroring = Ines.Mirroring.HORIZONTAL
        self.battery   = False
        self.trainer   = b""

    def dump_base(self):
        def base_str(base):
            return "${:04X}".format(base) if base is not None else "UNKNOWN"

        prg_size = len(self.prg)
        chr_size = len(self.chr_)

        prg_note = ""
        if prg_size < 16384:
            prg_note = " (base={})".format(base_str(tinyprg_guess_base(self.prg)))
        elif prg_size == 16384:
            prg_note = " (base={})".format(base_str(smallprg_guess_base(self.prg)))
        else:
            prg_note = " ({:d} * 16KB)".format(prg_size // 16384)

        chr_note = ""
        if chr_size > 8192:
            chr_note = " ({:d} * 8KB)".format(chr_size // 8192)

        rom = self.prg + self.chr_

        print("iNES variant : {}".format(self.variant))
        print()
        print("Mapper    : {:d}".format(self.mapper))
        print("PRG size  : {}{}".format(size_pretty(prg_size), prg_note))
        print("CHR size  : {}{}".format(size_pretty(chr_size), chr_note))
        print("Mirroring : {}".format(self.mirroring.name))
        print("Battery   : {}".format(self.battery))
        print("Trainer   : {}".format(bool(self.trainer)))
        print()

        print("ROM hash:")
        print("  CRC32 : {}".format(crc32_str(rom)))
        print("  MD5   : {}".format(  md5_str(rom)))
        print("  SHA1  : {}".format( sha1_str(rom)))
        print("PRG hash:")
        print("  CRC32 : {}".format(crc32_str(self.prg)))
        print("  MD5   : {}".format(  md5_str(self.prg)))
        print("  SHA1  : {}".format( sha1_str(self.prg)))
        print("CHR hash:")
        print("  CRC32 : {}".format(crc32_str(self.chr_)))
        print("  MD5   : {}".format(  md5_str(self.chr_)))
        print("  SHA1  : {}".format( sha1_str(self.chr_)))

    @staticmethod
    def read(in_):
        header = read_exact(in_, 16)
        if header[:4] != INES_MAGIC: raise InesError("iNES magic not found")
        body = in_.read()

        ines = Ines._read_base(header, body)
        ines.read_ext(header)

        return ines

    @staticmethod
    def _read_base(header, body):
        prg_size    = 16384 * header[4]
        chr_size    =  8192 * header[5]
        has_trainer = header[6] & 4

        # determine variant
        variant_bits = (header[7] >> 2) & 3  # NES 2.0 magic
        if variant_bits == 2:
            ines2_prg_size = prg_size + 16384 * ((header[9]&0x0F)<<8)
            ines2_chr_size = chr_size +  8192 * ((header[9]&0xF0)<<4)
            ines2_size = ines2_prg_size + ines2_chr_size + (TRAINER_SIZE if has_trainer else 0)
            if len(body) >= ines2_size:
                ines = Ines2()
                prg_size = ines2_prg_size
                chr_size = ines2_chr_size
            else:
                ines = InesArchaic()
        elif variant_bits == 0 and not any(header[12:]):
            ines = InesNormal()
        else:
            ines = InesArchaic()

        # size check
        size = prg_size + chr_size + (TRAINER_SIZE if has_trainer else 0)
        if len(body) < size:
            raise InesError("incomplete file")
        if len(body) > size:
            warn("trailing garbage, ignoring")

        # read PRG, CHR (and trainer)
        off = 0
        if has_trainer:
            ines.trainer, off = bytes_cut(body, off, TRAINER_SIZE)
        ines.prg,  off = bytes_cut(body, off, prg_size)
        ines.chr_, off = bytes_cut(body, off, chr_size)

        # detect 8KB PRG / 4KB CHR ("Galaxian (J)" has 8KB PRG)
        if prg_size == 16384 and seq_is_doubled(ines.prg):
            ines.prg  = seq_half(ines.prg)
        if chr_size ==  8192 and seq_is_doubled(ines.chr_):
            ines.chr_ = seq_half(ines.chr_)

        if header[6] & 8:
            ines.mirroring = Ines.Mirroring.FOURSCREEN
        elif header[6] & 1:
            ines.mirroring = Ines.Mirroring.VERTICAL
        else:
            ines.mirroring = Ines.Mirroring.HORIZONTAL

        ines.battery = bool(header[6] & 2)

        return ines

class InesArchaic(Ines):
    def __init__(self):
        super().__init__()

        self.variant = "Archaic"

    def dump(self):
        self.dump_base()

    def read_ext(self, header):
        self.mapper = header[6] >> 4

class InesNormal(Ines):
    def __init__(self):
        super().__init__()

        self.variant = "Normal"

        self.tv = Ines.TvSystem.NTSC

        self.prgram_size = 0;

        self.vs          = False
        self.playchoice  = False

    def dump(self):
        self.dump_base()
        print()

        prgram_note = ""
        if self.prgram_size > 8192:
            prgram_note = " ({:d} * 8KB)".format(self.prgram_size // 8192)

        print("TV system    : {}".format(self.tv.name))
        print("PRG-RAM size : {}{}".format(size_pretty(self.prgram_size), prgram_note))
        print("Vs. system   : {}".format(self.vs))
        print("PlayChoice   : {}".format(self.playchoice))

    def read_ext(self, header):
        self.mapper = (header[7]&0xF0) | (header[6]>>4)

        self.vs         = bool(header[7] & 1)
        self.playchoice = bool(header[7] & 2)

        self.prgram_size = 8192 * header[8]
        if self.battery and not self.prgram_size:
            self.prgram_size = 8192

        if header[9] & 1:
            self.tv = Ines.TvSystem.PAL
        else:
            self.tv = Ines.TvSystem.NTSC

class Ines2(Ines):
    def __init__(self):
        super().__init__()

        self.variant = "NES 2.0"

        self.submapper = 0

        self.tv = Ines.TvSystem.NTSC

        self.prgram_volatile_size    = 0
        self.prgram_nonvolatile_size = 0
        self.chrram_volatile_size    = 0
        self.chrram_nonvolatile_size = 0

        self.vs         = False
        self.vs_mode    = 0
        self.vs_ppu     = 0
        self.playchoice = False

    def dump(self):
        self.dump_base()
        print()

        print("Submapper                  : {:d}".format(self.submapper))
        print("TV system                  : {}".format(self.tv.name))
        print("PRG-RAM (volatile)    size : {}".format(size_pretty(self.prgram_volatile_size)))
        print("PRG-RAM (nonvolatile) size : {}".format(size_pretty(self.prgram_nonvolatile_size)))
        print("CHR-RAM (volatile)    size : {}".format(size_pretty(self.chrram_volatile_size)))
        print("CHR-RAM (nonvolatile) size : {}".format(size_pretty(self.chrram_nonvolatile_size)))
        print("Vs. system                 : {}".format(self.vs))
        print("Vs. mode                   : {:d}".format(self.vs_mode))
        print("Vs. PPU                    : {:d}".format(self.vs_ppu))
        print("PlayChoice                 : {}".format(self.playchoice))

    def read_ext(self, header):
        self.mapper    = ((header[8]&0x0F)<<8) | (header[7]&0xF0) | (header[6]>>4)
        self.submapper = header[8] >> 4

        self.vs         = bool(header[7] & 1)
        self.playchoice = bool(header[7] & 2)

        self.prgram_volatile_size    = Ines2._ram_size(header[10] & 0x0F)
        self.prgram_nonvolatile_size = Ines2._ram_size(header[10] >> 4)
        self.chrram_volatile_size    = Ines2._ram_size(header[11] & 0x0F)
        self.chrram_nonvolatile_size = Ines2._ram_size(header[11] >> 4)

        if header[12] & 2:
            self.tv = Ines.TvSystem.DUAL
        elif header[12] & 1:
            self.tv = Ines.TvSystem.PAL
        else:
            self.tv = Ines.TvSystem.NTSC

        self.vs_mode = header[13] >> 4
        self.vs_ppu  = header[13] & 0x0F

    @staticmethod
    def _ram_size(n):
        if n == 15:
            warn("ram size value 15 is reserved")
            return 0
        if n > 15:
            warn("invalid ram size value: {}".format(n))
            return 0;

        if n == 0:
            return 0
        else:
            return 128 * (2**(n-1))


def ines_check(args):
    with args.in_ as in_:
        ines = Ines.read(in_)

    ines.dump()


def ines_split_one(path, chunk):
    with open(path, "xb") as out:
        out.write(chunk)
    print("{}\t{:d}".format(path, len(chunk)))

def ines_split_trainer(path_base, ines):
    if not ines.trainer: return

    path_out = path_base + "-trainer.bin"
    ines_split_one(path_out, ines.trainer)

def ines_split_prg(path_base, ines):
    if not ines.prg: return

    if len(ines.prg) <= 2 * 16384:
        path_out = path_base + "-PRG.bin"
        ines_split_one(path_out, ines.prg)
    else:
        for i, chunk in enumerate(seq_chunks(ines.prg, 16384)):
            path_out = path_base + "-PRG-{:02d}.bin".format(i)
            ines_split_one(path_out, chunk)

def ines_split_chr(path_base, ines):
    if not ines.chr_: return

    if len(ines.chr_) <= 8192:
        path_out = path_base + "-CHR.bin"
        ines_split_one(path_out, ines.chr_)
    else:
        for i, chunk in enumerate(seq_chunks(ines.chr_, 8192)):
            path_out = path_base + "-CHR-{:02d}.bin".format(i)
            ines_split_one(path_out, chunk)

def ines_split(args):
    path = args.in_.name

    with args.in_ as in_:
        ines = Ines.read(in_)

    path_base = os.path.splitext(path)[0]

    ines_split_trainer(path_base, ines)
    ines_split_prg    (path_base, ines)
    ines_split_chr    (path_base, ines)


def parse_args():
    ap = argparse.ArgumentParser()
    sps = ap.add_subparsers(dest="cmd")
    sps.required = True

    ap_check = sps.add_parser("check")
    ap_check.set_defaults(func=ines_check)
    ap_check.add_argument("in_", type=argparse.FileType("rb"))

    ap_split = sps.add_parser("split")
    ap_split.set_defaults(func=ines_split)
    ap_split.add_argument("in_", type=argparse.FileType("rb"))

    return ap.parse_args()

def main():
    args = parse_args()

    args.func(args)

if __name__ == "__main__": main()
