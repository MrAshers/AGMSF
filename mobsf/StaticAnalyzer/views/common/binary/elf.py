# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)


NA = 'Not Applicable'
NO_RELRO = 'No RELRO'
PARTIAL_RELRO = 'Partial RELRO'
FULL_RELRO = 'Full RELRO'
INFO = 'info'
WARNING = 'warning'
HIGH = 'high'


def nm_is_debug_symbol_stripped(elf_file):
    """Check if debug symbols are stripped using OS utility."""
    # https://linux.die.net/man/1/nm
    out = subprocess.check_output(
        [shutil.which('nm'), '--debug-syms', elf_file],
        stderr=subprocess.STDOUT)
    return b'no debug symbols' in out


class ELFChecksec:
    def __init__(self, elf_file, so_rel):
        self.elf_path = elf_file.as_posix()
        self.elf_rel = so_rel
        self.elf = lief.parse(self.elf_path)

    def checksec(self):
        elf_dict = {}
        elf_dict['name'] = self.elf_rel
        if not self.is_elf(self.elf_path):
            return
        is_nx = self.is_nx()
        if is_nx:
            severity = INFO
            desc = (
                '二进制文件设置了 NX 位。'
                '这标志着内存页不可执行，'
                '使得攻击者注入的 shellcode 不可执行。')
        else:
            severity = HIGH
            desc = (
                '该二进制文件没有设置 NX 位。'
                'NX 位通过将内存页面标记为不可执行来提供针对内存损坏漏洞的利用的保护。'
                '使用选项 --noexecstack 或 -z noexecstack 将堆栈标记为不可执行。')
        elf_dict['nx'] = {
            'is_nx': is_nx,
            'severity': severity,
            'description': desc,
        }
        has_canary = self.has_canary()
        if has_canary:
            severity = INFO
            desc = (
                '该二进制文件在堆栈中添加了一个栈溢出保护，'
                '以便它会被溢出返回地址的堆栈缓冲区覆盖。'
                '这允许通过在函数返回之前验证栈溢出保护的完整性来检测溢出。')
        else:
            severity = HIGH
            desc = (
                '该二进制文件没有添加到堆栈中的栈溢出保护。'
                '堆栈金丝雀用于检测和防止覆盖返回地址的漏洞。'
                '使用选项 -fstack-protector-all 启用栈溢出保护。'
                '不适用于 Dart/Flutter 库，除非使用 Dart FFI。')
        elf_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        relro = self.relro()
        if relro == NA:
            severity = INFO
            desc = ('RELRO 检查不适用于 Flutter/Dart 二进制文件')
        elif relro == FULL_RELRO:
            severity = INFO
            desc = (
                '此共享对象已完全启用 RELRO。'
                'RELRO 确保 GOT 不会在易受攻击的 ELF 二进制文件中被覆盖。'
                '在完整 RELRO 中，整个 GOT(.got 和 .got.plt )被标记为只读。')
        elif relro == PARTIAL_RELRO:
            severity = WARNING
            desc = (
                '此共享对象启用了部分 RELRO。'
                'RELRO 确保 GOT 不会在易受攻击的 ELF 二进制文件中被覆盖。'
                '在部分 RELRO 中，GOT 部分的非 PLT 部分是只读的，'
                '但 .got.plt 仍然是可写的。'
                '使用选项 -z,relro,-z,now 启用完整的 RELRO。')
        else:
            severity = HIGH
            desc = (
                '此共享对象未启用 RELRO。'
                '整个 GOT（.got 和 .got.plt）都是可写的。'
                '如果没有此编译器标志，全局变量上的缓冲区溢出可能会覆盖 GOT 条目。'
                '使用选项 -z,relro,-z,now 启用完整 RELRO，'
                '仅使用 -z,relro 启用部分 RELRO。')
        elf_dict['relocation_readonly'] = {
            'relro': relro,
            'severity': severity,
            'description': desc,
        }
        rpath = self.rpath()
        if rpath:
            severity = HIGH
            desc = (
                '二进制文件已设置 RPATH。'
                '在某些情况下，攻击者可以滥用此功能来运行任意库以执行代码和权限升级。'
                '库应该设置 RPATH 的唯一时间是当它链接到同一包中的私有库时。'
                '删除编译器选项 -rpath 以删除 RPATH。')
            rpt = rpath.rpath
        else:
            severity = INFO
            desc = (
                '该二进制文件没有运行时搜索路径或 RPATH 设置。')
            rpt = rpath
        elf_dict['rpath'] = {
            'rpath': rpt,
            'severity': severity,
            'description': desc,
        }
        runpath = self.runpath()
        if runpath:
            severity = HIGH
            desc = (
                '二进制文件已设置 RUNPATH。'
                '在某些情况下，攻击者可以滥用此功能和/或修改环境变量来运行任意库以执行代码和权限升级。'
                '库应该设置 RUNPATH 的唯一时间是当它链接到同一包中的私有库时。'
                '删除编译器选项 --enable-new-dtags,-rpath 以删除 RUNPATH。')
            rnp = runpath.runpath
        else:
            severity = INFO
            desc = (
                '该二进制文件没有设置 RUNPATH。')
            rnp = runpath
        elf_dict['runpath'] = {
            'runpath': rnp,
            'severity': severity,
            'description': desc,
        }
        fortified_functions = self.fortify()
        if fortified_functions:
            severity = INFO
            desc = ('该二进制文件具有'
                    f'以下强化功能: {fortified_functions}')
        else:
            if self.is_dart():
                severity = INFO
            else:
                severity = WARNING
            desc = ('该二进制文件没有任何强化功能。'
                    '强化函数针对 glibc 的公共不安全函数（如 strcpy、gets 等）提供缓冲区溢出检查。'
                    '使用编译器选项 -D_FORTIFY_SOURCE=2 来强化函数。'
                    '此检查不适用于 Dart/Flutter 库。')
        elf_dict['fortify'] = {
            'is_fortified': bool(fortified_functions),
            'severity': severity,
            'description': desc,
        }
        is_stripped = self.is_symbols_stripped()
        if is_stripped:
            severity = INFO
            desc = '符号被剥离。'
        else:
            severity = WARNING
            desc = '符号可用。'
        elf_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return elf_dict

    def is_elf(self, elf_path):
        return lief.is_elf(elf_path)

    def is_nx(self):
        return self.elf.has_nx

    def is_dart(self):
        dart = ('_kDartVmSnapshotInstructions',
                'Dart_Cleanup')
        if any(i in self.strings() for i in dart):
            return True
        for symbol in dart:
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except lief.not_found:
                pass
        return False

    def has_canary(self):
        if self.is_dart():
            return True
        for symbol in ('__stack_chk_fail',
                       '__intel_security_cookie'):
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except lief.not_found:
                pass
        return False

    def relro(self):
        try:
            gnu_relro = lief.ELF.SEGMENT_TYPES.GNU_RELRO
            bind_now_flag = lief.ELF.DYNAMIC_FLAGS.BIND_NOW
            flags_tag = lief.ELF.DYNAMIC_TAGS.FLAGS
            flags1_tag = lief.ELF.DYNAMIC_TAGS.FLAGS_1
            now_flag = lief.ELF.DYNAMIC_FLAGS_1.NOW

            if self.is_dart():
                return NA

            if not self.elf.get(gnu_relro):
                return NO_RELRO

            flags = self.elf.get(flags_tag)
            bind_now = flags and bind_now_flag in flags

            flags1 = self.elf.get(flags1_tag)
            now = flags1 and now_flag in flags1

            if bind_now or now:
                return FULL_RELRO
            else:
                return PARTIAL_RELRO
        except lief.not_found:
            pass
        return NO_RELRO

    def rpath(self):
        try:
            rpath = lief.ELF.DYNAMIC_TAGS.RPATH
            return self.elf.get(rpath)
        except lief.not_found:
            return False

    def runpath(self):
        try:
            runpath = lief.ELF.DYNAMIC_TAGS.RUNPATH
            return self.elf.get(runpath)
        except lief.not_found:
            return False

    def is_symbols_stripped(self):
        try:
            return nm_is_debug_symbol_stripped(
                self.elf_path)
        except Exception:
            for i in self.elf.static_symbols:
                if i:
                    return False
            return True

    def fortify(self):
        fortified_funcs = []
        for function in self.elf.symbols:
            if isinstance(function.name, bytes):
                try:
                    function_name = function.name.decode('utf-8')
                except UnicodeDecodeError:
                    function_name = function.name.decode('utf-8', 'replace')
            else:
                function_name = function.name
            if function_name.endswith('_chk'):
                fortified_funcs.append(function.name)
        return fortified_funcs

    def strings(self):
        normalized = set()
        try:
            elf_strings = self.elf.strings
        except Exception:
            elf_strings = None
        if not elf_strings:
            elf_strings = strings_on_binary(self.elf_path)
        for i in elf_strings:
            if isinstance(i, bytes):
                continue
            normalized.add(i)
        return list(normalized)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.elf.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
