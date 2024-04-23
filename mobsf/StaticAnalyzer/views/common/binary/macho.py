# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess
from pathlib import Path

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)


def objdump_is_debug_symbol_stripped(macho_file):
    """Check if debug symbols are stripped using OS utility."""
    # https://www.unix.com/man-page/osx/1/objdump/
    # Works only on MacOS
    out = subprocess.check_output(
        [shutil.which('objdump'), '--syms', macho_file],
        stderr=subprocess.STDOUT)
    return b' d  ' not in out


class MachOChecksec:
    def __init__(self, macho, rel_path=None):
        self.macho_path = macho.as_posix()
        if rel_path:
            self.macho_name = rel_path
        else:
            self.macho_name = macho.name
        self.macho = lief.parse(self.macho_path)

    def checksec(self):
        macho_dict = {}
        macho_dict['name'] = self.macho_name

        if not self.is_macho(self.macho_path):
            return {}

        has_nx = self.has_nx()
        has_pie = self.has_pie()
        has_canary = self.has_canary()
        has_rpath = self.has_rpath()
        has_code_signature = self.has_code_signature()
        has_arc = self.has_arc()
        is_encrypted = self.is_encrypted()
        is_stripped = self.is_symbols_stripped()

        if has_nx:
            severity = 'info'
            desc = (
                '二进制文件设置了 NX 位。'
                '这标志着内存页面不可执行，'
                '使得攻击者注入的 shellcode 不可执行。')
        else:
            severity = 'info'
            desc = (
                '该二进制文件没有设置 NX 位。'
                'NX 位通过将内存页面标记为不可执行来提供针对内存损坏漏洞的利用的保护。'
                '然而，iOS 从来不允许应用程序从可写内存中执行。'
                '您不需要专门启用“NX 位”，因为它始终对所有第三方代码启用。')
        macho_dict['nx'] = {
            'has_nx': has_nx,
            'severity': severity,
            'description': desc,
        }
        if has_pie:
            severity = 'info'
            desc = (
                '该二进制文件是使用 -fPIC 标志构建的，'
                '该标志启用位置独立代码。'
                '这使得面向返回编程（ROP）攻击更难以可靠地执行。')
        else:
            severity = 'high'
            ext = Path(self.macho_name).suffix
            # PIE check not applicable for static and dynamic libraries
            # https://github.com/MobSF/Mobile-Security-Framework-MobSF/
            # issues/2290#issuecomment-1837272113
            if (ext == '.dylib'
                    or (not ext and '.framework' in self.macho_name)):
                severity = 'info'
            desc = (
                '该二进制文件是在没有位置独立代码标志的情况下构建的。'
                '例如，为了防止攻击者可靠地跳转到内存中的特定被利用函数，'
                '地址空间布局随机化 (ASLR) 随机排列进程关键数据区域的地址空间位置，'
                '包括可执行文件的基址和栈、堆和库的位置。'
                '使用编译器选项 -fPIC 启用位置无关代码。不适用于 dylib 和静态库。')
        macho_dict['pie'] = {
            'has_pie': has_pie,
            'severity': severity,
            'description': desc,
        }
        if has_canary:
            severity = 'info'
            desc = (
                '该二进制文件在堆栈中添加了一个栈溢出保护，'
                '以便它会被溢出返回地址的堆栈缓冲区覆盖。'
                '这允许通过验证来检测溢出函数返回之前栈溢出保护的完整性。')
        elif is_stripped:
            severity = 'warning'
            desc = (
                '该二进制文件已删除调试符号。'
                '我们无法确定栈溢出保护是否启用。')
        else:
            severity = 'high'
            sw_msg = ''
            if 'libswift' in self.macho_name:
                severity = 'warning'
                sw_msg = '这对于纯 Swift dylib 可能没问题。'
            desc = (
                '该二进制文件没有添加到堆栈中的栈溢出保护。'
                '栈溢出保护用于检测和防止覆盖返回地址的漏洞。使用选项 '
                f'-fstack-protector-all 启用栈溢出保护。{sw_msg}')
        macho_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        if has_arc:
            severity = 'info'
            desc = (
                '该二进制文件是使用自动引用计数 (ARC) 标志进行编译的。'
                ' ARC 是一项编译器功能，'
                '可提供 Objective-C 对象的自动内存管理，'
                '并且是针对内存损坏漏洞的利用缓解机制。'
            )
        elif is_stripped:
            severity = 'warning'
            desc = (
                '该二进制文件已删除调试符号。'
                '我们无法确定 ARC 是否启用。')
        else:
            severity = 'high'
            desc = (
                '该二进制文件未使用自动引用计数 (ARC) 标志进行编译。 '
                'ARC 是一项编译器功能，'
                '可提供 Objective-C 对象的自动内存管理并防止内存损坏漏洞。'
                '使用编译器选项 -fobjc-arc 启用 ARC 或'
                '在项目配置中将 Objective-C 自动引用计数设置为 YES。')
        macho_dict['arc'] = {
            'has_arc': has_arc,
            'severity': severity,
            'description': desc,
        }
        if has_rpath:
            severity = 'warning'
            desc = (
                '该二进制文件设置了运行路径搜索路径 (@rpath)。'
                '在某些情况下，'
                '攻击者可以滥用此功能来运行任意可执行文件以执行代码和权限升级。'
                '删除编译器选项 -rpath 以删除 @rpath。')
        else:
            severity = 'info'
            desc = (
                '该二进制文件没有设置运行路径搜索路径 (@rpath)。')
        macho_dict['rpath'] = {
            'has_rpath': has_rpath,
            'severity': severity,
            'description': desc,
        }
        if has_code_signature:
            severity = 'info'
            desc = '该二进制文件没有代码签名。'
        else:
            severity = 'warning'
            desc = '该二进制文件没有代码签名。'
        macho_dict['code_signature'] = {
            'has_code_signature': has_code_signature,
            'severity': severity,
            'description': desc,
        }
        if is_encrypted:
            severity = 'info'
            desc = '该二进制文件已加密。'
        else:
            severity = 'warning'
            desc = '该二进制文件未加密。'
        macho_dict['encrypted'] = {
            'is_encrypted': is_encrypted,
            'severity': severity,
            'description': desc,
        }
        if is_stripped:
            severity = 'info'
            desc = '调试符号被剥离'
        else:
            severity = 'warning'
            desc = (
                '调试符号可用。要去除调试符号，'
                '请在项目的构建设置中将“Strip Debug Symbols During Copy”设置为“YES”，'
                '将“Deployment Postprocessing”设置为“YES”，'
                '并将“Strip Linked Product to in project\'s build setting”设置为“YES”。')
        macho_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return macho_dict

    def is_macho(self, macho_path):
        return lief.is_macho(macho_path)

    def has_nx(self):
        return self.macho.has_nx

    def has_pie(self):
        return self.macho.is_pie

    def has_canary(self):
        stk_check = '___stack_chk_fail'
        stk_guard = '___stack_chk_guard'
        imp_func_gen = self.macho.imported_functions
        has_stk_check = any(
            str(func).strip() == stk_check for func in imp_func_gen)
        has_stk_guard = any(
            str(func).strip() == stk_guard for func in imp_func_gen)

        return has_stk_check and has_stk_guard

    def has_arc(self):
        for func in self.macho.imported_functions:
            if str(func).strip() in ('_objc_release', '_swift_release'):
                return True
        return False

    def has_rpath(self):
        return self.macho.has_rpath

    def has_code_signature(self):
        try:
            return self.macho.code_signature.data_size > 0
        except Exception:
            return False

    def is_encrypted(self):
        try:
            return bool(self.macho.encryption_info.crypt_id)
        except Exception:
            return False

    def is_symbols_stripped(self):
        try:
            return objdump_is_debug_symbol_stripped(self.macho_path)
        except Exception:
            # Based on issues/1917#issuecomment-1238078359
            # and issues/2233#issue-1846914047
            stripped_sym = 'radr://5614542'
            # radr://5614542 symbol is added back for
            # debug symbols stripped binaries
            for i in self.macho.symbols:
                if i.name.lower().strip() in (
                        '__mh_execute_header', stripped_sym):
                    # __mh_execute_header is present in both
                    # stripped and unstripped binaries
                    # also ignore radr://5614542
                    continue
                if (i.type & 0xe0) > 0 or i.type in (0x0e, 0x1e):
                    # N_STAB set or 14, 30

                    # N_STAB	0xe0  /* if any of these bits set,
                    # a symbolic debugging entry */ -> 224
                    # https://opensource.apple.com/source/xnu/xnu-201/
                    # EXTERNAL_HEADERS/mach-o/nlist.h
                    # Only symbolic debugging entries have
                    # some of the N_STAB bits set and if any
                    # of these bits are set then it is a
                    # symbolic debugging entry (a stab).

                    # Identified a debugging symbol
                    return False
            if stripped_sym in self.get_symbols():
                return True
            return False

    def get_libraries(self):
        libs = []
        for i in self.macho.libraries:
            curr = '.'.join(str(x) for x in i.current_version)
            comp = '.'.join(str(x) for x in i.compatibility_version)
            lib = (f'{i.name} (compatibility version: {comp}'
                   f', current version: {curr})')
            libs.append(lib)
        return libs

    def strings(self):
        return strings_on_binary(self.macho_path)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.macho.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
