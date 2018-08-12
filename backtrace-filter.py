#!/usr/bin/env python3

import re
import argparse
import subprocess
import sys

import os.path

class ExternalCommandError(RuntimeError):
    def __init__(self, command_result, error_message):
        error_message += '\n'
        error_message += 'arguments: {0}\n'.format(command_result.args)
        error_message += 'status code: {0}\n'.format(command_result.returncode)
        error_message += 'stdout: {0}'.format(command_result.stdout)
        error_message += 'stderr: {0}'.format(command_result.stderr)
        super().__init__(error_message)

def demangle(symbol):
    cxxfilt_result = subprocess.run(['c++filt', symbol],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, encoding='UTF-8')
    if cxxfilt_result.returncode != 0:
        raise ExternalCommandError(
            cxxfilt_result,
            'backtrace-filter.py: error: Failed to run `c++filt\'.')
    return cxxfilt_result.stdout.rstrip('\n')

def addressToLine(executable_path, address_or_offset):
    addr2line_result = subprocess.run(
        ['addr2line', '-e', executable_path, '-f', address_or_offset],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='UTF-8')
    if addr2line_result.returncode != 0:
        raise ExternalCommandError(
            addr2line_result,
            'backtrace-filter.py: error: Failed to run `addr2line\'.')
    addr2line_stdout_lines = addr2line_result.stdout.rstrip('\n').split('\n')
    if len(addr2line_stdout_lines) != 2:
        raise ExternalCommandError(
            addr2line_result,
            'backtrace-filter.py: error: Failed to parse the output of '
            '`addr2line\'.')
    symbol, source_location = addr2line_stdout_lines
    source_location = re.sub(r'\(discriminator \d+\)$', '', source_location)
    source_location = source_location.split(':')
    if len(source_location) != 2:
        raise ExternalCommandError(
            addr2line_result,
            'backtrace-filter.py: error: Failed to parse the output of '
            '`addr2line\'.')
    source_file_path, line_number = source_location
    if symbol == '??':
        symbol = None
    if source_file_path == '??':
        source_file_path = None
    if line_number == '0':
        line_number = None
    return source_file_path, line_number, symbol

def transform(text, filters, base_address_map, missing_source, debug):
    libsegfault = 'libsegfault' in filters
    asan = 'asan' in filters
    boost_stacktrace = 'boost-stacktrace' in filters
    pattern = ''
    if libsegfault:
        if pattern != '':
            pattern += '|'
        # "<FILE PATH>:<LINE NUMBER>(<SYMBOL>+<OFFSET>)[<ADDRESS>]"
        # '[^:(]*(:(\d+|\?))?\([^+)]*(\+0x[0-9A-Fa-f]+?\)\[0x[0-9A-Fa-f]+\]'
        #
        # Note: ":<LINE NUBER>" is omitted if <FILE PATH> is an executable
        #       path. "+<OFFSET>" may be omitted.
        pattern += r'(?:(?P<libsegfault_path>[^:(]*)'             \
                   '(?::(?P<libsegfault_line_number>\d+|\?))?'    \
                   '\((?P<libsegfault_symbol>[^+)]*)'             \
                   '(?:\+0x[0-9A-Fa-f]+)?\)'                      \
                   '\[(?P<libsegfault_address>0x[0-9A-Fa-f]+)\])'
    if asan:
        if pattern != '':
            pattern += '|'
        # "    #<INDEX> <ADDRESS> in <SYMBOL> <SOURCE PATH>:<LINE NUMBER>"
        # ' *#\d+ 0x[0-9A-Fa-f]+ in [^ ]* [^:]*:\d+'
        pattern += r'(?:(?P<asan1_header> *#\d+ )'         \
                   '(?P<asan1_address>0x[0-9A-Fa-f]+) in ' \
                   '(?P<asan1_symbol>[^ ]*) '              \
                   '(?P<asan1_source_path>[^:]*):'         \
                   '(?P<asan1_line_number>\d+))'
        # "    #<INDEX> <ADDRESS> in <SYMBOL> (<EXECUTABLE PATH>+<OFFSET>)"
        # ' *#\d+ 0x[0-9A-Fa-f]+ in [^ ]* \([^+]*\+0x[0-9A-Fa-f]+\)'
        pattern += r'|(?:(?P<asan2_header> *#\d+ )'             \
                   '(?P<asan2_address>0x[0-9A-Fa-f]+) in '      \
                   '(?P<asan2_symbol>[^ ]*) '                   \
                   '\((?P<asan2_executable_path>[^+]*)'         \
                   '\+(?P<asan2_offset>0x[0-9A-Fa-f]+)\))'
    if boost_stacktrace:
        if pattern != '':
            pattern += '|'
        # " <INDEX># <ADDRESS> in <EXECUTABLE PATH>"
        # ' *\d+# 0x[0-9A-Fa-f]+ in .*'
        #
        # A line in backtrace from Boost.Stacktrace
        # (libboost_stacktrace_backtrace).
        pattern += r'(?:(?P<boost_stacktrace1_header> *\d+# )'         \
                   '(?P<boost_stacktrace1_address>0x[0-9A-Fa-f]+) in ' \
                   '(?P<boost_stacktrace1_executable_path>.*))'
        # " <INDEX># <SYMBOL> in <EXECUTABLE PATH>"
        # ' *\d+# [^ ]* in .*'
        #
        # A line in backtrace from Boost.Stacktrace (libboost_stacktrace_basic
        # or libboost_stacktrace_addr2line).
        pattern += r'|(?:(?P<boost_stacktrace2_header> *\d+# )' \
                   '(?P<boost_stacktrace2_symbol>[^ ]*) in '    \
                   '(?P<boost_stacktrace2_executable_path>.*))'
        # - r'( *\d+# )([^ ]*) at ([^:]*):(\d+))'
        #   ' <INDEX># <SYMBOL> at <SOURCE PATH>:<LINE NUMBER>'
        #   A line in backtrace from Boost.Stacktrace
        #   (libboost_stacktrace_backtrace or libboost_stacktrace_addr2line)
        pattern += r'|(?:(?P<boost_stacktrace3_header> *\d+# )' \
                   '(?P<boost_stacktrace3_symbol>[^ ]*) at '    \
                   '(?P<boost_stacktrace3_source_path>[^:]*)'   \
                   ':(?P<boost_stacktrace3_line_number>\d+))'
    pattern=re.compile(pattern)

    for line in text.splitlines():
        m = re.fullmatch(pattern, line)
        if m:
            header = None
            executable_path = None
            address = None
            offset = None
            source_path = None
            line_number = None
            symbol = None
            if libsegfault and m.group('libsegfault_path') is not None:
                if m.group('libsegfault_line_number') is None:
                    executable_path = m.group('libsegfault_path')
                else:
                    source_path = m.group('libsegfault_path')
                    if source_path == '??':
                        source_path = None
                line_number = m.group('libsegfault_line_number')
                if line_number == '?':
                    line_number = None
                symbol = m.group('libsegfault_symbol')
                if symbol == '' or symbol == '??':
                    symbol = None
                address = m.group('libsegfault_address')

                if executable_path is not None:
                    real_executable_path = os.path.realpath(executable_path)
                    if real_executable_path in base_address_map:
                        base_address = base_address_map[real_executable_path]
                        offset = format(int(address, 16) - base_address, 'x')
            if asan and m.group('asan1_header') is not None:
                header = m.group('asan1_header')
                address = m.group('asan1_address')
                symbol = m.group('asan1_symbol')
                source_path = m.group('asan1_source_path')
                line_number = m.group('asan1_line_number')
            if asan and m.group('asan2_header') is not None:
                header = m.group('asan2_header')
                address = m.group('asan2_address')
                symbol = m.group('asan2_symbol')
                executable_path = m.group('asan2_executable_path')
                offset = m.group('asan2_offset')
            if boost_stacktrace \
               and m.group('boost_stacktrace1_header') is not None:
                header = m.group('boost_stacktrace1_header')
                address = m.group('boost_stacktrace1_address')
                executable_path = m.group('boost_stacktrace1_executable_path')
            if boost_stacktrace \
               and m.group('boost_stacktrace2_header') is not None:
                header = m.group('boost_stacktrace2_header')
                symbol = m.group('boost_stacktrace2_symbol')
                executable_path = m.group('boost_stacktrace2_executable_path')
            if boost_stacktrace \
               and m.group('boost_stacktrace3_header') is not None:
                header = m.group('boost_stacktrace3_header')
                symbol = m.group('boost_stacktrace3_symbol')
                source_path = m.group('boost_stacktrace3_source_path')
                line_number = m.group('boost_stacktrace3_line_number')

            if debug:
                print(line)
                print('  backtrace-filter.py: executable path: {0}'
                      .format(executable_path))
                print('  backtrace-filter.py: address: {0}'.format(address))
                print('  backtrace-filter.py: offset: {0}'.format(offset))
                print('  backtrace-filter.py: source path: {0}'
                      .format(source_path))
                print('  backtrace-filter.py: line number: {0}'
                      .format(line_number))
                print('  backtrace-filter.py: symbol: {0}'.format(symbol))

            if executable_path is not None \
               and (address is not None or offset is not None) \
               and (source_path is None or line_number is None \
                    or symbol is None):
                if offset is not None:
                    addr2line_result = addressToLine(executable_path, offset)
                else:
                    addr2line_result = addressToLine(executable_path, address)
                if source_path is None and addr2line_result[0] is not None:
                    source_path = addr2line_result[0]
                if line_number is None and addr2line_result[1] is not None:
                    line_number = addr2line_result[1]
                if symbol is None and addr2line_result[2] is not None:
                    symbol = addr2line_result[2]

            if symbol is not None:
                symbol = demangle(symbol)

            backtrace_line = ''
            if debug:
                backtrace_line += '  backtrace-filter.py: '
            if header is not None:
                backtrace_line += header
            if symbol is not None:
                backtrace_line += symbol
            else:
                backtrace_line += address
            if source_path is not None and line_number is not None \
               or executable_path is not None and offset is not None:
                backtrace_line += ' at '
            elif source_path is not None or executable_path is not None:
                backtrace_line += ' in '
            if source_path is not None:
                if not os.path.exists(source_path) and not missing_source:
                    backtrace_line += executable_path
                    if offset is not None:
                        backtrace_line += '+'
                        backtrace_line += offset
                else:
                    backtrace_line += source_path
                    if line_number is not None:
                        backtrace_line += ':'
                        backtrace_line += line_number
            elif executable_path is not None:
                backtrace_line += executable_path
                if offset is not None:
                    backtrace_line += '+'
                    backtrace_line += offset
            print(backtrace_line)
        else:
            print(line)

def parseLibSegFaultMemoryMap(text):
    base_address_map = {}
    pattern = re.compile(
        r'([0-9A-Za-z]+)-[0-9A-Za-z]+ [r-][w-]([x-])[p-] [0-9A-Za-z]+ \d\d:\d\d \d+(?: (.+))?')
    for line in text.splitlines():
        m = re.fullmatch(pattern, line)
        if m and m.group(2) == 'x' and m.group(3) is not None:
            base_address = int(m.group(1), 16)
            path = m.group(3)
            base_address_map[path] = base_address
    return base_address_map

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Scan each line in the input, and if a line is backtrace '
        'from either libSegFault, AddressSanitier, or Boost.Stacktrace, '
        'then transform the line into a format suitable to Emacs '
        'Compilation mode and output it. The other lines are output as they '
        'are.')
    parser.add_argument('FILE', nargs='?',
                        help='Without FILE, or when FILE is -, read standard '
                        'input.')
    parser.add_argument('--filter', action='append',
                        choices=['libsegfault', 'asan', 'boost-stacktrace'],
                        help='Enable transformation of backtrace lines '
                        'generated by libSegFault, AddressSanitizer, and '
                        'Boost.Stacktrace, respectively. Should be '
                        'specified at least once, and can be specified '
                        'multiple times.',
                        required=True)
    parser.add_argument('--missing-source', action='store_true',
                        help='Print the source file path (and the line '
                        'number if any) even if the source file does not '
                        'exist.')
    parser.add_argument('--debug', action='store_true',
                        help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.FILE is None or args.FILE == '-':
        text = sys.stdin.read()
    else:
        with open(args.FILE) as f:
            text = f.read()

    filters = set(args.filter)

    base_address_map = None
    if 'libsegfault' in filters:
        base_address_map = parseLibSegFaultMemoryMap(text)

    transform(text, filters, base_address_map, args.missing_source, args.debug)
