###
#    Symbol Importer for WebTV (MSNTV) Builds
#
#    Author: Eric MacDonald <ubergeek03@gmail.com>
#    Date: January 30th, 2015
#
# Imports WebTV ROM symbols into IDA, Ghidra or direct to a text file
# @author Eric MacDonald (eMac)
# @category Data
# @keybinding 
# @menupath Tools.WebTV Symbol Import
# @toolbar 
#
###

import sys
import os
import struct
import re

#####################################################
#####################################################
#####################################################
#####################################################

class OUTPUT_MODE(str):
    DIRECT = 'DIRECT'
    IDA    = 'IDA'
    GHIDRA = 'GHIDRA'

class SYMBOL_DATA_TYPE(str):
    UNKNOWN       = 'UNKNOWN'
    EARLY_FORMAT1 = 'EARLY_FORMAT1'
    PRODUCTION0   = 'PRODUCTION0'
    PRODUCTION1   = 'PRODUCTION1'
    
#####################################################
#####################################################
#####################################################
#####################################################

output_mode = OUTPUT_MODE.DIRECT

try:
    from idaapi import * 
    import idautils
    import idc

    output_mode = OUTPUT_MODE.IDA
except ImportError:
    pass

if output_mode == OUTPUT_MODE.DIRECT:
    try:
        from ghidra.program.model.symbol.SourceType import *

        if createLabel:
            output_mode = OUTPUT_MODE.GHIDRA
    except:
        pass

#####################################################
#####################################################
#####################################################
#####################################################

def echo(message):
    if output_mode == OUTPUT_MODE.IDA:
        msg(message + "\n")
    else:
        print(message)

def read_symbol_file(file_name):
    echo("Reading '" + file_name)

    symbol_file_contents = open(file_name, "rb").read()

    echo("Read " + str(len(symbol_file_contents)) + " bytes.")

    return  symbol_file_contents

def detect_symbol_data_type(file_path):
    symbol_data_type = SYMBOL_DATA_TYPE.UNKNOWN
    
    with open(file_path, "rb") as hFILE:
        start = hFILE.read(0x04)

        # The symbol file format can be found by checking the first 4 bytes of the file
        version_check = struct.unpack_from(">I", start, 0x0000)[0]

    # Format that isn't used much.  This seems to be the first symbol file format used.
    # These files start with "TIMN" or "timn" Probably named after "Tim Nicholas" who worked on parts of the WebTV debugger.
    #
    #    Bytes 0x00-0x04[uint32]: Data version magic (TIMN or timn)
    #    Bytes 0x04-0x08[uint32]: Symbol count
    #    Bytes 0x08-XXXX[      ]: Symbols that are a 3tuple of a uint32 address, uint8 name string length and a name string
    #
    if version_check == 0x54494d4e or version_check == 0x74696d6e:
        symbol_data_type = SYMBOL_DATA_TYPE.EARLY_FORMAT1
    # Symbol file that starts with the symbol data without any header.
    #
    #    Bytes 0x00-XXXX[      ]: Symbols that are pairs of a uint32 address and a null-terminated name string
    #
    elif (version_check & 0xFF000000) == 0x80000000:
        symbol_data_type = SYMBOL_DATA_TYPE.PRODUCTION0
    # This is the most common symbol file format and seems to be what Microsoft settled on.
    # Classes are named at the bottom of the file.
    #
    #    Bytes 0x00-0x04[uint32]: Data version (seems to be always 0x00000001 but I assume they intended this to be a version number)
    #    Bytes 0x04-0x08[uint32]: Class name list offset. Class names are separated by a new line.
    #    Bytes 0x08-0x0c[uint32]: Symbol count
    #    Bytes 0x0c-XXXX[      ]: Symbols that are pairs of a uint32 address, possible class name index, and a null-terminated name string
    #
    elif version_check == 1:
        symbol_data_type = SYMBOL_DATA_TYPE.PRODUCTION1

    return symbol_data_type

def read_symbols(file_path):
    symbols = {}
    class_name_list = []

    if file_path == None or file_path == "" or not os.path.isfile(file_path):
        raise Exception("Input file '" + str(file_name) + "' doesn't seem to exist?")

    echo("Checking symbol file type")

    data_type = detect_symbol_data_type(file_path)

    echo("Parsing symbols for symbol file of type '" + str(data_type) + "'.")

    symbol_file_data = read_symbol_file(file_path)

    file_data_length = len(symbol_file_data)
    symbol_data_start = 0x0000
    symbol_data_end = file_data_length

    # Check we at least have the header and a few symbols.
    if file_data_length <= 0x30:
        raise Exception("Symbol data seems too short for this file?")

    # Skip the header and grab the class name list (if needed)
    if data_type == SYMBOL_DATA_TYPE.EARLY_FORMAT1:
        symbol_data_start = 0x0008
    elif data_type == SYMBOL_DATA_TYPE.PRODUCTION0 or data_type == SYMBOL_DATA_TYPE.UNKNOWN:
        symbol_data_start = 0x0000
    if data_type == SYMBOL_DATA_TYPE.PRODUCTION1:
        class_list_offset = struct.unpack_from(">I", symbol_file_data, 0x0004)[0]
        class_name_list = symbol_file_data[class_list_offset:].split(b"\x0a")

        symbol_data_start = 0x000c
        symbol_data_end = class_list_offset

    parse_offset = symbol_data_start
    while parse_offset < symbol_data_end:
        symbol_address = struct.unpack_from(">I", symbol_file_data, parse_offset)[0]
        parse_offset += 4

        # This can be the class name index, name length or the first character of the symbol name
        byte_check = struct.unpack_from(">B", symbol_file_data, parse_offset)[0]

        name_length = 0
        class_name = ""
        if data_type == SYMBOL_DATA_TYPE.EARLY_FORMAT1:
            name_length = byte_check
            parse_offset += 1
        # If the next byte is 0x80 (when we expect an ASCII char) then we need to prepend a class name
        elif byte_check == 0x80 and data_type == SYMBOL_DATA_TYPE.PRODUCTION1:
            parse_offset += 1

            class_name_index = struct.unpack_from(">H", symbol_file_data, parse_offset)[0]
            parse_offset += 2

            if class_name_index < len(class_name_list):
                class_name = class_name_list[class_name_index]
            else:
                class_name = "UNKNOWN_CLASS"

            name_length = (symbol_file_data[parse_offset:]).find(b"\x00")
        else:
            name_length = (symbol_file_data[parse_offset:]).find(b"\x00")

        symbol_name = ""
        if name_length > 0:
            symbol_name = symbol_file_data[parse_offset:(parse_offset + name_length)].decode('utf-8')

            parse_offset += len(symbol_name)

        # Skip the null character used to terminate the name string
        if data_type != SYMBOL_DATA_TYPE.EARLY_FORMAT1:
            parse_offset += 1

        if class_name != "":
            symbol_name = class_name.decode('utf-8') + "::" + symbol_name

        if symbol_name in symbols:
            symbols[symbol_name].append(symbol_address)
        else:
            symbols[symbol_name] = [symbol_address]

    return symbols

#####################################################
#####################################################
#####################################################
#####################################################

# Assign IDA names to addresses based on a symbol list.
def import_symbols_into_ida(symbols):
    echo("Importing symbols into IDA.")

    for object_name in symbols.keys():
        for object_address in symbols[object_name]:
            set_name(object_address, object_name, idc.SN_NOCHECK | idc.SN_PUBLIC | idc.SN_NOWARN)

    echo("Done importing.")

# Assign Ghidra names to addresses based on a symbol list.
def import_symbols_into_ghidra(symbols):
    echo("Importing symbols into Ghidra.")
    
    functionManager = currentProgram.getFunctionManager()
    
    for object_name in symbols.keys():
        for object_address in symbols[object_name]:
            ghidra_address = toAddr(object_address)
            ghidra_name = re.sub(r"[^!-~]", "_", object_name)

            if re.search(r"^k[A-Z]", ghidra_name) != None or re.search(r"^g[A-Z]", ghidra_name) != None:
                createLabel(ghidra_address, ghidra_name, True)
            else:
                func = functionManager.getFunctionAt(ghidra_address)
                if func != None:
                    func.setName(ghidra_name, USER_DEFINED)
                else:
                    func = createFunction(ghidra_address, ghidra_name)

    echo("Done importing.")

# Assign Ghidra names to addresses based on a symbol list.
def output_symbols_to_file(file_path, symbols):
    echo("Outpitting symbols to a file.")

    file_data = ""
    for object_name in symbols.keys():
        for object_address in symbols[object_name]:
            object_name = re.sub(r"[^!-~]", "_", object_name)

            file_data += object_name + " " + hex(object_address) + "\n"

    open(file_path, "w").write(file_data)

    echo("Done.")

#####################################################
#####################################################
#####################################################
#####################################################

echo("== eMac's symbol file loader ==")

if output_mode == OUTPUT_MODE.IDA:
    # Show a prompt to the user allowing them to select the symbol file.
    file_path = ask_file(0, "*.*", "WebTV Build Symbol File")

    if file_path != None and file_path != "":
        symbols = read_symbols(file_path)
        import_symbols_into_ida(symbols)
    else:
        echo("No symbol file selected. Exiting")
elif output_mode == OUTPUT_MODE.GHIDRA:
    # Show a prompt to the user allowing them to select the symbol file.
    file = askFile("WebTV Build Symbol File", "Import")

    if file != None and file.absolutePath != "":
        symbols = read_symbols(file.absolutePath)
        import_symbols_into_ghidra(symbols)
    else:
        echo("No symbol file selected. Exiting")
else:
    if len(sys.argv) >= 3:
        symbols = read_symbols(sys.argv[1])
        output_symbols_to_file(sys.argv[2], symbols)
    else:
        echo("Not enough arguments. Please run this as '" + sys.argv[0] + " INPUT_FILE OUTPUT_FILE'")

