# -*- coding: utf-8 -*-
#   Copyright 2017 FireEye, Inc. All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""PostgreSQL Parser"""
from __future__ import absolute_import
from __future__ import print_function
import struct
import sys
import datetime
import csv
import argparse
import logging
import os
from os import listdir
from os.path import isfile, join
import six
import vstruct
import xlsxwriter
import postgrok.schema_reader as schema_reader



def parsing_loop(file_to_parse, k, filename, output_dir, out_type):
    """Main function to read raw image/file
    1. Identify all pages/tables (find_tables function) in binary file provided (file_to_parse)
    2. Begin main loop for carving rows from identified tables
       - Each table is made up of several pages, parse row pointers from each page (parse_pointers function)
       - Loop through the pointers for each page. Each Pointer is a list made up of three items:
        - 1. Length of Row - byte length of tuple
          2. Flags - State of the item pointer:
             - 0 = Unused (should always have lp_len=0)
             - 1 = Used (should always have lp_len>0) - THE CURRENT FOCUS OF POSTGROK
             - 2 = HOT redirect (should have lp_len=0)
             - 3 = dead, may or may not have storage - TODO
          3. Offset - This is the location of the start of the row, offset from
          start of page
       - Based on the row pointers, begin parsing the headers for the Row Entries themselves, using VISECT
       - Verify the headers to validate they aren't INDEX rows. Not the focus of this tool
       - Get the BITMAP of the Row. If the row has a lot of attributes, may need to parse the extra bitmap data
       - Use all of the data obtained from the Row header to parse the row itself (parsed_row function)
       - Append parsed row to list
    3. Once all rows of been carved, output tables
    """
    total_row = 0
    successful_carves = 0

    carved_tables = list()
    all_tables = find_tables(file_to_parse)
    for table in all_tables:
        table_rows = list()
        for page in table:
            pointers = []
            start = 24
            end = start + 4
            count = 0
            while len(pointers) < page[1]:
                count += 1
                pointers.append(parse_pointers(page[0][start:end]))
                start = end
                end = start + 4
            for p in pointers:
                if (successful_carves % 20000) == 0 and successful_carves != 0:
                    print("++++++ Still working through rows, successfully parsed " + str(successful_carves) + " rows. Failed to parse: " + str(total_row-successful_carves) +  " ++++++")
                if p[0] >= 24 and p[1] == 1:
                    #deleted = "Deleted = False"
                    row_header = ROW_HEADER()
                    row_header.vsParse(page[0][p[2]:p[2] + 24])

                    if not validate_header(row_header.T_XMIN, row_header.T_XMAX, row_header.T_NATTS, row_header.T_HOFF):
                        logging.info("Identified a row containing less than 24 bytes. Likely an INDEX row. Skipping!")
                        break

                    if row_header.T_HOFF > 40:
                        d = page[0][p[2] + 24:p[2] + row_header.T_HOFF]
                        logging.info("Identified an large starting offset for a row, likely overwritten data or a non-standard table. ASCII Data: " + d + " BYTE Data: " + d.encode("hex"))
                    if row_header.T_HOFF > 24 and row_header <= 28:
                        bitmap = get_bit_mask(row_header.T_BITS, page[0][p[2] + 24:p[2] + row_header.T_HOFF])
                    else:
                        bitmap = get_bit_mask(row_header.T_BITS, "")

                    total_row += 1
                    parsed_row = parse_row(page[0], p[0], p[2], k, row_header.T_HOFF, row_header.T_NATTS, bitmap)

                    if parsed_row is not None:
                        table_rows.append(parsed_row)
                        successful_carves += 1
            #print(table_rows)
        carved_tables.append(table_rows)

    better_carved_tables = filter(None, carved_tables)
    do_output(better_carved_tables, k+"_"+filename, output_dir, out_type)
    sys.stdout.write(("\r++++++ Successful Row Carves: " + str(successful_carves)+ " / " + "Total Rows: " + str(total_row)) + " ++++++")

def find_tables(file_to_parse):
    """Function to find all tables within an image/file
    1. Function of main parsing loop:
       - Read a sector (512 bytes)
       - Determine if section *looks* like a PostgreSQL table
       - If the header check is successful, read 8192 bytes (size of postgresql page)
       - Determine the amount of bytes between the current page, and the previous page.
          - sequential pages are likely going to be a part of the same Table (will be helpful for output)
    2. Append all of the tables identified to a new list, All_tables.
    3. Return All_Tables"""

    current_pos = 0
    start_pos = 0
    previous_table_pos = 0
    count = 0
    all_tables = list()
    f = open(file_to_parse, 'rb')
    tables = list()

    while True:
        if (count % 2000) == 0 and count != 0:
            print("++++++ Still working through file, successfully identified " + str(count) + " PostgreSQL pages ++++++")
        sector = f.read(512)
        if not sector:
            break
        row_numbers, lower, start_of_rows, header_check = read_header(sector[:24])
        if header_check:
            f.seek(current_pos)
            table_chunk = f.read(8192)
            if current_pos-previous_table_pos == 8192 or current_pos-previous_table_pos == 0:
                table = [table_chunk, row_numbers]
                tables.append(table)
                count += 1
                previous_table_pos = current_pos
            elif (current_pos-previous_table_pos) != 8192:
                table = [table_chunk, row_numbers]
                all_tables.append(tables)
                tables = list()
                count += 1
                previous_table_pos = current_pos
        current_pos = (current_pos + 8192)
        f.seek(current_pos)
    f.close()
    all_tables.append(tables)
    print("++++++ Finished finding tables. Found " + str(count) + " PostgreSQL pages in " + str(len(all_tables)) + " tables. Beginning row parsing... ++++++")
    return all_tables

def parse_row(table, length, offset, keyword, hoff, natts, bitmap):
    """function to handle parsing a row
    1. Read the row header
    2. Get the schema
    3. Return the schema"""
    row_array = []
    schema_builder = ""

    row_data = table[offset + hoff:(offset+hoff) + (length - hoff)]

    if keyword in row_data.lower() or keyword == "":

        row_schema = schema_reader.SchemaReader(bitmap[:natts], row_data)
        schema = row_schema.get_schema()
        row_parsed = FIELD_DATA(schema)

        try:
            row_parsed.vsParse(row_data)
        except struct.error:
            with open("Error.log", "ab") as w:
                w.write("\rVStruct Parsing Error! Could not parse row, schema: {}, row_data: {}".format(schema, row_data.encode("hex")))
            w.close()
            return None

        for item in schema:
            if "U" in item[0] or "P" in item[0]:
                pass
            else:
                schema_builder += item[0]

        for r in row_parsed.vsGetFields():
            if 'P' in r[0] or 'U' in r[0]:
                pass
            elif 'Q' in r[0]:
                row_array.append(parse_date(r[1]))
            elif 'S' in r[0]:
                row_array.append(str(r[1]))
            else:
                row_array.append(int(r[1]))

        row_array.append(schema_builder)
        return row_array

def validate_header(xmin, xmax, natts, hoff):
    """Function to validate the header parsed from vstruct
       If the header check fails, it's likely because we've found
       an INDEX table
       1. T_XMIN - this is a transaction ID and is assoicated with the when
          the row was inserted. SHOULD NEVER BE 0.
       2. T_XMAX - Refers to the last time a row is visible.
          This is the transaction ID that identifies when this row was deleted.
       3. T_CID - a composite field that can be used to backtrack to a min and max
          command but is typically used when inserting or deleting so we can backtrack
          to the original version of the row.
       4. T_CTID - This stores a pointer to the current version of this row.
          When a row is updated, PostgreSQL will write a new version of the row
          and mark the old version as deleted (a new version of the row is written
          and the original row’s t_xmax field will gets a value). The t_ctid is 6 bytes
          – 4 bytes to store the BlockIdData (the physical location of the page in the database file)
          and the OffsetNumber (a 1-based index to a row on a disk page). Combining these two gives
          us the coordinates of the row on a page.
       5. T_NATTS -  information about NULLs, variable width columns, the current state of the row
          (is it in a transaction, the state of any transaction, how the row arrived at this location)
       8. T_HOFF - the size of the header including the size of the t_bits
          bitmap plus any associated padding that may be lurking about in the row.
          This cannot be less than 24 bytes, because that is the minumum length
          of row header
       9. T_BITS - is a variable length bitmap of null values. """

    if xmin == 0 or xmin > xmax:
        return False
    elif hoff < 24:
        return False
    elif natts == 0:
        return False

    return True



def read_header(header):
    """Function to read table header, originally used vstruct for this
       but took a huge hit on performance by running every sector
       through vstruct.
       1. pd_pagesize_version:  Beginning with PostgreSQL 8.3 the version number is 4;
            PostgreSQL 8.1 and 8.2 used version number 3; PostgreSQL 8.0 used version number 2;
            PostgreSQL 7.3 and 7.4 used version number 1; prior releases used version number 0.
            (The basic page layout and header format has not changed in most of these versions,
            but the layout of heap row headers has.)"""
    pd_lsn = header[:8] #8 bytes LSN: next byte after last byte of xlog record for last change to this page
    pd_tli = header[8:10] #2 bytes TimeLineID of last change (only its lowest 16 bits)
    pd_flags = header[10:12] # 2 bytes Flag bits
    pd_lower = header[12:14] # 2 bytes Offset to start of free space
    pd_upper = header[14:16] #2 bytes Offset to end of free space
    pd_special = header[16:18] #2 bytes Offset to start of special space
    pd_pagesize_version = header[18:20] #2 bytes Page size and layout version number information
    pd_prune_xid = header[20:24] #4 bytes Oldest unpruned XMAX on page, or zero if none
    is_valid_header = True
    number_of_row_pointers = (struct.unpack('<h', pd_lower)[0] - 24) / 4 #row entries = (pd_lower - 24) / 4 (bytes)
    start_of_row_data = struct.unpack('<h', pd_upper)[0]
    lower = struct.unpack("<h", pd_lower)[0]

    if struct.unpack('<Q', pd_lsn) == 0:
        is_valid_header = False
    elif number_of_row_pointers > 341:
        is_valid_header = False
    elif start_of_row_data <= 0 or start_of_row_data > 8192 or start_of_row_data < struct.unpack('<h', pd_lower)[0]:
        is_valid_header = False
    elif struct.unpack("<h", pd_pagesize_version)[0] != 8196:
        is_valid_header = False

    return number_of_row_pointers, lower, start_of_row_data, is_valid_header

def parse_pointers(pointer):
    """Function to parse row pointers, and return data as tuple
       Row Pointers contain three pieces of data
       1. Length of Row - from header to last column
       2. Offset - This is the location of the start of the row, offset from
          start of table
       3. Flag - FILL THIS IN"""

    unpacked_pointer = struct.unpack('<i', pointer)[0] #little_endian the pointer
    binary_equiv = bin(unpacked_pointer)[2:].zfill(32)
    length = int(binary_equiv[:15], 2)
    flag = int(binary_equiv[15:17], 2)
    offset = int(binary_equiv[17:], 2)
    p = (length, flag, offset)
    return p

def null_space_check(null_space):
    """Part of the entorpy check to verify we've got a legitimate table
    Following the row pointers, there should be some bit of null space
    This just checks for at least 16 sequential null bytes... probably
    not the best check - revist this"""
    if null_space != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00":
        return False
    else:
        return True


def get_bit_mask(t_bits, additional_bits):
    """Function to get the bitmask
       The bitmask tells us which columns have data and which do not"""
    binary = bin(struct.unpack("<B", t_bits)[0])[2:].zfill(8)[::-1]
    if binary == "00000000":
        binary = "11111111"
    if additional_bits != "":
        if len(additional_bits) > 4:
            binary_2 = bin(struct.unpack("<q", additional_bits)[0])[2:].zfill(8)[::-1]
        else:
            binary_2 = bin(struct.unpack("<i", additional_bits)[0])[2:].zfill(8)[::-1]
        combined = binary + binary_2
        return combined
    else:
        return binary

def parse_date(date):
    """Function to parse date"""
    return datetime.datetime(2000, 1, 1) + datetime.timedelta(seconds=(date / 1000000))

def do_output(parsed_table, filename, output_dir, out_type):
    """Function to output results to a file"""
    if ":" in filename:
        fn = filename.replace(":", "_")
    else:
        fn = filename
    if os.sep in fn:
        fn = fn.replace(os.sep, "_")
    else:
        fn = filename
    count = 0
    if "csv" in out_type:
        with open(output_dir + os.sep +"carved_" + fn + str(count) + ".csv", 'wb') as csvfile:
            for table in parsed_table:
                for item in table:
                    writer = csv.writer(csvfile)
                    writer.writerow(item)
    else:
        for table in parsed_table:
            count += 1
            row = 0
            col = 0
            workbook = xlsxwriter.Workbook(output_dir + os.sep +"carved_" + fn + str(count) + ".xlsx")
            worksheet = workbook.add_worksheet()
            for item in table:
                for i in item:
                    if isinstance(i, six.string_types):
                        worksheet.write(row, col, "".join([x if ord(x) < 128 else '?' for x in i]))
                    else:
                        worksheet.write(row, col, i)
                    col += 1
                row += 1
                col = 0
            workbook.close()

class ROW_HEADER(vstruct.VStruct):
    """vstruct class to parse a row header"""
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.T_XMIN = vstruct.primitives.v_int32()
        self.T_XMAX = vstruct.primitives.v_int32()
        self.T_CID = vstruct.primitives.v_int32()
        self.T_CTID = vstruct.primitives.v_bytes(size=6)
        self.T_NATTS = vstruct.primitives.v_int8()
        self.FLAGS = vstruct.primitives.v_int8()
        self.T_INFOMASK = vstruct.primitives.v_uint16()
        self.T_HOFF = vstruct.primitives.v_uint8()
        self.T_BITS = vstruct.primitives.v_bytes(size=1)

class FIELD_DATA(vstruct.VStruct):
    """Class using vstruct to dynamically parse and
    add fields as needed for a particular row given
    a row schema"""
    def __init__(self, schema):
        super(FIELD_DATA, self).__init__()
        count = 0
        for item in schema:
            count += 1
            if item[0] == 'D':
                FIELD_DATA.vsAddField(self, item[0] + str(count), vstruct.primitives.v_int32())
            elif item[0] == 'U':
                FIELD_DATA.vsAddField(self, item[0]+ str(count), vstruct.primitives.v_bytes(size=item[1]))
            elif item[0] == 'S':
                FIELD_DATA.vsAddField(self, item[0] + str(count), vstruct.primitives.v_bytes(size=item[1]))
            elif item[0] == 'P':
                FIELD_DATA.vsAddField(self, item[0] + str(count), vstruct.primitives.v_bytes(size=item[1]))
            elif item[0] == 'Q':
                FIELD_DATA.vsAddField(self, item[0] + str(count), vstruct.primitives.v_int64())


def main():
    """Main execution entry point
    1. Setup logging
    2. If the user run the program with no arguments, print help output
    3. If the user supplies a keyword, convert keyword to lowercase and store keyword
    4. If the user supplies a file, check to see what the seperator is ('\' for Windows, '/' for Linux
       Get name of file, verify file is over 8192 bytes, and then begin parsing loop
    5. If the user supplies a directory, get the files within the directory, verify file size is over
       8192 bytes, begin parsing loop for each file"""

    logging.basicConfig(filename="postgrok.log", level=logging.DEBUG, format="%(asctime)s;%(levelname)s;%(message)s")


    logging.info("PostGrok has started")

    parser = argparse.ArgumentParser(description='PostGreSQL Parser')
    parser.add_argument('-i', '--input', required=True, action='store', help='You can provide a flat binary file (ex: RAW, DD, flat binary file), or a directory containing an image, or PostgreSQL tables')
    parser.add_argument('-k', '--keyword', action='store', help='Provide a keyword to search for in a PostGreSQL row, example: "Metasploit"')
    parser.add_argument('-t', '--output_type', action='store', help="Options include CSV or XLSX. XLSX output replaces non ascii chars with '?', CSV outputs everything, but formatting will be broken on rows containing line breaks. Default is CSV")
    parser.add_argument('-o', '--output', action='store', help="Provide an output directory, if no output directory is provided, output will be written to current directory")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    args = vars(parser.parse_args())

    k = ""
    out_type = "csv"
    if 'output_type' in args and args['output_type'] != None:
        out_type = args['output_type']

    if 'keyword' in args and args['keyword'] != None:
        k = args['keyword'].lower()

    if 'output' in args and args['output'] != None:
        output_dir = args['output']
    else:
        output_dir = os.curdir

    if 'input' in args and args['input'] != None and os.path.isfile(args['input']):
        if "/" in args['input']:
            filename = args['input'].rsplit("/", 1)[-1]
        elif "\\" in args['input']:
            filename = args['input'].rsplit("\\", 1)[-1]
        else:
            filename = args['input']

        file_size = os.path.getsize(args['input'])
        if file_size < 8192:
            print("Based on size, this is not a valid table. The file should be at least 8192 bytes, " + filename + " " + "is: " + str(file_size) + " bytes")
        else:
            sys.stdout.write("\nReading from: " + filename+ "\n")
            parsing_loop(args['input'], k, filename, output_dir, out_type)

    elif 'input' in args and args['input'] != None and not os.path.isfile(args['input']):
        onlyfiles = [f for f in listdir(args['input']) if isfile(join(args['input'], f))]
        for filename in onlyfiles:
            file_size = os.path.getsize(args['input'] + os.sep + filename)
            if file_size < 8192:
                print("Based on size, this is not a valid table. The file should be at least 8192 bytes, " + filename + " " + "is: " + str(file_size) + " bytes")
            else:
                sys.stdout.write("\nReading from: " + filename + "\n")
                parsing_loop(args['input'] + os.sep + filename, k, filename, output_dir, out_type)

    logging.info("PostGrok has finished")
    return 0

if __name__ == '__main__':
    sys.exit(main())
