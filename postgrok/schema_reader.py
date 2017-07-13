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

"""Libary to handle reading the row schema"""
from __future__ import absolute_import
import struct
import datetime
import sys

class SchemaReader():
    """Class for handling schema reading operations"""
    def __init__(self, bitmap, row_data):
        """Initialize the Schema Reader class with
        information needed to parse a row.
        1. Bitmap - Bitmap corresponds to the attributes that
           have data, and those that don't. Use the bitmap to
           understand which columns have data, and how many iterations
           the loop needs to go through
        2. row_data - contains the actual binary data mapping starting at
           the end of the row header"""
        self.bitmap = bitmap
        self.row_data = row_data

    def get_schema(self):
        """Essentailly a loop to intelligently predict what type of data is
           in a structure.
        1. Every row starts with a row ID, so the first iteration we can add a
           four byte structure corresponding to the row id
        2. Next, if the bit is 0, then this is a blank column, and we can move on
           to the next column, but we still need to track it
        3. Next, we check for a 8 byte structure, so far, and 8 byte structure always
           corresponds to a date
        4. Next, we check four a for a 1 byte varlen structure. Varlen structures tell
           us how long the following variable length string is
        5. Next, we check to see if the byte is a padding byte (\x00)
        6. If none of the above checks out, the assumption is that we have a
           DWORD value
           TODO: This algorithm doesn't always work. In situations where (what situations?)
        7. Encapsulated in a Try-Except because sometimes the loop gets to the end of the 
            row data and tries to keep parsing, some sort of issue with the len of bitmap."""
        pos = 0
        row_schema = list()
        counter = 0
        try:
            while counter < len(self.bitmap):
                if counter == 0:
                    field_tuple = ('D', 4)
                    pos += 4
                elif self.check_string_zero(self.bitmap[counter]):
                    field_tuple = ("S", 0)
                elif self.check_qword(self.row_data[pos:pos + 8]):
                    field_tuple = ("Q", 8)
                    pos += 8
                elif self.check_varlen1b_struct(struct.unpack("<B", (self.row_data[pos:pos + 1]))[0], self.row_data[pos:]):
                    var_byte = struct.unpack("<B", (self.row_data[pos:pos + 1]))[0]
                    field_size = self.get_varlena_size_1b(var_byte)
                    len_byte = ("U", 1)
                    row_schema.append(len_byte)
                    field_tuple = ("S", field_size)
                    pos += field_size + 1
                elif self.check_padding(self.row_data[pos:pos + 1]):
                    field_tuple = ("P", 1)
                    pos += 1
                    counter = counter - 1
                elif self.check_varlen4b_struct(self.row_data[pos:pos + 4]):
                    field_size = self.get_varlena_size_4b(self.row_data[pos:pos + 4]) - 4
                    len_byte = ("U", 4)
                    row_schema.append(len_byte)
                    field_tuple = ("S", field_size)
                    pos += field_size + 4
                else:
                    field_tuple = ("D", 4)
                    pos += 4
                row_schema.append(field_tuple)
                counter += 1
        except struct.error as e:
            return row_schema
        return row_schema
        

    @staticmethod
    def check_string_zero(item):
        """Helper method for determining if a bit is a 0 or 1"""
        if item == '0':
            return True

    @staticmethod
    def check_varlen4b_struct(structure):
        """Helper method for identifying a 4 byte varlen structure
        A 4 byte varlen structure MUST be greater than 126 (max size for 1 byte varlen struct)
        and less than 8192 (max len of a table).
        NOTE: This is a potential pitfall, this could return true, but potentially map to DWORD
        int field, rather than varlen struct. Implement verify field check for this"""
        field_size = SchemaReader.get_varlena_size_4b(structure) - 4
        return field_size > 126 and field_size < 8192

    @staticmethod
    def check_qword(structure):
        """Helper method for checking to see if a QWORD will map to a legitmate date"""
        current_time = ((datetime.datetime.now() - datetime.datetime(2000, 1, 1)).total_seconds())*1000000
        lower_bound = ((datetime.datetime(2001, 1, 1) - datetime.datetime(2000, 1, 1)).total_seconds())*1000000
        try:
            data_comp = struct.unpack("<Q", structure)[0]
        except struct.error:
            return False
        return data_comp < current_time and data_comp > lower_bound

    @staticmethod
    def check_padding(byte):
        """Helper method to check if byte is a padding byte"""
        if byte == '\x00':
            return True

    @staticmethod
    def check_varlen1b_struct(byte, row_data):
        """Helper method to check if byte corresponds to 1 byte varlen structure
           To be a legit varlen struct the following must be true
           1. ord(byte) > 0
           2. ord(byte) mod 2 must be 1 (why is this true, postgres doc tells)
           3. ord(byte) - 3 /2 must be greater than 0. (why?)
           If all of these checks are true, go onto the second check - verify ascii characters"""
        pos = 0
        if byte > 0 and byte % 2 == 1 and (byte - 3)/2 > 0:
            field_size = SchemaReader.get_varlena_size_1b(byte)
            is_valid_string = SchemaReader.verify_field(row_data[pos+1:pos + field_size])
            if is_valid_string:
                if (byte == 5 or byte == 7) and row_data[1:2] == '\x00':
                    return False
            return is_valid_string
        else:
            return False

    @staticmethod
    def get_varlena_size_1b(byte):
        """Helper method to decode and obtain the size of
           a 1 byte varlena structure"""
        shift_byte = byte >> 1
        mask_byte = shift_byte & 127
        var_column_size = mask_byte - 1
        return var_column_size

    @staticmethod
    def get_varlena_size_4b(byte):
        """Helper method to decode and obtain the size of a 4 byte
        varlena structure"""
        #print(byte.encode("hex"))
        unpacked = struct.unpack("<i", byte)[0]
        shift_byte = unpacked >> 2
        anded_byte = shift_byte & 2147483647
        return anded_byte

    @staticmethod
    def verify_field(field_data):
        """Helper method to check that following a varlen structure
        the subsequent X bytes (obtained by decoding varlen struct)
        are actually ascii characters"""
        #can do the check for \x03, \x05, \x07 here
        for char in field_data:
            if (ord(char) < 32 or ord(char) > 126) and char != '\x0a':
                return False
        return True
