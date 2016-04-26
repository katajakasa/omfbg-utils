import argparse
import os
import sys
import struct
import uuid


class DEParser(object):
    def __init__(self, file):
        self.file = file

    def get_str(self, len):
        return self.file.read(len) if len > 0 else ''

    def get_int8(self):
        return struct.unpack('<b', self.file.read(1))[0]

    def get_uint8(self):
        return struct.unpack('<B', self.file.read(1))[0]

    def get_int16(self):
        return struct.unpack('<h', self.file.read(2))[0]

    def get_uint16(self):
        return struct.unpack('<H', self.file.read(2))[0]

    def get_int32(self):
        return struct.unpack('<i', self.file.read(4))[0]

    def get_uint32(self):
        return struct.unpack('<I', self.file.read(4))[0]

    def get_var_str(self):
        return self.get_str(self.get_int32())

    def get_guid(self):
        return uuid.UUID(bytes=self.get_str(16))

    def get_pos(self):
        return self.file.tell()


class DEString(object):
    def __init__(self, value, version=1):
        self.value = value
        self.version = version

    def __str__(self):
        return u'version {} string: "{}"'.format(self.version, self.value)


class DEHeader(DEParser):
    def __init__(self, file):
        super(DEHeader, self).__init__(file)
        self.header_str = DEString(self.get_var_str(), self.get_uint8())
        self.unknown_a = self.get_uint32()
        self.object_dir_len = self.get_uint32()
        self.unknown_b = self.get_uint8()
        self.unknown_c = self.get_uint8()
        self.unknown_d = self.get_uint32()
        self.unknown_e = self.get_uint8()
        self.unknown_f = self.get_uint8()
        self.file_name = DEString(self.get_var_str())
        self.transfer_agent = DEString(self.get_var_str())
        self.some_guid = self.get_guid()
        self.unknown_g = self.get_str(9)
        self.unknown_h = self.get_uint8()
        print(self.get_pos())

    def print_content(self):
        print("Header:")
        print(u'    header_str:     {}'.format(self.header_str))
        print(u'    unknown_a:      {}'.format(self.unknown_a))
        print(u'    object_dir_len: {}'.format(self.object_dir_len))
        print(u'    unknown_b:      {}'.format(self.unknown_b))
        print(u'    unknown_c:      {}'.format(self.unknown_c))
        print(u'    unknown_d:      {}'.format(self.unknown_d))
        print(u'    unknown_e:      {}'.format(self.unknown_e))
        print(u'    unknown_f:      {}'.format(self.unknown_f))
        print(u'    file_name:      {}'.format(self.file_name))
        print(u'    transfer_agent: {}'.format(self.transfer_agent))
        print(u'    some_guid:      {}'.format(self.some_guid))
        print(u'    unknown_g:      {}'.format(repr(self.unknown_g)))
        print(u'    unknown_h:      {}'.format(self.unknown_h))


class DEFile(object):
    def __init__(self, file):
        self.header = DEHeader(file)

    def print_content(self):
        self.header.print_content()


if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser(description='Parse OMF:BG DEObjects')
    parser.add_argument(
        '-i', '--input',
        type=argparse.FileType('rb'),
        required=True,
        help='File to parse')

    args = parser.parse_args()

    # Parse file
    de_file = DEFile(args.input)
    de_file.print_content()
    args.input.close()
