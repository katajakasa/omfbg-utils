import argparse
import logging
import struct
import uuid
import sys


class DEParser(object):
    def __init__(self, handle):
        self.handle = handle

    def get_str(self, length):
        return self.handle.read(length) if length > 0 else ''

    def get_int8(self):
        return struct.unpack('<b', self.handle.read(1))[0]

    def get_uint8(self):
        return struct.unpack('<B', self.handle.read(1))[0]

    def get_int16(self):
        return struct.unpack('<h', self.handle.read(2))[0]

    def get_uint16(self):
        return struct.unpack('<H', self.handle.read(2))[0]

    def get_int32(self):
        return struct.unpack('<i', self.handle.read(4))[0]

    def get_uint32(self):
        return struct.unpack('<I', self.handle.read(4))[0]

    def get_var_str(self):
        return self.get_str(self.get_int32())

    def get_guid(self):
        return uuid.UUID(bytes=self.get_str(16))

    def get_pos(self):
        return self.handle.tell()


class DEString(object):
    def __init__(self, value, version=1):
        self.value = value
        self.version = version

    def __str__(self):
        return u'version {} string: "{}"'.format(self.version, self.value)


class DEHeader(DEParser):
    def __init__(self, handle):
        super(DEHeader, self).__init__(handle)
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
    def __init__(self, handle):
        self.header = DEHeader(handle)

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
    parser.add_argument(
        '-l', '--log',
        type=str,
        required=False,
        help='Logfile')
    parser.add_argument(
        '-d',
        action='count',
        help='Enable more verbose logging (-d for info, -dd for debug)')

    args = parser.parse_args()

    # Set up logging
    log_level = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }[args.d]
    log_format = '[%(asctime)s] %(message)s'
    log_datefmt = '%d.%m.%Y %I:%M:%S'
    if args.log:
        logging.basicConfig(filename=args.log,
                            filemode='wb',
                            level=log_level,
                            format=log_format,
                            datefmt=log_datefmt)
    else:
        logging.basicConfig(stream=sys.stderr,
                            level=log_level,
                            format=log_format,
                            datefmt=log_datefmt)

    log = logging.getLogger(__name__)
    log.info(u'Parsing file "%s"', args.input.name)

    # Parse file
    de_file = DEFile(args.input)
    de_file.print_content()
    args.input.close()
