import argparse
import logging
import struct
import uuid
import sys


class DEOParserException(Exception):
    pass


class DEOInvalidDataException(DEOParserException):
    pass


class DEOParser(object):
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
        return self.get_str(self.get_uint32())

    def get_var_len(self):
        len_a = self.get_uint8()
        if len_a == 0xFF:
            return self.get_uint32()
        return len_a

    def get_guid(self):
        return uuid.UUID(bytes=self.get_str(16))

    def get_pos(self):
        return self.handle.tell()


class DEOString(object):
    def __init__(self, value, version=1):
        self.value = value
        self.version = version

    def __str__(self):
        return u'version {} string: "{}"'.format(self.version, self.value)


class DEOPrintHelperMixin(object):
    @staticmethod
    def print_helper(name, var, compare=None):
        check_str = ''
        if compare:
            if compare == var:
                check_str = ' [OK]'
            else:
                check_str = ' [NOK]'
        print(u'    {:<20}{}{}'.format(name, var, check_str))


class DEOHeader(DEOParser, DEOPrintHelperMixin):
    def __init__(self, handle):
        super(DEOHeader, self).__init__(handle)
        self.header_str = DEOString(self.get_var_str(), self.get_uint8())
        self.unknown_a = self.get_uint32()
        self.object_dir_len = self.get_uint32()
        self.unknown_b = self.get_uint8()
        if self.unknown_b != 9:
            raise DEOInvalidDataException()
        self.unknown_len = self.get_var_len()
        self.unknown_e = self.get_uint8()
        if self.unknown_e != 4:
            raise DEOInvalidDataException()
        self.unknown_f = self.get_uint8()
        self.file_name = DEOString(self.get_var_str())
        self.transfer_agent = DEOString(self.get_var_str())
        self.some_guid = self.get_guid()
        self.unknown_g = self.get_str(9)
        self.unknown_h = self.get_uint8()
        if self.unknown_h != 4:
            raise DEOInvalidDataException()
        self.unknown_i = self.get_uint32()
        self.unknown_j = self.get_uint8()
        if self.unknown_j != 1:
            raise DEOInvalidDataException()
        self.unknown_blob_len = self.get_var_len()
        self.unknown_blob = self.get_str(self.unknown_blob_len)
        self.unknown_k = self.get_uint32()

    def print_content(self):
        print("Header:")
        self.print_helper("header_str", self.header_str)
        self.print_helper("unknown_a", self.unknown_a)
        self.print_helper("object_dir_len", self.object_dir_len)
        self.print_helper("unknown_b", self.unknown_b, compare=9)
        self.print_helper("unknown_len", self.unknown_len)
        self.print_helper("unknown_e", self.unknown_e, compare=4)
        self.print_helper("unknown_f", self.unknown_f)
        self.print_helper("file_name", self.file_name)
        self.print_helper("transfer_agent", self.transfer_agent)
        self.print_helper("some_guid", self.some_guid)
        self.print_helper("unknown_g", repr(self.unknown_g))
        self.print_helper("unknown_h", self.unknown_h, compare=4)
        self.print_helper("unknown_i", self.unknown_i)
        self.print_helper("unknown_j", self.unknown_j, compare=1)
        self.print_helper("unknown_blob_len", self.unknown_blob_len)
        self.print_helper("unknown_blob", repr(self.unknown_blob))
        self.print_helper("unknown_k", self.unknown_k)


class DEOObject(DEOParser):
    def __init__(self, handle):
        super(DEOObject, self).__init__(handle)
        if self.get_uint8() != 4:
            raise DEOInvalidDataException()
        self.entry_len = self.get_var_len()
        self.name = self.get_var_str()
        self.type = self.get_var_str()
        self.guid = self.get_guid()
        if self.get_uint8() != 0:
            raise DEOInvalidDataException()
        self.unknown_a = self.get_uint32()
        if self.get_uint32() != 0:
            raise DEOInvalidDataException()
        if self.get_uint8() != 4:
            raise DEOInvalidDataException()
        self.data_position = self.get_uint32()

    def print_content(self):
        print(u"    {:<4}{:<4}{:<9}{:<38}{:<24}{:<32}".format(
            self.entry_len,
            self.unknown_a,
            self.data_position,
            self.guid,
            self.name,
            self.type,
        ))


class DEODirectory(DEOParser, DEOPrintHelperMixin):
    def __init__(self, handle, length):
        super(DEODirectory, self).__init__(handle)
        self.dir_len = length
        self.dir_list = []
        while self.get_pos() < self.dir_len:
            self.dir_list.append(DEOObject(handle))

    def print_content(self):
        print("Directory:")
        print(u"    {:<4}{:<4}{:<9}{:<38}{:<24}{:<32}".format(
            u'Len', u'Unk', u'Off', u'GUID', u'Name', u'Type',))
        for entry in self.dir_list:
            entry.print_content()


class DEOFile(object):
    def __init__(self, handle):
        self.header = DEOHeader(handle)
        self.directory = DEODirectory(handle, self.header.object_dir_len)


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
    parser.add_argument(
        '--directory',
        action='count',
        help='Dump directory contents to stdout')
    parser.add_argument(
        '--header',
        action='count',
        help='Dump header contents to stdout')

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
    try:
        de_file = DEOFile(args.input)
        if args.directory > 0:
            de_file.directory.print_content()
        if args.header > 0:
            de_file.header.print_content()
    except DEOInvalidDataException:
        log.error("File is invalid type or malformed.")
    finally:
        args.input.close()
