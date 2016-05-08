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

    def close(self):
        self.handle.close()

    def get_pos(self):
        return self.handle.tell()

    def check_uint8(self, compare_to):
        if self.get_uint8() != compare_to:
            raise DEOInvalidDataException()

    def check_uint32(self, compare_to):
        if self.get_uint32() != compare_to:
            raise DEOInvalidDataException()

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

    def put_str(self, data):
        self.handle.write(data)

    def put_int8(self, data):
        self.handle.write(struct.pack('<b', data))

    def put_uint8(self, data):
        self.handle.write(struct.pack('<B', data))

    def put_int16(self, data):
        self.handle.write(struct.pack('<h', data))

    def put_uint16(self, data):
        self.handle.write(struct.pack('<H', data))

    def put_int32(self, data):
        self.handle.write(struct.pack('<i', data))

    def put_uint32(self, data):
        self.handle.write(struct.pack('<I', data))

    def put_var_str(self, data, length):
        self.put_uint32(length)
        self.put_str(data)

    def put_var_len(self, data):
        if data >= 0xFF:
            self.put_uint8(0xFF)
            self.put_uint32(data)
        else:
            self.put_uint8(data)

    def put_guid(self, data):
        self.handle.write(data.bytes)


class DEOElement(object):
    def write(self, parser):
        raise NotImplementedError


class DEOBlob(DEOElement):
    def __init__(self, parser=None, length=0):
        self.length = length
        self.value = ''
        if parser:
            self.read(parser)

    def read(self, parser):
        self.value = parser.get_str(self.length)

    def write(self, parser):
        parser.put_str(self.value)

    def __str__(self):
        return repr(self.value)


class DEOVariableBlob(DEOElement):
    def __init__(self, parser=None):
        self.length = 0
        self.data = ''
        if parser:
            self.read(parser)

    def read(self, parser):
        self.length = parser.get_var_len()
        self.data = parser.get_str(self.length)

    def write(self, parser):
        parser.put_var_len(self.length)
        parser.put_str(self.data)

    def __str__(self):
        return repr(self.data)


class DEOString(DEOElement):
    def __init__(self, parser=None, has_version=False):
        self.value = ''
        self.version = 1
        self.has_version = has_version
        if parser:
            self.read(parser, has_version)

    def read(self, parser, read_version=False):
        self.value = parser.get_var_str()
        if read_version:
            self.version = parser.get_uint8()
            self.has_version = True

    def write(self, parser):
        parser.put_var_str(self.value, len(self.value))
        if self.has_version:
            parser.put_uint8(self.version)

    def __str__(self):
        return unicode(self.value)


class DEOPrintHelperMixin(object):
    @staticmethod
    def print_helper(name, var):
        print(u'    {:<20}{}'.format(name, var))


class DEOHeader(DEOPrintHelperMixin, DEOElement):
    def __init__(self, parser=None):
        super(DEOHeader, self).__init__()
        self.header_str = DEOString()
        self.unknown_a = 0
        self.object_dir_len = 0
        self.unknown_len = 0
        self.unknown_f = 0
        self.file_name = DEOString()
        self.transfer_agent = DEOString()
        self.some_guid = uuid.uuid4()
        self.unknown_g = ''
        self.unknown_i = 0
        self.unknown_blob = DEOVariableBlob()
        self.unknown_k = 0
        if parser:
            self.read(parser)

    def read(self, parser):
        self.header_str = DEOString(parser, has_version=True)
        self.unknown_a = parser.get_uint32()
        self.object_dir_len = parser.get_uint32()
        parser.check_uint8(9)
        self.unknown_len = parser.get_var_len()
        parser.check_uint8(4)
        self.unknown_f = parser.get_uint8()
        self.file_name = DEOString(parser)
        self.transfer_agent = DEOString(parser)
        self.some_guid = parser.get_guid()
        self.unknown_g = parser.get_str(9)
        parser.check_uint8(4)
        self.unknown_i = parser.get_uint32()
        parser.check_uint8(1)
        self.unknown_blob = DEOVariableBlob(parser)
        self.unknown_k = parser.get_uint32()

    def write(self, parser):
        pass

    def print_content(self):
        print("Header:")
        self.print_helper("header_str", self.header_str)
        self.print_helper("unknown_a", self.unknown_a)
        self.print_helper("object_dir_len", self.object_dir_len)
        self.print_helper("unknown_len", self.unknown_len)
        self.print_helper("unknown_f", self.unknown_f)
        self.print_helper("file_name", self.file_name)
        self.print_helper("transfer_agent", self.transfer_agent)
        self.print_helper("some_guid", self.some_guid)
        self.print_helper("unknown_g", repr(self.unknown_g))
        self.print_helper("unknown_i", self.unknown_i)
        self.print_helper("unknown_blob", self.unknown_blob)
        self.print_helper("unknown_k", self.unknown_k)


class DEOObject(DEOElement):
    def __init__(self, parser=None):
        super(DEOObject, self).__init__()
        self.entry_len = 0
        self.name = DEOString()
        self.type = DEOString()
        self.guid = uuid.uuid4()
        self.unknown_a = 0
        self.data_position = 0
        if parser:
            self.read(parser)

    def read(self, parser):
        parser.check_uint8(4)
        self.entry_len = parser.get_var_len()
        self.name = DEOString(parser)
        self.type = DEOString(parser)
        self.guid = parser.get_guid()
        parser.check_uint8(0)
        self.unknown_a = parser.get_uint32()
        parser.check_uint32(0)
        parser.check_uint8(4)
        self.data_position = parser.get_uint32()

    def write(self, parser):
        pass

    def print_content(self):
        print(u"    {:<4}{:<4}{:<9}{:<38}{:<24}{:<32}".format(
            self.entry_len, self.unknown_a, self.data_position, self.guid, self.name, self.type))


class DEODirectory(DEOElement, DEOPrintHelperMixin):
    def __init__(self, parser=None, length=0):
        super(DEODirectory, self).__init__()
        self.dir_len = length
        self.dir_list = []
        if parser:
            self.read(parser)

    def read(self, parser):
        while parser.get_pos() < self.dir_len:
            self.dir_list.append(DEOObject(parser))

    def write(self, parser):
        for dir_obj in self.dir_list:
            dir_obj.write(parser)

    def print_content(self):
        print("Directory:")
        print(u"    {:<4}{:<4}{:<9}{:<38}{:<24}{:<32}".format(
            u'Len', u'Unk', u'Off', u'GUID', u'Name', u'Type',))
        for entry in self.dir_list:
            entry.print_content()


class DEOFile(object):
    def __init__(self, parser):
        self.header = DEOHeader(parser)
        self.directory = DEODirectory(parser, self.header.object_dir_len)


if __name__ == "__main__":
    # Parse args
    argparser = argparse.ArgumentParser(description='Parse OMF:BG DEObjects')
    argparser.add_argument(
        '-i', '--input',
        type=argparse.FileType('rb'),
        required=True,
        help='File to parse')
    argparser.add_argument(
        '-l', '--log',
        type=str,
        required=False,
        help='Logfile')
    argparser.add_argument(
        '-d',
        action='count',
        help='Enable more verbose logging (-d for info, -dd for debug)')
    argparser.add_argument(
        '--directory',
        action='count',
        help='Dump directory contents to stdout')
    argparser.add_argument(
        '--header',
        action='count',
        help='Dump header contents to stdout')

    args = argparser.parse_args()

    # Set up logging
    try:
        log_level = {
            0: logging.WARNING,
            1: logging.INFO,
            2: logging.DEBUG,
        }[args.d]
    except KeyError:
        log_level = logging.WARNING
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
        de_parser = DEOParser(args.input)
        de_file = DEOFile(de_parser)
        if args.header:
            de_file.header.print_content()
        if args.directory:
            de_file.directory.print_content()
    except DEOInvalidDataException:
        log.error("File is invalid type or malformed.")
    finally:
        args.input.close()
