"""An appended read/execute section for stackless retry helpers.

The original sections, exception tables and shared functions stay intact.
All helper references are relative, and the journal restores the headers and
truncates the appended section back to the exact original signed file.
"""
import struct


def layout(data, pe):
    def align(value, alignment):
        if alignment <= 0 or alignment & (alignment-1):
            raise ValueError('invalid PE alignment')
        return (value+alignment-1) & -alignment

    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    header = pe.sections[-1].get_file_offset()+40
    if (header+40 > min(pe.OPTIONAL_HEADER.SizeOfHeaders,
                        min(s.PointerToRawData for s in pe.sections if s.SizeOfRawData))
            or data[header:header+40] != bytes(40)):
        raise ValueError('no unused PE section header')
    rva = align(max(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)
                    for s in pe.sections), section_alignment)
    raw = align(len(data),file_alignment)
    return dict(header=header,rva=rva,raw=raw,base=pe.OPTIONAL_HEADER.ImageBase,
                original_size=len(data),file_alignment=file_alignment,
                section_alignment=section_alignment,sections=pe.FILE_HEADER.NumberOfSections,
                count_offset=pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),
                image_offset=pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),
                code_offset=pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),
                code_size=pe.OPTIONAL_HEADER.SizeOfCode)


def section_patches(s, code):
    def align(value, alignment):
        return (value+alignment-1) & -alignment
    raw_size = align(len(code),s['file_alignment'])
    header = struct.pack('<8sIIIIIIHHI',b'.cretry',len(code),s['rva'],raw_size,s['raw'],0,0,0,0,0x60000020)
    tail = bytes(s['raw']-s['original_size'])+code.ljust(raw_size,b'\0')
    return [(s['count_offset'],2,struct.pack('<H',s['sections']+1),'retry_section_count'),
            (s['image_offset'],4,struct.pack('<I',align(s['rva']+len(code),s['section_alignment'])),'retry_image_size'),
            (s['code_offset'],4,struct.pack('<I',s['code_size']+raw_size),'retry_code_size'),
            (s['header'],40,header,'retry_section_header'),
            (s['original_size'],len(tail),tail,'retry_helpers')]


class Code:
    """Resolve local rel32 branches and RIP references without an assembler."""
    def __init__(self):
        self.data = bytearray()
        self.labels = {}
        self.fixups = []

    def emit(self, value):
        self.data.extend(bytes.fromhex(value) if isinstance(value,str) else value)

    def label(self, name):
        if name in self.labels:
            raise ValueError('duplicate helper label')
        self.labels[name] = len(self.data)

    def relative(self, opcode, target):
        self.emit(opcode)
        self.fixups.append((len(self.data),target))
        self.emit(bytes(4))

    def finish(self):
        for offset,target in self.fixups:
            struct.pack_into('<i',self.data,offset,self.labels[target]-offset-4)
        return bytes(self.data)
