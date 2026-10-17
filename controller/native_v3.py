"""Strict r13/r12 sampling-loop family first verified on 0.160.0.

Addresses and state offsets come from instructions, not a version lookup.
The classifier mask and register layout are deliberately exact. Live loopback
breakpoints confirmed generic 429=29 and insufficient_quota=26 for this family.
"""
import re
import struct


def outer_sites(data, classify, bounds, unique, off, va):
    def u32(at):
        return struct.unpack_from('<I',data,at)[0]
    def match(at, size, pattern, label):
        if not re.fullmatch(pattern,data[at:at+size],re.S):
            raise ValueError('v3 '+label+' changed')

    # Normalize the tagged r15 error to rax before the mask lookup.
    match(classify-28,28,
          rb'\x4c\x89\xf8\x48\xba\x00\x00\x00\x00\x00\x00\x00\x80\x48\x31\xd0\x4d\x85\xff\xba\x0d\x00\x00\x00\x48\x0f\x49\xc2',
          'error normalization')
    policy=off(va(classify)+16+struct.unpack_from('<b',data,classify+15)[0])
    match(policy,28,rb'\x41\x8b\x85....\x3d\x00\xca\x9a\x3b\x75.\xe8....\x90\x81\xfa\x00\xca\x9a\x3b\x75.', 'duration branch')
    resume=va(policy)+28+struct.unpack_from('<b',data,policy+27)[0]
    at=off(resume)
    match(at,55,rb'\x4c\x8b\xa5....\x49\x89\x84\x24....\x41\x89\x94\x24....\x49\x8b\x84\x24....\x41\x8b\x8c\x24....\x49\x89\x84\x24....\x41\x89\x8c\x24....', 'duration stores')
    # Establish that policy r13 and resumed r12 refer to the same state.
    state_load=unique(rb'\x4c\x8b\xad....\x41\xc6\x85....\x00\x41\x0f\xb6\x85....\xfe\xc0\x4d\x8b\xa5....\x4d\x8b\xbd',off(bounds[0]),classify,label='v3 state load')
    if u32(state_load+3)!=u32(at+3):
        raise ValueError('v3 state base reload disagrees')
    deadline=at+31
    if u32(policy+3)!=u32(deadline+4) or u32(policy+3)!=u32(at+27)+8:
        raise ValueError('v3 server deadline fields disagree')
    connection=at+55
    match(connection,8,rb'\x49\x8b\x84\x24....','connection branch')
    count=unique(rb'\x49\x8b\x84\x24....\x48\x8b\x08\x49\x3b\x8c\x24....\x0f\x83....\x4d\x8b\x8c\x24....\x4c\x89\x08\x41\x0f\xb6\x8c\x24....\x49\x8b\x84\x24....\x49\x8b\x94\x24....\x48\x8b\x12\x48\x83\xc2\x10\x4d\x8b\x84\x24....\x45\x8b\x94\x24....',off(bounds[0]),off(bounds[1]-1)+1,label='v3 outer budget')
    budget=u32(count+15)
    if budget!=u32(count+49):
        raise ValueError('v3 budget load does not match comparison')
    if u32(at+11)!=u32(count+72) or u32(at+19)!=u32(count+80):
        raise ValueError('v3 duration loads do not match stores')
    if u32(connection+4)!=u32(count+57):
        raise ValueError('v3 connection state does not match budget path')
    return dict(policy=policy,policy_size=28,resume=resume,deadline=deadline,deadline_size=8,
                connection=connection,connection_size=8,count_site=count,budget=budget,
                policy_prefix=b'\x49\xc7\x85',classify_prefix=b'\x48\xba',mask=0x8facffd9e3,rate_bit=29)
