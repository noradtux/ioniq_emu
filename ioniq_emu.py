#!/usr/bin/env python3
""" Dongle for testing """

from socket import (socket, timeout as sock_timeout,
                    AF_CAN, PF_CAN, SOCK_DGRAM, SOCK_RAW, CAN_ISOTP,
                    CAN_RAW, CAN_EFF_FLAG, CAN_EFF_MASK, CAN_RAW_FILTER,
                    SOL_CAN_BASE, SOL_CAN_RAW)
from struct import Struct

CANFMT = Struct("<IB3x8s")


def can_str(msg):
    """ Returns a text representation of a CAN frame """
    can_id, length, data = CANFMT.unpack(msg)
    return "%x#%s (%d)" % (can_id & CAN_EFF_MASK, data.hex(' '), length)


B2101 = bytes.fromhex('2101')
B2102 = bytes.fromhex('2102')
B2103 = bytes.fromhex('2103')
B2104 = bytes.fromhex('2104')
B2105 = bytes.fromhex('2105')
B2180 = bytes.fromhex('2180')
B220100 = bytes.fromhex('220100')
B220101 = bytes.fromhex('220101')
B220102 = bytes.fromhex('220102')
B220103 = bytes.fromhex('220103')
B220104 = bytes.fromhex('220104')
B220105 = bytes.fromhex('220105')
B22b002 = bytes.fromhex('22b002')

data = {
    'IONIQ_BEV': {
        0x7e4: {
            B2101:   bytes.fromhex("""6101FFFFFFFF
                                    A5264326480300
                                    070EE912121212
                                    1212120012C615
                                    C60A0000910003
                                    4F0E00034C0400
                                    01374300012C20
                                    009B02DE0D017D
                                    0000000003E800""")[:0x03d],
            B2102:   bytes.fromhex("""6102FFFFFFFF
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6000000""")[:0x026],
            B2103:   bytes.fromhex("""6103FFFFFFFF
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6000000""")[:0x026],
            B2104:   bytes.fromhex("""6104FFFFFFFF
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6C6C6C6
                                    C6C6C6C6000000""")[:0x026],
            B2105:   bytes.fromhex("""6105FFFFFFFF
                                    00000000001212
                                    12121212122643
                                    26480001501112
                                    03E81003E80AAD
                                    00310000000000
                                    00000000000000""")[:0x02d],
            },
        0x7e6: {
            B2180:   bytes.fromhex("""6180C366C000
                                    01130000000000
                                    2273003B3A0000
                                    7A130096960000""")[:0x019],
            },
        0x7c6: {
            B22b002: bytes.fromhex("""62B002E00000
                                    0000AD00B56C00
                                    00000000000000""")[:0x00f],
            }
        },
    'IONIQ_FL_EV': {
        0x7e4: {
            B220101: bytes.fromhex("""620101FFFDE7
                                    FFC10000000003
                                    00060E491F1E1E
                                    1D1D1F1F001BD0
                                    09CF2500009400
                                    05516200047810
                                    0001C924000168
                                    A0005D9CB00D01
                                    6D0000000003E8""")[:0x03e],
            B220102: bytes.fromhex("""620102FFFFFF
                                    FFCFCFCFCFCFCF
                                    CFCFD0CFCFD0CF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCFCFAAAA""")[:0x027],
            B220103: bytes.fromhex("""620103FFFFFF
                                    FFCFCFCFCFCFCF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCFCFAAAA""")[:0x027],
            B220104: bytes.fromhex("""620104FFFFFF
                                    00CFCFCFCFCFCF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCFCFCFCF
                                    CFCFCFCF010000
                                    0000000402AAAA""")[:0x027],
            B220105: bytes.fromhex("""620105003F46
                                    10000000000000
                                    0000001B940010
                                    EC2C2400015019
                                    C703E80903E823
                                    C7001002090525
                                    186D010000AAAA""")[:0x02e],
            },
        0x7c6: {
            B22b002: bytes.fromhex("""62B002E00000
                                    00FFB300862900
                                    00000000000000""")[:0x00f],
            },
        },

    }

if __name__ == '__main__':
    car_type = 'IONIQ_BEV'

    with socket(PF_CAN, SOCK_RAW, CAN_RAW) as sock:
        sock.bind(('can0',))

        print("Waiting for frame")

        data_set = bytes()
        data_offset = 0
        data_len = 0
        frame_idx = 0

        while frame := sock.recv(72):
            print("Received frame: %s" % can_str(frame))
            can_id, length, msg_data = CANFMT.unpack(frame)

            msg_type = msg_data[0] & 0xf0
            msg_len = msg_data[0] & 0x0f

            if msg_type == 0x00:    # Command frame
                cmd = msg_data[1:msg_len+1]

                data_set = data[car_type][can_id][cmd]
                data_len = len(data_set)

                # Return first frame
                ret_msg = bytes([0x10 | (data_len >> 16)] + [data_len & 0xff]) + data_set[:6]
                ret_frame = CANFMT.pack(can_id | 8, len(ret_msg), ret_msg)
                frame_idx = 0
                data_offset = 6
                print("Send frame:     %s" % can_str(ret_frame))
                sock.send(ret_frame)

            elif msg_type == 0x30:  # Flow control frame
                if msg_data[1:] != bytes([0, 0, 0, 0, 0, 0, 0]):
                    print("TODO: proper flow control, will just send everything")

                # Return first frame
                while data_offset < data_len:
                    frame_idx = (frame_idx + 1) % 0x10
                    new_offset = min(data_len, data_offset+7)

                    ret_msg = bytes([0x20 | frame_idx]) + data_set[data_offset:new_offset]
                    if new_offset - data_offset < 7:
                        ret_msg += bytes([0] * (7 - (new_offset - data_offset)))

                    data_offset = new_offset

                    ret_frame = CANFMT.pack(can_id | 8, len(ret_msg), ret_msg)
                    print("Send frame:     %s" % can_str(ret_frame))
                    sock.send(ret_frame)

