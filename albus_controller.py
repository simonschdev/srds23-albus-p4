import argparse

import nnpy
import struct
import threading
import time
from scapy.all import Ether, sniff, Packet, BitField, raw

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI

crc32_polinomials = [0x04C11DB7, 0xEDB88320]

class AlbusController:

    def __init__(self):
        self.topo = load_topo('topology.json')
        sw_name = 's1'
        self.sw_name = sw_name
        self.cpu_port =  self.topo.get_cpu_port_index(sw_name)
        device_id = self.topo.get_p4switch_id(sw_name)
        grpc_port = self.topo.get_grpc_port(sw_name)
        sw_data = self.topo.get_p4rtswitches()[sw_name]
        self.controller = SimpleSwitchP4RuntimeAPI(device_id, grpc_port,
                                                   p4rt_path=sw_data['p4rt_path'],
                                                   json_path=sw_data['json_path'])

        self.init()

    def reset(self):
        # Reset grpc server
        self.controller.reset_state()
        # Due to a bug in the way the grpc switch reset its states with the message 
        # SetForwardingPipelineConfigRequest and Action VERIFY_AND_COMMIT (this is
        # a problem in the implementation of the server), subsequent initializations
        # (i.e. those which happen after the switch reset) of multicast groups 
        # (with the same multicast id) are appended to the previous ones 
        # (i.e. those present before the reset), which are supposed to be erased by the reset, but 
        # they actually are not. This leads to duplicate packets sent to the same port.
        # This seems to be caused by the fact that, even if the grpc server is reset, the
        # switch forwarding states are not completely erased. In order to overcome this,
        # a complete reset can be achieved by resetting the switch via thrift.
        thrift_port = self.topo.get_thrift_port(self.sw_name)
        self.controller_thrift = SimpleSwitchThriftAPI(thrift_port)
        # Reset forwarding states
        self.controller_thrift.reset_state()
        i = 0
        for custom_crc32, width in sorted(self.controller_thrift.get_custom_crc_calcs().items()):
            self.controller_thrift.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1



    def init(self):
        self.reset()
        #self.add_broadcast_groups()
        #self.add_clone_session()
        #self.fill_table_test()


    def config_digest(self):
        # Up to 10 digests can be sent in a single message. Max timeout set to 1 ms.
        self.controller.digest_enable('blacklist_report_t', 1000000, 10, 1000000)

    def unpack_digest(self, dig_list):
        message_data = []
        for dig in dig_list.data:
            src_addr = '{}.{}.{}.{}'.format(*bytearray(dig.struct.members[0].bitstring))
            dst_addr = '{}.{}.{}.{}'.format(*bytearray(dig.struct.members[1].bitstring))
            src_port = "%d" % int.from_bytes(dig.struct.members[2].bitstring, byteorder='big')
            dst_port = "%d" % int.from_bytes(dig.struct.members[3].bitstring, byteorder='big')
            protocol = "%d" % int.from_bytes(dig.struct.members[4].bitstring, byteorder='big')
            message_data.append([src_addr, dst_addr, src_port, dst_port, protocol])
        return message_data

    def recv_msg_digest(self, dig_list):
        message_data = self.unpack_digest(dig_list)
        print(message_data)
        for flow in message_data:
            self.controller.table_add("blacklist", "drop", flow, [])

    def run_digest_loop(self):
        self.config_digest()
        self.controller.table_add("process_packet", "albus_update",  ['1'], ['2'])
        self.controller.table_add("process_packet", "forward_reply", ['2'], ['1'])
        self.controller.table_add("check_block", "block", ['65535'], [])
        while True:
            dig_list = self.controller.get_digest_list()
            self.recv_msg_digest(dig_list)

    def run_reading_loop(self, print_interval):
        register_names = ['LB_flow_ids', 'LB_counts', 'LB_timestamps',\
                          'PC_flow_ids', 'PC_counts']
        register_map = {}
        old_register_map = {}
        last_print_time = 0
        while True:
            time.sleep(0.05)
            now = time.time()
            change_happened = False
            for register_name in register_names:
                register_map[register_name] = self.controller_thrift.register_read(register_name)
                change_happened = change_happened or \
                                  (register_name in old_register_map.keys() and\
                                   old_register_map[register_name] != register_map[register_name])
            if change_happened or last_print_time < now - print_interval:
                last_print_time = now
                print('============================================================================')
                for register_name in register_names:
                    print(register_name, register_map[register_name])
                    old_register_map[register_name] = register_map[register_name]


if __name__ == "__main__":
    controller = AlbusController()
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', action='store_true')
    args = parser.parse_args()
    if args.r:
        register_reading_thread = threading.Thread(target=lambda x:controller.run_reading_loop(x), args=(1000,))
        register_reading_thread.start()
    controller.run_digest_loop()