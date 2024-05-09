#!/usr/bin/env python
'''
This file contains Python command to enable PFC storm using SDK APIs on a fanout switch.
The idea is
    1. Set QoS mappings
    2. Set PG to lossless and enable the shared headroom pool
    3. Set shared headroom pool size to 0
    4. The PFC will be triggered

'''
import sys
import time
from python_sdk_api.sx_api import *
import argparse
import logging
import logging.handlers

class SdkError(Exception):
    pass

def on_sdk_error(info):
    print(info)
    raise SdkError


PG_SIZE = 200
PG_XON = 100
PG_XOFF = 100
LOSSY = 1
LOSSLESS = 0

def pfc_port_set(handle, port, priority, fc_mode):
    rc = sx_api_port_pfc_enable_set(handle, port, priority, fc_mode)
    if rc != SX_STATUS_SUCCESS:
        on_sdk_error(("sx_api_port_pfc_enable_set: 0x%x enabled, rc %d" % (port, rc)))


switch_prio_p = new_sx_cos_priority_t_arr(1)
ieee_prio_p = new_sx_cos_ieee_prio_t_arr(1)
prio_to_buff_p = new_sx_cos_port_prio_buff_t_p()

def set_ieee_priority_sp_mapping(handle, port, priority):
    sx_cos_priority_t_arr_setitem(switch_prio_p, 0, priority)
    sx_cos_ieee_prio_t_arr_setitem(ieee_prio_p, 0, priority)

    rc = sx_api_cos_prio_to_ieeeprio_set(handle, switch_prio_p, ieee_prio_p, 1)
    if rc != SX_STATUS_SUCCESS:
        on_sdk_error("Failed to set priority to IEEE priority mapping, rc = %d\n" % (rc))


def set_port_prio_buffer_mapping(handle, port, sp, pg):
    rc = sx_api_cos_port_prio_buff_map_get(handle, port, prio_to_buff_p)
    if rc != SX_STATUS_SUCCESS:
        on_sdk_error("sx_api_cos_port_prio_buff_map_get failed, rc = %d\n" % (rc))

    sx_cos_port_buff_t_arr_setitem(prio_to_buff_p.prio_to_buff, sp, pg)

    rc = sx_api_cos_port_prio_buff_map_set(handle, SX_ACCESS_CMD_SET, port, prio_to_buff_p)
    if rc != SX_STATUS_SUCCESS:
        on_sdk_error("sx_api_cos_port_prio_buff_map_set failed, rc = %d\n" % (rc))


def set_port_pg_lossless(handle, log_port, pg, enable):
    port_buffer_attr_cnt = 1
    port_buffer_attr_list_p = new_sx_cos_port_buffer_attr_t_arr(1)

    attr_item_min = sx_cos_port_buffer_attr_t_arr_getitem(port_buffer_attr_list_p, 0)

    attr_item_min.type = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E
    attr_item_min.attr.ingress_port_pg_buff_attr.pg = pg
    attr_item_min.attr.ingress_port_pg_buff_attr.pool_id = 0
    if enable:
        attr_item_min.attr.ingress_port_pg_buff_attr.is_lossy = LOSSLESS
        attr_item_min.attr.ingress_port_pg_buff_attr.xon = PG_XON
        attr_item_min.attr.ingress_port_pg_buff_attr.xoff = PG_XOFF
        attr_item_min.attr.ingress_port_pg_buff_attr.use_shared_headroom = 1
        attr_item_min.attr.ingress_port_pg_buff_attr.size = PG_SIZE
    else:
        attr_item_min.attr.ingress_port_pg_buff_attr.is_lossy = LOSSY
        attr_item_min.attr.ingress_port_pg_buff_attr.xon = 0
        attr_item_min.attr.ingress_port_pg_buff_attr.xoff = 0
        attr_item_min.attr.ingress_port_pg_buff_attr.use_shared_headroom = 0
        attr_item_min.attr.ingress_port_pg_buff_attr.size = 0

    print("\nSetting Port PG:")
    print("type  = SX_COS_INGRESS_PORT_PRIORITY_GROUP_ATTR_E")
    print(("size  = %d" % (attr_item_min.attr.ingress_port_pg_buff_attr.size)))
    print(("PG    = %d" % (attr_item_min.attr.ingress_port_pg_buff_attr.pg)))
    print(("is_lossy (0=Lossless)  = %d" % (attr_item_min.attr.ingress_port_pg_buff_attr.is_lossy)))
    print(("Xon  = %d" % (attr_item_min.attr.ingress_port_pg_buff_attr.xon)))
    print(("Xoff  = %d" % (attr_item_min.attr.ingress_port_pg_buff_attr.xoff)))
    print(("use_shared_headroom = %d" % (attr_item_min.attr.ingress_port_pg_buff_attr.use_shared_headroom)))

    attr_item_min = sx_cos_port_buffer_attr_t_arr_setitem(port_buffer_attr_list_p, 0, attr_item_min)

    rc = sx_api_cos_port_buff_type_set(handle, SX_ACCESS_CMD_SET, log_port, port_buffer_attr_list_p, 1)
    if rc != SX_STATUS_SUCCESS:
        sys.exit(rc)
        on_sdk_error(("sx_api_cos_port_buff_type_set [cmd=%d, log_port=0x%x , cnt=%d, rc=%d] " % (SX_ACCESS_CMD_SET, log_port, 1, rc)))


def build_port_name_dict():
    result = {}
    for port in range(64):
        result['ethsl1p{}'.format(port+1)] = port, 0
        for split_port in range(8):
            result['ethsl1p{}sp{}'.format(port+1, split_port+1)] = port, split_port

    return result


def get_port_map(handle):
    portmap = {}

    # Get ports count
    port_cnt_p = new_uint32_t_p()
    uint32_t_p_assign(port_cnt_p, 0)
    port_attributes_list = new_sx_port_attributes_t_arr(0)
    rc = sx_api_port_device_get(handle, 1, 0, port_attributes_list, port_cnt_p)
    if rc != SX_STATUS_SUCCESS:
        print("sx_api_port_device_get failed, rc = %d" % (rc))
        sys.exit(rc)
    port_cnt = uint32_t_p_value(port_cnt_p)

    # Get ports
    port_attributes_list = new_sx_port_attributes_t_arr(port_cnt)
    rc = sx_api_port_device_get(handle, 1, 0, port_attributes_list, port_cnt_p)
    if (rc != SX_STATUS_SUCCESS):
        print("sx_api_port_device_get failed, rc = %d")
        sys.exit(rc)

    for i in range(0, port_cnt):
        port_attributes = sx_port_attributes_t_arr_getitem(port_attributes_list, i)
        log_port = int(port_attributes.log_port)
        subports = portmap.get(port_attributes.port_mapping.module_port)
        if subports:
            subports.append(log_port)
            subports.sort()
        else:
            subports = [log_port]

        portmap[port_attributes.port_mapping.module_port] = subports

    return portmap


def parse_priority(x):
    priorities = []
    for i in range(8):
        if (1 << i) & x:
            priorities.append(i)
    return priorities


def start_pfc(handle, log_ports, priority):
    for log_port in log_ports:
        set_ieee_priority_sp_mapping(handle, log_port, priority)
        set_port_prio_buffer_mapping(handle, log_port, priority, priority)

        pfc_port_set(handle, log_port, priority, SX_PORT_FLOW_CTRL_MODE_TX_EN_RX_EN)

        # Set port PG to use the port shared headroom
        set_port_pg_lossless(handle, log_port, priority, True)


def stop_pfc(handle, log_ports, priority):
    for log_port in log_ports:
        set_port_pg_lossless(handle, log_port, priority, False)
        pfc_port_set(handle, log_port, priority, SX_PORT_FLOW_CTRL_MODE_TX_DIS_RX_DIS)
        set_port_prio_buffer_mapping(handle, log_port, priority, 0)

######################################################
#    main
######################################################


def main():

    parser = argparse.ArgumentParser(description='pfc_gen.py -i <port> -p <priority>',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--interface_list", type=str, help="Interface list to send packets, seperated by ','", required=True)
    parser.add_argument('-p', "--priority", type=int, help="PFC class enable bitmap.", default=-1)
    parser.add_argument('-d', "--disable", action='store_true', help="PFC class enable bitmap.")
    parser.add_argument("-r", "--rsyslog-server", type=str, default="127.0.0.1", help="Rsyslog server IPv4 address")
    parser.add_argument("-n", "--num", type=int, help="Number of packets to be sent", default=1)
    parser.add_argument("-s", "--send-pfc-frame-interval", type=float, help="Interval between two PFC frames", default=0)
    args = parser.parse_args()

    print("[+] opening sdk")
    rc, handle = sx_api_open(None)
    print(("sx_api_open handle:0x%x , rc %d " % (handle, rc)))
    if (rc != SX_STATUS_SUCCESS):
        print("Failed to open api handle.\nPlease check that SDK is running.")
        sys.exit(rc)

    log_ports = []
    portmap = get_port_map(handle)
    print(portmap)
    port_name_dict = build_port_name_dict()
    for port in args.interface_list.split(','):
        p,sp = port_name_dict[port]
        log_port = portmap[p][sp]
        print(log_port)
        log_ports.append(log_port)

    priority = parse_priority(args.priority)[0]

    logger = logging.getLogger('MyLogger')
    logger.setLevel(logging.DEBUG)
    # Configure logging
    handler = logging.handlers.SysLogHandler(address=(args.rsyslog_server, 514))
    logger.addHandler(handler)

    if args.disable:
        print("disable")
        stop_pfc(handle, log_ports, priority)
        logger.debug('PFC_STORM_END')
        sys.exit(0)

    try:
        start_pfc(handle, log_ports, priority)
        logger.debug('PFC_STORM_START')
        if args.num != 0 and args.send_pfc_frame_interval != 0:
            total_time = args.num / args.send_pfc_frame_interval
            time.sleep(total_time)
            stop_pfc(handle, log_ports, priority)
            logger.debug('PFC_STORM_END')
    except SdkError as se:
        stop_pfc(handle, log_ports, priority)


if __name__ == "__main__":
    main()
