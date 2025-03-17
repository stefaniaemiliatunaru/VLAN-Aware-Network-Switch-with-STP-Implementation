#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name                                         

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    # dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

# functia de citire a configuratiei unui switch din fisier
def read_switch_configs(switch_id):
    config_path = f"configs/switch{switch_id}.cfg"
    # retin configuratia switch-ului intr-un dictionar
    switch_config = {
        "priority": None,
        "interfaces": {}
    }
    with open(config_path, "r") as config_file:
        lines = config_file.readlines()
        # setez prioritatea switch-ului
        switch_config["priority"] = int(lines[0].strip())
        for line in lines[1:]:
            parts = line.strip().split()
            interface_name = parts[0]
            type_or_vlan = parts[1]
            # daca tipul interfetei este trunk, retin 'T' in dictionar
            if (type_or_vlan == 'T'):
                switch_config["interfaces"][interface_name] = 'T'
            else:
            # altfel setez vlan-ul corespunzator interfetei
                switch_config["interfaces"][interface_name] = int(type_or_vlan)
    return switch_config

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# functia de adaugare a unui tag VLAN la un frame
def add_vlan_tag(data, vlan_id):
    vlan_tag = create_vlan_tag(vlan_id)
    return data[:12] + vlan_tag + data[12:]

# functia de eliminare a unui tag VLAN dintr-un frame
def remove_vlan_tag(data):
    return data[:12] + data[16:]

# functia de construire BPDU
def create_bpdu(root_bridge_id, root_path_cost, own_bridge_id, interface_id):
    # setez campurile BPDU
    dst_mac = bytes.fromhex('0180C2000000')
    src_mac = get_switch_mac()
    llc_length = (38).to_bytes(2, 'big')
    dsap = 0x42
    ssap = 0x42
    control = 0x03
    llc_header = (
        dsap.to_bytes(1, 'big') +
        ssap.to_bytes(1, 'big') +
        control.to_bytes(1, 'big')
    )
    protocol_id = 0
    protocol_version_id = 0
    bpdu_type = 0
    bpdu_header = (
        protocol_id.to_bytes(2, 'big') +
        protocol_version_id.to_bytes(1, 'big') +
        bpdu_type.to_bytes(1, 'big')
    )
    flags = 0
    message_age = 0
    max_age = 20
    hello_time = 2
    forward_delay = 15
    bpdu_config = (
        flags.to_bytes(1, 'big') +
        root_bridge_id.to_bytes(8, 'big') +
        root_path_cost.to_bytes(4, 'big') +
        own_bridge_id.to_bytes(8, 'big') +
        interface_id.to_bytes(2, 'big') +
        message_age.to_bytes(2, 'big') +
        max_age.to_bytes(2, 'big') +
        hello_time.to_bytes(2, 'big') +
        forward_delay.to_bytes(2, 'big')
    )
    # alcatuiesc BPDU folosing campurile setate anterior
    bpdu = (
        dst_mac +
        src_mac +
        llc_length +
        llc_header +
        bpdu_header +
        bpdu_config
    )
    return bpdu

# functia de trimitere BPDU la fiecare secunda
def send_bdpu_every_sec(switch_config, interfaces, own_bridge_id, root_bridge_id):
    while True:
        # verific daca switch-ul curent este root
        if own_bridge_id == root_bridge_id:
            for next_interface in interfaces:
                # trimit BPDU pe toate interfetele trunk
                if switch_config["interfaces"][get_interface_name(next_interface)] == 'T':
                    bpdu = create_bpdu(own_bridge_id, 0, own_bridge_id, next_interface)
                    send_to_link(next_interface, len(bpdu), bpdu)
        time.sleep(1)

# functia de initializare a interfetelor pentru BPDU
def intiliaze_interfaces_for_bpdu(switch_config):
    # retin starile interfetelor intr-un dictionar
    interfaces_states = {}
    # iterez prin toate interfetele switch-ului
    for current_interface_name in switch_config["interfaces"]:
        current_interface_type_or_vlan = switch_config["interfaces"][current_interface_name]
        # setez interfetele de tip trunk la BLOCKING, iar restul la DESIGNATED
        if current_interface_type_or_vlan == 'T':
            interfaces_states[current_interface_name] = "BLOCKING"
        else:
            interfaces_states[current_interface_name] = "DESIGNATED"
    own_bridge_id = switch_config["priority"]
    root_bridge_id = own_bridge_id
    root_path_cost = 0
    # daca interfata devine root bridge, setez toate interfetele switch-ului la DESIGNATED
    if own_bridge_id == root_bridge_id:
        for current_interface_name in switch_config["interfaces"]:
            interfaces_states[current_interface_name] = "DESIGNATED"
    return interfaces_states, own_bridge_id, root_bridge_id, root_path_cost

# functia de primire si procesare a BPDU
def receive_and_process_bpdu(switch_config, interfaces, interfaces_states, interface, bpdu, own_bridge_id, root_bridge_id, root_path_cost):
    # extrag campurile necesare din configuratia BPDU
    bpdu_root_bridge_id = int.from_bytes(bpdu[21:29], 'big')
    bpdu_root_path_cost = int.from_bytes(bpdu[29:33], 'big')
    bpdu_bridge_id = int.from_bytes(bpdu[33:41], 'big')
    root_interface = interface
    # verific daca root bridge id este mai mic decat cel curent
    if bpdu_root_bridge_id < root_bridge_id:
        was_root = (own_bridge_id == root_bridge_id)
        # actualizez root bridge id, root path cost si root interface
        root_bridge_id = bpdu_root_bridge_id
        root_path_cost = bpdu_root_path_cost + 10
        root_interface = interface
        # daca am fost root, setez toate interfetele la BLOCKING, in afara de root interface
        if was_root:
            for next_interface in interfaces:
                if next_interface != root_interface and switch_config["interfaces"][get_interface_name(next_interface)] == 'T':
                    interfaces_states[get_interface_name(next_interface)] = "BLOCKING"
        # daca interfata root este BLOCKING, o setez la DESIGNATED
        if interfaces_states[get_interface_name(root_interface)] == "BLOCKING":
            interfaces_states[get_interface_name(root_interface)] = "DESIGNATED"
        # trimit BPDU cu informatiile actualizate pe toate interfetele de tip trunk
        for next_interface in interfaces:
            if next_interface != root_interface and switch_config["interfaces"][get_interface_name(next_interface)] == 'T':
                bpdu = create_bpdu(root_bridge_id, root_path_cost, own_bridge_id, next_interface)
                send_to_link(next_interface, len(bpdu), bpdu)
    # daca root bridge ID din BPDU este egal cu root bridge ID curent
    elif bpdu_root_bridge_id == root_bridge_id:
        # daca interfata curenta este root interface si costul caii din BPDU este mai mic
        if interface == root_interface and bpdu_root_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_root_path_cost + 10
        # daca interfata curenta nu este root interface
        elif interface != root_interface:
            if bpdu_root_path_cost > root_path_cost:
                # daca costul caii din BPDU este mai mare decat root path cost curent
                if interfaces_states[get_interface_name(interface)] == "BLOCKING":
                    interfaces_states[get_interface_name(interface)] = "DESIGNATED"
    elif bpdu_bridge_id == root_bridge_id:
        interfaces_states[get_interface_name(interface)] = "BLOCKING"
    else:
        return interfaces_states, root_bridge_id, root_path_cost
    # daca switch-ul curent este root bridge, setez toate interfetele la DESIGNATED
    if own_bridge_id == root_bridge_id:
        for next_interface in interfaces:
            interfaces_states[get_interface_name(next_interface)] = "DESIGNATED"
    return interfaces_states, root_bridge_id, root_path_cost

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    switch_config = read_switch_configs(switch_id)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    # intitializez interfetele pentru BPDU
    interfaces_states, own_bridge_id, root_bridge_id, root_path_cost = intiliaze_interfaces_for_bpdu(switch_config)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(switch_config, interfaces, own_bridge_id, root_bridge_id))
    t.start()

    mac_table = {}
    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # data is of type bytes.
        # send_to_link(i, length, data)

        # actualizez tabela MAC cu sursa si interfata corespunzatoare
        mac_table[src_mac] = interface
        # daca VLAN ID nu a fost inca setat, il obtin din configuratia switch-ului
        if vlan_id == -1:
            vlan_id = switch_config["interfaces"][get_interface_name(interface)]
        # verific daca destinatia este adresa de broadcast specifica BPDU
        if dest_mac == '01:80:c2:00:00:00':
            # verific daca interfata este in BLOCKING pentru a sti daca se poate trimite frame-ul
            if interfaces_states[get_interface_name(interface)] == "BLOCKING":
                continue
            interfaces_states, root_bridge_id, root_path_cost = receive_and_process_bpdu(switch_config, interfaces, interfaces_states, interface, data, own_bridge_id, root_bridge_id, root_path_cost)
            continue
        # verific daca adresa MAC destinatie este de tip unicast
        if (int(dest_mac[:2], 16) & 1) == 0:
            # daca adresa destinatie a fost retinuta anterior in tabela MAC
            if dest_mac in mac_table:
                next_interface = mac_table[dest_mac]
                next_interface_type_or_vlan = switch_config["interfaces"][get_interface_name(next_interface)]
                current_interface_type_or_vlan = switch_config["interfaces"][get_interface_name(interface)]
                # daca sunt in cazul de a trimite frame de pe interfata de tip trunk pe alta interfata de tip trunk
                if next_interface_type_or_vlan == 'T' and current_interface_type_or_vlan == 'T':
                    # verific daca interfata pe care vreau sa trimit este in BLOCKING
                    if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                        continue
                    # trimit frame-ul pe interfata corespunzatoare
                    send_to_link(next_interface, length, data)
                # daca sunt in cazul de a trimite frame de pe interfata de tip trunk pe o interfata de tip access
                elif next_interface_type_or_vlan == 'T' and current_interface_type_or_vlan != 'T':
                    if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                        continue
                    # adaug tag-ul VLAN corespunzator si trimit frame-ul pe interfata corespunzatoare
                    send_to_link(next_interface, length + 4, add_vlan_tag(data, vlan_id))
                # daca sunt in cazul de a trimite frame de pe o interfata de tip access pe o interfata de tip trunk
                elif next_interface_type_or_vlan != 'T' and current_interface_type_or_vlan == 'T':
                    if vlan_id == int(next_interface_type_or_vlan):
                        if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                            continue
                        # elimin tag-ul VLAN si trimit frame-ul pe interfata corespunzatoare
                        send_to_link(next_interface, length - 4, remove_vlan_tag(data))
                # daca sunt in cazul de a trimite frame de pe o interfata de tip access pe o alta interfata de tip access
                elif vlan_id == int(next_interface_type_or_vlan):
                    if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                        continue
                    # trimit frame-ul pe interfata corespunzatoare
                    send_to_link(next_interface, length, data)
            else:
                # daca adresa destinatie nu a fost retinuta anterior in tabela MAC, trimit frame-ul pe toate interfetele
                for next_interface in interfaces:
                    if next_interface != interface:
                        next_interface_type_or_vlan = switch_config["interfaces"][get_interface_name(next_interface)]
                        current_interface_type_or_vlan = switch_config["interfaces"][get_interface_name(interface)]
                        # tratez diferitele cazuri de transmitere a frame-ului asa cum le-am tratat anterior
                        if next_interface_type_or_vlan == 'T' and current_interface_type_or_vlan == 'T':
                            if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                                continue
                            send_to_link(next_interface, length, data)
                        elif next_interface_type_or_vlan == 'T' and current_interface_type_or_vlan != 'T':
                            if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                                continue
                            send_to_link(next_interface, length + 4, add_vlan_tag(data, vlan_id))
                        elif next_interface_type_or_vlan != 'T' and current_interface_type_or_vlan == 'T':
                            if vlan_id == int(next_interface_type_or_vlan):
                                if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                                    continue
                                send_to_link(next_interface, length - 4, remove_vlan_tag(data))
                        elif vlan_id == int(next_interface_type_or_vlan):
                            if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                                continue
                            send_to_link(next_interface, length, data)
        else:
            # daca adresa MAC destinatie este de tip multicast, trimit frame-ul pe toate interfetele
            for next_interface in interfaces:
                if next_interface != interface:
                    next_interface_type_or_vlan = switch_config["interfaces"][get_interface_name(next_interface)]
                    current_interface_type_or_vlan = switch_config["interfaces"][get_interface_name(interface)]
                    # tratez diferitele cazuri de transmitere a frame-ului asa cum le-am tratat anterior
                    if next_interface_type_or_vlan == 'T' and current_interface_type_or_vlan == 'T':
                        if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                            continue
                        send_to_link(next_interface, length, data)
                    elif next_interface_type_or_vlan == 'T' and current_interface_type_or_vlan != 'T':
                        if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                            continue
                        send_to_link(next_interface, length + 4, add_vlan_tag(data, vlan_id))
                    elif next_interface_type_or_vlan != 'T' and current_interface_type_or_vlan == 'T':
                        if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                            continue
                        if vlan_id == int(next_interface_type_or_vlan):
                            send_to_link(next_interface, length - 4, remove_vlan_tag(data))
                    elif vlan_id == int(next_interface_type_or_vlan):
                        if interfaces_states[get_interface_name(next_interface)] == "BLOCKING":
                            continue
                        send_to_link(next_interface, length, data)

if __name__ == "__main__":
    main()