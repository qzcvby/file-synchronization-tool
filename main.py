import argparse
import json
import os
import struct
from socket import *
import hashlib
import time
import math
from threading import Thread

port = 23222
port_tcp = 25222
file_path = '/home/tc/workplace/cw1/share/'
operator_num = 0
new_folder = ''
buffer_size = 2 * 1024 * 1024
buffer = 1024 * 1024
last_mtime = []
control_hello = 0
old_list = []
op_target = []
stop_flag = 0
connection_pool = []
ser1_flag = 0
ser2_flag = 0
listen_flag = 0
past_file_list = []
first_time_flag = 0
last_mtime_file = 0
encrype_flag = 0
first_encrype_flag = 0

client_socket_udp = socket(AF_INET, SOCK_DGRAM)
client_socket_udp.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)  # set the udp
client_socket_udp.bind(('', port))

client_socket = socket(AF_INET, SOCK_STREAM)  # set the tcp
client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)


def send_list(new_list, server_address):
    list_length = len(new_list)  # send the op_num and list
    length = struct.pack('!II', 1, list_length)
    json_string = json.dumps(new_list).encode()
    client_socket_udp.sendto(length + json_string, server_address)
    print("send success")


def get_information(file_path, file_name):
    md5 = get_md5(file_path, file_name)  # get the information md5, file_size, number for the file
    file_size = os.path.getsize(file_path + file_name)
    number = math.ceil(file_size / buffer)
    return md5, file_size, number


def get_list(file_path):
    global first_time_flag
    global past_file_list
    global last_mtime
    global old_list
    target_final = []
    reset_flag = 0
    target_o = os.listdir(file_path)
    if len(past_file_list) == 0:
        past_file_list = target_o
    else:
        for file_x in target_o:
            if file_x not in past_file_list:
                past_file_list.append(file_x)
                last_mtime.append(getmtime(file_path, file_x))
    old_list = target_o
    if os.path.exists(file_path + '1.left') == 1 and first_time_flag == 0:
        target_o.remove('1.left')  # fake copy, just remove from the target_o
        reset_flag = 1
    elif os.path.exists(file_path + '1.left') == 1:
        target_o.remove('1.left')
    first_time_flag = 1
    for file_z in target_o:
        if os.path.isfile(file_path + file_z):  # find the final target, put the file first, then the folder
            target_final.append(file_z)
    for file_dir in target_o:
        if os.path.isdir(file_path + file_dir):
            target_final.append(file_dir)
    return target_final, reset_flag


def get_md5(file_path, file_name):
    md5_big = hashlib.md5()  # calcute the md5
    file_x = open(file_path + file_name, 'rb')
    file_size = os.path.getsize(file_path + file_name)
    if file_size > 125 * buffer_size:
        while file_x is True:
            data = file_x.read(2024)
            if not data:
                break
            md5_big.update(data)
            file_x.close()
        return md5_big.hexdigest()
    else:
        md5 = hashlib.md5(file_x.read()).hexdigest()
        file_x.close()
        return md5


def send_header(file_name, file_path, client_num):
    # if client_num == 1:
    if os.path.isfile(file_path + file_name):
        operator_num = 1
        operator_pack = struct.pack('!I', operator_num)
        md5, file_size, number = get_information(file_path, file_name)
        name_length = len(file_name)
        header = struct.pack('!IQQQ', client_num, file_size, number, name_length)  # pack the file's information
        header_length = len(header + operator_pack + file_name.encode() + md5.encode())
        return struct.pack('!I', header_length) + operator_pack + header + file_name.encode() + md5.encode()
    if os.path.isdir(file_path + file_name):  # pack the folder's information
        new_folder = file_name
        operator_num = 2
        operator_pack = struct.pack('!I', operator_num)
        client_pack = struct.pack('!I', client_num)
        # name_length = struct.pack('!I', len(file_name.encode()))
        header_length = len(operator_pack + client_pack + new_folder.encode())
        return struct.pack('!I', header_length) + operator_pack + client_pack + new_folder.encode()


def handle_header_file(msg_n, operator_num):
    global new_folder
    if operator_num == 1:
        client_num = struct.unpack('!I', msg_n[0:4])[0]  # handle the header file and return the information
        if client_num == 0:
            file_size, number, name_length = struct.unpack('!QQQ', msg_n[4:28])
            file_name = msg_n[28:28 + name_length].decode()
            md5 = msg_n[28 + name_length:].decode()
            return file_name, file_size, number, md5
        # if client_num == 1:
    if operator_num == 2:
        new_folder = msg_n[4:].decode()
        return new_folder


# def server_trans():
def server(cli_ip, port_tcp, file_name1, file_path, connectionSocket):
    msg1_length = connectionSocket.recv(4)
    msg1_length = struct.unpack('!I', msg1_length)[0]
    msg1 = connectionSocket.recv(msg1_length)
    client_num = struct.unpack('!I', msg1[0:4])[0]  # get the file name from client
    file_name1 = msg1[4:].decode()
    if os.path.isfile(file_path + file_name1) == 1:  # whether is a file, if yes transfer
        header = send_header(file_name1, file_path, client_num)
        connectionSocket.sendall(header)
        md5, file_size, number_ = get_information(file_path, file_name1)
        server_trans(cli_ip, file_path, file_name1, connectionSocket, number_, md5)
    if os.path.isdir(
            file_path + file_name1) == 1:  # whe ther is a dir, if yes get the file_list in dir and send to client
        header = send_header(file_name1, file_path, client_num)
        connectionSocket.sendall(header)
        new_path = file_path + file_name1 + '/'
        file_dir_list = os.listdir(new_path)
        file_dir_list_json = json.dumps(file_dir_list).encode()
        file_dir_length = struct.pack('!I', len(file_dir_list_json))
        connectionSocket.sendall(file_dir_length)
        connectionSocket.sendall(file_dir_list_json)
        folder_num = connectionSocket.recv(4)
        folder_num = struct.unpack('!I', folder_num)[0]
        if folder_num == 0:
            for file_1 in file_dir_list:
                server(cli_ip, port_tcp, file_1, new_path, connectionSocket)
                # md5, file_size, number_ = get_information(new_path, file)
        if folder_num == 1:
            cli_num = connectionSocket.recv(4)
            cli_num = struct.unpack('!I', cli_num)[0]  # send the list to client
            if cli_num == 1:
                ser_list_length = connectionSocket.recv(4)  # folder reconnect transport
                ser_list_length = struct.unpack('!I', ser_list_length)[0]
                ser_list = connectionSocket.recv(ser_list_length)
                ser_list = json.loads(ser_list)
                for file_p in ser_list:
                    server(cli_ip, port_tcp, file_p, new_path, connectionSocket)


def server_trans(cli_ip, file_t_path, file_name, connectionSocket, number, md5):
    global file_path
    global stop_flag
    img = open(file_t_path + file_name, 'rb')
    try:
        fn_flag = 'finish'
        fn_size = len(fn_flag.encode())
        stop_number_not = 0
        while number > 0 and fn_flag == 'finish':
            data = img.read(buffer)
            connectionSocket.sendall(data)
            print(number)
            fn_flag = connectionSocket.recv(fn_size)  # wait the client get all the data in the block
            fn_flag = fn_flag.decode()
            number = number - 1
            stop_number_not = stop_number_not + 1
            print(number)
        img.close()
    except ConnectionResetError or BrokenPipeError:  # if the connection have been killed
        img.close()
        print('connect have been cut')


def client(filename, file_path_, client_socket, ip_server):
    global last_mtime
    global op_target
    client_num = 0
    client_pack = struct.pack('!I', client_num)
    client_socket.sendall(struct.pack('!I', len(client_pack + filename.encode())))
    client_socket.sendall(client_pack + filename.encode())
    msg_length = client_socket.recv(4)
    msg_length_ = struct.unpack('!I', msg_length)[0]
    msg_x = client_socket.recv(msg_length_)
    operator_num = struct.unpack('!I', (msg_x[0:4]))[0]  # get the op_num send file_name
    if operator_num == 1:  # is a file
        file_name, file_size, number, md5 = handle_header_file(msg_x[4:], operator_num)
        result = transform(file_name, file_size, number, md5, file_path_, client_socket, ip_server)
        if result == md5:  # compare the md5
            print('right')
        if result != md5:
            print('false')
    if operator_num == 2:  # is a dir
        new_folder = handle_header_file(msg_x[4:], operator_num)
        new_folder_len = client_socket.recv(4)
        new_folder_len = struct.unpack('!I', new_folder_len)[0]
        new_folder_list = client_socket.recv(new_folder_len)
        new_folder_list = json.loads(new_folder_list)
        new_folder_x = file_path_ + new_folder + '/'
        ser_list = []
        if os.path.exists(new_folder_x) == 1:
            client_socket.sendall(struct.pack('!I', 1))
            cli_list = os.listdir(new_folder_x)
            for file_u in new_folder_list:
                if file_u not in cli_list:
                    ser_list.append(file_u)
            if len(ser_list) != 0:
                client_socket.sendall(struct.pack('!I', 1))
                ser_list_json = json.dumps(ser_list).encode()
                ser_length = struct.pack('!I', len(ser_list_json))
                client_socket.sendall(ser_length)
                client_socket.sendall(ser_list_json)
                for file_i in ser_list:
                    client(file_i, new_folder_x, client_socket, ip_server)  # get the file in dir from server
            if len(ser_list) == 0:
                client_socket.sendall(struct.pack('!I', 0))
        if os.path.exists(new_folder_x) != 1:  # the folder reconnect
            client_socket.sendall(struct.pack('!I', 0))
            os.makedirs(new_folder_x)
            for file_2 in new_folder_list:
                client(file_2, new_folder_x, client_socket, ip_server)


def transform(file_name, file_size, number, md5, file_path_, client_socket, ip_server):
    global last_mtime
    global buffer_size
    global file_path
    with open(file_path_ + file_name, 'wb') as f:
        with open(file_path_ + '1.left', 'wb+') as f2:  # write a log file for reconnect
            stop_number_not = 0
            finish_w = 'finish'
            finish_p = finish_w.encode()
            the_num = number
            data = finish_p
            while number > 0:
                print(number)
                total = b''
                while len(data) > 0:
                    data = client_socket.recv(buffer_size)
                    total = total + data
                    if len(total) == buffer and number > 1:  # make sure that accept all the data in the buffer
                        break
                    if len(total) == (file_size - buffer * (
                            the_num - 1)) and number == 1:  # make sure that accept all the data in the last block
                        break
                f2.seek(0)
                stop_ip_pack = ip_server[0].encode()
                stop_pack = struct.pack('!II', stop_number_not, len(stop_ip_pack))
                f2.write(stop_pack + stop_ip_pack + file_name.encode())
                f.write(total)
                number = number - 1
                stop_number_not = stop_number_not + 1
                client_socket.sendall(finish_p)  # send back to ask next block
    f.close()
    f2.close()
    last_mtime.append(getmtime(file_path_, file_name))
    os.remove(file_path_ + '1.left')
    cutt_md5 = get_md5(file_path_, file_name)
    return cutt_md5


def handle_list(msg):
    length_a = struct.unpack('!I', msg[4:8])[0]
    my_list = os.listdir(file_path)
    if length_a == len(my_list):
        return 0
    new_list = msg[8:]
    new_list = json.loads(new_list)
    target_a = []
    for file_ in new_list:
        if file_ not in my_list:
            target_a.append(file_)
    if len(target_a) > 0:
        return target_a  # get the file do not have
    else:
        return 0


def getmtime(file_path_m, file_name_m):
    current_mtime = time.localtime(os.path.getmtime(file_path_m + file_name_m))
    return current_mtime.tm_sec


def calculate_mtime(file_path_now):
    global last_mtime
    global old_list
    global last_mtime_file
    target_mtime_file = []
    now_time = []
    mtime_file_list = os.listdir(file_path_now)
    print(len(last_mtime))  # calculate the mtime and find out the file to update
    if len(last_mtime) == 0:
        for file_b in mtime_file_list:
            last_mtime.append(getmtime(file_path_now, file_b))
        return 0
    else:
        for file_a in mtime_file_list:
            the_mtime = getmtime(file_path_now, file_a)
            now_time.append(the_mtime)
            if the_mtime not in last_mtime:
                if file_a in old_list:
                    if file_a != last_mtime_file:
                        target_mtime_file.append(file_a)
                        print(the_mtime)  # avoid the same file been update two times
                        last_mtime_file = file_a
        if len(target_mtime_file) == 0:
            last_mtime = now_time
            return 0
        if len(target_mtime_file) != 0:
            last_mtime = now_time
            print(target_mtime_file)
            return target_mtime_file


def change_server(file_path_m, connectionSocket):
    m_length = connectionSocket.recv(4)
    mtime_file = connectionSocket.recv(struct.unpack('!I', m_length)[0])
    mtime_file = mtime_file.decode()
    img = open(file_path_m + mtime_file, 'wb')  # exchange the information
    mtime_size = os.path.getsize(file_path_m + mtime_file)
    change_size = math.ceil(mtime_size / 1000 * 2)  # calculate the change size of file
    block_num = math.ceil(change_size / buffer)
    mtime_pack = struct.pack('!Q', block_num)
    connectionSocket.sendall(mtime_pack)
    fn_flag = 'finish'
    fn_size = len(fn_flag.encode())
    while block_num > 0 and fn_flag == 'finish':
        data = img.read(buffer)
        connectionSocket.sendall(data)
        block_num = block_num - 1
        fn_flag = connectionSocket.recv(fn_size)
        fn_flag = fn_flag.decode()
    img.close()


def change_client(file_name_mtime, m_path, client_socket):
    global last_mtime
    global old_list
    name_pack = struct.pack('!I', len(file_name_mtime.encode()))
    client_socket.sendall(name_pack)
    client_socket.sendall(file_name_mtime.encode())
    block_m_num = client_socket.recv(8)
    block_m_num = struct.unpack('!Q', block_m_num)[0]
    with open(m_path + file_name_mtime, 'rb+') as f:
        finish_w = 'finish'
        finish_p = finish_w.encode()
        data = finish_p
        while block_m_num > 0:
            print(block_m_num)
            total = b''
            while len(data) > 0:  # transform like common
                data = client_socket.recv(buffer_size)
                total = total + data
                if len(total) == buffer and block_m_num > 1:
                    break
                if len(total) <= buffer and block_m_num == 1:
                    break
            f.write(total)
            block_m_num = block_m_num - 1
            client_socket.sendall(finish_p)
    old_list = os.listdir(m_path)
    f.close()
    last_mtime.append(getmtime(m_path, file_name_mtime))  # add the mtime into the list


def reconnect_server(connectionSocket, stop_num, stop_name):
    global file_path
    global listen_flag
    md5, file_size, number_ = get_information(file_path, stop_name)
    stop_pack = struct.pack('!QI', file_size, number_)
    stop_pack_length = struct.pack('!I', len(stop_pack + md5.encode()))
    connectionSocket.sendall(stop_pack_length + stop_pack + md5.encode())
    img = open(file_path + stop_name, 'rb+')  # exchange the data
    fn_flag = 'finish'
    fn_size = len(fn_flag.encode())
    img.seek(buffer * stop_num)
    number = number_ - stop_num
    while number > 0 and fn_flag == 'finish':
        data = img.read(buffer)
        connectionSocket.sendall(data)
        print(number)
        fn_flag = connectionSocket.recv(fn_size)  # transform
        fn_flag = fn_flag.decode()
        number = number - 1
    img.close()
    connectionSocket.close()
    listen_flag = 5


def restart_client(client_socket, stop_num, old_name):
    global file_path
    pack_length = client_socket.recv(4)
    pack_length = struct.unpack('!I', pack_length)[0]
    stop_pack = client_socket.recv(pack_length)  # exchange the information
    file_size, number_ = struct.unpack('!QI', stop_pack[:12])
    md5 = stop_pack[12:].decode()
    number = number_ - stop_num
    with open(file_path + old_name, 'rb+') as f:
        f.seek(buffer * stop_num)
        finish_w = 'finish'
        finish_p = finish_w.encode()
        the_num = number_
        data = finish_p
        while number > 0:
            print(number)
            total = b''
            while len(data) > 0:
                data = client_socket.recv(buffer_size)
                total = total + data
                if len(total) == buffer and number > 1:
                    break  # transform the data
                if len(total) == (file_size - buffer * (the_num - 1)) and number == 1:
                    break
            number = number - 1
            f.write(total)
            client_socket.sendall(finish_p)
    f.close()
    last_mtime.append(getmtime(file_path, old_name))
    cutt_md5 = get_md5(file_path, old_name)
    if cutt_md5 == md5:
        print('true')
    else:
        print('false')


def parse():  # to get the ip and print encryption
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--ip', action='store', required=True, dest='ip', help='The ip of peer', type=str)
    parser.add_argument('--encryption', action='store', required=False, dest='encryption', type=str)
    return parser.parse_args()


def print_parse():  # encryption method
    print('''__________________________________________________________________________________
            About how to encryption:
                import rsa
                def encryption(msg):
                    public_key, private_key = rsa.newkeys(1024)
                    public_key_save = public_key.save_pkcs1()
                    private_ket_save = private_key.save_pkcs1()
                    with open('file_path + pub_key.pem', 'wb') as f1:
                       with open('pri_key.pem', 'wb') as f2:
                           f1.write(public_key_save)
                           f2.write(private_ket_save)
                    msg_pack = msg.encode()
                    msg_pack = rsa.encrypt(msg_pack, public_key)
                    return msg_pack

                def decryption(msg):
                    with open('file_path + pub_key.pem', 'rb') as f1:
                       with open('file_path + pri_key.pem', 'rb') as f2:
                          public_key_save = f1.read()
                          private_ket_save = f2.read()
                    public_key = rsa.PublicKey.load_pkcs1(public_key_save)
                    private_key = rsa.PrivateKey.load_pkcs1(private_ket_save)
                    msg_pack = rsa.decrypt(msg, private_key)
                    msg = msg_pack.decode()
                    return msg
            __________________________________________________________________________________
                ''')


def start_server(connectionSocket, addre):
    global port_tcp
    global file_path
    global stop_flag
    global connection_pool
    global listen_flag  # start the server with thread
    target_len = connectionSocket.recv(4)
    target_len = struct.unpack('!I', target_len)[0]
    target_ = connectionSocket.recv(target_len)
    target_ = json.loads(target_)
    flag_size = len('success'.encode())
    stop_flag = 0
    for file in target_:
        if stop_flag == 1:
            break
        print("begin 1")
        server(addre[0], port_tcp, file, file_path, connectionSocket)
    connectionSocket.close()
    print('connection is closed')
    connection_pool.remove(connectionSocket)  # make sure there are no connections
    if len(connection_pool) == 0:  # control to reset the tcp
        listen_flag = 5


def set_change_server(connectionSocket, target_my_mtime, mtime_list):
    global listen_flag
    connectionSocket.sendall(target_my_mtime)
    for file_m in mtime_list:
        change_server(file_path, connectionSocket)
    connection_pool.remove(connectionSocket)
    connectionSocket.close()
    if len(connection_pool) == 0:
        listen_flag = 5  # control to reset the tcp


def handle_other_list(op_num, target_my_mtime, msg_, server_address_, mtime_list_str):
    global op_target
    global listen_flag
    global client_socket
    global recv_flag
    global connection_pool
    if listen_flag == 5 and op_num != 2 and target_my_mtime == 0:
        client_socket.close()  # reset the TCP state
        client_socket = socket(AF_INET, SOCK_STREAM)
        client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        listen_flag = 0
        print('client_socket is closed')
    if op_num == 1:  # get the list from others
        op_target = handle_list(msg_)
        if op_target != 0:
            se_num = 2
            client_socket_udp.sendto(struct.pack('!I', se_num), server_address_)
            time.sleep(0.5)
            while True:
                try:  # try to connect if cannot sleep for 1s and try again
                    client_socket.connect((server_address_[0], port_tcp))
                    break
                except ConnectionRefusedError or OSError or ConnectionResetError:
                    time.sleep(1)
            recv_flag = 1
            target_json = json.dumps(op_target).encode()
            target_length = struct.pack('!I', len(target_json))
            client_socket.sendall(target_length)
            client_socket.sendall(target_json)
            for files in op_target:
                print("begin 2")
                client(files, file_path, client_socket, (server_address_[0], port_tcp))
            client_socket.close()  # reset the TCP
            client_socket = socket(AF_INET, SOCK_STREAM)
            client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    if op_num == 2:
        try:
            client_socket.bind(('', port_tcp))
            client_socket.listen(10)
            connectionSocket, addr = client_socket.accept()
        except OSError:
            connectionSocket, addr = client_socket.accept()
        print('wait to accept')
        connection_pool.append(connectionSocket)  # USE the thread to transform
        t1 = Thread(target=start_server, args=(connectionSocket, addr,))
        t1.start()
    if op_num == 3:  # if there are something asked to update
        mtime_length = struct.unpack('!I', msg_[4:8])[0]
        time.sleep(0.5)
        while True:
            try:
                client_socket.connect((server_address_[0], port_tcp))
                break
            except ConnectionRefusedError or OSError or ConnectionResetError:
                time.sleep(0.5)
        change_list = client_socket.recv(mtime_length)  # send the mtime_length
        change_list = json.loads(change_list)
        for file_m in change_list:
            change_client(file_m, file_path, client_socket)
        client_socket.close()
        client_socket = socket(AF_INET, SOCK_STREAM)  # reset the tcp
        client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    if target_my_mtime != 0:  # find something to update
        print('start to fresh')
        try:
            client_socket.bind(('', port_tcp))
            client_socket.listen(10)
            connectionSocket, addr = client_socket.accept()
        except OSError:
            connectionSocket, addr = client_socket.accept()
        connection_pool.append(connectionSocket)
        t2 = Thread(target=set_change_server, args=(connectionSocket, target_my_mtime, mtime_list_str,))
        t2.start()  # use the thread to update
    if op_num == 4:
        stop_num = struct.unpack('!I', msg_[4:8])[0]
        stop_name = msg_[8:].decode()
        try:  # as the server to reconnect
            client_socket.bind(('', port_tcp))
            client_socket.listen(10)
            connectionSocket, addr = client_socket.accept()
        except OSError:
            connectionSocket, addr = client_socket.accept()
        reconnect_server(connectionSocket, stop_num, stop_name)


if __name__ == '__main__':
    while True:
        parser = parse()
        tar_ip = parser.ip
        tar_ip = tar_ip.split(',')
        ser_ip_1 = tar_ip[0]
        ser_ip_2 = tar_ip[1]  # get the ip
        tar_encry = parser.encryption  # get the order to print encryption
        if tar_encry == 'yes':
            encrype_flag = 1
        if encrype_flag == 1 and first_encrype_flag == 0:
            print_parse()
            encrype_flag = 0
            first_encrype_flag = 1
        server_address_1 = (ser_ip_1, port)
        server_address_2 = (ser_ip_2, port)
        op_target = []
        target_my_mtime = calculate_mtime(file_path)  # get mtime
        mtime_list = target_my_mtime
        target, reset_num = get_list(file_path)
        if reset_num == 1:
            with open(file_path + '1.left', 'rb+') as f2:  # find the log file try to reconnect
                f2.seek(0)
                data_pack = f2.read(1024)
                left_num, left_ip_length = struct.unpack('!II', data_pack[0:8])
                left_ip = data_pack[8:8 + left_ip_length].decode()
                left_file_name = data_pack[8 + left_ip_length:].decode()
                restart_num = struct.pack('!II', 4, left_num)
            print(left_num)
            client_socket_udp.sendto(restart_num + left_file_name.encode(), (left_ip, port))
            f2.close()
            os.remove(file_path + '1.left')
            while True:
                try:
                    client_socket.connect((left_ip, port_tcp))
                    break
                except ConnectionRefusedError or OSError or ConnectionResetError:
                    time.sleep(1)
            restart_client(client_socket, left_num, left_file_name)
            client_socket.close()
            client_socket = socket(AF_INET, SOCK_STREAM)
            client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)  # reset the tcp
            reset_num = 0
        if target_my_mtime != 0:
            op_num = 3
            target_my_mtime = json.dumps(target_my_mtime).encode()
            op_pack = struct.pack('!II', op_num, len(target_my_mtime))
            client_socket_udp.sendto(op_pack, server_address_1)
            client_socket_udp.sendto(op_pack, server_address_2)
        else:  # check the mtime and send the request
            send_list(target, server_address_2)
            send_list(target, server_address_1)
        time.sleep(1)
        msg, server_address_udp = client_socket_udp.recvfrom(20480)
        oper_num = struct.unpack('!I', msg[0:4])[0]
        print(oper_num)
        handle_other_list(oper_num, target_my_mtime, msg, server_address_udp, mtime_list)
        if server_address_udp == server_address_1:
            ser1_flag = 1
        if server_address_udp == server_address_2:
            ser2_flag = 1
        if ser1_flag == 1 and ser2_flag == 1:  # open the recvfrom2
            print('udp2 open')
            msg2, server_address_udp = client_socket_udp.recvfrom(20480)
            op_num = struct.unpack('!I', msg2[0:4])[0]
            print(op_num)
            handle_other_list(op_num, target_my_mtime, msg2, server_address_udp, mtime_list)
