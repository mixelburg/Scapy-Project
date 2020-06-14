# check installed packages
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1, sniff, send, srp1

import myLib

myLib.install_check()

from wrappers import make_green, make_red, make_blue
import scapy

server_IP = "54.71.128.194"
sever_Port = 99
bufferSize = 1024

MESSAGE_WAKE = "WAK000up"
MESSAGE_ENT = "ENT"
MESSAGE_ERROR = "ERR"
MESSAGE_DATA = ""


def get_char(char, iterations):
    value = ord(char)

    new_value = value + iterations
    if new_value > 122:
        new_value = new_value % 122 + 96

    return chr(new_value)


def get_reverse_char(char, iterations):
    value = ord(char)

    new_value = value - iterations
    if new_value < 97:
        new_value = new_value + 26

    return chr(new_value)


def encrypt(data, iterations):
    data = data.lower()
    result = ""

    for i in range(len(data)):
        if (i + 1) % 2 == 0:
            result += data[i]
        elif data[i] == ' ':
            result += ' '
        else:
            result += get_char(data[i], iterations)

    return result


def decrypt(data, iterations):
    data = data.lower()
    result = ""

    for i in range(len(data)):
        if (i + 1) % 2 == 0:
            result += data[i]
        elif data[i] == ' ':
            result += ' '
        else:
            result += get_reverse_char(data[i], iterations)

    return result


def answer_separator(server_answer):
    status = server_answer[:3]
    code = int(server_answer[3:6])
    message = server_answer[6:]

    return status, code, message


def alien_checker(packet):
    return UDP in packet \
           and IP in packet \
           and Raw in packet \
           and packet[IP].src == server_IP


@make_green
def alien_print(packet):
    server_answer = packet[Raw].load.decode()
    status, code, message = answer_separator(server_answer)

    print(f"Status: {status}, code: {code}")
    print(f"Decrypted: {decrypt(message, code)}")


def main():
    print("Sending Aliens to Jupiter")
    payload = encrypt("jupiter", 3)
    print(payload)
    udp_message = IP(dst=server_IP) / UDP(dport=sever_Port) / Raw(load=MESSAGE_ENT + "003" + payload)

    send(udp_message)
    print("Sniffing answers: ")
    packets = sniff(lfilter=alien_checker, prn=alien_print)


if __name__ == '__main__':
    main()
