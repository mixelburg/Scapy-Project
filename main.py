# check installed packages
import myLib
myLib.install_check()

from wrappers import make_green, make_red, make_blue
import scapy
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1, sniff, send, srp1
import hashlib

server_IP = "54.71.128.194"
sever_Port = 99
bufferSize = 1024

vehicle_id = ''
airport = ''
sent = False

DESTINATION = "jupiter"

MESSAGE_WAKE = "WAK000up"
MESSAGE_ENT = "ENT"
MESSAGE_ERROR = "ERR"
MESSAGE_DATA = ""
MESSAGE_FLY = "FLY"
MESSAGE_LANDING = "location_md5={},airport={},time=15:52,lane=earth.jup,vehicle={},fly"


def get_char(char, iterations):
    if char.isalpha():
        value = ord(char)

        new_value = value + iterations
        if new_value > 122:
            new_value = new_value % 122 + 96

        return chr(new_value)
    return char


def get_reverse_char(char, iterations):
    if char.isalpha():
        value = ord(char)

        new_value = value - iterations
        if new_value < 97:
            new_value = new_value + 26

        return chr(new_value)
    return char


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
    message = decrypt(message, code)

    global vehicle_id
    global airport
    global sent

    print(f"Status: {status}, code: {code}")
    print(f"Decrypted: {message}")

    if "vehicle chosed" in message:
        vehicle_id = message.split(' id ')[1]
    elif "airport selected" in message:
        airport = message.split("takeoff: ")[1]

    if not sent and vehicle_id != '' and airport != '':
        send_fly(vehicle_id, airport)
        sent = True


def send_fly(vehicle, airprt):
    # sending landing info
    print("Giving md5")
    str2hash = DESTINATION
    result = hashlib.md5(str2hash.encode())
    result = result.hexdiget()

    data = MESSAGE_LANDING.format(result, airprt, vehicle)
    print("********************************")
    print(f"Data: {data}")
    payload = encrypt(data, 8)

    udp_message = IP(dst=server_IP) / UDP(dport=sever_Port) / Raw(load=MESSAGE_FLY + "008" + payload)
    send(udp_message)


def main():
    # sending destination planet
    print("Sending Aliens to Jupiter")
    payload = encrypt(DESTINATION, 3)
    udp_message = IP(dst=server_IP) / UDP(dport=sever_Port) / Raw(load=MESSAGE_ENT + "003" + payload)
    send(udp_message)

    print("Sniffing answers: ")
    packets = sniff(lfilter=alien_checker, prn=alien_print)


if __name__ == '__main__':
    main()
