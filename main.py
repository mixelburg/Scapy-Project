# check installed packages
import myLib

myLib.install_check()

# importing libraries
import scapy
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1, sniff, send, srp1, sendp
import hashlib
from colorama import init, Fore

# initialize colorama
init()
# define colors
RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET
MAGENTA = Fore.MAGENTA

# server info
server_IP = "54.71.128.194"
sever_Port = 99
bufferSize = 1024
local_port = 0

# data about aliens
vehicle_id = ''
airport = ''
sent = False
sent_planet = False
location_data = {}
DESTINATION = "jupiter"

# alien protocol data
MESSAGE_ENT = "ENT"
MESSAGE_ERROR = "ERR"
MESSAGE_FLY = "FLY"
# landing data pattern
MESSAGE_LANDING = "location_md5={},airport={},time=15:52,lane=earth.jup,vehicle={},fly"


def print_end():
    """
    prints end message
    :return: None
    """
    print(f"""{MAGENTA}
     _    _ _____  ______ ___________   _____ _____ 
    | |  | |  ___| |  _  \_   _|  _  \ |_   _|_   _|
    | |  | | |__   | | | | | | | | | |   | |   | |  
    | |/\| |  __|  | | | | | | | | | |   | |   | |  
    \  /\  / |___  | |/ / _| |_| |/ /   _| |_  | |  
     \/  \/\____/  |___/  \___/|___/    \___/  \_/
    {RESET}""")


def print_start():
    """
    prints program info
    :return: None
    """
    print(f"""{BLUE}
     _   _                      _            _   _             
    | | | |                    | |          | | (_)            
    | |_| |__   ___   ___  __ _| |_   ____ _| |_ _  ___  _ __  
    | __| '_ \ / _ \ / __|/ _` | \ \ / / _` | __| |/ _ \| '_ \\
    | |_| | | |  __/ \__ \ (_| | |\ V / (_| | |_| | (_) | | | |
     \__|_| |_|\___| |___/\__,_|_| \_/ \__,_|\__|_|\___/|_| |_|
    created by: mixelburg 
    {RESET}""")


def get_char(char, iterations):
    """
    encrypts given char according to given encryption data
    :param char: letter
    :param iterations: encryption data
    :return: encrypted char
    """
    if char.isalpha():
        # get ascii value
        value = ord(char)

        # get new ascii value
        new_value = value + iterations
        if new_value > 122:
            new_value = new_value % 122 + 96

        return chr(new_value)
    return char


def get_reverse_char(char, iterations):
    """
    decrypts data according to given encryption data
    :param char: encrypted letter
    :param iterations: encryption data
    :return: decrypted letter
    """
    if char.isalpha():
        # get ascii value
        value = ord(char)

        # get new ascii value
        new_value = value - iterations
        if new_value < 97:
            new_value = new_value + 26

        return chr(new_value)
    return char


def encrypt(data, iterations):
    """
    encrypts give data (text) according to a given encryption data
    :param data: text
    :param iterations: encryption data
    :return: encrypted data
    """
    data = data.lower()
    result = ""

    # encrypt data
    for i in range(len(data)):
        # pass every second letter
        if (i + 1) % 2 == 0:
            result += data[i]
        # pass spaces
        elif data[i] == ' ':
            result += ' '
        else:
            # get decrypted char
            result += get_char(data[i], iterations)

    return result


def decrypt(data, iterations):
    """
    decrypts give data (text) according to a given decryption data
    :param data: text
    :param iterations: encryption data
    :return: decrypted data
    """
    data = data.lower()
    result = ""

    # decrypt data
    for i in range(len(data)):
        # pass every second letter
        if (i + 1) % 2 == 0:
            result += data[i]
        # pass spaces
        elif data[i] == ' ':
            result += ' '
        else:
            # get decrypted char
            result += get_reverse_char(data[i], iterations)

    return result


def answer_separator(server_answer):
    """
    separates data fro server
    :param server_answer: data from server
    :return: separated data
    """
    status = server_answer[:3]
    code = int(server_answer[3:6])
    message = server_answer[6:]

    return status, code, message


def alien_checker(packet):
    """
    checks if packet is valid
    :param packet: sniffed packet
    :return: if packet is valid
    """
    return UDP in packet \
           and IP in packet \
           and Raw in packet \
           and packet[IP].src == server_IP


def alien_print(packet):
    """
    prints data from server, collects needed data and more
    :param packet: sniffed packet
    :return: None
    """
    # getting data and decrypting it
    server_answer = packet[Raw].load.decode()
    status, code, message = answer_separator(server_answer)
    message = decrypt(message, code)

    # getting port of Alien Client
    global local_port
    local_port = packet[UDP].dport

    global vehicle_id
    global airport
    global sent
    global sent_planet

    # printing server answer data
    print(f"""{GREEN}
    Status: {status}, code: {code}
    Decrypted: {message}
    {RESET}""")

    # collection and parcing data
    if not sent_planet:
        # sending destination planet
        print(f"{RED}Sending Aliens to Jupiter{RESET}")

        # encrypting data
        payload = encrypt(DESTINATION, 3)

        # sending
        udp_message = IP(dst=server_IP) / UDP(dport=sever_Port, sport=local_port) / Raw(
            load=MESSAGE_ENT + "003" + payload)
        send(udp_message)
        sent_planet = True
    elif "vehicle chosed" in message:
        # collecting vehicle info
        vehicle_id = message.split(' id ')[1]

        # print vehicle info
        print(f"""{RED} 
        Vehicle Found
        Vehicle id: {vehicle_id} 
        {RESET}""")
    elif "airport selected" in message:
        # collecting airport info
        airport = message.split("takeoff: ")[1]

        # printing airport info
        print(f"""{RED} 
        Airport Found
        Airport name: {airport} 
        {RESET}""")
    elif "location data" in message:
        # collecting airport info and parcing it
        data = message[13:]
        number = data.split("/")[0]
        info = data.split(": ")[1]
        location_data[number] = info

        # printing location data
        print(f"""{RED} 
        Data: {data} 
        {RESET}""")
    elif status == "YES":
        print_end()

    # checking if it is possible to send them back
    if not sent and vehicle_id != '' and airport != '' and len(location_data) == 10:
        data = ""
        # creating location data string
        for val in location_data.values():
            data += val

        # sending aliens home
        send_fly(vehicle_id, airport, data)
        sent = True


def send_fly(vehicle, airprt, location):
    """
    sends FLY request to aliens
    :param vehicle: vehicle id
    :param airprt: airport info
    :param location: location info
    :return: None
    """
    # encoding location data
    result = hashlib.md5(location.encode())
    result = result.hexdigest()

    # creating landing data
    data = MESSAGE_LANDING.format(result, airprt, vehicle)
    # printing data
    print(f"{BLUE}Sending a FLY request: {RESET}")
    # creating payload
    payload = encrypt(data, 8)

    # sending
    udp_message = IP(dst=server_IP) / UDP(dport=sever_Port, sport=local_port) / Raw(load=MESSAGE_FLY + "008" + payload)
    send(udp_message)


def main():
    print_start()
    print(f"{BLUE}Collecting data: {RESET}")

    # starting data collection
    packets = sniff(lfilter=alien_checker, prn=alien_print)


if __name__ == '__main__':
    main()
