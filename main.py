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
from datetime import datetime

# initialize colorama
init()
# define colors
RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET
MAGENTA = Fore.MAGENTA

# ASCII info
FIRST_ASCII = 97
LAST_ASCII = 122
NUM_ASCII = 26

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
NUM_LOCATION_PARTS = 10
DESTINATION = "jupiter"

# alien protocol data
MESSAGE_ENT = "ENT"
MESSAGE_ERROR = "ERR"
MESSAGE_FLY = "FLY"
MESSAGE_END = "YES"
# landing data pattern
MESSAGE_LANDING = "location_md5={},airport={},time=15:52,lane=earth.jup,vehicle={},fly"

# time
DATETIME_FORMAT = '%B %d, %Y | %H:%M:%S'


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
    print(f"""{GREEN}
     _   _                         _            _   _             
    | | | |                       | |          | | (_)            
    | |_| |__   ___      ___  __ _| |_   ____ _| |_ _  ___  _ __  
    | __| '_ \ / _ \    / __|/ _` | \ \ / / _` | __| |/ _ \| '_ \\
    | |_| | | |  __/    \__ \ (_| | |\ V / (_| | |_| | (_) | | | |
     \__|_| |_|\___|    |___/\__,_|_| \_/ \__,_|\__|_|\___/|_| |_|
    created by: mixelburg 
    {RESET}""")


def get_char(char, iterations, reverse=False):
    """
    encrypts or decrypts given char according to
    given encryption data and 'reverse' flag
    :param char: letter
    :param iterations: encryption data
    :param reverse: flag
    :return: encrypted char
    """
    if char.isalpha():
        # get ascii value
        value = ord(char)

        if reverse:
            # get new ascii value
            new_value = value - iterations
            if new_value < FIRST_ASCII:
                new_value = new_value + NUM_ASCII
        else:
            # get new ascii value
            new_value = value + iterations
            if new_value > LAST_ASCII:
                new_value = new_value % LAST_ASCII + (FIRST_ASCII - 1)

        return chr(new_value)
    return char


def encrypt_decrypt(data, iterations, reverse=False):
    """
    decrypts or encrypts data according to 'reverse' flag
    :param data: data to work with
    :param iterations: encryption pattern
    :param reverse: flag
    :return: reworked data
    """
    data = data.lower()
    result = ""

    # encrypt or decrypt data
    for i in range(len(data)):  # for letter in string
        # skip every second letter
        if (i + 1) % 2 == 0:
            result += data[i]
        # skip spaces
        elif data[i] == ' ':
            result += ' '
        else:
            # get decrypted or encrypted char according to 'reverse' flag
            if reverse:
                result += get_char(data[i], iterations, True)
            else:
                result += get_char(data[i], iterations)

    return result


def answer_separator(server_answer):
    """
    separates data fro server
    :param server_answer: data from server
    :return: separated data
    """
    status = server_answer[:3]
    try:
        code = int(server_answer[3:6])
    except ValueError:
        print("Invalid code, setting it to 0 (no encryption)")
        code = 0
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
    global local_port
    global vehicle_id
    global airport
    global sent

    # getting data and decrypting it
    server_answer = packet[Raw].load.decode()
    # send data to a separator
    status, code, message = answer_separator(server_answer)
    # decrypt data
    message = encrypt_decrypt(message, code, reverse=True)

    # getting port of Alien Client
    local_port = packet[UDP].dport

    # printing server answer data
    print(f"""{GREEN}
    Status: {status}, code: {code}
    Decrypted: {message}
    {RESET}""")

    # collection and parcing data
    if not sent_planet:
        send_initial()
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

        # split location data
        data = message[13:]
        # get num of location data
        number = data.split("/")[0]
        # get the status code
        info = data.split(": ")[1]
        # store part of location data (use dictionary to avoid repeating)
        location_data[number] = info

        # printing location data
        print(f"""{RED} 
        Data: {data} 
        {RESET}""")
    # if aliens agreed to go home, then print the end message
    elif status == MESSAGE_END:
        print_end()
        print(f"Earth saved on: {datetime.now().strftime(DATETIME_FORMAT)}")
        raise KeyboardInterrupt
    elif "timed out" in message: # if some error accured
        print(f"{RED} Error, probably yo didn't receive some packets {RESET}")
        print(f"{BLUE}Starting collecting data and trying one more time: {RESET}")
        send_initial()
        sniff(lfilter=alien_checker, prn=alien_print)

    # checking if it is possible to send them back
    if not sent and vehicle_id != '' and airport != '' and len(location_data) == NUM_LOCATION_PARTS:
        data = ""
        # creating location data string
        for val in location_data.values():
            data += val

        # sending aliens home
        send_fly(vehicle_id, airport, data)
        # raise the flag
        sent = True


def send_initial():
    global sent_planet

    # sending destination planet
    print(f"{RED}Sending Aliens to Jupiter{RESET}")

    # encrypting data
    payload = encrypt_decrypt(DESTINATION, 3)

    # creating message and sending it
    udp_message = IP(dst=server_IP) / UDP(dport=sever_Port, sport=local_port) / Raw(
        load=MESSAGE_ENT + "003" + payload)
    send(udp_message)
    # raising the flag
    sent_planet = True


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
    payload = encrypt_decrypt(data, 8)

    # sending
    udp_message = IP(dst=server_IP) / UDP(dport=sever_Port, sport=local_port) / Raw(load=MESSAGE_FLY + "008" + payload)
    send(udp_message)


def main():
    # print program info
    print_start()
    print(f"{BLUE}Collecting data: {RESET}")
    print(f"{BLUE}Please open Alien client{RESET}")

    # starting data collection
    sniff(lfilter=alien_checker, prn=alien_print)


if __name__ == '__main__':
    main()
