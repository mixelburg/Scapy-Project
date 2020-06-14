import test

# check installed packages
import myLib
myLib.install_check()

from wrappers import make_green, make_red, make_blue


IP = "54.71.128.194"
Port = 99
bufferSize = 1024


def extractor():
    encrypt_pattern = {}
    with open("encryption.txt", 'r') as file:
        for line in file.readlines():
            data = line.split('-')

            encrypt_pattern[str(data[0])] = \
                str(data[1][:-1])

    return encrypt_pattern


def encrypt(data, encryption_pattern):
    data = data.lower()
    result = ""

    for i in range(len(data)):
        if (i + 1) % 2 == 0:
            result += data[i]
        elif data[i] == ' ':
            result += ' '
        else:
            result += encryption_pattern[data[i]]

    return result


@make_green
def main():
    print("Hello")
    encrypt_pattern = extractor()

    UDP_socket = test.create_udp_socket(IP, Port)


    # while (True):
    #     bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    #
    #     message = bytesAddressPair[0]
    #
    #     address = bytesAddressPair[1]
    #
    #     clientMsg = "Message from Client:{}".format(message)
    #     clientIP = "Client IP Address:{}".format(address)
    #
    #     print(clientMsg)
    #     print(clientIP)
    #
    #     # Sending a reply to client
    #
    #     UDPServerSocket.sendto(bytesToSend, address)



if __name__ == '__main__':
    main()