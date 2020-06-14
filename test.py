import socket


def create_udp_socket(localIP, localPort):
    # Create a datagram socket
    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    server_address = (localIP, localPort)

    # Bind to address and ip
    UDPServerSocket.bind(server_address)

    print("UDP server up and listening")

    return UDPServerSocket

