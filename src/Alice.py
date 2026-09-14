from transport import connect_to_peer, send_message, receive_message
import sys

isManInTheMiddle = False
BOB_PORT = 5000
MALLORY_PORT = 5005

argLen = len(sys.argv)

def SendAndReceiveMessage(ip, port):
    sock = connect_to_peer(ip, port)
    print("LOG: Alice connected to ", ip, ":", port)
    send_message(sock, b"The secret is 1234")
    print("LOG: Message sent to ", ip, ":", port)
    message = receive_message(sock)
    print("MSG: ", message.decode())
    return 0

if (argLen < 2):
    print("Usage: python Alice.py <Receiver-IP> [MITM-IP]")
    raise SystemExit(1)
elif (argLen == 2):
    BobIP = sys.argv[1]
elif (argLen == 3):
    BobIP = sys.argv[1]
    MalloryIP = sys.argv[2]
    isManInTheMiddle = True
else:
    print("Usage: python Alice.py <Receiver-IP> [MITM-IP]")
    raise SystemExit(1)

if (not isManInTheMiddle):
    # sending without MITM
    SendAndReceiveMessage(BobIP, BOB_PORT)
else:
    # sending through MITM
    SendAndReceiveMessage(MalloryIP, MALLORY_PORT)
    pass
