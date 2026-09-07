from transport import connect_to_peer, send_message, receive_message
import sys

isManInTheMiddle = False
BOB_PORT = 5000
MALLORY_PORT = 5005

argLen = len(sys.argv)

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
    sock = connect_to_peer(BobIP, BOB_PORT)
    print("Alice connected to Bob")
    send_message(sock, b"Hello Bob from Alice")
    pass
else:
    # sending through MITM
    sock = connect_to_peer(MalloryIP, MALLORY_PORT)
    print("Alice connected to  Mallory")
    send_message(sock, b"Hello Bob from Alice")
    pass
