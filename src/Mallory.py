from transport import accept_peer, send_message, receive_message, connect_to_peer
import sys

MALLORY_PORT = 5005
BOB_PORT = 5000

if len(sys.argv) != 3:
    print("Usage: python Mallory.py <Alice-IP> <Bob-IP>")
    raise SystemExit(1)

BobIP = sys.argv[2]

print(f"LOG: Mallory ready to intercept on TCP port {MALLORY_PORT}...")

sockAlice, peerAlice = accept_peer(MALLORY_PORT)
print("LOG: Mallory connected to", peerAlice)
# print("Mallory: connected to BOB")

# Alice -> Mallory -> Bob
message = receive_message(sockAlice)
print("MSG: ", message.decode())

message = message + b"89"

sockBob = connect_to_peer(BobIP, BOB_PORT)
send_message(sockBob, message)
print("LOG: Message Modified and passed on")

# Bob -> Mallory -> Alice
message = receive_message(sockBob)
print("MSG: ", message.decode())

message = message + b"00"
print("Message Modified and passed on")

send_message(sockAlice, message)