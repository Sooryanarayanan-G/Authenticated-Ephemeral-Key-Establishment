from transport import accept_peer, send_message, receive_message, connect_to_peer
import sys

MALLORY_PORT = 5005
BOB_PORT = 5000

if len(sys.argv) != 3:
    print("Usage: python Mallory.py <Alice-IP> <Bob-IP>")
    raise SystemExit(1)

BobIP = sys.argv[2]

print(f"Mallory ready to interfere on TCP port {MALLORY_PORT}...")

sockAlice, peerAlice = accept_peer(MALLORY_PORT)
print("Mallory: connected to", peerAlice)
message = receive_message(sockAlice)

sockBob = connect_to_peer(BobIP, BOB_PORT)
message = message + b" Hello There..."

send_message(sockBob, message)

