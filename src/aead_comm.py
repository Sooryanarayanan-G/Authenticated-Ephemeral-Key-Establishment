import struct
import json
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from transport import send_message, receive_message

logger = logging.getLogger(__name__)

ALICE_ID = b"CS26D400"
BOB_ID = b"CS26M016"

class AEADSession:
    """
    Encapsulates the state for one direction of communication.
    Provides methods to encrypt and decrypt application data using AES-256-GCM.
    """
    def __init__(self, send_key: bytes, recv_key: bytes, alice_id: bytes, bob_id: bytes, alice_sid: bytes, bob_sid: bytes, role: str):
        """
        Initialize the AEAD session state for sending and receiving.
        :param send_key: 32-byte AES key for sending
        :param recv_key: 32-byte AES key for receiving
        :param alice_id: 8-byte ASCII Sender ID
        :param bob_id: 8-byte ASCII Receiver ID
        :param alice_sid: 16-byte Session ID for Alice
        :param bob_sid: 16-byte Session ID for Bob
        :param role: 'Alice' or 'Bob'
        """
        self.send_key = send_key
        self.recv_key = recv_key
        self.alice_id = alice_id
        self.bob_id = bob_id
        self.alice_sid = alice_sid
        self.bob_sid = bob_sid
        self.role = role

        self.send_counter = 0
        self.expected_recv_counter = 0

        self._aesgcm_send = AESGCM(self.send_key)
        self._aesgcm_recv = AESGCM(self.recv_key)

    def _construct_aad(self, sender_id: bytes, receiver_id: bytes, counter: int) -> bytes:
        """Constructs AAD exactly as: Sender_ID || Receiver_ID || Alice_SID || Bob_SID || Message_Counter"""
        counter_bytes = struct.pack(">Q", counter)
        aad = sender_id + receiver_id + self.alice_sid + self.bob_sid + counter_bytes
        return aad

    def _construct_nonce(self, counter: int) -> bytes:
        """Derives the 96-bit nonce as: 0x00000000 || uint64_be(counter)"""
        counter_bytes = struct.pack(">Q", counter)
        nonce = b"\x00\x00\x00\x00" + counter_bytes
        return nonce

    def encrypt_message(self, plaintext: bytes) -> dict:
        """
        Encrypts plaintext into an AEAD record.
        Constructs nonce and AAD based on the current send_counter and role.
        """
        counter = self.send_counter
        nonce = self._construct_nonce(counter)

        if self.role == 'Alice':
            sender_id = self.alice_id
            receiver_id = self.bob_id
        elif self.role == 'Bob':
            sender_id = self.bob_id
            receiver_id = self.alice_id
        else:
            raise ValueError("Invalid role")

        aad = self._construct_aad(sender_id, receiver_id, counter)

        ciphertext = self._aesgcm_send.encrypt(nonce, plaintext, aad)

        self.send_counter += 1

        print(f"[LOG] {self.role} (Sender) encrypting record:")
        print(f"      Counter: {counter}")
        print(f"      Nonce  : {nonce.hex()}")
        print(f"      AAD    : {aad.hex()} (SenderID={sender_id.decode()}, ReceiverID={receiver_id.decode()})")
        print(f"      Ciphertext length: {len(ciphertext)} bytes")
        print(f"      SUCCESS")

        return {
            "counter": counter,
            "ciphertext": ciphertext.hex()
        }

    def decrypt_message(self, record: dict) -> bytes:
        """
        Decrypts an AEAD record into plaintext.
        Rejects stale/unexpected counters and fails on AEAD verification failure.
        """
        counter = record["counter"]
        if counter != self.expected_recv_counter:
            print(f"[LOG] {self.role} (Receiver) FAILED: Replay/Stale counter. Expected {self.expected_recv_counter}, got {counter}")
            raise ValueError(f"Unexpected counter value: expected {self.expected_recv_counter}, got {counter}")

        nonce = self._construct_nonce(counter)

        if self.role == 'Alice':
            sender_id = self.bob_id
            receiver_id = self.alice_id
        elif self.role == 'Bob':
            sender_id = self.alice_id
            receiver_id = self.bob_id
        else:
            raise ValueError("Invalid role")

        aad = self._construct_aad(sender_id, receiver_id, counter)
        ciphertext = bytes.fromhex(record["ciphertext"])

        try:
            plaintext = self._aesgcm_recv.decrypt(nonce, ciphertext, aad)
            self.expected_recv_counter += 1
            print(f"[LOG] {self.role} (Receiver) decrypting record:")
            print(f"      Counter: {counter}")
            print(f"      Nonce  : {nonce.hex()}")
            print(f"      AAD    : {aad.hex()} (SenderID={sender_id.decode()}, ReceiverID={receiver_id.decode()})")
            print(f"      SUCCESS")
            return plaintext
        except Exception as e:
            print(f"[LOG] {self.role} (Receiver) FAILED: AEAD decryption verification failed for counter {counter}")
            raise ValueError("AEAD decryption failed") from e

def send_aead_record(sock, session: AEADSession, plaintext: bytes):
    """Encrypts and sends an AEAD record via transport."""
    record = session.encrypt_message(plaintext)
    payload = json.dumps(record).encode('utf-8')
    send_message(sock, payload)

def receive_aead_record(sock, session: AEADSession) -> bytes:
    """Receives an AEAD record via transport and decrypts it."""
    payload = receive_message(sock)
    record = json.loads(payload.decode('utf-8'))
    return session.decrypt_message(record)

