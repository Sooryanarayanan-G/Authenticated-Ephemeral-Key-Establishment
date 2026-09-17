# README


## How to Run
Follow these steps to run the simulation
### Generate fresh Long-Term keys
The long term key pair for Alice and Bob are already generated. If you want to generate a fresh pair, run this command.
```bash
python3 generate_keys.py <folder-path>
```
**Note:** The *folder-path* should be of the form *../keys/Name* where *Name* can be Alice or Bob. 
### Run with Authentication Enabled and Disabled

Running the script by default enables the authentication. These are the commands for Alice and Bob.

- Run Bob first
    ```bash
    python3 Bob.py
    ```
- Then run Alice
    ```bash
    python3 Alice.py <Bob-IP>
    ```

To Disable authentication, use the ```--disable-ed-auth``` flag

- Run Bob first with disabling auth
    ```bash
    python3 Bob.py --disable-ed-auth
    ```
- Then run Alice with disabling auth
    ```bash
    python3 Alice.py <Bob-IP> --disable-ed-auth
    ```
### Run with Man in the Middle

To enable man in the middle follow these steps. Disabling authentication is optional, but Mallory will always try to attack, and hence, the session will be terminated everytime with MITM if authentication is enabled.
These scripts can be run on the same machine or different, it will work all the same.
- Run Bob first
    ```bash
    python3 Bob.py [--disable-ed-auth]
    ```
- Then run Mallory with the correction arguments
    ```bash
    python3 Mallory.py <Alice-IP> <Bob-IP> [--disable-ed-auth]
    ```
- Now run Alice
    ```bash
    python3 Alice.py <Mallory-IP> [--disable-ed-auth]
    ```

**Note**: Mallory IP is fixed to 5005 and Bob IP to 5000
### Perform TR:2
TR:2 specifically disables authentication and lets MITM to modify the messages during the handshake. The result is a successful handshake. Now repeat the experiment with authentication enabled to detect the attack and abort the session.
- Run these in the following order disabling auth
    ```bash
    python3 Bob.py [--disable-ed-auth]
    ```
    ```bash
    python3 Mallory.py <Alice-IP> <Bob-IP> [--disable-ed-auth]
    ```
    ```bash
    python3 Alice.py <Mallory-IP> [--disable-ed-auth]
    ```
    Notice the successful handshake completion.
- Now run the normal session with MITM
    ```bash
    python3 Bob.py
    ```
    ```bash
    python3 Mallory.py <Alice-IP> <Bob-IP>
    ```
    ```bash
    python3 Alice.py <Mallory-IP>
    ```
    Notice the Hanshake failure

### Perform TR:4
TR:4 is checking forward secrecy. We show that if the session keys are compromised, then that session data can be reconstructed.
After every normal session alice session data and keys are stored to the file ```records/recorded_session.txt```. Run the following for this experiment.

- You do no require an immediate MITM here, we need a successful Authenticated Handshake. Therefore run Bob and Alice as mentioned above with auth enabled and without MITM.
- Now run this
    ```bash
    python3 Forward_Secrecy_Expt.py
    ```

We assume that the session keys are also compromised, and show that the data can be reconstructed