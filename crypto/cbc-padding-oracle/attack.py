import requests
requests.packages.urllib3.disable_warnings()
from Crypto.Util.Padding import pad, unpad
from os import urandom

LocalURL = 'http://localhost:5000'
RemoteURL = 'https://cbc.syssec.dk/'

BLOCK_SIZE = 16
URL = LocalURL

def retrieve_authtoken() -> bytes:
    '''Request the authtoken from the server'''
    try:
        # Send a GET request to the server
        response = requests.get(URL, verify=False)
        # Return the authtoken from the response cookies as bytes
        return bytes.fromhex(response.cookies['authtoken'])
    except Exception as e:
        print(f"Error retrieving authtoken: {e}")
        raise

def split_into_blocks(data: bytes, block_size: int) -> list[bytes]:
    '''Split the given data into blocks of the specified size'''
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def is_padding_valid(ciphertext: bytes) -> bool:
    '''Send the ciphertext to the padding oracle and check if the padding is valid'''
    try:
        response = requests.get(URL + '/quote/', cookies={'authtoken': ciphertext.hex()}, verify=False)
        return "No quote for you!" in response.text or "can't decode" in response.text
    except Exception as e:
        print(f"Error validating padding: {e}")
        raise

def single_block_attack(block: bytes) -> bytes:
    '''Perform a padding oracle attack on a single block'''
    cbc_decryption_output = bytearray(BLOCK_SIZE)
    attack_iv = bytearray(BLOCK_SIZE)

    # Iterate over each padding value
    for padding_value in range(1, BLOCK_SIZE + 1):
        for i in range(-1, -padding_value, -1):
            # Zero out the IV values that have already been decrypted
            attack_iv[i] = cbc_decryption_output[i] ^ padding_value
            print('Zeroing IV: ', attack_iv)

        # Iterate over each possible byte value
        for byte_value in range(256):
            attack_iv[-padding_value] = byte_value
            # Check if the padding is valid
            if is_padding_valid(bytes(attack_iv + block)):
                cbc_decryption_output[-padding_value] = byte_value ^ padding_value
                break

    return cbc_decryption_output

def decrypt_block(iv: bytes, cbc_decryption_output: bytes) -> bytes:
    ''' Decrypt a block using the IV and the output of the padding oracle attack '''
    return bytes([cbc_decryption_output[i] ^ iv[i] for i in range(BLOCK_SIZE)])

def decrypt(ciphertext: bytes) -> bytes:
    '''Decrypt the given ciphertext'''
    blocks = split_into_blocks(ciphertext, BLOCK_SIZE)
    iv, ciphertext_blocks = blocks[0], blocks[1:]
    plaintext = bytearray()

    for block in ciphertext_blocks:
        # Perform a padding oracle attack on each block½
        cbc_decryption_output = single_block_attack(block)
        plaintext.extend(decrypt_block(iv, cbc_decryption_output))
        iv = block

    return unpad(plaintext, BLOCK_SIZE)

def extract_secret(plaintext: bytes) -> str:
    '''Extract the secret from the decrypted plaintext'''
    try:
        decoded_string = plaintext.decode()
        prefix = 'You never figure out that "'
        suffix = '". :)'
        if decoded_string.startswith(prefix) and decoded_string.endswith(suffix):
            return decoded_string[len(prefix):-len(suffix)]
        else:
            raise ValueError("Invalid plaintext format")
    except Exception as e:
        print(f"Error extracting secret: {e}")
        raise

def create_authtoken(secret: str) -> bytes:
    '''Create an authtoken using the given secret'''
    return (secret + ' plain CBC is not secure!').encode()

def encrypt(message: bytes) -> bytes:
    '''Encrypt the given message'''
    plaintext = pad(message, BLOCK_SIZE)
    plaintext_blocks = split_into_blocks(plaintext, BLOCK_SIZE)
    ciphertext_blocks = [urandom(BLOCK_SIZE)]

    for block in reversed(plaintext_blocks):
        decryption_output = single_block_attack(ciphertext_blocks[0])
        new_block = bytes([block[i] ^ decryption_output[i] for i in range(BLOCK_SIZE)])
        ciphertext_blocks.insert(0, new_block)

    return b''.join(ciphertext_blocks)

def validate_ciphertext(ciphertext: bytes):
    '''Validate the given ciphertext'''
    try:
        response = requests.get(URL + '/quote/', cookies={'authtoken': ciphertext.hex()}, verify=False)
        print("Quote:", response.text)
    except Exception as e:
        print(f"Error validating ciphertext: {e}")
        raise

def main():
    try:
        encrypted_authtoken = retrieve_authtoken()
        decrypted_authtoken = decrypt(encrypted_authtoken)
        secret = extract_secret(decrypted_authtoken)
        message = create_authtoken(secret)
        ciphertext = encrypt(message)
        print(f"Secret: {secret}")
        print('Ciphertext:', ciphertext.hex())
        validate_ciphertext(ciphertext)
    except Exception as e:
        print(f"Fatal error: {e}")

if __name__ == '__main__':
    main()