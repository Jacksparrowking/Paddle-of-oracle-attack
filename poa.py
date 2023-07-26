import sys
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad

BLOCKSIZE = 8


#  Step 2:
def add_padding(text):
    return pad(data_to_pad=f'{text}'.encode('utf-8'), block_size=BLOCKSIZE)


# Step 3:
def cipher(key, iv, encoded_text):
    ciphertext = DES.new(key=key, mode=DES.MODE_CBC, iv=iv)
    return ciphertext.encrypt(encoded_text)


# Step 4:
def decrypt(key, iv, ciphertext):
    decryption = DES.new(key=key, mode=DES.MODE_CBC, iv=iv)
    d = decryption.decrypt(ciphertext)
    return unpad(d, block_size=BLOCKSIZE)


#  Step 5:
def xor(x, y, z):
    return x ^ y ^ z


#  Step 6:
def oracle(key, iv, ciphertext):
    try:
        decrypt(key, iv, ciphertext)
        return True
    except ValueError:
        return False


#  Step 7:
def c(ciphertext):
    return bytearray(b"\x00" * 8 + ciphertext[8:16])


#  Step 8:
def use_oracle(key, replace_iv, ciphertext, digit):
    for i in range(256):
        ciphertext[digit] = i
        if oracle(key, replace_iv, bytes(ciphertext)):
            return i


#  Step 9:
def decryption(t, original_cipher, byte_digit, byte_num):
    return xor(t, original_cipher, byte_digit[byte_num])


#  step 11:
def block_decryption(previous_block, ciphertext, key, iv):
    plain_text_block = [None] * 8
    for i in range(8):
        xj = use_oracle(key, iv, ciphertext, 7 - i)
        plain_text_block[7 - i] = (xor(xj, previous_block[7 - i], i + 1))
        for j in range(i + 1):
            ciphertext[7 - j] = xor(plain_text_block[7 - j], i + 2, previous_block[7 - j])
            
    return ''.join([chr(i) for i in plain_text_block])


# step 12:
def for_all_blocks(key, iv, ciphertext):
    final_word = []
    blocks = [ciphertext[i: i + BLOCKSIZE] for i in range(0, len(ciphertext), BLOCKSIZE)]
    for idx, block in reversed(list(enumerate(blocks))):
        if idx > 0:
            final_word.append(block_decryption(blocks[idx - 1], bytearray(b'\00' * 8 + block), key, iv))
        else:
            final_word.append(block_decryption(iv, bytearray(b'\00' * 8 + block), key, iv))
    return ''.join(final_word[::-1])


def poa(text, key, ivtemp):
    # ivtemp = b'\x00' * 8
    # key = b'poaisfun'
    # text = 'HeRlo WorRld'

    # pad_text = add_padding(text=text)
    # ciphertext = cipher(key=key, iv=ivtemp, encoded_text=pad_text)
    #print(for_all_blocks(text, ivtemp, ciphertext))
    print(for_all_blocks(key, IVTEMP, text))

def main():
    ciphertext = bytes.fromhex(sys.argv[1])
    key = bytes.fromhex(sys.argv[2])
    iv = bytes.fromhex(sys.argv[3])
    poa(ciphertext, key, iv)
    # poa()

if __name__ == "__main__":
    main()
