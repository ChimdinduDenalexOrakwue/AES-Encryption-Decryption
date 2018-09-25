#!/usr/bin/python3

from utils import least_significant_mask, most_significant_mask, transpose, print_3d_bytes, print_2d_bytes, padding
from lookup_tables import s_box, s_box_inv, rcon, mul2, mul3, mul9, mul11, mul13, mul14
from copy import deepcopy
import argparse


def encrypt_128(block, expanded_keys):
    """
    Encrypts a single 16-byte block using AES 128.
    """
    add_round_key(block, expanded_keys[0])

    # performs AES encryption rounds on the block
    for i in range(9):
        sub_bytes(block)
        # transpose because columns are represented as rows in our
        # implementation
        block = transpose(block)
        shift_rows(block)
        block = transpose(block)
        block = mix_columns(block)
        add_round_key(block, expanded_keys[i + 1])

    # performs the final round before returning the block
    sub_bytes(block)
    block = transpose(block)
    shift_rows(block)
    block = transpose(block)
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    return block


def decrypt_128(block, expanded_keys):
    """
    Decrypts a single 16-byte block using AES 128.
    """
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    # performs AES decryption rounds on the block
    for i in range(9):
        block = transpose(block)
        inv_shift_rows(block)
        block = transpose(block)
        inv_sub_bytes(block)
        add_round_key(block, expanded_keys[len(expanded_keys) - 2 - i])
        block = inv_mix_columns(block)

    # performs the final round before returning the block
    block = transpose(block)
    inv_shift_rows(block)
    block = transpose(block)
    inv_sub_bytes(block)
    add_round_key(block, expanded_keys[0])

    return block


def encrypt_256(block, expanded_keys):
    """
    Encrypts a single 16-byte block using AES 256.
    """
    add_round_key(block, expanded_keys[0])

    # performs AES encryption rounds on the block
    for i in range(13):
        sub_bytes(block)
        block = transpose(block)
        shift_rows(block)
        block = transpose(block)
        block = mix_columns(block)
        add_round_key(block, expanded_keys[i + 1])

    # performs the final round before returning the block
    sub_bytes(block)
    block = transpose(block)
    shift_rows(block)
    block = transpose(block)
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    return block


def decrypt_256(block, expanded_keys):
    """
    Decrypts a single 16-byte block using AES 256.
    """
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    # performs AES decryption rounds on the block
    for i in range(13):
        block = transpose(block)
        inv_shift_rows(block)
        block = transpose(block)
        inv_sub_bytes(block)
        add_round_key(block, expanded_keys[len(expanded_keys) - 2 - i])
        block = inv_mix_columns(block)

    # performs the final round before returning the block
    block = transpose(block)
    inv_shift_rows(block)
    block = transpose(block)
    inv_sub_bytes(block)
    add_round_key(block, expanded_keys[0])

    return block


def get_sbox_indices(byte):
    """
    Returns the row and column in the AES S-Box for a given byte.
    """
    int_val = int.from_bytes(byte, byteorder='big')
    row = int_val // 16
    col = int_val % 16
    return (row, col)


def xor_columns(col1, col2):
    """ Returns the xor of col1 and col2. """
    for i in range(4):
        col1[i] = (col1[i][0] ^ col2[i][0]).to_bytes(1, byteorder='big')
    return col1


def key_expansion_core(column, i):
    """
    Performs the core of the key expansion which includes rotating the column to the left,
    swapping each byte with the corresponding value from the AES S-Box, and XORS the first
    byte in the column with a value from the rcon lookup table.
    """
    temp = column[0]
    column[0] = column[1]
    column[1] = column[2]
    column[2] = column[3]
    column[3] = temp

    row, col = get_sbox_indices(column[0])
    column[0] = s_box[row][col]

    row, col = get_sbox_indices(column[1])
    column[1] = s_box[row][col]

    row, col = get_sbox_indices(column[2])
    column[2] = s_box[row][col]

    row, col = get_sbox_indices(column[3])
    column[3] = s_box[row][col]

    column[0] = (column[0][0] ^ rcon[i][0]).to_bytes(1, byteorder='big')

    return column


def key_expansion(input_key):
    """
    Expands the key into 11 round keys for AES 128.
    """
    expanded_keys = []

    # qppends the initial input key as it is
    expanded_keys.append(input_key)

    num_bytes_generated = 16
    rcon_iteration = 1
    temp = []
    expanded_keys.append([])
    ek_index = 1

    # keeps expanding key until 11 round keys (176 bytes) are generated
    while num_bytes_generated < 176:

        # gets the expanded key column for a given round from the corresponding four
        # words of the round key for the previous round
        if num_bytes_generated % 16 == 0:
            temp = list(expanded_keys[(num_bytes_generated // 16) - 1][3])
        else:
            temp = list(expanded_keys[num_bytes_generated // 16][
                        ((num_bytes_generated % 16) // 4) - 1])

        # performs the core key expansion on this round key
        if num_bytes_generated % 16 == 0:
            temp = key_expansion_core(temp, rcon_iteration)
            rcon_iteration += 1

        # generates the new word by XORing the previous word and the corresponding word in
        # the previous 4-word grouping
        temp = xor_columns(
            temp, expanded_keys[(num_bytes_generated // 16) - 1][(num_bytes_generated % 16) // 4])

        expanded_keys[ek_index].append(list(temp))

        # appends an empty list to maintain 4-word grouping in the key
        # expansion
        if len(expanded_keys[ek_index]) == 4:
            expanded_keys.append([])
            ek_index += 1

        num_bytes_generated += 4

    # removes empty element from the end
    del expanded_keys[len(expanded_keys) - 1]

    return expanded_keys


def key_expansion_256(input_key):
    """
    Expands the key into 15 round keys for AES 256.
    """
    expanded_keys = []

    # qppends the initial input key as it is
    expanded_keys.append(input_key[0])
    expanded_keys.append(input_key[1])

    num_bytes_generated = 32
    rcon_iteration = 1
    temp = []
    expanded_keys.append([])
    ek_index = 2

    # keeps expanding key until 11 round keys (176 bytes) are generated
    while num_bytes_generated < 240:

        # gets the expanded key column for a given round from the corresponding four
        # words of the round key for the previous round
        if num_bytes_generated % 16 == 0:
            temp = list(expanded_keys[(num_bytes_generated // 16) - 1][3])
        else:
            temp = list(expanded_keys[num_bytes_generated // 16][
                        ((num_bytes_generated % 16) // 4) - 1])

        # performs the core key expansion on this round key
        if num_bytes_generated % 32 == 0 and num_bytes_generated % 16 == 0:
            temp = key_expansion_core(temp, rcon_iteration)
            rcon_iteration += 1

        if num_bytes_generated % 16 == 0 and num_bytes_generated % 32 != 0:
            for i in range(4):
                row, col = get_sbox_indices(temp[i])
                temp[i] = s_box[row][col]

        # generates the new word by XORing the previous word and the corresponding word in
        # the previous 4-word grouping
        temp = xor_columns(
            temp, expanded_keys[(num_bytes_generated // 16) - 2][(num_bytes_generated % 16) // 4])

        expanded_keys[ek_index].append(list(temp))

        # appends an empty list to maintain 4-word grouping in the key
        # expansion
        if len(expanded_keys[ek_index]) == 4:
            expanded_keys.append([])
            ek_index += 1

        num_bytes_generated += 4

    # removes empty element from the end
    del expanded_keys[len(expanded_keys) - 1]

    return expanded_keys


def inv_sub_bytes(block):
    """
    Replaces each value in the block with the corresponding value in the inverse AES S-Box.
    """
    for column in block:
        for i in range(len(column)):
            # col_index is the least significant nibble
            col_index = least_significant_mask & column[i][0]
            # rox_index is the most significant nibble
            row_index = (most_significant_mask & column[i][0]) >> 4
            # get inverse AES S-Box value based on col_index and row_index
            column[i] = s_box_inv[row_index][col_index]


def sub_bytes(block):
    """
    Replaces each value in the block with the corresponding value in the AES S-Box.
    """
    for column in block:
        for i in range(len(column)):
            # col_index is the least significant nibble
            col_index = least_significant_mask & column[i][0]
            # rox_index is the most significant nibble
            row_index = (most_significant_mask & column[i][0]) >> 4
            # get AES S-Box value based on col_index and row_index
            column[i] = s_box[row_index][col_index]


def inv_shift_rows(block):
    """
    Shifts every byte in the row to the right by i, where i == row position.
    """
    # row 2
    temp = block[1][3]
    block[1][3] = block[1][2]
    block[1][2] = block[1][1]
    block[1][1] = block[1][0]
    block[1][0] = temp

    # row 3
    temp = block[2][0]
    block[2][0] = block[2][2]
    block[2][2] = temp
    temp = block[2][1]
    block[2][1] = block[2][3]
    block[2][3] = temp

    # row 4
    temp = block[3][0]
    block[3][0] = block[3][1]
    temp2 = block[3][3]
    block[3][3] = temp
    block[3][1] = block[3][2]
    block[3][2] = temp2


def shift_rows(block):
    """
    Shifts every byte in the row to the left by i, where i == row position.
    """
    # row 2
    temp = block[1][0]
    block[1][0] = block[1][1]
    block[1][1] = block[1][2]
    block[1][2] = block[1][3]
    block[1][3] = temp

    # row 3
    temp = block[2][0]
    block[2][0] = block[2][2]
    block[2][2] = temp
    temp = block[2][1]
    block[2][1] = block[2][3]
    block[2][3] = temp

    # row 4
    temp = block[3][0]
    block[3][0] = block[3][3]
    block[3][3] = block[3][2]
    block[3][2] = block[3][1]
    block[3][1] = temp


def inv_mix_columns(block):
    """
    Peforms a matrix multiplication on the block using Galois arithmetic.
    """
    temp = deepcopy(block)
    for i in range(4):
        # uses lookup table for multiplication by 9, 11, 13, and 14
        temp[i][0] = (mul14[block[i][0][0]][0] ^ mul11[block[i][1][0]][0] ^ mul13[
                      block[i][2][0]][0] ^ mul9[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][1] = (mul9[block[i][0][0]][0] ^ mul14[block[i][1][0]][0] ^ mul11[
                      block[i][2][0]][0] ^ mul13[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][2] = (mul13[block[i][0][0]][0] ^ mul9[block[i][1][0]][0] ^ mul14[
                      block[i][2][0]][0] ^ mul11[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][3] = (mul11[block[i][0][0]][0] ^ mul13[block[i][1][0]][0] ^ mul9[
                      block[i][2][0]][0] ^ mul14[block[i][3][0]][0]).to_bytes(1, byteorder='big')
    return temp


def mix_columns(block):
    """
    Peforms a matrix multiplication on the block using Galois arithmetic.
    """
    temp = deepcopy(block)
    for i in range(4):
        # uses lookup table for multiplication by 2 and 3
        temp[i][0] = (mul2[block[i][0][0]][0] ^ mul3[block[i][1][0]][0]
                      ^ block[i][2][0] ^ block[i][3][0]).to_bytes(1, byteorder='big')
        temp[i][1] = (block[i][0][0] ^ mul2[block[i][1][0]][0] ^ mul3[
                      block[i][2][0]][0] ^ block[i][3][0]).to_bytes(1, byteorder='big')
        temp[i][2] = (block[i][0][0] ^ block[i][1][0] ^ mul2[block[i][2][0]][
                      0] ^ mul3[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][3] = (mul3[block[i][0][0]][0] ^ block[i][1][0] ^ block[
                      i][2][0] ^ mul2[block[i][3][0]][0]).to_bytes(1, byteorder='big')
    return temp


def add_round_key(block, round_key):
    """
    XORS every column in the block with the corresponding column in the round key.
    """
    for i in range(4):
        block[i] = xor_columns(block[i], round_key[i])
    return block


def read_and_pad(filename):
    """
    Reads in plaintext message and pads using Zero-byte padding to a multiple of 16 bytes.
    """
    state = []
    file = open(filename, 'rb')
    byte = file.read(1)
    real_byte_count = 0
    padding_byte_count = 0

    while byte != b'':
        block = []
        for i in range(0, 4):
            col = []
            for i in range(0, 4):
                # append byte until EOF
                if byte != b'':
                    real_byte_count += 1
                    col.append(byte)
                # once EOF is reached, append 0 byte
                else:
                    col.append(b'\x00')
                byte = file.read(1)
            block.append(col)
        state.append(block)

    padding_byte_count = 16 - (real_byte_count % 16)

    # if message byte count was a multiple of 16, add padding block
    if real_byte_count % 16 == 0:
        state.append(padding)

    # add number of 0-bytes padded at the end of the last column
    if padding_byte_count != 16:
        state[len(state) - 1][3][
            3] = padding_byte_count.to_bytes(1, byteorder='big')

    return state


def read(filename):
    """
    Reads in file into 16-byte blocks.
    """
    key = []
    file = open(filename, 'rb')
    byte = file.read(1)

    while byte != b'':
        block = []
        for i in range(0, 4):
            col = []
            for i in range(0, 4):
                if byte != b'':
                    col.append(byte)
                else:
                    break
                byte = file.read(1)
            block.append(col)
        key.append(block)

    if len(key) == 1:
            key = key[0]

    return key


def remove_padding(state):
    """
    Removes Zero-byte padding from decrypted text.
    """
    padded_bytes = state[3][3][0]
    zero_bytes = 1
    # read last byte and confirm if it was padded correctly
    for i in range(3, -1, -1):
        for j in range(3, -1, -1):
            if i == 3 and j == 3:
                continue
            if state[i][j][0] == 0:
                zero_bytes += 1

    # replaces padded 0's with EOF
    if padded_bytes == zero_bytes:
        for i in range(3, -1, -1):
            for j in range(3, -1, -1):
                if zero_bytes > 0:
                    state[i][j] = b''
                    zero_bytes -= 1

    return state


def output_to_file(filename, state):
    """
    Writes bytes to output file, ignoring EOF bytes.
    """
    with open(filename, "wb") as file:
        for i in range(len(state)):
            for j in range(4):
                for k in range(4):
                    if state[i][j][k] != b'':
                        file.write(bytes(state[i][j][k]))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AES Implementation')

    parser.add_argument('keysize', metavar='keysize', type=int,
                        help='Which AES mode (128/256)', choices=[128, 256])

    parser.add_argument('keyfile', metavar='keyfile', type=str,
                        help='File used for key')

    parser.add_argument('inputfile', metavar='inputfile', type=str,
                        help='File used for message')

    parser.add_argument('outputfile', metavar='outputfile', type=str,
                        help='File used for output')

    parser.add_argument('mode', metavar='mode', type=str,
                        help='Which function (encrypt/decrypt)', choices=["encrypt", "decrypt", "e", "d"])

    args = parser.parse_args()

    keyfile = args.keyfile
    inputfile = args.inputfile
    outputfile = args.outputfile
    state = read_and_pad(inputfile)
    expanded_keys = []

    if args.keysize == 128:
        expanded_keys = key_expansion(read(keyfile))

        if args.mode == "encrypt" or args.mode == "e":  # performs AES 128 encryption
            for i in range(len(state)):
                state[i] = encrypt_128(state[i], expanded_keys)
        else:                                           # performs AES 128 decryption
            state = read(inputfile)
            for i in range(len(state)):
                state[i] = decrypt_128(state[i], expanded_keys)
            state[len(state) - 1] = remove_padding(state[len(state) - 1])

    else:
        expanded_keys = key_expansion_256(read(keyfile))

        if args.mode == "encrypt" or args.mode == "e":  # performs AES 256 encryption
            for i in range(len(state)):
                state[i] = encrypt_256(state[i], expanded_keys)
        else:                                           # performs AES 256 decryption
            state = read(inputfile)
            for i in range(len(state)):
                state[i] = decrypt_256(state[i], expanded_keys)
            state[len(state) - 1] = remove_padding(state[len(state) - 1])

    output_to_file(outputfile, state)
