#!/usr/bin/env python

from utils import least_significant_mask, most_significant_mask, s_box, s_box_inv, transpose, rcon, mul2, mul3, mul9, mul11, mul13, mul14, padding, test_key, test_key_256, print_3d_bytes, print_2d_bytes
from copy import copy, deepcopy
import argparse


def encrypt_128(block, expanded_keys):

    add_round_key(block, expanded_keys[0])

    for i in range(9):
        sub_bytes(block)
        block = transpose(block)
        shift_rows(block)
        block = transpose(block)
        block = mix_columns(block)
        add_round_key(block, expanded_keys[i + 1])

    sub_bytes(block)
    block = transpose(block)
    shift_rows(block)
    block = transpose(block)
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    return block


def decrypt_128(block, expanded_keys):
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    for i in range(9):
        block = transpose(block)
        inv_shift_rows(block)
        block = transpose(block)
        inv_sub_bytes(block)
        add_round_key(block, expanded_keys[len(expanded_keys) - 2 - i])
        block = inv_mix_columns(block)

    block = transpose(block)
    inv_shift_rows(block)
    block = transpose(block)
    inv_sub_bytes(block)
    add_round_key(block, expanded_keys[0])

    return block


def encrypt_256(block, expanded_keys):
    add_round_key(block, expanded_keys[0])

    for i in range(13):
        sub_bytes(block)
        block = transpose(block)
        shift_rows(block)
        block = transpose(block)
        block = mix_columns(block)
        add_round_key(block, expanded_keys[i + 1])

    sub_bytes(block)
    block = transpose(block)
    shift_rows(block)
    block = transpose(block)
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    return block


def decrypt_256(block, expanded_keys):
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    for i in range(13):
        block = transpose(block)
        inv_shift_rows(block)
        block = transpose(block)
        inv_sub_bytes(block)
        add_round_key(block, expanded_keys[len(expanded_keys) - 2 - i])
        block = inv_mix_columns(block)

    block = transpose(block)
    inv_shift_rows(block)
    block = transpose(block)
    inv_sub_bytes(block)
    add_round_key(block, expanded_keys[0])

    return block


def get_sbox_indices(byte):
    int_val = int.from_bytes(byte, byteorder='big')
    row = int_val // 16
    col = int_val % 16
    return (row, col)


def xor_columns(col1, col2):
    for i in range(4):
        col1[i] = (col1[i][0] ^ col2[i][0]).to_bytes(1, byteorder='big')
    return col1


def key_expansion_core(column, i):
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
    expanded_keys = []
    expanded_keys.append(input_key)

    num_bytes_generated = 16
    rcon_iteration = 1
    temp = []
    expanded_keys.append([])
    ek_index = 1

    while num_bytes_generated < 176:

        if num_bytes_generated % 16 == 0:
            temp = list(expanded_keys[(num_bytes_generated // 16) - 1][3])
        else:
            temp = list(expanded_keys[num_bytes_generated // 16][
                        ((num_bytes_generated % 16) // 4) - 1])

        if num_bytes_generated % 16 == 0:
            temp = key_expansion_core(temp, rcon_iteration)
            rcon_iteration += 1

        temp = xor_columns(
            temp, expanded_keys[(num_bytes_generated // 16) - 1][(num_bytes_generated % 16) // 4])

        expanded_keys[ek_index].append(list(temp))

        if len(expanded_keys[ek_index]) == 4:
            expanded_keys.append([])
            ek_index += 1

        num_bytes_generated += 4

    del expanded_keys[len(expanded_keys) - 1]

    return expanded_keys

def key_expansion_256(input_key):
    expanded_keys = []
    expanded_keys.append(input_key[0])
    expanded_keys.append(input_key[1])
    #expanded_keys.append(input_key)
    #print(input_key)

    num_bytes_generated = 32
    rcon_iteration = 1
    temp = []
    expanded_keys.append([])
    ek_index = 2

    while num_bytes_generated < 240:

        if num_bytes_generated % 16 == 0:
            temp = list(expanded_keys[(num_bytes_generated // 16) - 1][3])
        else:
            temp = list(expanded_keys[num_bytes_generated // 16][
                        ((num_bytes_generated % 16) // 4) - 1])

        if num_bytes_generated % 32 == 0 and num_bytes_generated % 16 == 0:
            temp = key_expansion_core(temp, rcon_iteration)
            rcon_iteration += 1

        if num_bytes_generated % 16 == 0 and num_bytes_generated % 32 != 0:
            for i in range(4):
                row, col = get_sbox_indices(temp[i])
                temp[i] = s_box[row][col]


        #print(type(temp[0][0]))
        #print_2d_bytes(temp)

        temp = xor_columns(
            temp, expanded_keys[(num_bytes_generated // 16) - 2][(num_bytes_generated % 16) // 4])

        expanded_keys[ek_index].append(list(temp))

        if len(expanded_keys[ek_index]) == 4:
            expanded_keys.append([])
            ek_index += 1

        num_bytes_generated += 4

    del expanded_keys[len(expanded_keys) - 1]

    return expanded_keys


def inv_sub_bytes(block):
    for column in block:
        for i in range(len(column)):
            col_index = least_significant_mask & column[i][0]
            row_index = (most_significant_mask & column[i][0]) >> 4
            column[i] = s_box_inv[row_index][col_index]


def sub_bytes(block):
    for column in block:
        for i in range(len(column)):
            col_index = least_significant_mask & column[i][0]
            row_index = (most_significant_mask & column[i][0]) >> 4
            column[i] = s_box[row_index][col_index]


def inv_shift_rows(block):
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
    temp = deepcopy(block)
    for i in range(4):
        temp[i][0] = (mul14[block[i][0][0]][0] ^ mul11[block[i][1][0]][0] ^ mul13[block[i][2][0]][0] ^ mul9[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][1] = (mul9[block[i][0][0]][0] ^ mul14[block[i][1][0]][0] ^ mul11[block[i][2][0]][0] ^ mul13[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][2] = (mul13[block[i][0][0]][0] ^ mul9[block[i][1][0]][0] ^ mul14[block[i][2][0]][0] ^ mul11[block[i][3][0]][0]).to_bytes(1, byteorder='big')
        temp[i][3] = (mul11[block[i][0][0]][0] ^ mul13[block[i][1][0]][0] ^ mul9[block[i][2][0]][0] ^ mul14[block[i][3][0]][0]).to_bytes(1, byteorder='big')
    return temp

def mix_columns(block):
    temp = deepcopy(block)
    for i in range(4):
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
    for i in range(4):
        block[i] = xor_columns(block[i], round_key[i])
    return block


def read_file(filename):
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
                if byte != b'':
                    real_byte_count += 1
                    col.append(byte)
                else:
                    col.append(b'\x00')
                byte = file.read(1)
            block.append(col)
        state.append(block)

    padding_byte_count = 16 - (real_byte_count % 16)

    if real_byte_count % 16 == 0:
        state.append(padding)

    if padding_byte_count != 16:
        state[len(state) - 1][3][
            3] = padding_byte_count.to_bytes(1, byteorder='big')

    return state

def read_key(filename):
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
    
    print(key)
    if len(key) == 1:
            key = key[0]

    return key

def remove_padding(state):
    padded_bytes = state[3][3][0]
    zero_bytes = 1
    for i in range(3, -1, -1):
        for j in range(3, -1, -1):
            if i == 3 and j == 3:
                continue
            if state[i][j][0] == 0:
                zero_bytes += 1

    if padded_bytes == zero_bytes:
        for i in range(3, -1, -1):
            for j in range(3, -1, -1):
                if zero_bytes > 0:
                    state[i][j] = b''
                    zero_bytes -= 1

    return state

def output_to_file(filename, state):
    with open(filename, "wb") as file:
        for i in range(len(state)):
            for j in range(4):
                for k in range(4):
                    if state[i][j][k] != b'':
                        file.write(bytes(state[i][j][k]))

def main():
    """
    state = read_file("test2.txt")
    for i in range(len(state)):
        # print(state[i])
        # print("")
        continue
    print()
    sub_bytes(state[0])
    print(state[0])
    print()
    print(transpose(state[0]))

    matrix = [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]
    print(matrix)
    print("")
    shift_rows(matrix)
    print(matrix)
    print(get_sbox_indices(b'\x02'))
    """

    test = [
        [b'\x00', b'\x00', b'\x00', b'\x00'], [
            b'\x00', b'\x00', b'\x00', b'\x00'],
        [b'\x00', b'\x00', b'\x00', b'\x00'], [b'\x00', b'\x00', b'\x00', b'\x00']]
    test2 = [
        [b'\x7c', b'\x6b', b'\x01', b'\xd7'], [
            b'\xf2', b'\x30', b'\xfe', b'\x63'],
        [b'\x2b', b'\x76', b'\x7b', b'\xc5'], [b'\xab', b'\x77', b'\x6f', b'\x67']]
    """
    print("")
    print("")
    result = key_expansion(test)
    for key in result:
        for row in key:
            print(row, end='')
            print("")
    """

    """
    print(test2)
    print("")

    print(len(mul2))
    print(len(mul3))

    print(transpose(mix_columns(transpose(test2))))
    """

    test3 = [
        [b'\x00', b'\x11', b'\x22', b'\x33'], [
            b'\x44', b'\x55', b'\x66', b'\x77'],
        [b'\x88', b'\x99', b'\xaa', b'\xbb'], [b'\xcc', b'\xdd', b'\xee', b'\xff']]

    test_key2 = [
        [b'\x00', b'\x01', b'\x02', b'\x03'], [
            b'\x04', b'\x05', b'\x06', b'\x07'],
        [b'\x08', b'\x09', b'\x0a', b'\x0b'], [b'\x0c', b'\x0d', b'\x0e', b'\x0f']]

    state = read_file("test/input")
    for i in range(len(state)):
        #print("Initial State: Block", i)
        #print_2d_bytes(state[i])
        #print("")
        continue

    test_key = read_key("test/key2")
    #print("This is the key")
    expanded_keys = key_expansion_256(test_key)
    #print("Expanded Key")
    #print_3d_bytes(expanded_keys)
    #print("")

    for i in range(len(state)):
        #print("Encrypted State: Block", i)
        #print_2d_bytes(decrypt_256(encrypt_256(state[i], expanded_keys), expanded_keys))
        state[i] = encrypt_256(state[i], expanded_keys)
        #print("")

    for i in range(len(state)):
        state[i] = decrypt_256(state[i], expanded_keys)

    #print(state[1])
    #print("No Padding")
    state[len(state) - 1] = remove_padding(state[len(state) - 1])
    #print(s)
    #print_2d_bytes(s)
    print_3d_bytes(state)

    output_to_file("test_output", state)

    #matrix = [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]
    #print("test inv_shift_rows")
    #inv_shift_rows(matrix)
    #print(matrix)
    #print(test_key_256)
    #expanded_keys = key_expansion_256(test_key_256)
    #print_3d_bytes(expanded_keys)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test AES implem')

    parser.add_argument('keysize', metavar='aes_size', type=int,
                        help='Which AES mode (128/256)', choices=[128,256])

    parser.add_argument('keyfile', metavar='key_file_name', type=str,
                        help='File used for key')

    parser.add_argument('inputfile', metavar='input_file_name', type=str,
                        help='File used for message')

    parser.add_argument('outputfile', metavar='output_file_name', type=str,
                        help='File used for output')

    parser.add_argument('mode', metavar='encrypt_or_decrypt', type=str,
                        help='Which function (encrypt/decrypt)'. choices=["encrypt","decrypt","e","d"])

    args = parser.parse_args()

    keyfile = args.inputfile
    inputfile = args.inputfile
    outputfile = args.outputfile
    state = read_file(inputfile)
    expanded_keys = []

    if args.keysize == 128:
        expanded_keys = key_expansion(read_key(keyfile))

        if args.mode == "encrypt" or args.mode == "e":
            state = encrypt_128(state, expanded_keys)
        else:
            state = decrypt_128(state, expanded_keys)
            state[len(state) - 1] = remove_padding(state[len(state) - 1])


    else:
        expanded_keys = key_expansion_256(read_key(keyfile))

        if args.mode == "encrypt" or args.mode == "e":
            state = encrypt_256(state, expanded_keys)
        else:
            state = decrypt_256(state, expanded_keys)
            state[len(state) - 1] = remove_padding(state[len(state) - 1])

    output_to_file(outputfile, state)
