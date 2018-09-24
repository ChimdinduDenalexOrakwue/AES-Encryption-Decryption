"""

"""
from utils import least_significant_mask, most_significant_mask, s_box, s_box_inv, transpose, rcon, mul2, mul3, padding, test_key
from copy import copy, deepcopy


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
    shift_rows(block)
    add_round_key(block, expanded_keys[len(expanded_keys) - 1])

    return block


def decrypt_128():
    return


def encrypt_256():
    return


def decrypt_256():
    return


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
            # expanded_keys[ek_index] = transpose(expanded_keys[ek_index])
            expanded_keys.append([])
            ek_index += 1

        num_bytes_generated += 4

    del expanded_keys[len(expanded_keys) - 1]

    return expanded_keys


def sub_bytes(block):
    for column in block:
        for i in range(len(column)):
            col_index = least_significant_mask & column[i][0]
            row_index = (most_significant_mask & column[i][0]) >> 4
            column[i] = s_box[row_index][col_index]


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


# does not work at all
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

    state = read_file("test/input")
    print (state)
    print("")

    expanded_keys = key_expansion(test_key)
    print(expanded_keys)
    print("")

    for i in state:
        print(encrypt_128(i, expanded_keys))


if __name__ == '__main__':
    main()
