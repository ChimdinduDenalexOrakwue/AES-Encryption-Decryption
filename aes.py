"""

"""
from utils import least_significant_mask, most_significant_mask, s_box, s_box_inv, transpose


def encrypt():
    return


def decrypt():
    return


def key_expansion():
    return


def sub_bytes(block):
    for column in block:
        for i in range(len(column)):
            col_index = least_significant_mask & column[i][0]
            row_index = (most_significant_mask & column[i][0]) >> 4
            column[i] = s_box[row_index][col_index]


def shift_rows(block):
    return


def mix_columns(block):
    return


def add_round_key(block):
    return


def read_file(filename):
    state = []
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
                    col.append(b'\x00')
                byte = file.read(1)
            block.append(col)
        state.append(block)
    return state


def main():
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

if __name__ == '__main__':
    main()
