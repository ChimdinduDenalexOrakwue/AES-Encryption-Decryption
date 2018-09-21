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
        state.append(transpose(block))
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

    matrix = [[1,2,3,4], [1,2,3,4], [1,2,3,4], [1,2,3,4]]
    print(matrix)
    print("")
    shift_rows(matrix)
    print(matrix)

if __name__ == '__main__':
    main()
