"""

"""

def encrypt():
	return
	
def decrypt():
	return

def key_expansion():
	return

def sub_bytes():
	return

def shift_rows():
	return

def mix_columns():
	return

def add_round_key():
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
					col.append(0)
				byte = file.read(1)
			block.append(col)
		state.append(block)
	return state

def main():
	state = read_file("test2.txt")
	for i in range(len(state)):
		print(state[i])
		print("")

if __name__ == '__main__':
	main()