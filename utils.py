"""
utils for aes
"""

most_significant_mask = 0xf0
least_significant_mask = 0x0f

# block of Zero-byte padding
padding = [
    [b'\x00', b'\x00', b'\x00', b'\x00'], [b'\x00', b'\x00', b'\x00', b'\x00'],
    [b'\x00', b'\x00', b'\x00', b'\x00'], [b'\x00', b'\x00', b'\x00', b'\x10']]


def transpose(block):
	""" Transposes a N x N matrix. """
	new_block = [[block[col][row] for col in range(len(block))] for row in range(len(block[0]))]
	return new_block


def print_3d_bytes(list_of_matrix):
	"""
	Prints a 3D matrix of bytes in a readable fashion.
	"""
	print("\n".join([" ".join([" ".join([str(k.hex()) for k in j]) for j in i]) for i in list_of_matrix]))


def print_2d_bytes(matrix):
	"""
	Prints a 2D matrix of bytes in a readable fashion.
	"""
	print("\n".join([" ".join([str(k.hex()) for k in j]) for j in matrix]))
