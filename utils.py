"""
utils for aes
"""

most_significant_mask = 0xf0
least_significant_mask = 0x0f

s_box = [
    [b'\x63', b'\x7c', b'\x77', b'\x7b', b'\xf2', b'\x6b', b'\x6f', b'\xc5',
        b'\x30', b'\x01', b'\x67', b'\x2b', b'\xfe', b'\xd7', b'\xab', b'\x76'],
        [b'\xca', b'\x82', b'\xc9', b'\x7d', b'\xfa', b'\x59', b'\x47', b'\xf0',
            b'\xad', b'\xd4', b'\xa2', b'\xaf', b'\x9c', b'\xa4', b'\x72', b'\xc0'],
     [b'\xb7', b'\xfd', b'\x93', b'\x26', b'\x36', b'\x3f', b'\xf7', b'\xcc',
         b'\x34', b'\xa5', b'\xe5', b'\xf1', b'\x71', b'\xd8', b'\x31', b'\x15'],
     [b'\x04', b'\xc7', b'\x23', b'\xc3', b'\x18', b'\x96', b'\x05', b'\x9a',
         b'\x07', b'\x12', b'\x80', b'\xe2', b'\xeb', b'\x27', b'\xb2', b'\x75'],
     [b'\x09', b'\x83', b'\x2c', b'\x1a', b'\x1b', b'\x6e', b'\x5a', b'\xa0',
         b'\x52', b'\x3b', b'\xd6', b'\xb3', b'\x29', b'\xe3', b'\x2f', b'\x84'],
     [b'\x53', b'\xd1', b'\x00', b'\xed', b'\x20', b'\xfc', b'\xb1', b'\x5b',
         b'\x6a', b'\xcb', b'\xbe', b'\x39', b'\x4a', b'\x4c', b'\x58', b'\xcf'],
     [b'\xd0', b'\xef', b'\xaa', b'\xfb', b'\x43', b'\x4d', b'\x33', b'\x85',
         b'\x45', b'\xf9', b'\x02', b'\x7f', b'\x50', b'\x3c', b'\x9f', b'\xa8'],
     [b'\x51', b'\xa3', b'\x40', b'\x8f', b'\x92', b'\x9d', b'\x38', b'\xf5',
         b'\xbc', b'\xb6', b'\xda', b'\x21', b'\x10', b'\xff', b'\xf3', b'\xd2'],
     [b'\xcd', b'\x0c', b'\x13', b'\xec', b'\x5f', b'\x97', b'\x44', b'\x17',
         b'\xc4', b'\xa7', b'\x7e', b'\x3d', b'\x64', b'\x5d', b'\x19', b'\x73'],
     [b'\x60', b'\x81', b'\x4f', b'\xdc', b'\x22', b'\x2a', b'\x90', b'\x88',
         b'\x46', b'\xee', b'\xb8', b'\x14', b'\xde', b'\x5e', b'\x0b', b'\xdb'],
     [b'\xe0', b'\x32', b'\x3a', b'\x0a', b'\x49', b'\x06', b'\x24', b'\x5c',
         b'\xc2', b'\xd3', b'\xac', b'\x62', b'\x91', b'\x95', b'\xe4', b'\x79'],
     [b'\xe7', b'\xc8', b'\x37', b'\x6d', b'\x8d', b'\xd5', b'\x4e', b'\xa9',
         b'\x6c', b'\x56', b'\xf4', b'\xea', b'\x65', b'\x7a', b'\xae', b'\x08'],
     [b'\xba', b'\x78', b'\x25', b'\x2e', b'\x1c', b'\xa6', b'\xb4', b'\xc6',
         b'\xe8', b'\xdd', b'\x74', b'\x1f', b'\x4b', b'\xbd', b'\x8b', b'\x8a'],
     [b'\x70', b'\x3e', b'\xb5', b'\x66', b'\x48', b'\x03', b'\xf6', b'\x0e',
         b'\x61', b'\x35', b'\x57', b'\xb9', b'\x86', b'\xc1', b'\x1d', b'\x9e'],
     [b'\xe1', b'\xf8', b'\x98', b'\x11', b'\x69', b'\xd9', b'\x8e', b'\x94',
         b'\x9b', b'\x1e', b'\x87', b'\xe9', b'\xce', b'\x55', b'\x28', b'\xdf'],
     [b'\x8c', b'\xa1', b'\x89', b'\x0d', b'\xbf', b'\xe6', b'\x42', b'\x68', b'\x41', b'\x99', b'\x2d', b'\x0f', b'\xb0', b'\x54', b'\xbb', b'\x16']]

s_box_inv = [
    [b'\x52', b'\x09', b'\x6a', b'\xd5', b'\x30', b'\x36', b'\xa5', b'\x38',
        b'\xbf', b'\x40', b'\xa3', b'\x9e', b'\x81', b'\xf3', b'\xd7', b'\xfb'],
      [b'\x7c', b'\xe3', b'\x39', b'\x82', b'\x9b', b'\x2f', b'\xff', b'\x87',
          b'\x34', b'\x8e', b'\x43', b'\x44', b'\xc4', b'\xde', b'\xe9', b'\xcb'],
      [b'\x54', b'\x7b', b'\x94', b'\x32', b'\xa6', b'\xc2', b'\x23', b'\x3d',
          b'\xee', b'\x4c', b'\x95', b'\x0b', b'\x42', b'\xfa', b'\xc3', b'\x4e'],
      [b'\x08', b'\x2e', b'\xa1', b'\x66', b'\x28', b'\xd9', b'\x24', b'\xb2',
          b'\x76', b'\x5b', b'\xa2', b'\x49', b'\x6d', b'\x8b', b'\xd1', b'\x25'],
      [b'\x72', b'\xf8', b'\xf6', b'\x64', b'\x86', b'\x68', b'\x98', b'\x16',
          b'\xd4', b'\xa4', b'\x5c', b'\xcc', b'\x5d', b'\x65', b'\xb6', b'\x92'],
      [b'\x6c', b'\x70', b'\x48', b'\x50', b'\xfd', b'\xed', b'\xb9', b'\xda',
          b'\x5e', b'\x15', b'\x46', b'\x57', b'\xa7', b'\x8d', b'\x9d', b'\x84'],
      [b'\x90', b'\xd8', b'\xab', b'\x00', b'\x8c', b'\xbc', b'\xd3', b'\x0a',
          b'\xf7', b'\xe4', b'\x58', b'\x05', b'\xb8', b'\xb3', b'\x45', b'\x06'],
      [b'\xd0', b'\x2c', b'\x1e', b'\x8f', b'\xca', b'\x3f', b'\x0f', b'\x02',
          b'\xc1', b'\xaf', b'\xbd', b'\x03', b'\x01', b'\x13', b'\x8a', b'\x6b'],
      [b'\x3a', b'\x91', b'\x11', b'\x41', b'\x4f', b'\x67', b'\xdc', b'\xea',
          b'\x97', b'\xf2', b'\xcf', b'\xce', b'\xf0', b'\xb4', b'\xe6', b'\x73'],
      [b'\x96', b'\xac', b'\x74', b'\x22', b'\xe7', b'\xad', b'\x35', b'\x85',
          b'\xe2', b'\xf9', b'\x37', b'\xe8', b'\x1c', b'\x75', b'\xdf', b'\x6e'],
      [b'\x47', b'\xf1', b'\x1a', b'\x71', b'\x1d', b'\x29', b'\xc5', b'\x89',
          b'\x6f', b'\xb7', b'\x62', b'\x0e', b'\xaa', b'\x18', b'\xbe', b'\x1b'],
      [b'\xfc', b'\x56', b'\x3e', b'\x4b', b'\xc6', b'\xd2', b'\x79', b'\x20',
          b'\x9a', b'\xdb', b'\xc0', b'\xfe', b'\x78', b'\xcd', b'\x5a', b'\xf4'],
      [b'\x1f', b'\xdd', b'\xa8', b'\x33', b'\x88', b'\x07', b'\xc7', b'\x31',
          b'\xb1', b'\x12', b'\x10', b'\x59', b'\x27', b'\x80', b'\xec', b'\x5f'],
      [b'\x60', b'\x51', b'\x7f', b'\xa9', b'\x19', b'\xb5', b'\x4a', b'\x0d',
          b'\x2d', b'\xe5', b'\x7a', b'\x9f', b'\x93', b'\xc9', b'\x9c', b'\xef'],
      [b'\xa0', b'\xe0', b'\x3b', b'\x4d', b'\xae', b'\x2a', b'\xf5', b'\xb0',
          b'\xc8', b'\xeb', b'\xbb', b'\x3c', b'\x83', b'\x53', b'\x99', b'\x61'],
      [b'\x17', b'\x2b', b'\x04', b'\x7e', b'\xba', b'\x77', b'\xd6', b'\x26', b'\xe1', b'\x69', b'\x14', b'\x63', b'\x55', b'\x21', b'\x0c', b'\x7d']]

mul2 = [
    b'\x00', b'\x02', b'\x04', b'\x06', b'\x08', b'\x0a', b'\x0c', b'\x0e', b'\x10', b'\x12', b'\x14', b'\x16', b'\x18', b'\x1a', b'\x1c', b'\x1e',
        b'\x20', b'\x22', b'\x24', b'\x26', b'\x28', b'\x2a', b'\x2c', b'\x2e', b'\x30', b'\x32', b'\x34', b'\x36', b'\x38', b'\x3a', b'\x3c', b'\x3e',
        b'\x40', b'\x42', b'\x44', b'\x46', b'\x48', b'\x4a', b'\x4c', b'\x4e', b'\x50', b'\x52', b'\x54', b'\x56', b'\x58', b'\x5a', b'\x5c', b'\x5e',
        b'\x60', b'\x62', b'\x64', b'\x66', b'\x68', b'\x6a', b'\x6c', b'\x6e', b'\x70', b'\x72', b'\x74', b'\x76', b'\x78', b'\x7a', b'\x7c', b'\x7e',
        b'\x80', b'\x82', b'\x84', b'\x86', b'\x88', b'\x8a', b'\x8c', b'\x8e', b'\x90', b'\x92', b'\x94', b'\x96', b'\x98', b'\x9a', b'\x9c', b'\x9e',
        b'\xa0', b'\xa2', b'\xa4', b'\xa6', b'\xa8', b'\xaa', b'\xac', b'\xae', b'\xb0', b'\xb2', b'\xb4', b'\xb6', b'\xb8', b'\xba', b'\xbc', b'\xbe',
        b'\xc0', b'\xc2', b'\xc4', b'\xc6', b'\xc8', b'\xca', b'\xcc', b'\xce', b'\xd0', b'\xd2', b'\xd4', b'\xd6', b'\xd8', b'\xda', b'\xdc', b'\xde',
        b'\xe0', b'\xe2', b'\xe4', b'\xe6', b'\xe8', b'\xea', b'\xec', b'\xee', b'\xf0', b'\xf2', b'\xf4', b'\xf6', b'\xf8', b'\xfa', b'\xfc', b'\xfe',
        b'\x1b', b'\x19', b'\x1f', b'\x1d', b'\x13', b'\x11', b'\x17', b'\x15', b'\x0b', b'\x09', b'\x0f', b'\x0d', b'\x03', b'\x01', b'\x07', b'\x05',
        b'\x3b', b'\x39', b'\x3f', b'\x3d', b'\x33', b'\x31', b'\x37', b'\x35', b'\x2b', b'\x29', b'\x2f', b'\x2d', b'\x23', b'\x21', b'\x27', b'\x25',
        b'\x5b', b'\x59', b'\x5f', b'\x5d', b'\x53', b'\x51', b'\x57', b'\x55', b'\x4b', b'\x49', b'\x4f', b'\x4d', b'\x43', b'\x41', b'\x47', b'\x45',
        b'\x7b', b'\x79', b'\x7f', b'\x7d', b'\x73', b'\x71', b'\x77', b'\x75', b'\x6b', b'\x69', b'\x6f', b'\x6d', b'\x63', b'\x61', b'\x67', b'\x65',
        b'\x9b', b'\x99', b'\x9f', b'\x9d', b'\x93', b'\x91', b'\x97', b'\x95', b'\x8b', b'\x89', b'\x8f', b'\x8d', b'\x83', b'\x81', b'\x87', b'\x85',
        b'\xbb', b'\xb9', b'\xbf', b'\xbd', b'\xb3', b'\xb1', b'\xb7', b'\xb5', b'\xab', b'\xa9', b'\xaf', b'\xad', b'\xa3', b'\xa1', b'\xa7', b'\xa5',
        b'\xdb', b'\xd9', b'\xdf', b'\xdd', b'\xd3', b'\xd1', b'\xd7', b'\xd5', b'\xcb', b'\xc9', b'\xcf', b'\xcd', b'\xc3', b'\xc1', b'\xc7', b'\xc5',
        b'\xfb', b'\xf9', b'\xff', b'\xfd', b'\xf3', b'\xf1', b'\xf7', b'\xf5', b'\xeb', b'\xe9', b'\xef', b'\xed', b'\xe3', b'\xe1', b'\xe7', b'\xe5']

mul3 = [
    b'\x00', b'\x03', b'\x06', b'\x05', b'\x0c', b'\x0f', b'\x0a', b'\x09', b'\x18', b'\x1b', b'\x1e', b'\x1d', b'\x14', b'\x17', b'\x12', b'\x11',
        b'\x30', b'\x33', b'\x36', b'\x35', b'\x3c', b'\x3f', b'\x3a', b'\x39', b'\x28', b'\x2b', b'\x2e', b'\x2d', b'\x24', b'\x27', b'\x22', b'\x21',
        b'\x60', b'\x63', b'\x66', b'\x65', b'\x6c', b'\x6f', b'\x6a', b'\x69', b'\x78', b'\x7b', b'\x7e', b'\x7d', b'\x74', b'\x77', b'\x72', b'\x71',
        b'\x50', b'\x53', b'\x56', b'\x55', b'\x5c', b'\x5f', b'\x5a', b'\x59', b'\x48', b'\x4b', b'\x4e', b'\x4d', b'\x44', b'\x47', b'\x42', b'\x41',
        b'\xc0', b'\xc3', b'\xc6', b'\xc5', b'\xcc', b'\xcf', b'\xca', b'\xc9', b'\xd8', b'\xdb', b'\xde', b'\xdd', b'\xd4', b'\xd7', b'\xd2', b'\xd1',
        b'\xf0', b'\xf3', b'\xf6', b'\xf5', b'\xfc', b'\xff', b'\xfa', b'\xf9', b'\xe8', b'\xeb', b'\xee', b'\xed', b'\xe4', b'\xe7', b'\xe2', b'\xe1',
        b'\xa0', b'\xa3', b'\xa6', b'\xa5', b'\xac', b'\xaf', b'\xaa', b'\xa9', b'\xb8', b'\xbb', b'\xbe', b'\xbd', b'\xb4', b'\xb7', b'\xb2', b'\xb1',
        b'\x90', b'\x93', b'\x96', b'\x95', b'\x9c', b'\x9f', b'\x9a', b'\x99', b'\x88', b'\x8b', b'\x8e', b'\x8d', b'\x84', b'\x87', b'\x82', b'\x81',
        b'\x9b', b'\x98', b'\x9d', b'\x9e', b'\x97', b'\x94', b'\x91', b'\x92', b'\x83', b'\x80', b'\x85', b'\x86', b'\x8f', b'\x8c', b'\x89', b'\x8a',
        b'\xab', b'\xa8', b'\xad', b'\xae', b'\xa7', b'\xa4', b'\xa1', b'\xa2', b'\xb3', b'\xb0', b'\xb5', b'\xb6', b'\xbf', b'\xbc', b'\xb9', b'\xba',
        b'\xfb', b'\xf8', b'\xfd', b'\xfe', b'\xf7', b'\xf4', b'\xf1', b'\xf2', b'\xe3', b'\xe0', b'\xe5', b'\xe6', b'\xef', b'\xec', b'\xe9', b'\xea',
        b'\xcb', b'\xc8', b'\xcd', b'\xce', b'\xc7', b'\xc4', b'\xc1', b'\xc2', b'\xd3', b'\xd0', b'\xd5', b'\xd6', b'\xdf', b'\xdc', b'\xd9', b'\xda',
        b'\x5b', b'\x58', b'\x5d', b'\x5e', b'\x57', b'\x54', b'\x51', b'\x52', b'\x43', b'\x40', b'\x45', b'\x46', b'\x4f', b'\x4c', b'\x49', b'\x4a',
        b'\x6b', b'\x68', b'\x6d', b'\x6e', b'\x67', b'\x64', b'\x61', b'\x62', b'\x73', b'\x70', b'\x75', b'\x76', b'\x7f', b'\x7c', b'\x79', b'\x7a',
        b'\x3b', b'\x38', b'\x3d', b'\x3e', b'\x37', b'\x34', b'\x31', b'\x32', b'\x23', b'\x20', b'\x25', b'\x26', b'\x2f', b'\x2c', b'\x29', b'\x2a',
        b'\x0b', b'\x08', b'\x0d', b'\x0e', b'\x07', b'\x04', b'\x01', b'\x02', b'\x13', b'\x10', b'\x15', b'\x16', b'\x1f', b'\x1c', b'\x19', b'\x1a']

mul9 = [
    b'\x00',  b'\x09',  b'\x12',  b'\x1b',  b'\x24',  b'\x2d',  b'\x36',  b'\x3f',  b'\x48',  b'\x41',  b'\x5a',  b'\x53',  b'\x6c',  b'\x65',  b'\x7e',  b'\x77',
   b'\x90',  b'\x99',  b'\x82',  b'\x8b',  b'\xb4',  b'\xbd',  b'\xa6',  b'\xaf',  b'\xd8',  b'\xd1',  b'\xca',  b'\xc3',  b'\xfc',  b'\xf5',  b'\xee',  b'\xe7',
   b'\x3b',  b'\x32',  b'\x29',  b'\x20',  b'\x1f',  b'\x16',  b'\x0d',  b'\x04',  b'\x73',  b'\x7a',  b'\x61',  b'\x68',  b'\x57',  b'\x5e',  b'\x45',  b'\x4c',
   b'\xab',  b'\xa2',  b'\xb9',  b'\xb0',  b'\x8f',  b'\x86',  b'\x9d',  b'\x94',  b'\xe3',  b'\xea',  b'\xf1',  b'\xf8',  b'\xc7',  b'\xce',  b'\xd5',  b'\xdc',
   b'\x76',  b'\x7f',  b'\x64',  b'\x6d',  b'\x52',  b'\x5b',  b'\x40',  b'\x49',  b'\x3e',  b'\x37',  b'\x2c',  b'\x25',  b'\x1a',  b'\x13',  b'\x08',  b'\x01',
   b'\xe6',  b'\xef',  b'\xf4',  b'\xfd',  b'\xc2',  b'\xcb',  b'\xd0',  b'\xd9',  b'\xae',  b'\xa7',  b'\xbc',  b'\xb5',  b'\x8a',  b'\x83',  b'\x98',  b'\x91',
   b'\x4d',  b'\x44',  b'\x5f',  b'\x56',  b'\x69',  b'\x60',  b'\x7b',  b'\x72',  b'\x05',  b'\x0c',  b'\x17',  b'\x1e',  b'\x21',  b'\x28',  b'\x33',  b'\x3a',
   b'\xdd',  b'\xd4',  b'\xcf',  b'\xc6',  b'\xf9',  b'\xf0',  b'\xeb',  b'\xe2',  b'\x95',  b'\x9c',  b'\x87',  b'\x8e',  b'\xb1',  b'\xb8',  b'\xa3',  b'\xaa',
   b'\xec',  b'\xe5',  b'\xfe',  b'\xf7',  b'\xc8',  b'\xc1',  b'\xda',  b'\xd3',  b'\xa4',  b'\xad',  b'\xb6',  b'\xbf',  b'\x80',  b'\x89',  b'\x92',  b'\x9b',
   b'\x7c',  b'\x75',  b'\x6e',  b'\x67',  b'\x58',  b'\x51',  b'\x4a',  b'\x43',  b'\x34',  b'\x3d',  b'\x26',  b'\x2f',  b'\x10',  b'\x19',  b'\x02',  b'\x0b',
   b'\xd7',  b'\xde',  b'\xc5',  b'\xcc',  b'\xf3',  b'\xfa',  b'\xe1',  b'\xe8',  b'\x9f',  b'\x96',  b'\x8d',  b'\x84',  b'\xbb',  b'\xb2',  b'\xa9',  b'\xa0',
   b'\x47',  b'\x4e',  b'\x55',  b'\x5c',  b'\x63',  b'\x6a',  b'\x71',  b'\x78',  b'\x0f',  b'\x06',  b'\x1d',  b'\x14',  b'\x2b',  b'\x22',  b'\x39',  b'\x30',
   b'\x9a',  b'\x93',  b'\x88',  b'\x81',  b'\xbe',  b'\xb7',  b'\xac',  b'\xa5',  b'\xd2',  b'\xdb',  b'\xc0',  b'\xc9',  b'\xf6',  b'\xff',  b'\xe4',  b'\xed',
   b'\x0a',  b'\x03',  b'\x18',  b'\x11',  b'\x2e',  b'\x27',  b'\x3c',  b'\x35',  b'\x42',  b'\x4b',  b'\x50',  b'\x59',  b'\x66',  b'\x6f',  b'\x74',  b'\x7d',
   b'\xa1',  b'\xa8',  b'\xb3',  b'\xba',  b'\x85',  b'\x8c',  b'\x97',  b'\x9e',  b'\xe9',  b'\xe0',  b'\xfb',  b'\xf2',  b'\xcd',  b'\xc4',  b'\xdf',  b'\xd6',
   b'\x31',  b'\x38',  b'\x23',  b'\x2a',  b'\x15',  b'\x1c',  b'\x07',  b'\x0e',  b'\x79',  b'\x70',  b'\x6b',  b'\x62',  b'\x5d',  b'\x54',  b'\x4f',  b'\x46'
]

mul11 = [
    b'\x00',  b'\x0b',  b'\x16',  b'\x1d',  b'\x2c',  b'\x27',  b'\x3a',  b'\x31',  b'\x58',  b'\x53',  b'\x4e',  b'\x45',  b'\x74',  b'\x7f',  b'\x62',  b'\x69',
   b'\xb0',  b'\xbb',  b'\xa6',  b'\xad',  b'\x9c',  b'\x97',  b'\x8a',  b'\x81',  b'\xe8',  b'\xe3',  b'\xfe',  b'\xf5',  b'\xc4',  b'\xcf',  b'\xd2',  b'\xd9',
   b'\x7b',  b'\x70',  b'\x6d',  b'\x66',  b'\x57',  b'\x5c',  b'\x41',  b'\x4a',  b'\x23',  b'\x28',  b'\x35',  b'\x3e',  b'\x0f',  b'\x04',  b'\x19',  b'\x12',
   b'\xcb',  b'\xc0',  b'\xdd',  b'\xd6',  b'\xe7',  b'\xec',  b'\xf1',  b'\xfa',  b'\x93',  b'\x98',  b'\x85',  b'\x8e',  b'\xbf',  b'\xb4',  b'\xa9',  b'\xa2',
   b'\xf6',  b'\xfd',  b'\xe0',  b'\xeb',  b'\xda',  b'\xd1',  b'\xcc',  b'\xc7',  b'\xae',  b'\xa5',  b'\xb8',  b'\xb3',  b'\x82',  b'\x89',  b'\x94',  b'\x9f',
   b'\x46',  b'\x4d',  b'\x50',  b'\x5b',  b'\x6a',  b'\x61',  b'\x7c',  b'\x77',  b'\x1e',  b'\x15',  b'\x08',  b'\x03',  b'\x32',  b'\x39',  b'\x24',  b'\x2f',
   b'\x8d',  b'\x86',  b'\x9b',  b'\x90',  b'\xa1',  b'\xaa',  b'\xb7',  b'\xbc',  b'\xd5',  b'\xde',  b'\xc3',  b'\xc8',  b'\xf9',  b'\xf2',  b'\xef',  b'\xe4',
   b'\x3d',  b'\x36',  b'\x2b',  b'\x20',  b'\x11',  b'\x1a',  b'\x07',  b'\x0c',  b'\x65',  b'\x6e',  b'\x73',  b'\x78',  b'\x49',  b'\x42',  b'\x5f',  b'\x54',
   b'\xf7',  b'\xfc',  b'\xe1',  b'\xea',  b'\xdb',  b'\xd0',  b'\xcd',  b'\xc6',  b'\xaf',  b'\xa4',  b'\xb9',  b'\xb2',  b'\x83',  b'\x88',  b'\x95',  b'\x9e',
   b'\x47',  b'\x4c',  b'\x51',  b'\x5a',  b'\x6b',  b'\x60',  b'\x7d',  b'\x76',  b'\x1f',  b'\x14',  b'\x09',  b'\x02',  b'\x33',  b'\x38',  b'\x25',  b'\x2e',
   b'\x8c',  b'\x87',  b'\x9a',  b'\x91',  b'\xa0',  b'\xab',  b'\xb6',  b'\xbd',  b'\xd4',  b'\xdf',  b'\xc2',  b'\xc9',  b'\xf8',  b'\xf3',  b'\xee',  b'\xe5',
   b'\x3c',  b'\x37',  b'\x2a',  b'\x21',  b'\x10',  b'\x1b',  b'\x06',  b'\x0d',  b'\x64',  b'\x6f',  b'\x72',  b'\x79',  b'\x48',  b'\x43',  b'\x5e',  b'\x55',
   b'\x01',  b'\x0a',  b'\x17',  b'\x1c',  b'\x2d',  b'\x26',  b'\x3b',  b'\x30',  b'\x59',  b'\x52',  b'\x4f',  b'\x44',  b'\x75',  b'\x7e',  b'\x63',  b'\x68',
   b'\xb1',  b'\xba',  b'\xa7',  b'\xac',  b'\x9d',  b'\x96',  b'\x8b',  b'\x80',  b'\xe9',  b'\xe2',  b'\xff',  b'\xf4',  b'\xc5',  b'\xce',  b'\xd3',  b'\xd8',
   b'\x7a',  b'\x71',  b'\x6c',  b'\x67',  b'\x56',  b'\x5d',  b'\x40',  b'\x4b',  b'\x22',  b'\x29',  b'\x34',  b'\x3f',  b'\x0e',  b'\x05',  b'\x18',  b'\x13',
   b'\xca',  b'\xc1',  b'\xdc',  b'\xd7',  b'\xe6',  b'\xed',  b'\xf0',  b'\xfb',  b'\x92',  b'\x99',  b'\x84',  b'\x8f',  b'\xbe',  b'\xb5',  b'\xa8',  b'\xa3'
]

mul13 = [
    b'\x00',  b'\x0d',  b'\x1a',  b'\x17',  b'\x34',  b'\x39',  b'\x2e',  b'\x23',  b'\x68',  b'\x65',  b'\x72',  b'\x7f',  b'\x5c',  b'\x51',  b'\x46',  b'\x4b',
   b'\xd0',  b'\xdd',  b'\xca',  b'\xc7',  b'\xe4',  b'\xe9',  b'\xfe',  b'\xf3',  b'\xb8',  b'\xb5',  b'\xa2',  b'\xaf',  b'\x8c',  b'\x81',  b'\x96',  b'\x9b',
   b'\xbb',  b'\xb6',  b'\xa1',  b'\xac',  b'\x8f',  b'\x82',  b'\x95',  b'\x98',  b'\xd3',  b'\xde',  b'\xc9',  b'\xc4',  b'\xe7',  b'\xea',  b'\xfd',  b'\xf0',
   b'\x6b',  b'\x66',  b'\x71',  b'\x7c',  b'\x5f',  b'\x52',  b'\x45',  b'\x48',  b'\x03',  b'\x0e',  b'\x19',  b'\x14',  b'\x37',  b'\x3a',  b'\x2d',  b'\x20',
   b'\x6d',  b'\x60',  b'\x77',  b'\x7a',  b'\x59',  b'\x54',  b'\x43',  b'\x4e',  b'\x05',  b'\x08',  b'\x1f',  b'\x12',  b'\x31',  b'\x3c',  b'\x2b',  b'\x26',
   b'\xbd',  b'\xb0',  b'\xa7',  b'\xaa',  b'\x89',  b'\x84',  b'\x93',  b'\x9e',  b'\xd5',  b'\xd8',  b'\xcf',  b'\xc2',  b'\xe1',  b'\xec',  b'\xfb',  b'\xf6',
   b'\xd6',  b'\xdb',  b'\xcc',  b'\xc1',  b'\xe2',  b'\xef',  b'\xf8',  b'\xf5',  b'\xbe',  b'\xb3',  b'\xa4',  b'\xa9',  b'\x8a',  b'\x87',  b'\x90',  b'\x9d',
   b'\x06',  b'\x0b',  b'\x1c',  b'\x11',  b'\x32',  b'\x3f',  b'\x28',  b'\x25',  b'\x6e',  b'\x63',  b'\x74',  b'\x79',  b'\x5a',  b'\x57',  b'\x40',  b'\x4d',
   b'\xda',  b'\xd7',  b'\xc0',  b'\xcd',  b'\xee',  b'\xe3',  b'\xf4',  b'\xf9',  b'\xb2',  b'\xbf',  b'\xa8',  b'\xa5',  b'\x86',  b'\x8b',  b'\x9c',  b'\x91',
   b'\x0a',  b'\x07',  b'\x10',  b'\x1d',  b'\x3e',  b'\x33',  b'\x24',  b'\x29',  b'\x62',  b'\x6f',  b'\x78',  b'\x75',  b'\x56',  b'\x5b',  b'\x4c',  b'\x41',
   b'\x61',  b'\x6c',  b'\x7b',  b'\x76',  b'\x55',  b'\x58',  b'\x4f',  b'\x42',  b'\x09',  b'\x04',  b'\x13',  b'\x1e',  b'\x3d',  b'\x30',  b'\x27',  b'\x2a',
   b'\xb1',  b'\xbc',  b'\xab',  b'\xa6',  b'\x85',  b'\x88',  b'\x9f',  b'\x92',  b'\xd9',  b'\xd4',  b'\xc3',  b'\xce',  b'\xed',  b'\xe0',  b'\xf7',  b'\xfa',
   b'\xb7',  b'\xba',  b'\xad',  b'\xa0',  b'\x83',  b'\x8e',  b'\x99',  b'\x94',  b'\xdf',  b'\xd2',  b'\xc5',  b'\xc8',  b'\xeb',  b'\xe6',  b'\xf1',  b'\xfc',
   b'\x67',  b'\x6a',  b'\x7d',  b'\x70',  b'\x53',  b'\x5e',  b'\x49',  b'\x44',  b'\x0f',  b'\x02',  b'\x15',  b'\x18',  b'\x3b',  b'\x36',  b'\x21',  b'\x2c',
   b'\x0c',  b'\x01',  b'\x16',  b'\x1b',  b'\x38',  b'\x35',  b'\x22',  b'\x2f',  b'\x64',  b'\x69',  b'\x7e',  b'\x73',  b'\x50',  b'\x5d',  b'\x4a',  b'\x47',
   b'\xdc',  b'\xd1',  b'\xc6',  b'\xcb',  b'\xe8',  b'\xe5',  b'\xf2',  b'\xff',  b'\xb4',  b'\xb9',  b'\xae',  b'\xa3',  b'\x80',  b'\x8d',  b'\x9a',  b'\x97'
]

mul14 = [
    b'\x00',  b'\x0e',  b'\x1c',  b'\x12',  b'\x38',  b'\x36',  b'\x24',  b'\x2a',  b'\x70',  b'\x7e',  b'\x6c',  b'\x62',  b'\x48',  b'\x46',  b'\x54',  b'\x5a',
   b'\xe0',  b'\xee',  b'\xfc',  b'\xf2',  b'\xd8',  b'\xd6',  b'\xc4',  b'\xca',  b'\x90',  b'\x9e',  b'\x8c',  b'\x82',  b'\xa8',  b'\xa6',  b'\xb4',  b'\xba',
   b'\xdb',  b'\xd5',  b'\xc7',  b'\xc9',  b'\xe3',  b'\xed',  b'\xff',  b'\xf1',  b'\xab',  b'\xa5',  b'\xb7',  b'\xb9',  b'\x93',  b'\x9d',  b'\x8f',  b'\x81',
   b'\x3b',  b'\x35',  b'\x27',  b'\x29',  b'\x03',  b'\x0d',  b'\x1f',  b'\x11',  b'\x4b',  b'\x45',  b'\x57',  b'\x59',  b'\x73',  b'\x7d',  b'\x6f',  b'\x61',
   b'\xad',  b'\xa3',  b'\xb1',  b'\xbf',  b'\x95',  b'\x9b',  b'\x89',  b'\x87',  b'\xdd',  b'\xd3',  b'\xc1',  b'\xcf',  b'\xe5',  b'\xeb',  b'\xf9',  b'\xf7',
   b'\x4d',  b'\x43',  b'\x51',  b'\x5f',  b'\x75',  b'\x7b',  b'\x69',  b'\x67',  b'\x3d',  b'\x33',  b'\x21',  b'\x2f',  b'\x05',  b'\x0b',  b'\x19',  b'\x17',
   b'\x76',  b'\x78',  b'\x6a',  b'\x64',  b'\x4e',  b'\x40',  b'\x52',  b'\x5c',  b'\x06',  b'\x08',  b'\x1a',  b'\x14',  b'\x3e',  b'\x30',  b'\x22',  b'\x2c',
   b'\x96',  b'\x98',  b'\x8a',  b'\x84',  b'\xae',  b'\xa0',  b'\xb2',  b'\xbc',  b'\xe6',  b'\xe8',  b'\xfa',  b'\xf4',  b'\xde',  b'\xd0',  b'\xc2',  b'\xcc',
   b'\x41',  b'\x4f',  b'\x5d',  b'\x53',  b'\x79',  b'\x77',  b'\x65',  b'\x6b',  b'\x31',  b'\x3f',  b'\x2d',  b'\x23',  b'\x09',  b'\x07',  b'\x15',  b'\x1b',
   b'\xa1',  b'\xaf',  b'\xbd',  b'\xb3',  b'\x99',  b'\x97',  b'\x85',  b'\x8b',  b'\xd1',  b'\xdf',  b'\xcd',  b'\xc3',  b'\xe9',  b'\xe7',  b'\xf5',  b'\xfb',
   b'\x9a',  b'\x94',  b'\x86',  b'\x88',  b'\xa2',  b'\xac',  b'\xbe',  b'\xb0',  b'\xea',  b'\xe4',  b'\xf6',  b'\xf8',  b'\xd2',  b'\xdc',  b'\xce',  b'\xc0',
   b'\x7a',  b'\x74',  b'\x66',  b'\x68',  b'\x42',  b'\x4c',  b'\x5e',  b'\x50',  b'\x0a',  b'\x04',  b'\x16',  b'\x18',  b'\x32',  b'\x3c',  b'\x2e',  b'\x20',
   b'\xec',  b'\xe2',  b'\xf0',  b'\xfe',  b'\xd4',  b'\xda',  b'\xc8',  b'\xc6',  b'\x9c',  b'\x92',  b'\x80',  b'\x8e',  b'\xa4',  b'\xaa',  b'\xb8',  b'\xb6',
   b'\x0c',  b'\x02',  b'\x10',  b'\x1e',  b'\x34',  b'\x3a',  b'\x28',  b'\x26',  b'\x7c',  b'\x72',  b'\x60',  b'\x6e',  b'\x44',  b'\x4a',  b'\x58',  b'\x56',
   b'\x37',  b'\x39',  b'\x2b',  b'\x25',  b'\x0f',  b'\x01',  b'\x13',  b'\x1d',  b'\x47',  b'\x49',  b'\x5b',  b'\x55',  b'\x7f',  b'\x71',  b'\x63',  b'\x6d',
   b'\xd7',  b'\xd9',  b'\xcb',  b'\xc5',  b'\xef',  b'\xe1',  b'\xf3',  b'\xfd',  b'\xa7',  b'\xa9',  b'\xbb',  b'\xb5',  b'\x9f',  b'\x91',  b'\x83',  b'\x8d'
]

rcon = [
  b'\x8d', b'\x01', b'\x02', b'\x04', b'\x08', b'\x10', b'\x20', b'\x40', b'\x80', b'\x1b', b'\x36', b'\x6c', b'\xd8', b'\xab', b'\x4d', b'\x9a', b'\x2f',
  b'\x5e', b'\xbc', b'\x63', b'\xc6', b'\x97', b'\x35', b'\x6a', b'\xd4', b'\xb3', b'\x7d', b'\xfa', b'\xef', b'\xc5', b'\x91', b'\x39', b'\x72', b'\xe4', b'\xd3',
  b'\xbd', b'\x61', b'\xc2', b'\x9f', b'\x25', b'\x4a', b'\x94', b'\x33', b'\x66', b'\xcc', b'\x83', b'\x1d', b'\x3a', b'\x74', b'\xe8', b'\xcb', b'\x8d', b'\x01',
  b'\x02', b'\x04', b'\x08', b'\x10', b'\x20', b'\x40', b'\x80', b'\x1b', b'\x36', b'\x6c', b'\xd8', b'\xab', b'\x4d', b'\x9a', b'\x2f', b'\x5e', b'\xbc', b'\x63',
  b'\xc6', b'\x97', b'\x35', b'\x6a', b'\xd4', b'\xb3', b'\x7d', b'\xfa', b'\xef', b'\xc5', b'\x91', b'\x39', b'\x72', b'\xe4', b'\xd3', b'\xbd', b'\x61', b'\xc2',
  b'\x9f', b'\x25', b'\x4a', b'\x94', b'\x33', b'\x66', b'\xcc', b'\x83', b'\x1d', b'\x3a', b'\x74', b'\xe8', b'\xcb', b'\x8d', b'\x01', b'\x02', b'\x04', b'\x08',
  b'\x10', b'\x20', b'\x40', b'\x80', b'\x1b', b'\x36', b'\x6c', b'\xd8', b'\xab', b'\x4d', b'\x9a', b'\x2f', b'\x5e', b'\xbc', b'\x63', b'\xc6', b'\x97', b'\x35',
  b'\x6a', b'\xd4', b'\xb3', b'\x7d', b'\xfa', b'\xef', b'\xc5', b'\x91', b'\x39', b'\x72', b'\xe4', b'\xd3', b'\xbd', b'\x61', b'\xc2', b'\x9f', b'\x25', b'\x4a',
  b'\x94', b'\x33', b'\x66', b'\xcc', b'\x83', b'\x1d', b'\x3a', b'\x74', b'\xe8', b'\xcb', b'\x8d', b'\x01', b'\x02', b'\x04', b'\x08', b'\x10', b'\x20', b'\x40',
  b'\x80', b'\x1b', b'\x36', b'\x6c', b'\xd8', b'\xab', b'\x4d', b'\x9a', b'\x2f', b'\x5e', b'\xbc', b'\x63', b'\xc6', b'\x97', b'\x35', b'\x6a', b'\xd4', b'\xb3',
  b'\x7d', b'\xfa', b'\xef', b'\xc5', b'\x91', b'\x39', b'\x72', b'\xe4', b'\xd3', b'\xbd', b'\x61', b'\xc2', b'\x9f', b'\x25', b'\x4a', b'\x94', b'\x33', b'\x66',
  b'\xcc', b'\x83', b'\x1d', b'\x3a', b'\x74', b'\xe8', b'\xcb', b'\x8d', b'\x01', b'\x02', b'\x04', b'\x08', b'\x10', b'\x20', b'\x40', b'\x80', b'\x1b', b'\x36',
  b'\x6c', b'\xd8', b'\xab', b'\x4d', b'\x9a', b'\x2f', b'\x5e', b'\xbc', b'\x63', b'\xc6', b'\x97', b'\x35', b'\x6a', b'\xd4', b'\xb3', b'\x7d', b'\xfa', b'\xef',
  b'\xc5', b'\x91', b'\x39', b'\x72', b'\xe4', b'\xd3', b'\xbd', b'\x61', b'\xc2', b'\x9f', b'\x25', b'\x4a', b'\x94', b'\x33', b'\x66', b'\xcc', b'\x83', b'\x1d',
  b'\x3a', b'\x74', b'\xe8', b'\xcb']

padding = [
    [b'\x00', b'\x00', b'\x00', b'\x00'], [b'\x00', b'\x00', b'\x00', b'\x00'],
    [b'\x00', b'\x00', b'\x00', b'\x00'], [b'\x00', b'\x00', b'\x00', b'\x10']]


test_key = 4 * [4 * [b'\x00']]
test_key_256 = 8 * [4 * [b'\x00']]


def transpose(block):
    new_block = [[block[col][row]
                  for col in range(len(block))] for row in range(len(block[0]))]
    return new_block


def print_3d_bytes(list_of_matrix):
    print("\n".join([" ".join([" ".join([str(k.hex()) for k in j]) for j in i])
          for i in list_of_matrix]))


def print_2d_bytes(matrix):
    print("\n".join([" ".join([str(k.hex()) for k in j]) for j in matrix]))
