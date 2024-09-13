import sys
import glob
import os
import struct
from tqdm import tqdm

input_folder = sys.argv[1]
dir_path = os.path.dirname(input_folder)
base_name = os.path.splitext(os.path.basename(input_folder))[0]
output_file = os.path.join(dir_path, base_name + '.cmp')

def lzCompress(input_bytes):
    input_bytes = bytearray(input_bytes)
    input_length = len(input_bytes)
    output = bytearray()

    window_size = 0x800
    min_length = 2
    max_length = 0x1E + min_length

    def find_longest_match(data, current_pos):
        best_length = 0
        best_offset = 0
        start_pos = max(0, current_pos - window_size)

        while start_pos < current_pos:
            length = 0
            while length < max_length and current_pos + length < len(data) and data[start_pos + length] == data[current_pos + length]:
                length += 1

            if length > best_length:
                best_length = length
                best_offset = current_pos - start_pos - 1

            start_pos += 1

        return best_offset, best_length

    pos = 0
    while pos < input_length:
        offset, length = find_longest_match(input_bytes, pos)

        if length >= min_length and length % 2 == 0:
            num = 0x8000  # 압축 플래그 1
            num += offset
            num += (length - min_length) << 10
            output.append(num >> 8)
            output.append(num & 0xFF)
            pos += length
        else:
            literals = []
            # 리터럴 길이를 7비트로
            while pos < input_length and len(literals) < 0x7F:
                offset, length = find_longest_match(input_bytes, pos)
                if length >= min_length and length % 2 == 0:
                    break
                literals.append(input_bytes[pos])
                pos += 1

            if literals:
                output.append(len(literals) - 1)
                output.extend(literals)
            else:
                output.append(0)
                output.append(input_bytes[pos])
                pos += 1

    return bytes(output)
    
def xor_encrypt(data, key):
    key_len = len(key)
    encrypted_data = bytearray(len(data))
    
    for i in range(len(data)):
        encrypted_data[i] = data[i] ^ key[i % key_len]
    
    return bytes(encrypted_data)
    
def pad_data(data):
    padding_required = 16 - (len(data) % 16)
    if padding_required == 16:
        padding_required = 0
    padded_data = data + b'\x00' * padding_required
    return padded_data

def write_footer(cmp_file, entries):
    #key = bytes.fromhex('00000000000000000000000000000000')
    key = bytes.fromhex('6C14F203E36232AC0304ACF2D384F8CA')
    footer_pos = cmp_file.tell()
    footer = b''
    
    for entry in entries:
        name_bytes = entry['name'].encode('utf-16le')
        name_length = len(name_bytes) // 2
        footer += struct.pack('<I B B 4x', entry['offset'], name_length, entry['is_packed']) + name_bytes
    # 푸터 완성
    footer += struct.pack('<I', footer_pos)
    footer = pad_data(footer)
    
    # 푸터 압축
    footer_size = len(footer)  # 원래 크기
    footer = lzCompress(footer)

    # 푸터 암호화
    footer = xor_encrypt(footer, key)
    footer = struct.pack('<I', footer_size) + footer
    cmp_file.write(footer)
    
    # 시그니처 쓰기
    pack_str = xor_encrypt(b'PACK', key)
    cmp_file.write(pack_str)
    
    # 푸터 위치 쓰기
    cmp_file.write(struct.pack('<I', footer_pos))

def compress_and_pack(directory, output_file):
    entries = []
    with open(output_file, 'wb') as cmp_file:
        file_paths = list(glob.glob(os.path.join(directory, '**'), recursive=True))
        for file_path in tqdm(file_paths, desc="Archiving"):
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    original_data = f.read()
                    original_size = len(original_data)

                    # 압축
                    compressed_data = lzCompress(original_data)
                    compressed_data = struct.pack('<I', original_size) + compressed_data

                    # 파일 정보
                    relative_path = os.path.relpath(file_path, directory)
                    offset = cmp_file.tell()
                    entries.append({'name': relative_path.replace('\\', '/'), 'offset': offset, 'is_packed': 1})

                    # 데이터 쓰기
                    cmp_file.write(compressed_data)

        # 푸터 기록
        write_footer(cmp_file, entries)
                
compress_and_pack(input_folder, output_file)
