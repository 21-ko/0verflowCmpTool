import sys
import glob
import os
import struct

input_folder = sys.argv[1]
#output_file = input_folder.with_name(input_folder.stem + '.cmp')
dir_path = os.path.dirname(input_folder)
base_name = os.path.splitext(os.path.basename(input_folder))[0]
output_file = os.path.join(dir_path, base_name + '.cmp')

def lz77(input_bytes):
    input_bytes = bytearray(input_bytes)
    input_length = len(input_bytes)
    output = bytearray()
    
    # 윈도우 크기
    window_size = 0x800
    # 찾을 수 있는 최대 일치 길이
    max_length = 0x1E + 2

    def find_longest_match(data, current_pos):
        best_length = 0
        best_offset = 0
        # 현재 위치에서 최대 window_size만큼 떨어진 곳부터 검색
        start_pos = max(0, current_pos - window_size)

        # 검색 시작 위치부터 현재 위치까지 반복하며 가장 긴 일치를 찾는다
        for search_pos in range(start_pos, current_pos):
            length = 0
            # 현재 위치에서 시작하는 데이터와 검색 위치에서 시작하는 데이터를 비교하여
            # 일치하는 최대 길이를 측정
            while length < max_length and current_pos + length < len(data) and data[search_pos + length] == data[current_pos + length]:
                length += 1

            # 더 긴 일치를 찾았다면 최대 일치 길이와 오프셋을 갱신
            if length > best_length:
                best_length = length
                best_offset = current_pos - search_pos - 1

        return best_offset, best_length

    pos = 0
    while pos < input_length:
        offset, length = find_longest_match(input_bytes, pos)

        # length가 짝수이면서 2 이상인 경우에만 압축
        if length >= 2 and length % 2 == 0:
            num = 0x8000  # 압축 플래그 1
            num += offset
            num += (length - 2) << 10
            output.append(num >> 8)
            output.append(num & 0xFF)
            pos += length
        else:
            literals = []
            initial_pos = pos  # 리터럴 시작 위치 추적
            # 리터럴을 최대 0x7F 길이까지 (압축 여부 1비트 때문에)
            while pos < input_length and len(literals) < 0x7F:
                offset, length = find_longest_match(input_bytes, pos)
                if length >= 2 and length % 2 == 0:
                    break
                literals.append(input_bytes[pos])
                pos += 1
            
            # 리터럴 길이가 0일 경우를 처리하기 위한 조건
            if literals:
                output.append(len(literals) - 1)
                output.extend(literals)
            else:
                output.append(0)
                output.append(input_bytes[initial_pos])
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
    footer = lz77(footer)

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
    with open('TEST.EXE', 'rb') as test_exe, open(output_file, 'wb') as cmp_file:
        cmp_file.write(test_exe.read())

        for file_path in glob.glob(os.path.join(directory, '*')):
            with open(file_path, 'rb') as f:
                original_data = f.read()
                original_size = len(original_data)
                
                # 압축
                compressed_data = lz77(original_data)
                compressed_data = struct.pack('<I', original_size) + compressed_data
                
                # 파일 정보
                name = os.path.basename(file_path)
                offset = cmp_file.tell()
                entries.append({'name': name, 'offset': offset, 'is_packed': 1})
                #print(f"Offset for {name}: {hex(offset)} ...AND SIZE: {hex(len(compressed_data))}")
                print(f"Complete: {name}")
                
                # 데이터 쓰기
                cmp_file.write(compressed_data)
                
        # 푸터 기록
        write_footer(cmp_file, entries)
                
compress_and_pack(input_folder, output_file)