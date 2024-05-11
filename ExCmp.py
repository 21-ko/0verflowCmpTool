from struct import unpack
import struct
import sys
import os
from pathlib import Path

def xor_decrypt(data, key):
    key_bytes = key.to_bytes(16, 'big')
    decrypted_data = bytearray()
    for i in range(len(data)):
        decrypted_byte = data[i] ^ key_bytes[i % len(key_bytes)]
        decrypted_data.append(decrypted_byte)
    return bytes(decrypted_data)

# unlz77 codebase by GARbro
def unlz77(input_bytes, output_length):
    input_bytes = bytearray(input_bytes)
    output = bytearray(output_length)
    dst = 0
    input_index = 0

    def binary_copy_overlapped(source, src_offset, dst_offset, count):
        for i in range(count):
            source[dst_offset + i] = source[src_offset + i]

    while dst < output_length:
        ctl = input_bytes[input_index]
        input_index += 1
        if ctl & 0x80:
            num = input_bytes[input_index] + (ctl << 8)
            input_index += 1
            offset = num & 0x7FF
            count = min(((num >> 10) & 0x1E) + 2, output_length - dst)
            binary_copy_overlapped(output, dst - offset - 1, dst, count)
            dst += count
        else:
            count = min(ctl + 1, output_length - dst)
            output[dst:dst + count] = input_bytes[input_index:input_index + count]
            input_index += count
            dst += count

    return output

def read_index(file, key=None):
    is_encrypted = key is not None
    eof = file.seek(0, 2)
    
    file.seek(-4, 2)  # goto (EoF - 4)
    index_offset = unpack('<I', file.read(4))[0]
    if index_offset >= file.seek(0, 2):
        return None
    file.seek(index_offset)  # goto index
    uncompressed_index_size = unpack('<i', file.read(4))[0]
    if uncompressed_index_size <= 0:
        return None
    # 압축된 인덱스 크기
    index_size = eof - index_offset - 0x0c
    index = file.read(index_size)  # 인덱스 읽기
    
    if is_encrypted:
        # 암호화 해제
        index = xor_decrypt(index, key)
    # 압축 해제
    index = unlz77(index, uncompressed_index_size)
    
    dir = []
    index_pos = 0
    offset = unpack('<I', index[index_pos:index_pos + 4])[0]
    while index_pos < len(index):
        index_pos += 4
        name_length = index[index_pos]  # 이름 길이
        if name_length == 0:
            break
        is_packed = index[index_pos + 1] != 0  # 패킹 여부
        index_pos += 6
        name_length <<= 1  # 이름 길이 조정
        name = index[index_pos:index_pos + name_length].decode('utf-16le')  # 이름 디코딩
        index_pos += name_length
        next_offset = unpack('<I', index[index_pos:index_pos + 4])[0]
        entry = {
            'name': name,
            'offset': offset,
            'size': next_offset - offset,
            'is_packed': is_packed
        }
        #print(entry)

        dir.append(entry)
        offset = next_offset
    return dir
    
def extract_file(file, dir_entry, base_dir):
    file.seek(dir_entry['offset'])
    header = file.read(4)
    unsize = unpack('<I', header)[0]
    payload = file.read(dir_entry['size'] - 4)
    
    if dir_entry['is_packed']:
        payload = unlz77(payload, unsize)  # 압축 해제
    
    output_path = os.path.join(base_dir, dir_entry['name'])
    with open(output_path, 'wb') as output_file:
        output_file.write(payload)

def main():
    file_path = sys.argv[1]
    base_dir = Path(file_path).stem
    os.makedirs(base_dir, exist_ok=True)
    
    # Summer Radish Vacation 1.1, Summer Radish Vacation 2
    keys = [0x0F253E5C2A4B7790058A8E46EB3D1143, 0x6C14F203E36232AC0304ACF2D384F8CA]
    
    with open(file_path, 'rb') as file:
        file.seek(-8, 2)
        signature = file.read(4)
        
        if signature != b'PACK':
            key_found = False
            for key in keys:
                decrypted_signature = xor_decrypt(signature, key)
                if decrypted_signature == b'PACK':
                    key_found = True
                    break
            if key_found:
                file_index = read_index(file, key)
            else:
                print("No valid key found. Invalid file format or wrong key.")
        else:  # 암호화가 되어있지 않을 때
            file_index = read_index(file, None)
            
        if file_index is not None:
            for dir_entry in file_index:
                extract_file(file, dir_entry, base_dir)  # 파일 추출

if __name__ == "__main__":
    main()