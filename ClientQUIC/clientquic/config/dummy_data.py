import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
file_name = f"{BASE_DIR}/dummy_data.bin"
with open(file_name, 'wb') as f:
    f.write(b'\xaa'* 1024 * 1024 * 60)

# 2. 파일을 4개의 청크로 나누기
def split_file_into_chunks(filename, num_chunks=4):
    chunks = []
    with open(filename, 'rb') as f:
        dummy = f.read()
        chunk_size = len(dummy) // num_chunks
        for i in range(num_chunks):
            chunk = dummy[chunk_size*i:(chunk_size*(i+1))]
            chunks.append(chunk)

    return chunks

chunks = split_file_into_chunks(file_name, 4)