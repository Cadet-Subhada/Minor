from PIL import Image
import numpy as np
import struct

def extract_data(stego_image_path):
    img = Image.open(stego_image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten()

    bits = ''.join(str(p & 1) for p in flat_pixels)

    # ---- Read header (first 32 bits) ----
    header_bits = bits[:32]
    data_len = struct.unpack(">I", int(header_bits, 2).to_bytes(4, 'big'))[0]

    # ---- Read payload ----
    data_bits = bits[32:32 + data_len * 8]

    data_bytes = bytearray(
        int(data_bits[i:i+8], 2)
        for i in range(0, len(data_bits), 8)
    )

    return bytes(data_bytes)
