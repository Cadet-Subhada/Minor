from PIL import Image
import numpy as np
import struct

def embed_data(input_image_path, data_bytes, output_image_path):
    img = Image.open(input_image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten()

    # ---- HEADER: 4 bytes payload length ----
    header = struct.pack(">I", len(data_bytes))
    payload = header + data_bytes

    bit_stream = ''.join(format(b, '08b') for b in payload)

    if len(bit_stream) > len(flat_pixels):
        raise ValueError("Data too large for this image")

    for i, bit in enumerate(bit_stream):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)

    stego_pixels = flat_pixels.reshape(pixels.shape)
    Image.fromarray(stego_pixels).save(output_image_path)
