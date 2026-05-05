import numpy as np
from PIL import Image

def calculate_image_metrics(original_path, stego_path):
    original = np.array(Image.open(original_path), dtype=np.float32)
    stego = np.array(Image.open(stego_path), dtype=np.float32)

    mse = np.mean((original - stego) ** 2)

    if mse == 0:
        psnr = float('inf')
    else:
        psnr = 20 * np.log10(255.0 / np.sqrt(mse))

    return mse, psnr
