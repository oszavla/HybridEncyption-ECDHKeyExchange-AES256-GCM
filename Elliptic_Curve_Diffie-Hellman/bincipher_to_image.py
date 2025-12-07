# --- Image Processing: binary to image for Ciphertext Visualization ---

# input encrypted_binary.txt
# input lebar, tinggi (from original image)
# output gambar 'encrypted_image.png'

import cv2
import numpy as np
import json

# Define paths for ciphertext visualization
input_ciphertext_binary_path = r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\encrypted_binary.txt"
output_ciphertext_image_path = r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\encrypted_image.png"

def convert_from_binary_for_visual(binary_value):
    # Ensure binary_value is long enough for at least one pixel (24 bits)
    if len(binary_value) < 24: # Handle cases where there isn't enough data for a full pixel
        return np.array([0, 0, 0], dtype=np.uint8)
    return np.array([int(binary_value[i:i+8], 2) for i in range(0, 24, 8)])

def binary_to_img_for_visual(input_file_path, output_file_path, width, height):
    with open(input_file_path, 'r') as f:
        binary_data_str = f.read().replace('\n', '')

    image = np.zeros((height, width, 3), dtype=np.uint8)

    for y in range(height):
        for x in range(width):
            start = (y * width + x) * 24
            end = start + 24
            if end <= len(binary_data_str):
                pixel_binary_str = binary_data_str[start:end]
                pixel = convert_from_binary_for_visual(pixel_binary_str)
                image[y, x] = pixel
            else:
                # If ciphertext is shorter than expected image data, fill remaining with black
                image[y, x] = [0, 0, 0]

    cv2.imwrite(output_file_path, image)
    print(f"Encrypted image saved to {output_file_path}")

dimensions_path = r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\image_dimensions.json"
with open(dimensions_path, 'r') as f:
    dimensions = json.load(f)
    lebar = dimensions['width']
    tinggi = dimensions['height']

print(f"Dimensi gambar: {lebar}x{tinggi}")   
# Use the 'lebar' and 'tinggi' obtained from the original image processing
binary_to_img_for_visual(input_ciphertext_binary_path, output_ciphertext_image_path, lebar, tinggi)