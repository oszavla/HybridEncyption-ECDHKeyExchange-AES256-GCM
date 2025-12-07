# input test_image.png
# output image resolution (width x height)
# 1 pixel = RGB
# R = 8bit
# G = 8bit
# B = 8bit
# 1 pixel = 24bit

# all pixel are changed to be binary, arranged in test_img_binary.txt
# output test_img_binary.txt

import cv2
import numpy as np
import json

input_image_path=r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\test_image.png"
output_image_path=r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\test_image_binary.txt"

def convert_to_binary(pixel):
    return ''.join([f'{value:08b}' for value in pixel])

def img_to_binary(image_path):
    image = cv2.imread(image_path)

    height, width, channels = image.shape # type: ignore
    lebar, tinggi = width, height

    with open(output_image_path, 'w') as f:
        for y in range(height):
            for x in range(width):
                pixel = image[y, x] # type: ignore
                binary_value = convert_to_binary(pixel)
                f.write(binary_value)

    print(f"Resolusi gambar: {width}x{height}")

    return lebar, tinggi

lebar, tinggi = img_to_binary(input_image_path)

# Save image dimensions for later use
dimensions_path = r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\image_dimensions.json"
with open(dimensions_path, 'w') as f:
    json.dump({'width': lebar, 'height': tinggi}, f)        

