#qrcodeGenerate_modified.py

import time # time 라이브러리 import
import qrcode
from urllib.parse import urlparse
import re
import base64
import json
from PIL import Image
import piheaan as heaan
import numpy as np
from PIL import ImageDraw, ImageFont

params = heaan.ParameterPreset.FGb
context = heaan.make_context(params)
heaan.make_bootstrappable(context)

# Load pre-exisisting key
key_file_path = "./keys"

sk = heaan.SecretKey(context,key_file_path+"/secretkey.bin") # load sk
pk = heaan.KeyPack(context, key_file_path+"/") # load pk
pk.load_enc_key()
pk.load_mult_key()

eval = heaan.HomEvaluator(context,pk)
dec = heaan.Decryptor(context)
enc = heaan.Encryptor(context)

log_slots = 15
num_slots = 2**log_slots

# Updated step function
def step(learning_rate, ctxt_X, ctxt_Y, ctxt_beta, n, log_slots, context, eval):
    ctxt_rot = heaan.Ciphertext(context)
    ctxt_tmp = heaan.Ciphertext(context)
    ctxt_poly = heaan.Ciphertext(context)

    # Step 1: Compute linear combination of beta and X plus beta0 more efficiently
    ctxt_beta0 = heaan.Ciphertext(context)
    eval.left_rotate(ctxt_beta, 8 * n, ctxt_beta0)

    eval.mult(ctxt_beta, ctxt_X, ctxt_tmp)
    eval.left_rotate(ctxt_tmp, n, ctxt_rot)
    eval.add(ctxt_tmp, ctxt_rot, ctxt_tmp)
    eval.left_rotate(ctxt_tmp, 2 * n, ctxt_rot)
    eval.add(ctxt_tmp, ctxt_rot, ctxt_tmp)
    eval.left_rotate(ctxt_tmp, 4 * n, ctxt_rot)
    eval.add(ctxt_tmp, ctxt_rot, ctxt_tmp)
    eval.add(ctxt_tmp, ctxt_beta0, ctxt_tmp)

    # Masking to keep first n elements
    msg_mask = heaan.Message(log_slots)
    for i in range(n):
        msg_mask[i] = 1
    eval.mult(ctxt_tmp, msg_mask, ctxt_tmp)

    # Step 2: Compute sigmoid using polynomial approximation
    # Sigmoid approximation: 0.5 + 0.15012x - 0.001593x^3
    eval.mult(ctxt_tmp, ctxt_tmp, ctxt_poly)  # x^2
    eval.mult(ctxt_poly, ctxt_tmp, ctxt_poly)  # x^3
    eval.mult(ctxt_tmp, 0.15012, ctxt_tmp)  # 0.15012x
    eval.mult(ctxt_poly, -0.001593, ctxt_poly)  # -0.001593x^3
    eval.add(ctxt_tmp, ctxt_poly, ctxt_tmp)  # 0.15012x - 0.001593x^3

    # Manually add 0.5 to all slots in ctxt_tmp using approximate method
    msg_const = heaan.Message(log_slots)
    for i in range(n):
        msg_const[i] = 0.5
    ctxt_const = heaan.Ciphertext(context)
    enc.encrypt(msg_const, pk, ctxt_const)
    eval.add(ctxt_tmp, ctxt_const, ctxt_tmp)  # 0.5 + 0.15012x - 0.001593x^3

    eval.bootstrap(ctxt_tmp, ctxt_tmp)

    # Masking for sigmoid output
    msg_mask = heaan.Message(log_slots)
    for i in range(n, num_slots):
        msg_mask[i] = 0.0
    ctxt_mask = heaan.Ciphertext(context)
    enc.encrypt(msg_mask, pk, ctxt_mask)
    eval.mult(ctxt_tmp, ctxt_mask, ctxt_tmp)

    # Step 3: Compute (dynamic_learning_rate / n) * (y_(j) - sigmoid(x)) with optimized rotations
    # Dynamic learning rate adjustment
    dynamic_learning_rate = learning_rate / (1 + 0.1 * n)  # Increased rate of decay for learning rate adjustment
    ctxt_d = heaan.Ciphertext(context)
    eval.sub(ctxt_Y, ctxt_tmp, ctxt_d)
    eval.mult(ctxt_d, dynamic_learning_rate / n, ctxt_d)

    eval.right_rotate(ctxt_d, 8 * n, ctxt_tmp)  # For beta0 update
    for i in range(3):
        eval.right_rotate(ctxt_d, n * 2 ** i, ctxt_rot)
        eval.add(ctxt_d, ctxt_rot, ctxt_d)
    eval.add(ctxt_d, ctxt_tmp, ctxt_d)
    
    # Step 4: Compute (learning_rate / n) * (y_(j) - p_(j)) * x_(j) more effectively
    ctxt_X_j = heaan.Ciphertext(context)
    msg_X0 = heaan.Message(log_slots)
    for i in range(8 * n, 9 * n):
        msg_X0[i] = 1
    eval.add(ctxt_X, msg_X0, ctxt_X_j)
    
    # Encrypt ctxt_X_j with noise
    noise = heaan.Message(log_slots)
    for i in range(len(noise)):
        noise[i] = np.random.normal(0, noise_level)
    ctxt_noise = heaan.Ciphertext(context)
    enc.encrypt(noise, sk, ctxt_noise)  # Use SecretKey to encrypt
    eval.add(ctxt_X_j, ctxt_noise, ctxt_X_j)
    
    # Multiply (y_(j) - p_(j)) by (learning_rate / n) * x_(j)
    eval.mult(ctxt_X_j, ctxt_d, ctxt_d)

   # Step 5: Sum the products over all j with fewer rotations
    for i in range(8):
        ctxt_tmp = heaan.Ciphertext(context)
    
        # Rotate ctxt_d by 2^i
        eval.right_rotate(ctxt_d, 2 ** i, ctxt_tmp)
    
        # Multiply ctxt_tmp with a mask that selects every n-th slot
        ctxt_masked = heaan.Ciphertext(context)
        msg_mask = heaan.Message(log_slots)
        for j in range(num_slots):
            if j % n == 0:
                msg_mask[j] = 1
            else:
                msg_mask[j] = 0
        eval.mult(ctxt_tmp, msg_mask, ctxt_masked)
    
        # Sum ctxt_masked into ctxt_d
        eval.add(ctxt_d, ctxt_masked, ctxt_d)
        
    # Step 6: Update beta
    eval.add(ctxt_beta, ctxt_d, ctxt_d)

    return ctxt_d

# Enhanced encryption function
def enhanced_encrypt(msg, enc, eval, sk, noise_level=0.1):
    noise_level=0.1
    
    ctxt = heaan.Ciphertext(context)
    enc.encrypt(msg, sk, ctxt)  # Use SecretKey to encrypt

    noise = heaan.Message(log_slots)
    for i in range(len(noise)):
        noise[i] = np.random.normal(0, noise_level)
    ctxt_noise = heaan.Ciphertext(context)
    enc.encrypt(noise, sk, ctxt_noise)  # Use SecretKey to encrypt

    eval.add(ctxt, ctxt_noise, ctxt)
    return ctxt

def generate_qr_code(data, authorized):
    try:
        
        # Define the text to be displayed
        if authorized:
            text = "Made by Seoultech"
        else:
            text = "Error: Unauthorized Access"
            raise ValueError("Unauthorized access detected")
                    
        # Parse the url and extract the domain, and sanitize the domain name for file path
        parsed_url = urlparse(data)
        domain_name = parsed_url.netloc
        changedDomainName = re.sub(r'[^\w\d-]', '_', domain_name)

        msg = heaan.Message(log_slots)
        for i in range(len(msg)):
            msg[i] = np.random.rand()

        ctxt_X = enhanced_encrypt(msg, enc, eval, sk)
        ctxt_Y = enhanced_encrypt(msg, enc, eval, sk)
        ctxt_beta = enhanced_encrypt(msg, enc, eval, sk)
        n = 10

        encrypted_signature = step(0.01, ctxt_X, ctxt_Y, ctxt_beta, n, log_slots, context, eval)
        signature_b64 = base64.b64encode(str(encrypted_signature).encode('utf-8')).decode('utf-8')

        combined_data = json.dumps({'data': data, 'signature': signature_b64})

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(combined_data)
        qr.make(fit=True)

        qr_img = qr.make_image(fill='black', back_color='white')

        # Define the image size
        image_width = 1000  # Adjust this as needed
        image_height = 1000  # Adjust this as needed

        # Create a blank image with the desired size
        img = Image.new('RGB', (image_width, image_height), color='white')

        # Paste the QR code onto the blank image
        qr_width, qr_height = img.size

        # Calculate the position to paste the QR code onto the blank image
        qr_position = ((image_width - qr_width) // 2, (image_height - qr_height) // 2)

        # Paste the QR code onto the blank image
        img.paste(qr_img, qr_position)

        # Define the font size
        font_size = 40  # Adjust this as needed

        # Create a font object with the desired font size
        font = ImageFont.truetype("arial.ttf", font_size)

        # Create a draw object
        draw = ImageDraw.Draw(img)

        # Calculate text size and position
        text_width, text_height = draw.textsize(text, font=font)

        # Calculate text position to center horizontally within the image
        text_position = ((image_width - text_width) // 2, image_height - text_height - 20)

        # Ensure the text position is not outside the visible area of the image
        if text_position[1] < 0:
            text_position = ((image_width - text_width) // 2, 0)

        # Draw the text on the image
        draw.text(text_position, text, fill='red', font=font)

        img.save(f"{changedDomainName}.png")

        print(f"QR code generated and saved as {changedDomainName}.png")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Data to be encoded
    data = "https://www.seoultech.ac.kr/index.jsp"

    noise_level = 0.1  # Define the noise level
    
    authorized = input("Enter your Identity: ")
    
    start = time.time() # start for measuring excution time

    
    if authorized == "seoultech" or authorized == "Seoultech":
        authorized = True
    else:
        authorized = False

    generate_qr_code(data, authorized)

    print("excution time:" f"{time.time()-start:.4f} sec") # Output excution time with exit
