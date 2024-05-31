# qrcodeGenerate.py

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import qrcode
from urllib.parse import urlparse
import re
import base64
import json
from PIL import Image, ImageDraw, ImageFont

#  generate and save RSA private and public key
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# save private key as a file
with open("private.pem", "wb") as private_file:
    private_file.write(private_key)

# save public key as a file
with open("public.pem", "wb") as public_file:
    public_file.write(public_key)
    
private_key = RSA.import_key(open("private.pem").read())
public_key = RSA.import_key(open("public.pem").read())

def generate_qr_code(data, authorized=True):
    try:
        # Parse the url and extract the domain, and sanitize the domain name for file path
        parsed_url = urlparse(data)
        domain_name = parsed_url.netloc
        changedDomainName = re.sub(r'[^\w\d-]', '_', domain_name)

        # Load private key
        private_key = RSA.import_key(open("private.pem").read())

        # Create a hash of the data
        hash_obj = SHA256.new(data.encode())

        # Generate a digital signature of the hash
        signature = pkcs1_15.new(private_key).sign(hash_obj)

        # Encode the signature in base64 to make it easier to embed in QR codes
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        # Combine the data and the signature into one JSON object
        combined_data = json.dumps({'data': data, 'signature': signature_b64})

        # Create QR code instance
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )

        # Add the combined data to the QR code
        qr.add_data(combined_data)
        qr.make(fit=True)

        # Create an image from the QR Code instance
        qr_img = qr.make_image(fill='black', back_color='white')

        # Define the image size
        image_width = 1000  # Adjust this as needed
        image_height = 1000  # Adjust this as needed

        # Create a blank image with the desired size
        img = Image.new('RGB', (image_width, image_height), color='white')

        # Paste the QR code onto the blank image
        qr_width, qr_height = qr_img.size
        img.paste(qr_img, ((image_width - qr_width) // 2, (image_height - qr_height) // 2))

        # Define the text to be displayed
        if authorized:
            text = "Made by Seoultech"
        else:
            text = "Error: Unauthorized Access"

        # Define the font size
        font_size = 40  # Adjust this as needed

        # font = ImageFont.load_default()

        # Create a font object with the desired font size
        font = ImageFont.truetype("arial.ttf", font_size)

        # Create a draw object
        draw = ImageDraw.Draw(img)

        # Calculate text size and position
        text_width, text_height = draw.textsize(text, font=font)

        # Calculate text position to center horizontally within the image
        text_position = ((image_width - text_width) // 2, (image_height + qr_height) // 2)

        # Ensure the text position is not outside the visible area of the image
        if text_position[1] < 0:
            text_position = ((image_width - text_width) // 2, 0)

        # Print text size and position for debugging
        print("Text Size:", (text_width, text_height))
        print("Text Position:", text_position)

        # Draw the text on the image
        draw.text(text_position, text, fill='red', font=font)

        # Define the file path and file name
        file_path = f"C:/Users/sehong/Desktop/QRCode/qr_{changedDomainName}.png"

        # Save the image
        img.save(file_path)

        print(f"QR code with digital signature saved as {file_path}")
    
    except Exception as e:
        print(f"An error occurred: {e}")

# Data to be encoded
data = "https://www.seoultech.ac.kr/index.jsp"

generate_qr_code(data, authorized=True)