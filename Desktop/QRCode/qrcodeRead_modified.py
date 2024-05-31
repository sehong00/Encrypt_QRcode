from PIL import Image
from pyzbar.pyzbar import decode
import json
import base64
import piheaan as heaan
import tempfile
import os
import time

# Assuming the student ID and password are stored in the database
stored_student_id = "seoultech"
stored_password = "itm"

# Load homomorphic encryption context and keys
params = heaan.ParameterPreset.FGb
context = heaan.make_context(params)
heaan.make_bootstrappable(context)

key_file_path = "./keys"
sk = heaan.SecretKey(context, key_file_path + "/secretkey.bin")  # load sk
pk = heaan.KeyPack(context, key_file_path + "/")  # load pk
pk.load_enc_key()
pk.load_mult_key()

eval = heaan.HomEvaluator(context, pk)
dec = heaan.Decryptor(context)

def decrypt_content(encrypted_content_b64):
    # Decode the base64 content
    encrypted_content_bytes = base64.b64decode(encrypted_content_b64)
   
    # Create a temporary file and write the byte content to it
    temp_file_path = ''
    temp_file = None
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(encrypted_content_bytes)
        temp_file_path = temp_file.name
       
        # Load the ciphertext from the temporary file
        encrypted_message = heaan.Ciphertext(context)
        encrypted_message.load(temp_file_path)
       
        # Decrypt the ciphertext
        decrypted_message = dec.decrypt(encrypted_message)
       
        # Convert decrypted message to string
        decrypted_text = ''.join([chr(int(round(val))) for val in decrypted_message[:len(decrypted_message)]])
       
        return decrypted_text
    finally:
        # Ensure the temporary file is closed and deleted
        if temp_file:
            temp_file.close()
            time.sleep(100)

        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
def decode_qr_code(file_path):
    try:
        image = Image.open(file_path)
        decoded_objects = decode(image)

        if not decoded_objects:
            print("No QR codes found in the image.")
            return

        qr_data = decoded_objects[0].data.decode("utf-8")
        qr_json = json.loads(qr_data)

        data = qr_json.get('data', '')
        encrypted_content = qr_json.get('encrypted_content', '')

        print("QR code data:", data)
        decrypted_content = decrypt_content(encrypted_content)
        print("Decrypted Content:", decrypted_content)
        print("QR Code Content:", qr_json)

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    student_id = input("Enter your student ID: ")
    password = input("Enter your password: ")

    if student_id == stored_student_id and password == stored_password:
        file_path = "C:/Users/sehong/Desktop/QRCode/www_seoultech_ac_kr.png"

        decode_qr_code(file_path)
    else:
        print("Error: Incorrect student ID or password.")