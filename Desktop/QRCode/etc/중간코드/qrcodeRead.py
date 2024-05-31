# qrcodeRead.py

# qr_data = input("Enter the QR code data: ")  # Assuming the QR code data is provided by the user
# 실제 시나리오에서는 QR 코드 데이터가 실제 QR 코드 이미지에서 스캔됩니다.
# 그러나 여기서는 프로세스를 시뮬레이션하고 QR 코드를 직접 스캔하는 것을 다루지 않기 때문에
# 사용자가 테스트 목적으로 QR 코드 데이터를 수동으로 입력할 수 있도록 해당 라인을 추가했습니다.
# 원하는 경우 해당 줄을 제거하고 사전 정의된 QR 코드 데이터 문자열을 사용하여 'decode_qr_code' 함수를 직접 호출할 수 있습니다. 

from PIL import Image
from pyzbar.pyzbar import decode
import json
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import subprocess
import base64

# Assuming the student ID and password are stored in the database
stored_student_id = "seoultech"
stored_password = "itm"

def verify_signature(data, signature_b64, public_key):
    try:
        # Decode the base64 encoded signature
        signature = base64.b64decode(signature_b64.encode('utf-8'))

        # Create a hash of the data
        hash_obj = SHA256.new(data.encode())

        # Verify the digital signature
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True  # Signature verification successful
    except Exception as e:
        print(f"Error verifying signature: {e}")
        return False  # Signature verification failed

def decode_qr_code(file_path):
    try:
        # Load the image containing the QR code
        image = Image.open(file_path)

        # Decode the QR code
        decoded_objects = decode(image)

        if not decoded_objects:
            print("No QR codes found in the image.")
            return

        # Assuming only one QR code is present in the image
        qr_data = decoded_objects[0].data.decode("utf-8")

        # Decode the QR code data
        qr_json = json.loads(qr_data)

        # Extract data and signature from the decoded QR code
        data = qr_json.get('data', '')
        signature_b64 = qr_json.get('signature', '')

        # Load public key
        public_key = RSA.import_key(open("public.pem").read())

        # Verify the digital signature
        if verify_signature(data, signature_b64, public_key):
            print("Signature verified. QR code content:")
            print("Digital Identity:", data)
            print("QR Code Content:", qr_json)
        else:
            print("Error: Signature verification failed. QR code content could not be trusted.")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":

    # Input student ID and password
    student_id = input("Enter your student ID: ")
    password = input("Enter your password: ")

    # Check if the input matches the stored data
    if student_id == stored_student_id and password == stored_password:
        # Define the file path of the QR code image
        file_path = f"C:/Users/sehong/Desktop/QRCode/qr_www_seoultech_ac_kr.png"

        # Decode the QR code from the image
        decode_qr_code(file_path)
    else:
        print("Error: Incorrect student ID or password.")


#이 코드는 id password가 확인되어 public key를 받고 qrcode를 decoding 해서 디지털 신원이랑 qr코드 내용을 둘다 확인한거야?
#정확히 맞아요! 입력한 학번과 비밀번호가 저장된 값과 일치하면 public.pem 파일에서 공개 키를 읽어오고,
# 그것을 사용하여 QR 코드의 내용과 디지털 서명을 확인합니다. 서명이 유효하면 QR 코드의 내용을 신뢰할 수 있으며,
# QR Code Content: {'data': 'https://www.seoultech.ac.kr/index.jsp', 'signature': 'J9K984uDmhsDGJ3H... ...'}