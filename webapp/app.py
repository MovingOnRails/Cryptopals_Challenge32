import time
import hmac
import hashlib
from flask import Flask, request

# signature
# 7af51ee0e84bc075c85833faf01619b7dc920dde

def insecure_compare(hash, signature):
    for i in range(len(hash)):
        time.sleep(0.005)
        if hash[i] != signature[i]:
            return False
    return True
        

def compute_file_hmac(file_path, key):
    # Ensure the key is in bytes
    if isinstance(key, str):
        key = key.encode('utf-8')

    # Initialize the HMAC object with the key and SHA1 algorithm
    h = hmac.new(key, digestmod=hashlib.sha1)

    try:
        with open(file_path, 'rb') as f:
            # Read the file in 64KB chunks
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except FileNotFoundError:
        return "File not found."

    # Return the hexadecimal representation of the HMAC
    return h.hexdigest()


app = Flask(__name__)

@app.route('/test', methods=['GET'])
def test_endpoint():
    filename = request.args.get('file')
    signature = request.args.get('signature')

    if filename == None or signature == None:
        return f'Missing file or signature parameters', 400

    filehash = compute_file_hmac('./'+filename, "THISISATESTKEY!!!!!!")

    if insecure_compare(filehash, signature):
        return f'filehash and signature are identical', 200
    else:
        return f'filehash is different from signature', 403




if __name__ == '__main__':
    app.run(port=9000)
