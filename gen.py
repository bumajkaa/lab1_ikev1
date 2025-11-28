import argparse
import hashlib
import hmac
import os
import binascii
import sys

class IKEv1Generator:
    def __init__(self, traffic_file=None):
        self.load_from_file(traffic_file)

    
    def load_from_file(self, filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Traffic file not found: {filename}")
        
        with open(filename, 'r') as f:
            content = f.read()
        
        data = self.parse_traffic_file(content)
        
        self.Ci = binascii.unhexlify(data.get('Ci', ''))
        self.Ni = binascii.unhexlify(data.get('Ni', ''))
        self.g_x = binascii.unhexlify(data.get('g_x', ''))
        self.Cr = binascii.unhexlify(data.get('Cr', ''))
        self.Nr = binascii.unhexlify(data.get('Nr', ''))
        self.g_y = binascii.unhexlify(data.get('g_y', ''))
        self.SAi = binascii.unhexlify(data.get('SAi', ''))
        self.IDr = binascii.unhexlify(data.get('IDr', ''))
    
    def parse_traffic_file(self, content):
        data = {}

        lines = content.strip().split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                data[key] = value  
        
        return data 
        
    def generate_hash(self, password, hash_algorithm):
        
        # SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
        skeyid_input = self.Ni + self.Nr
        
        if hash_algorithm.lower() == 'md5':
            skeyid = hmac.new(password.encode(), skeyid_input,  hashlib.md5).digest()
        elif hash_algorithm.lower() == 'sha1':
            skeyid = hmac.new(password.encode(), skeyid_input, hashlib.sha1).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
        
        # HASH_I = prf(SKEYID, g_y | g_x | Cr | Ci | SAi | IDr)
        hash_input = (self.g_y + self.g_x + self.Cr + self.Ci + 
                     self.SAi + self.IDr)
        
        if hash_algorithm.lower() == 'md5':
            ike_hash = hmac.new(skeyid, hash_input, hashlib.md5).digest()
        else:  
            ike_hash = hmac.new(skeyid, hash_input, hashlib.sha1).digest()
            
        return ike_hash
    
    def generate_test_data(self, password, hash_algorithm):
        ike_hash = self.generate_hash(password, hash_algorithm)
        
        result = (
            f"{binascii.hexlify(self.Ni).decode()}*"
            f"{binascii.hexlify(self.Nr).decode()}*"
            f"{binascii.hexlify(self.g_x).decode()}*"
            f"{binascii.hexlify(self.g_y).decode()}*"
            f"{binascii.hexlify(self.Ci).decode()}*"
            f"{binascii.hexlify(self.Cr).decode()}*"
            f"{binascii.hexlify(self.SAi).decode()}*"
            f"{binascii.hexlify(self.IDr).decode()}*"
            f"{binascii.hexlify(ike_hash).decode()}"
        )
        
        return result

def main():
    parser = argparse.ArgumentParser(description='IKEv1 Aggressive Mode Test Data Generator')
    parser.add_argument('-m', '--mode', required=True, choices=['md5', 'sha1'], 
                       help='Hash algorithm (md5 or sha1)')
    parser.add_argument('-p', '--password', required=True, 
                       help='Password to generate test data')
    parser.add_argument('-f', '--file', 
                       help='Traffic file with IKE data (optional)')
    parser.add_argument('-o', '--output', 
                       help='Output file to save results (optional)')
    
    args = parser.parse_args()
    
    try:
        generator = IKEv1Generator(args.file)
        test_data = generator.generate_test_data(args.password, args.mode)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(test_data)
            print(f"Test data saved to: {args.output}")
        else:
            print(test_data)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()