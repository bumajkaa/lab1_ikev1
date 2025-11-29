import argparse
import hashlib
import hmac
import binascii
import itertools
import sys
import time

class IKEv1Cracker:
    def __init__(self, test_data_file):
        self.load_test_data(test_data_file)
        self.determine_hash_algorithm()
        
    def load_test_data(self, filename):
        with open(filename, 'r') as f:
            data = f.read().strip()
        
        parts = data.split('*')
        if len(parts) != 9:
            raise ValueError("Invalid test data format")
        
        self.Ni = binascii.unhexlify(parts[0])
        self.Nr = binascii.unhexlify(parts[1])
        self.g_x = binascii.unhexlify(parts[2])
        self.g_y = binascii.unhexlify(parts[3])
        self.Ci = binascii.unhexlify(parts[4])
        self.Cr = binascii.unhexlify(parts[5])
        self.SAi = binascii.unhexlify(parts[6])
        self.IDr = binascii.unhexlify(parts[7])
        self.target_hash = binascii.unhexlify(parts[8])
        
    def determine_hash_algorithm(self):
        hash_size = len(self.target_hash)
        
        if hash_size == 16:  
            self.hash_algorithm = 'md5'
            self.hash_func = hashlib.md5
        elif hash_size == 20:  
            self.hash_algorithm = 'sha1'
            self.hash_func = hashlib.sha1
        else:
            raise ValueError(f"Unknown hash algorithm with size: {hash_size}")
            
        print(f"Detected hash algorithm: {self.hash_algorithm.upper()}")
    
    def generate_alphabets(self, mask):
        alphabets = []
        
        char_sets = {
            'a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'd': '0123456789',
            'l': 'abcdefghijklmnopqrstuvwxyz',
            'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        }
        
        for char in mask:
            if char in char_sets:
                alphabets.append(char_sets[char])
            else:
                raise ValueError(f"Unknown mask character: {char}")
                
        return alphabets
    
    def compute_ike_hash(self, password):
        # SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
        skeyid_input = self.Ni + self.Nr
        
        if self.hash_algorithm == 'md5':
            skeyid = hmac.new(password.encode(),skeyid_input, hashlib.md5).digest()
        else:  
            skeyid = hmac.new(password.encode(), skeyid_input, hashlib.sha1).digest()
        
        hash_input = (self.g_y + self.g_x + self.Cr + self.Ci + 
                     self.SAi + self.IDr)
        
        if self.hash_algorithm == 'md5':
            computed_hash = hmac.new(skeyid, hash_input, hashlib.md5).digest()
        else:  
            computed_hash = hmac.new(skeyid, hash_input, hashlib.sha1).digest()
            
        return computed_hash
    
    def print_progress_bar(self, iteration, total, length=50, prefix='', suffix=''):
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = '█' * filled_length + '─' * (length - filled_length)    
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='', flush=True)
        
        if iteration == total:
            print()

    def crack_password(self, mask):
        alphabets = self.generate_alphabets(mask)
        total_combinations = 1
        for alphabet in alphabets:
            total_combinations *= len(alphabet)
            
        print(f"Starting password cracking...")
        print(f"Mask: {mask}")
        print(f"Password length: {len(mask)}")
        print(f"Total combinations: {total_combinations:,}")
        print("-" * 60)
        
        self.start_time = time.time()
        attempts = 0
        last_update = 0
        update_interval = max(1, total_combinations // 1000)  
        
        # Для расчета скорости
        last_time = self.start_time
        last_attempts = 0
        
        for password_chars in itertools.product(*alphabets):
            password = ''.join(password_chars)
            attempts += 1
            
            # Расчет текущей скорости
            current_time = time.time()
            elapsed_since_last = current_time - last_time
            
            if attempts % update_interval == 0 or attempts == total_combinations:
                # Обновляем скорость каждую секунду или при обновлении прогресса
                if elapsed_since_last >= 1.0:
                    current_speed = (attempts - last_attempts) / elapsed_since_last
                    last_time = current_time
                    last_attempts = attempts
                else:
                    total_elapsed = current_time - self.start_time
                    current_speed = attempts / total_elapsed if total_elapsed > 0 else 0
                
                elapsed = current_time - self.start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                self.print_progress_bar(
                    attempts, 
                    total_combinations, 
                    prefix='Progress:',
                    suffix=f' | Speed: {current_speed:,.0f} p/s'
                )
            
            computed_hash = self.compute_ike_hash(password)
            
            if computed_hash == self.target_hash:
                elapsed = time.time() - self.start_time
                avg_speed = attempts / elapsed if elapsed > 0 else 0
                print("\n" + "="*60)
                print(f"PASSWORD FOUND: {password}")
                print(f"Total attempts: {attempts:,}")
                print(f"Time elapsed: {elapsed:.2f} seconds")
                print(f"Average speed: {avg_speed:,.0f} passwords/second")
                print("="*60)
                return password  
        
        elapsed = time.time() - self.start_time
        avg_speed = attempts / elapsed if elapsed > 0 else 0
        print("\n" + "="*60)
        print("PASSWORD NOT FOUND")
        print(f"Total attempts: {attempts:,}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"Average speed: {avg_speed:,.0f} passwords/second")
        print("="*60)
        return None

def main():
    parser = argparse.ArgumentParser(description='IKEv1 Aggressive Mode Password Cracker')
    parser.add_argument('-m', '--mask', required=True, 
                       help='Password mask (a=alphanumeric, d=digits, l=lowercase, u=uppercase)')
    parser.add_argument('test_file', help='File with test data')
    
    args = parser.parse_args()
    
    try:
        cracker = IKEv1Cracker(args.test_file)
        password = cracker.crack_password(args.mask)
        
        if password:
            sys.exit(0)  # Успех
        else:
            sys.exit(1)  # Пароль не найден
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
