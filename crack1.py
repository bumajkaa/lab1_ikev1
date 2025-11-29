import argparse
import hashlib
import hmac
import binascii
import itertools
import sys
import time
import multiprocessing as mp
from functools import reduce

def index_to_password(index, alphabets, bases):
    password_chars = []
    current = index
    for j in range(len(bases) - 1, -1, -1):
        idx = current % bases[j]
        password_chars.append(alphabets[j][idx])
        current //= bases[j]
    password_chars.reverse()
    return ''.join(password_chars)

def compute_ike_hash(password, Ni, Nr, g_x, g_y, Ci, Cr, SAi, IDr, hash_algorithm):
    skeyid_input = Ni + Nr
    if hash_algorithm == 'md5':
        skeyid = hmac.new(password.encode(),skeyid_input, hashlib.md5).digest()
    else:
        skeyid = hmac.new(password.encode(),skeyid_input, hashlib.sha1).digest()
    
    hash_input = g_y + g_x + Cr + Ci + SAi + IDr
    if hash_algorithm == 'md5':
        computed_hash = hmac.new(skeyid, hash_input, hashlib.md5).digest()
    else:
        computed_hash = hmac.new(skeyid, hash_input, hashlib.sha1).digest()
    
    return computed_hash

def worker(start, end, alphabets, bases, Ni, Nr, g_x, g_y, Ci, Cr, SAi, IDr, target_hash, hash_algorithm, queue, found_event):
    attempts = 0
    update_interval = max(1, (end - start) // 100) 
    
    for i in range(start, end):
        if found_event.is_set():
            if attempts > 0:
                queue.put({'type': 'progress', 'attempts': attempts})
            queue.put({'type': 'done'})
            return
        
        password = index_to_password(i, alphabets, bases)
        computed_hash = compute_ike_hash(password, Ni, Nr, g_x, g_y, Ci, Cr, SAi, IDr, hash_algorithm)
        attempts += 1
        
        if computed_hash == target_hash:
            queue.put({'type': 'found', 'password': password, 'attempts': attempts})
            found_event.set()
            queue.put({'type': 'done'})
            return
        
        if attempts % update_interval == 0:
            queue.put({'type': 'progress', 'attempts': update_interval})
    
    # Send remaining attempts
    remaining = attempts % update_interval
    if remaining > 0:
        queue.put({'type': 'progress', 'attempts': remaining})
    queue.put({'type': 'done'})

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
    
    def print_progress_bar(self, iteration, total, length=50, prefix='', suffix=''):
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = '█' * filled_length + '─' * (length - filled_length)    
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='', flush=True)
        
        if iteration == total:
            print()

    def crack_password(self, mask):
        alphabets = self.generate_alphabets(mask)
        bases = [len(alphabet) for alphabet in alphabets]
        total_combinations = reduce(lambda x, y: x * y, bases, 1)
            
        print(f"Starting password cracking...")
        print(f"Mask: {mask}")
        print(f"Password length: {len(mask)}")
        print(f"Total combinations: {total_combinations:,}")
        print("-" * 60)
        
        n_proc = mp.cpu_count()
        print(f"Using {n_proc} processes for optimization")
        
        queue = mp.Queue()
        found_event = mp.Event()
        processes = []
        
        chunk_size = (total_combinations + n_proc - 1) // n_proc  
        start = 0
        for _ in range(n_proc):
            end = min(start + chunk_size, total_combinations)
            if start >= end:
                break
            p = mp.Process(target=worker, args=(start, end, alphabets, bases, self.Ni, self.Nr, self.g_x, self.g_y, self.Ci, self.Cr, self.SAi, self.IDr, self.target_hash, self.hash_algorithm, queue, found_event))
            p.start()
            processes.append(p)
            start = end
        
        self.start_time = time.time()
        total_attempts = 0
        done_count = 0
        password = None
        
        while done_count < len(processes):
            try:
                msg = queue.get()
                if msg['type'] == 'found':
                    password = msg['password']
                    total_attempts += msg['attempts']
                    found_event.set()  
                elif msg['type'] == 'progress':
                    total_attempts += msg['attempts']
                    self.print_progress_bar(
                        total_attempts, 
                        total_combinations, 
                        prefix='Progress:',
                        suffix=f'| Attempts: {total_attempts:,}'
                    )
                elif msg['type'] == 'done':
                    done_count += 1
            except Exception:
                pass
        
        for p in processes:
            p.join()
        
        elapsed = time.time() - self.start_time
        print()  
        
        if password:
            print("\n" + "="*60)
            print(f"PASSWORD FOUND: {password}")
            print(f"Total attempts: {total_attempts:,}")
            print(f"Time elapsed: {elapsed:.2f} seconds")
            print("="*60)
            return password  
        else:
            print("\n" + "="*60)
            print("PASSWORD NOT FOUND")
            print(f"Total attempts: {total_attempts:,}")
            print(f"Time elapsed: {elapsed:.2f} seconds")
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