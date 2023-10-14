import hashlib
import time
from multiprocessing import Manager, Process, Event, Barrier, Lock, managers, cpu_count

def crack_passwords(index: int, step: int, global_hashes: managers.ListProxy, results: dict, change: Event, barrier: Barrier, sync_frequency: int, lock: Lock) -> None:
    """
    Attempt to crack passwords by hashing and comparing to target hashes.
    
    Parameters:
    - index (int): Starting number for hash generation.
    - step (int): Step size for the numbers to be hashed.
    - global_hashes (ListProxy): Shared list of target hashes to crack.
    - results (dict): Shared dictionary to store cracked hashes and corresponding plaintext.
    - change (Event): Event to signal when a password is cracked.
    - barrier (Barrier): Barrier to synchronize processes after a change event is set to ensure that that every process updates their local_hashes (failure to do this could lead to processes continuing exection after all hashes have been found)
    - sync_frequency (int): Number of iterations between checks of the change_event.
    - lock (Lock): Lock for modifying global hashes and results.
    """
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    while True:
        # Accessing a ListProxy is a very expensive operation. If read on every itteration, it roughly increases execution time by 2 orders of magnatude
        local_hashes = list(global_hashes)
        while not change.is_set():
            # Accessing the shared object 'change' is an expensive operation. Only checking it occasionily roughly halves execution time
            for _ in range(sync_frequency):
                # Adapted from numpy's base_repr()
                n = index
                res = []
                while n:
                    res.append(digits[n % len(digits)])
                    n //= len(digits)
                plaintext = ''.join(reversed(res or '0'))

                hashed = hashlib.sha512(plaintext.encode()).hexdigest()
                
                index += step

                if hashed in local_hashes:
                    with lock:
                        global_hashes.remove(hashed)
                        results[hashed] = plaintext
                        change.set()
                    break
        
        if global_hashes:
            barrier.wait()
            change.clear()
        else:
            return

def brute_force_hashes(list_of_hashes: list) -> list:
    process_count = cpu_count()
    with Manager() as manager:
        hashes = manager.list(list_of_hashes)
        results = manager.dict()
        barrier = Barrier(process_count)
        processes = []
        change = Event()
        sync_frequency = 20
        lock = Lock()
        for process_num in range(process_count):
            process = Process(target=crack_passwords, args=(process_num, process_count, hashes, results, change, barrier, sync_frequency, lock))
            processes.append(process)
            process.start()
        for process in processes:
            process.join()    
        return [results[item] for item in list_of_hashes] # ensures the order of hashes matches the input order

def hash_dictionary(filename: str, salt: str) -> dict:
    hashes = dict()
    try:
        with open(filename) as f:
            for value in f:
                value = value.strip()
                hashes[hashlib.sha512((value + salt).encode()).hexdigest()] = value
    except FileNotFoundError:
        print("{filename} not found.")
    except IOError:
        print("An error occurred while reading the file.")
    return hashes

def find_hashes_in_list(filename: str, l: list) -> dict:
    hashes = hash_dictionary(filename, "")
    out = dict()
    for i in range(len(l)):    
        if l[i] in hashes:
            out[l[i]] = hashes[l[i]]
        else:
            out[l[i]] = "Not found" 
    return out

def find_salted_hashes_in_list(filename: str, l: list) -> dict:
    out = dict()
    for i in range(len(l)):
        hashes = hash_dictionary(filename, l[i][1])
        x = l[i][0]
        if x in hashes:
            out[x] = hashes[x]
        else:
            out[x] = "Not found"
    return out

def print_hash_password(x: dict):
    for i, j in x.items():
        print("Hash: " + i + " is " + j)

if __name__ == '__main__':
    # Task 1
    hashes = ['f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a', 'e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24','4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80', 'afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b']
    start = time.time()
    passwords = brute_force_hashes(hashes)
    print_hash_password({h:p for h,p in zip(hashes,passwords)})

    # Supstitute filename for the full path if it's not in your pwd
    filename = "PasswordDictionary.txt"
    # Task 2
    print_hash_password(find_hashes_in_list(filename, ['31a3423d8f8d93b92baffd753608697ebb695e4fca4610ad7e08d3d0eb7f69d75cb16d61caf7cead0546b9be4e4346c56758e94fc5efe8b437c44ad460628c70','9381163828feb9072d232e02a1ee684a141fa9cddcf81c619e16f1dbbf6818c2edcc7ce2dc053eec3918f05d0946dd5386cbd50f790876449ae589c5b5f82762','a02f6423e725206b0ece283a6d59c85e71c4c5a9788351a24b1ebb18dcd8021ab854409130a3ac941fa35d1334672e36ed312a43462f4c91ca2822dd5762bd2b','834bd9315cb4711f052a5cc25641e947fc2b3ee94c89d90ed37da2d92b0ae0a33f8f7479c2a57a32feabdde1853e10c2573b673552d25b26943aefc3a0d05699','0ae72941b22a8733ca300161619ba9f8314ccf85f4bad1df0dc488fdd15d220b2dba3154dc8c78c577979abd514bf7949ddfece61d37614fbae7819710cae7ab','6768082bcb1ad00f831b4f0653c7e70d9cbc0f60df9f7d16a5f2da0886b3ce92b4cc458fbf03fea094e663cb397a76622de41305debbbb203dbcedff23a10d8a','0f17b11e84964b8df96c36e8aaa68bfa5655d3adf3bf7b4dc162a6aa0f7514f32903b3ceb53d223e74946052c233c466fc0f2cc18c8bf08aa5d0139f58157350','cf4f5338c0f2ccd3b7728d205bc52f0e2f607388ba361839bd6894c6fb8e267beb5b5bfe13b6e8cc5ab04c58b5619968615265141cc6a8a9cd5fd8cc48d837ec','1830a3dfe79e29d30441f8d736e2be7dbc3aa912f11abbffb91810efeef1f60426c31b6d666eadd83bbba2cc650d8f9a6393310b84e2ef02efa9fe161bf8f41d','3b46175f10fdb54c7941eca89cc813ddd8feb611ed3b331093a3948e3ab0c3b141ff6a7920f9a068ab0bf02d7ddaf2a52ef62d8fb3a6719cf25ec6f0061da791']))
    # Task 3
    print_hash_password(find_salted_hashes_in_list(filename, [('63328352350c9bd9611497d97fef965bda1d94ca15cc47d5053e164f4066f546828eee451cb5edd6f2bba1ea0a82278d0aa76c7003c79082d3a31b8c9bc1f58b','dbc3ab99'),('86ed9024514f1e475378f395556d4d1c2bdb681617157e1d4c7d18fb1b992d0921684263d03dc4506783649ea49bc3c9c7acf020939f1b0daf44adbea6072be6','fa46510a'),('16ac21a470fb5164b69fc9e4c5482e447f04f67227102107ff778ed76577b560f62a586a159ce826780e7749eadd083876b89de3506a95f51521774fff91497e','9e8dc114'),('13ef55f6fdfc540bdedcfafb41d9fe5038a6c52736e5b421ea6caf47ba03025e8d4f83573147bc06f769f8aeba0abd0053ca2348ee2924ffa769e393afb7f8b5','c202aebb'),('9602a9e9531bfb9e386c1565ee733a312bda7fd52b8acd0e51e2a0a13cce0f43551dfb3fe2fc5464d436491a832a23136c48f80b3ea00b7bfb29fedad86fc37a','d831c568'),('799ed233b218c9073e8aa57f3dad50fbf2156b77436f9dd341615e128bb2cb31f2d4c0f7f8367d7cdeacc7f6e46bd53be9f7773204127e14020854d2a63c6c18','86d01e25'),('7586ee7271f8ac620af8c00b60f2f4175529ce355d8f51b270128e8ad868b78af852a50174218a03135b5fc319c20fcdc38aa96cd10c6e974f909433c3e559aa','a3582e40'),('8522d4954fae2a9ad9155025ebc6f2ccd97e540942379fd8f291f1a022e5fa683acd19cb8cde9bd891763a2837a4ceffc5e89d1a99b5c45ea458a60cb7510a73','6f966981'),('6f5ad32136a430850add25317336847005e72a7cfe4e90ce9d86b89d87196ff6566322d11c13675906883c8072a66ebe87226e2bc834ea523adbbc88d2463ab3','894c88a4'),('21a60bdd58abc97b1c3084ea8c89aeaef97d682c543ff6edd540040af20b5db228fbce66fac962bdb2b2492f40dd977a944f1c25bc8243a4061dfeeb02ab721e','4c8f1a45')]))

    end = time.time()
    print("Execution time: " + str(end - start))

