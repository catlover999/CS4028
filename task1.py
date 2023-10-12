from numpy import base_repr
from multiprocessing import Manager, Process, cpu_count, Event
import hashlib
import time

def crack(start: int, num: int, hashes: tuple, results: dict, stop: Event):
    i = start
    while not stop.is_set():
        plaintext = base_repr(i, 36).lower()
        hashed = hashlib.sha512(plaintext.encode()).hexdigest()
        if hashed in hashes:
            results[hashed] = plaintext
            if sorted(results.keys()) == sorted(hashes):
                stop.set()
        i += num   

def brute(list_of_hashes) -> list:
    try:
        processe_count = cpu_count()
    except NotImplementedError:
        processe_count = 4

    with Manager() as manager:
        results = manager.dict()
        processes = []
        stop = Event()
        for processe_num in range(processe_count):
            processe = Process(target=crack, args=(processe_num, processe_count, list_of_hashes, results, stop))
            processes.append(processe)
            processe.start()
        for processe in processes:
            processe.join()    
        return [results[item] for item in list_of_hashes]

if __name__ == '__main__':
    hashes = ['f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a', 'e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24','4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80', 'afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b']
    start = time.time()
    passwords = brute(hashes)
    end = time.time()
    for x in range(len(hashes)):
        print("The value for hash " + hashes[x] + " is " + passwords[x])
    print("Execution time: " + str(end - start))

