from numpy import base_repr
from multiprocessing import Manager, Event, Process, managers, synchronize, cpu_count
import hashlib
import time

def crack(start: int, num: int, target: str, results: managers.ListProxy, event: synchronize.Event) -> str:
    i = start
    while not event.is_set():
        x = base_repr(i, 36).lower()
        hash = hashlib.sha512(f"{x}".encode()).hexdigest()
        if hash == target:
            results.append(x)
            event.set()
        i += num

def brute(target: str) -> str:
    try:
        cores = cpu_count()
    except NotImplementedError:
        cores = 4
    
    with Manager() as manager:
        results = manager.list()
        event = Event()

        processes = []
        for i in range(cores):
            p = Process(target=crack, args=(i, cores, target, results, event))
            processes.append(p)
            p.start()
    
        for p in processes:
            p.join()
        
        return(results[0])


if __name__ == '__main__':
    task1 = ['f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a', 'e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24','4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80', 'afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b']
    start = time.time()
    for x in range(len(task1)):
        print("The value for hash #" + str(x) + " is " + brute(task1[x]))
    end = time.time()
    print("Execution time: " + str(end - start))

