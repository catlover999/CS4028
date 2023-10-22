extern crate base_custom;

use base_custom::BaseCustom;
use std::sync::{Arc, Barrier, RwLock, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::collections::HashMap;
use sha2::{Sha512, Digest};

const DIGITS: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

fn crack_passwords(mut index: usize, step: usize, global_hashes: Arc<RwLock<Vec<String>>>, results: Arc<RwLock<HashMap<String, String>>>, change: Arc<AtomicBool>, barrier: Arc<Barrier>) {
    let base36: BaseCustom<char> = BaseCustom::<char>::new(DIGITS.chars().collect());
    loop {
        let local_hashes = global_hashes.read().expect("Failed to acquire read lock").clone();
        if local_hashes.is_empty() {
            return;
        }
        barrier.wait();
        change.store(false, Ordering::Release);
        barrier.wait(); // A deadlock can occur if the a thread finds a hash and sets the change flag before a second thread is able to enter the while loop.
        while !change.load(Ordering::Acquire) {
                let plaintext = base36.gen(index.try_into().expect("Failed to convert index to the given base"));
                let hashed = format!("{:x}", Sha512::digest(plaintext.as_bytes()));
                if local_hashes.contains(&hashed) {
                    global_hashes.write().expect("Failed to remove hash from global hash list").retain(|x| x != &hashed);
                    results.write().expect("Failed to append result").insert(hashed.clone(), plaintext);
                    change.store(true, Ordering::Release);
                }
                index += step;
        }
    }
}

pub fn brute_force_hashes(list_of_hashes: Vec<String>) -> Vec<String> {
    let mut handles = vec![];
    let process_count: usize = num_cpus::get();
    let hashes: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(list_of_hashes.clone()));
    let results: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let change: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(process_count));

    for process_num in 0..process_count {
        let hashes = hashes.clone();
        let results = results.clone();
        let change = change.clone();
        let barrier = barrier.clone();
        let handle = thread::spawn(move || {
            crack_passwords(process_num, process_count, hashes, results, change, barrier);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread failed");
    }

    list_of_hashes.into_iter().map(|hash| results.read().expect("Failed to read results")[&hash].clone()).collect()
}

fn main() {
    let list_of_hashes: Vec<String> = [
        "f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a",
        "e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24",
        "4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80",
        "afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b"
        ].into_iter().map(String::from).collect();
    
    let start = std::time::Instant::now();
    let passwords = brute_force_hashes(list_of_hashes.clone());
    let duration = start.elapsed();

    for (hash, password) in list_of_hashes.iter().zip(passwords.iter()) {
        println!("Hash: {} is {}", hash, password);
    }

    println!("Execution time: {:?}", duration);
}
