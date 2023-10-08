use rand::RngCore;
use rand::rngs::OsRng;

pub trait KeyScheduler<K> {
    fn new(master_key: K) -> Self;
    // hack
    fn naive_next_key(&mut self) -> K;

    // fn next_key(&mut self) -> K;
}

pub struct RotatingKeyScheduler {
    current_key: u128,
    rounds: usize,
}

impl KeyScheduler<u128> for RotatingKeyScheduler {
    fn new(master_key: u128) -> Self {
        Self {
            current_key: master_key,
            rounds: 0,
        }
    }

    fn naive_next_key(&mut self) -> u128 {
        self.rounds += 1;
        self.current_key = self.current_key.rotate_left(1);
        return self.current_key;
    }
}

impl Default for RotatingKeyScheduler {
    fn default() -> Self {
        return RotatingKeyScheduler::new(KeyGenerator::generate());
    }
}

pub struct KeyGenerator;

fn bytes_to_u128(bytes: [u8; 16]) -> u128 {
    let mut v: u128 = 0;
    for &byte in bytes.iter() {
        v = (v << 8) | byte as u128;
    }
    return v;
}

impl KeyGenerator {
    pub fn generate() -> u128 {
        let mut rng = [0u8; 16];
        OsRng.fill_bytes(&mut rng);
        return bytes_to_u128(rng);
    }
}
