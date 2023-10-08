use core::ops::{Add, BitXor};
use num_traits::ops::wrapping::WrappingAdd;

pub trait Xorable<N>
where
    Self: BitXor<Output = N> + Add<Output = N> + Copy,
{
}

impl Xorable<u32> for u32 {}
impl Xorable<u64> for u64 {}
impl Xorable<u128> for u128 {}

#[allow(non_snake_case)]
pub struct CipherState<N, K>
where
    N: Xorable<N>,
    K: Xorable<K>,
{
    // LHS
    L_i: N,
    // RHS
    R_i: N,
    #[allow(dead_code)]
    Key: K,
}

#[allow(dead_code)]
impl<N, K> CipherState<N, K>
where
    N: Xorable<N> + core::fmt::Debug,
    K: Xorable<K>,
{
    #[allow(non_snake_case)]
    pub fn new(L_i: N, R_i: N, Key: K) -> Self {
        return Self { L_i, R_i, Key };
    }

    pub fn update(&mut self, left: N, right: N) {
        self.L_i = left;
        self.R_i = right;
    }

    // Let F be the round function and let K_0,K_1,...,K_n be the sub-keys for the rounds 0,1,...,n
    // respectively. Then the basic construction is as follows:
    //
    // 1. Split the plaintext block into two equal pieces (L_0, R_0).
    // 2. For each round i = 0,1,...,n compute
    //     a. L_{i+1}=R_i,
    //     b. R_{i+1}=L_i XOR F(R_i, K_i)
    // 3. Then the ciphertext is (R_{n+1}, L_{n+1})
    //
    // TODO: use real keys and generate subkeys per unique round
    pub fn compute_next_state<F>(&mut self, k: K, rounds: usize)
    where
        F: Function<N, K>,
    {
        let (mut left, mut right) = (self.L_i, self.R_i);
        log::debug!("splitting input on left and right");

        for i in 0..rounds {
            log::debug!("entering round {}", i);
            let temp = left;
            left = right ^ F::do_func(left, k);
            right = temp;
        }

        log::debug!("new-state: left -> {:?} right -> {:?}", left, right);
        self.update(left, right);
    }

    pub fn compute_next_state_with_keyschedule<F, S>(&mut self, k: &mut S, rounds: usize)
    where
        F: Function<N, K>,
        S: crate::crypto::keys::KeyScheduler<K>,
    {
        let (mut left, mut right) = (self.L_i, self.R_i);

        for _ in 0..rounds {
            // compute round key
            let round_key = k.next_key();
            let temp = left;
            left = right ^ F::do_func(left, round_key);
            right = temp;
        }

        self.update(left, right);
    }

    pub fn invert<F>(&mut self, k: K, rounds: usize)
    where
        F: Function<N, K>,
    {
        let (mut left, mut right) = (self.L_i, self.R_i);

        for _ in 0..rounds {
            let temp = right;
            right = left ^ F::do_func(right, k);
            left = temp;
        }

        self.update(left, right);
    }

    pub fn invert_with_keyschedule<F, S>(&mut self, k: &mut S, rounds: usize)
    where
        F: Function<N, K>,
        S: crate::crypto::keys::KeyScheduler<K>,
    {
        let (mut left, mut right) = (self.L_i, self.R_i);

        for _ in 0..rounds {
            let round_key = k.next_key();
            let temp = right;
            right = left ^ F::do_func(right, round_key);
            left = temp;
        }

        self.update(left, right);
    }
}

pub trait Function<N, K>
where
    N: Xorable<N>,
    K: Xorable<K>,
{
    fn do_func(data: N, key: K) -> N;
}

pub struct NaiveWrappingAdd<N, K>
where
    N: Xorable<N> + WrappingAdd,
    K: Xorable<K>,
{
    _n: N,
    _k: K,
}

impl<N, K> NaiveWrappingAdd<N, K>
where
    N: Xorable<N> + WrappingAdd,
    K: Xorable<K>,
{
}

impl Function<u128, u128> for NaiveWrappingAdd<u128, u128>
where
    u128: Xorable<u128> + WrappingAdd,
{
    fn do_func(data: u128, key: u128) -> u128 {
        return data.wrapping_add(key);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        pretty_env_logger::try_init().ok();

        let pt = (0x12345678u128, 0x9abcdef0u128);
        let k = 0xdeadbeefu128;
        let mut state = CipherState::<u128, u128>::new(pt.0, pt.1, k);
        log::info!("original state: {:?}", (state.L_i, state.R_i));
        let rounds = 64;

        state.compute_next_state::<NaiveWrappingAdd<u128, u128>>(k, rounds);
        let encrypted = (state.L_i, state.R_i);
        log::info!("state after {} rounds: {:?}", rounds, encrypted);

        state.invert::<NaiveWrappingAdd<u128, u128>>(k, rounds);
        let decrypted = (state.L_i, state.R_i);
        log::info!("state after inverting: {:?}", decrypted);

        assert_eq!(decrypted, pt, "Decrypted text should match the original");
    }
}
