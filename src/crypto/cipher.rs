#![allow(dead_code)]

use crate::crypto::round_function::RoundFunction;
use crate::prelude::{Block128, Block256, SplitBlock256};

#[allow(non_snake_case)]
pub struct CipherState256 {
    L_i: Block128,
    R_i: Block128,
    K_i: Block128,
}

#[allow(non_snake_case)]
impl CipherState256 {
    pub fn new(data: Block256, K_i: Block128) -> Self {
        let (L_i, R_i) = SplitBlock256::from(data);
        return Self { L_i, R_i, K_i };
    }

    pub fn update_state(&mut self, L_i: Block128, R_i: Block128) {
        self.L_i = L_i;
        self.R_i = R_i;
    }

    // F only operates on half of the input block for each state change,
    // so if the input block is 256-bits, the function takes as input only one half of it,
    // i.e., a Block128
    pub fn encrypt_with<F>(&mut self, K_i: Block128, r: usize)
    where
        // This is a round function that is defined by 
        //   F: Block128 x Block128 --> Block128
        // In other words, it operates on either side of a 256-bit input block, using a 
        // 128-bit key and outputs a 128-bit block.
        F: RoundFunction<Block128, Block128>,
    {
        let (mut left, mut right) = (self.L_i, self.R_i);

        for _ in 0..r {
            let temp = left;
            left = right ^ F::f(left, K_i);
            right = temp;
        }

        self.update_state(left, right);
    }

    pub fn decrypt_with<F>(&mut self, K_i: Block128, r: usize)
    where
        F: RoundFunction<Block128, Block128>,
    {
        let (mut left, mut right) = (self.L_i, self.R_i);

        for _ in 0..r {
            let temp = right;
            right = left ^ F::f(right, K_i);
            left = temp;
        }

        self.update_state(left, right);
    }
}
