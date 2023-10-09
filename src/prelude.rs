use core::ops::{Add, BitXor};
use arrayref::array_ref;

// Types which are xorable
pub trait Xorable<N>
where
    Self: Sized + BitXor<Output = N>,
{
}

impl Xorable<u16> for u16 {}
impl Xorable<u32> for u32 {}
impl Xorable<u64> for u64 {}
impl Xorable<u128> for u128 {}

pub trait Block {}

pub struct Block256 {
    pub data: [u8; 32],
}

impl Block for Block256 {}

impl Block256 {
    pub fn new(data: [u8; 32]) -> Self {
        Self { data }
    }
}

impl From<[u8; 32]> for Block256 {
    fn from(value: [u8; 32]) -> Self {
        Self { data: value }
    }
}

#[derive(Clone, Copy)]
pub struct Block128 {
    pub data: [u8; 16],
}

impl Block for Block128 {}

impl Block128 {
    pub fn wrapping_add(&self, other: &Self) -> Self {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = self.data[i].wrapping_add(other.data[i]);
        }
        Block128 { data: result }
    }
}

impl BitXor for Block128 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = self.data[i] ^ rhs.data[i];
        }

        Self { data: result }
    }
}

pub type SplitBlock256 = (Block128, Block128);

impl From<Block256> for SplitBlock256 {
    // Splits a Block256 into LHS and RHS parts
    fn from(value: Block256) -> Self {
        let left = array_ref!(value.data, 0, 16).clone();
        let right = array_ref!(value.data, 16, 16).clone();

        (Block128 { data: left }, Block128 { data: right })
    }
}
