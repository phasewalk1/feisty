# feisty
Generic Feistel ciphers

## Forewarning
The following code has been written only in purpose of furthering my understanding of [Feistel Ciphers](https://en.wikipedia.org/wiki/Feistel_cipher), and is not audited nor guaranteed to be _correct_. In other words, 
it wasn't developed to be used by anybody, i.e., don't roll this crypto.

## Construction
_Feistel_ ciphers (or _Fiestel networks_) are a permutation component utilized by many block ciphers, from DES to newer ones such as [Cemillia](https://en.wikipedia.org/wiki/Camellia_(cipher)) and [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)).
Feistel ciphers are good on bare metal because their entire substitution-permutation network is guaranteed to be invertible, nearly halving the required circuit size. 

> <q>A Feistel network uses a round function, a function which takes two inputs – a data block and a subkey – and returns one output of the same size as the data block.In each round, the round function is run on half of the data to be encrypted, and its output is 
XORed with the other half of the data. This is repeated a fixed number of times, and the final output is the encrypted data. An important advantage of Feistel networks compared to other cipher designs such as substitution–permutation networks is that the entire operation 
is guaranteed to be invertible (that is, encrypted data can be decrypted), even if the round function is not itself invertible. The round function can be made arbitrarily complicated, since it does not need to be designed to be invertible. Furthermore, 
the encryption and decryption operations are very similar, even identical in some cases, requiring only a reversal of the key schedule. Therefore, the size of the code or circuitry required to implement such a cipher is nearly halved. </q>
https://en.wikipedia.org/wiki/Feistel_cipher#Design

The construction is as follows:

### Encryption
Let $F$ be the round function, $\oplus$ denote the bitwise XOR operator, and let $K_0,K_1,...,K_n$ be the subkeys for the rounds $0,1,...,n$. Then the _forward_ operation is as follows,
1. Split the plaintext block into two equal pieces: $(L_0, R_0)$
2. For each round $i=0,1,...,n$ compute 
$$L_{i+1}=R_i$$
$$R_{i+1}=L_{i}\oplus F(R_i, K_i)$$
3. Output ciphertext: $(R_{n+1},L_{n+1}$

### Decryption
Since the substitution-permutation network is entirely invertible, decryption is trivial when in posession of $K$, and is computed as follows:
1. For $i=n,n-1,...,0$, compute
   $$R_i=L_{i+1},$$
   $$L_i=R_{i+1}\oplus F(L_{i+1},K_i)$$
2. Output plaintext: $(L_0,R_0)$

## What's Implemented
So far I've implemented the general encryption/decryption constructions over a generic `CipherState<N, K>` struct where `N: Xorable<N>` is a layer input type (e.g., `u32`, `u128`, etc.) and 
`K: Xorable<K>` is a similar type for determining key width (i.e., 64, 128, etc.). First by defining a simple interface for types we expect to operate on. Input data types need to be XORable, 
because we are going to XOR them against an output from $F$ (we add the additional paramater of `Add` so they are guaranteed to be addable in any $F$:
```Rust
pub trait Xorable<N>
where
    Self: BitXor<Output = N> + Add<Output = N> + Copy,
{
}

// We might implement this for the following types
impl Xorable<u32> for u32 {}
impl Xorable<u64> for u64 {}
impl Xorable<u128> for u128 {}
```
> [Xorable](https://github.com/phasewalk1/feisty/blob/master/src/prelude.rs#L4)
Round functions are easier to represent generically, since their requirements are simple. Let $F(x,k)$ be the round function such that $F:N\times K\rightarrow N$. So our interface becomes
```Rust
pub trait RoundFunction<N, K>
where
  N: Xorable<N>,
  K: Xorable<K>,
{
  fn f(x: N, k: K) -> N;
}
```
> [Function](https://github.com/phasewalk1/feisty/blob/master/src/prelude.rs#L123)

With these in place, we can construct a view of the `CipherState`, which contain $R_i$, $L_i$, and the round key $K_i$ (for reasons discussed later these are not being _scheduled_ yet and are instead static).
```Rust
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
```
> [CipherState](https://github.com/phasewalk1/feisty/blob/master/src/prelude.rs#L123)

To carry out the cipher, we follow the encryption construction as defined [above](https://github.com/phasewalk1/feisty/#readme#encryption), using the round function $F$ over $r$ rounds (as paramaterized by `compute_next_state`),
and where `invert` is the inverse construction which decrypts the ciphertext by reversing the permutations:

```Rust
impl<N, K> CipherState<N, K>
where
    N: Xorable<N> + core::fmt::Debug,
    K: Xorable<K>,
{
    pub fn update(&mut self, left: N, right: N) {
        self.L_i = left;
        self.R_i = right;
    }

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
}
```
> [impl CipherState](https://github.com/phasewalk1/feisty/blob/master/src/prelude.rs#L29)
