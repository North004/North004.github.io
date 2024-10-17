---
title: AES In Rust
date: 2024-10-16 23:58:00 +01:00
categories: [encryption]
tags: [math, security, rust]
math: true
comments: true
---

## Intro 
AES ( advanced encryption standard ) also known as Rijndael is a specification for the encryption of electronic data established by the US National institute of standards and technology NIST in 2001.
AES is a block cipher with a block size of 128 bits that supports 3 key sizes of length 128, 192 and 256 bits.
AES is being used by most militaries around the world and for most encryption needs including ssh.

## Project Goal
In this tutorial we will be implementing 128 Bit AES

## Overview 
Aes encryption can be seperated into 4 steps allowing us to easier understand the problem.
1. Generating Round Keys
2. Adding Round Key to block
3. For each round (except last)
 - Substitute Block Bytes with Sbox Values
 - Shift the rows of the Block
 - Mix the Columns
 - Add Round Key to Block
4. Final Round(no mix cols)
 - Add Round Key to block
 - Shift the rows of the block
 - Add round key to block

 As we can see here there are likley to be some functions which we will need to implement such as 
 - sub_bytes()
 - shift_rows()
 - mix_cols()
 - add_round_keys() 
 - generate_round_keys()
 
 In the next step you will learn to implement these functions , aswell as understandnig what they do and any maths required to understand it.

## Sub Bytes
```rust
fn sub_bytes(state: &mut [u8;16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}
```

$$
\begin{bmatrix}
67 & 68 & 69 & 83 \\
68 & 92 & 91 & 92 \\
91 & 78 & 99 & 67 \\
67 & 85 & 67 & 65
\end{bmatrix}
$$

```rust
fn main() {
    let data = String::from("Hello This is a string");
    println!("{:?}",data);
}
```
