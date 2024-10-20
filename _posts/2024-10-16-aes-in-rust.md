---
title: AES In Rust
date: 2024-10-16 23:58:00 +01:00
categories: [encryption]
tags: [math, security, rust]
math: true
comments: true
image:
  path: /assets/img/common/aes-encryption.jpg
  alt: Logo of a computer motherboard with a padlock across it
---

## Intro 
AES ( advanced encryption standard ) also known as Rijndael is a specification for the encryption of electronic data established by the US National institute of standards and technology NIST in 2001.
AES is a block cipher with a block size of 128 bits that supports 3 key sizes of length 128, 192 and 256 bits.
AES is being used by most militaries around the world and for most encryption needs including ssh.

## Project Goal
In this tutorial we will be implementing 128 Bit AES
> Do not use any unaudited encryption in production for a secure and tested alternative use [Aes-Gcm](https://crates.io/crates/aes-gcm)
{: .prompt-danger }

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
The SBOX ( substituon box ) is a bijective map that maps each input byte to a corrosponding output byte below is this substitution box that is computed in such a way that it adds nonlinearity thus significantly improving resilliance to linear and differential cryptoanalysis attacks.
```rust
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,0x16]
```
here is the rust code which mutably iterates over the block substituting each byte for the corrosponding output value defined by the sbox
```rust
fn sub_bytes(state: &mut [u8;16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}
```

# Shift Rows
the **shift rows** operation can be represented as a map $$ M $$, which transforms a $$ 4 \times 4 $$ matrix as follows:
$$
M : \mathbb{B}^{4 \times 4} \to \mathbb{B}^{4 \times 4}
$$

Where:
- $$ \mathbb{B} $$ is the set of bytes  $$ \mathbb{B} = \{0,1\}^8 $$.

The map M takes a matrix:

$$ 
\begin{bmatrix} 
b_0 & b_4 & b_8 & b_{12} \\
b_1 & b_5 & b_9 & b_{13} \\
b_2 & b_6 & b_{10} & b_{14} \\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}
$$

and transforms it cyclicly by shifting the rows, this is shown below

$$
M\left(\begin{bmatrix} 
b_0 & b_4 & b_8 & b_{12} \\
b_1 & b_5 & b_9 & b_{13} \\
b_2 & b_6 & b_{10} & b_{14} \\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}\right)
=
\begin{bmatrix} 
b_0 & b_4 & b_8 & b_{12} \\
b_5 & b_9 & b_{13} & b_1 \\
b_{10} & b_{14} & b_2 & b_6 \\
b_{15} & b_3 & b_7 & b_{11}
\end{bmatrix}
$$

this helps increase the complexity of the cipher by ensuring the influence of each byte is spread across multiple columns
this combined with the function mix_cols which will be covered later helps contribute to the diffusion of the cipher

below i have written this transformation in rust
```rust
fn shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}
```
this works by passing a mutable referance the block in its current state and creating a temporary copy where the values can be read from and assigned to the state
which changes it in place

# Mix Cols
The **mix cols** operation can be represented as another linear transformation that is applied to each column $$ P $$ which maps a $$ 4 \times 1 $$ matrix as follows
$$
P : \mathbb{B}^{4 \times 1} \to \mathbb{B}^{4 \times 1}
$$

Where:
- $$ \mathbb{B} $$ is the set of bytes  $$ \mathbb{B} = \{0,1\}^8 $$.

The map $ P $ takes a matrix:

$$ 
\begin{bmatrix} 
b_0 \\
b_1 \\
b_2 \\
b_3
\end{bmatrix}
$$

and transforms it by multiplying it with another matrix in the finite field $$ GF(2^8) $$ before we show how this function works we will first cover this field

### $ GF(2^8) $ Galios Field
- $ GF(2^8) $ is a finite field with $ 2^8 $ elements 
- The elements of this field are 8 bit numbers (bytes) represented as binary polynomials
- Addition in $ GF(2^8) $ is defined as bitwise XOR between two bytes as $ a \oplus b $
- Multiplication in $ GF(2^8) $ involves standard polynomial multiplication followed by a reduction moduolo an irreducible polynomial of degree 8 one such polynomial is $ x^8 + x^4 + x^3 +x + 1 $

### Example in $ GF(2^8) $
we will now show the multiplication of 255 by 3 in $ GF(2^8) $

$ 255 \oplus 3  $

We will now write each in its polynomial from

$ 255 = x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1 $

$ 3 = x + 1 $

We can now calculate this with polynomial multiplication 

$ (x^7+x^6+x^5+x^5+x^4+x^3+x^2+x+1)(x+1) = x^8+x^7+x^6+x^5+x^4+x^3+x^2+x+x^7+x^6+x^5+x^4+x^3+x^2+x^1+1 $

We can now rearange this and use the fact that $ x^n \oplus x^n = 0 $

$ x^8 + (x^7\oplus x^7) +(x^6\oplus x^6)+(x^5\oplus x^5)+(x^4\oplus x^4)+(x^3\oplus x^3)+(x^2\oplus x^2)+(x^1\oplus x^1) + 1 $

Thus giving us

$ x^8 + 1 $

But this does not belong to the field $ GF(2^8) $ so we must reduce modulo the polynomial 

$ x^8+x^4+x^3+x^1+1 $

we can use the fact that 

$ x^8 \equiv x^4 + x^3 + x^1 + 1\space(mod x^8+x^4+x^3+x^1) $

to rewrite our result giving us

$ x^4 + x^3 +x^1 + 1 + 1 $

then simplifying using additivng property to give us

$ x^4+x^3+x^1+(1 \oplus 1) = x^4+x^3+x $

This is equivilant to $ 0b00011010 $ which is $ 26 $

thus giving us the following result

$ 255 \cdot 3 = 26 $ in $ GF(2^8) $

> The operators + and $ \oplus $ are interchangable ans used only to clarify when XOR is being used
{: .prompt-info }

### Back to Transformation
now that we have coverd the finite field $ GF(2^8) $ we can continue to implement the transformation $ P : \mathbb{B}^{4 \times 1} \to \mathbb{B}^{4 \times 1} $
where $ P(c_i) = Mc_i $  where i is the column index and M is defined as follows

$$
M = \begin{pmatrix}
2 & 3 & 1 & 1 \\
1 & 2 & 3 & 1 \\
1 & 1 & 2 & 3 \\
3 & 1 & 1 & 2
\end{pmatrix}
$$






