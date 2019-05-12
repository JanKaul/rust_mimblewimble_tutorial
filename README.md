
# Mimblewimble

## Resources:

### Software:
- Get rust at:
[www.rust-lang.org](https://www.rust-lang.org)
- Get jupyter notebook directly at [jupyter.org](https://www.jupyter.org) or through anaconda distribution at [anaconda.com](https://www.anaconda.com) 
- get rust jupyter kernel at [https://github.com/google/evcxr/blob/master/evcxr_jupyter/README.md](https://github.com/google/evcxr/blob/master/evcxr_jupyter/README.md) or run the code normally

### Mimblewimble

- "Official" mimblewimble implementation [https://github.com/mimblewimble/grin/blob/master/doc/intro.md](https://github.com/mimblewimble/grin/blob/master/doc/intro.md)
- Helpful article expleining mimblewimble [https://medium.com/@brandonarvanaghi/grin-transactions-explained-step-by-step-fdceb905a853](https://medium.com/@brandonarvanaghi/grin-transactions-explained-step-by-step-fdceb905a853)
- Aggregate schnorr signatures [https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/)

# Mimblewimble History

In __2013__ Adam Back proposes confidential transactions in his bitcointalk post "bitcoins with homomorphic value" [https://bitcointalk.org/index.php?topic=305791.0](https://bitcointalk.org/index.php?topic=305791.0)

In __Aug. 2016__, Someone called Tom Elvis Jedusor (Voldemort's French name in J.K. Rowling's Harry Potter book series) placed the original MimbleWimble white paper on a bitcoin research channel, and then disappeared.

Tom's white paper "Mimblewimble" (a tongue-tying curse used in "The Deathly Hallows") was a blockchain proposal that could theoretically increase privacy, scalability and fungibility.

In __Oct. 2016__, Andrew Poelstra, a mathematician at Blockstream, wrote a precise paper, made precise Tom's original idea, and added further scaling improvements on it.

A __few days later__, Ignotus Peverell (name also came from "Harry Potter", the original owner of the invisibility cloak, if you know the Harry Potter characters) started a Github project called Grin, and began turning the MimbleWimble paper into something real.

And in __Mar. 2017__, Ignotus Peverell posted a technical introduction to MimbleWimble and Grin on Github.

# Mimblewimble deepdive


```Rust
:dep curve25519-dalek = "1.1.3"
rand = "0.6.5"
sha2 = "0.8.0"
```


```Rust
extern crate curve25519_dalek;
extern crate rand;
extern crate sha2;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::prelude::*;

use sha2::{Sha256, Digest};

let mut rng = rand::thread_rng();
```

## Discrete logarithm problem

![11hrclock](img/11hrclock.png)

- given the Generator _G = 3_ and the point _P = 2_ (publlic key) it is extremely difficult (assuming large numbers) to get the multiplicator _r_ (private key) that satisfies

<div align="center">_P = r*G_</div>

- however, knowing _r_ it is easy to compute _P_

## Schnorr signatures

- private key _r_, public key _U_ with

<div align="center">_U = r*G_</div>
 
- signer generates random nonce _rt_ and computes commitment to nonce

<div align="center">_Ut = rt*G_</div>

- using challenge _c=H(m,Ut)_ (challenge has to be unique for message _m_ and nonce _rt_) signer computes

<div align="center">_rz = rt + c*r_</div>

- signer sends _(Ut,rz)_ to verifier
- verifier checks

<div align="center">_rz\*G = Ut + c\*U_</div>

- which can be expressed as

<div align="center">_rz\*G = rt\*G + c\*r\*G_</div>


```Rust
//get generator for the elliptic curve points
let G = &constants::RISTRETTO_BASEPOINT_POINT;

//pick arbitrary private key
let r = Scalar::from_bytes_mod_order([2u8;32]);

//compute public key
let U = r*G;

//generate random nonce, has to be different every time
let mut temp: [u8;32] = [0u8;32];
temp.copy_from_slice((0..32).map(|x| rng.gen()).collect::<Vec<u8>>().as_slice());
let rt = Scalar::from_bytes_mod_order(temp);

//calculate commitment to nonce
let Ut = rt*G;

//generate challenge from hashfunction
let mut hasher = Sha256::new();
hasher.input("message".as_bytes());
hasher.input(Ut.compress().to_bytes());
temp.copy_from_slice(hasher.result().as_slice());
let c = Scalar::from_bytes_mod_order(temp);

let rz = rt + c*r;

//check whether signature is valid
assert_eq!(rz*G,Ut+c*U);

(rz*G).compress()
```




    CompressedRistretto: [8, 158, 9, 191, 193, 55, 46, 52, 105, 36, 247, 76, 240, 44, 189, 9, 235, 155, 219, 109, 132, 235, 218, 85, 130, 122, 216, 34, 47, 223, 248, 50]



## Simple aggregate schnorr signatures (insecure!!!)

- two signers with private keys _r1,r2_ and public keys _U1,U2_ with

<div align="center">_U1 = r1\*G,&nbsp; &nbsp; U2 = r2\*G_</div>
 
- signers generate random nonces _rt1,rt2_ and compute commitments to the nonces

<div align="center">_Ut1 = rt1\*G,&nbsp; &nbsp; Ut2 = rt2\*G_</div>

- using challenge _c=H(m,Ut1+Ut2,U1+U2)_ (this is insecure!!!, see secure version [here](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/)) signers compute

<div align="center">_rz1 = rt1 + c\*r1,&nbsp; &nbsp; rz2 = rt2 + c\*r2 _</div>

- signers send _(Ut1,rz1),(Ut2,rz2)_ to verifier
- verifier checks

<div align="center">_rz\*G = Ut + c\*U_</div>
<div align="center">_(rz1 + rz2)\*G = (Ut1 + Ut2) + c\*(U1 + U2)_</div>

- aggregate signatures allow to simply add puplic keys and signatures

<div align="center">_U = U1 + U2_</div>

<div align="center">_(Ut,rz) = (Ut1 + Ut2, rz1 + rz2)_</div>


```Rust
//pick arbitrary private keys
let r1 = Scalar::from_bytes_mod_order([3u8;32]);
let r2 = Scalar::from_bytes_mod_order([4u8;32]);

//compute public key
let U1 = r1*G;
let U2 = r2*G;

//generate random nonces, has to be different every time
let mut temp: [u8;32] = [0u8;32];
temp.copy_from_slice((0..32).map(|x| rng.gen()).collect::<Vec<u8>>().as_slice());
let rt1 = Scalar::from_bytes_mod_order(temp);

let mut temp: [u8;32] = [0u8;32];
temp.copy_from_slice((0..32).map(|x| rng.gen()).collect::<Vec<u8>>().as_slice());
let rt2 = Scalar::from_bytes_mod_order(temp);

//calculate commitment to nonce
let Ut1 = rt1*G;
let Ut2 = rt2*G;

//generate challenge from hashfunction
let mut hasher = Sha256::new();
hasher.input("message".as_bytes());
hasher.input((Ut1+Ut2).compress().to_bytes());
hasher.input((U1+U2).compress().to_bytes());
temp.copy_from_slice(hasher.result().as_slice());
let c = Scalar::from_bytes_mod_order(temp);

let rz1 = rt1 + c*r1;
let rz2 = rt2 + c*r2;

let U = U1 + U2;
let rz = rz1 + rz2;
let Ut = Ut1 + Ut2;

//check whether signature is valid
assert_eq!(rz*G,Ut+c*U);

(rz*G).compress()
```




    CompressedRistretto: [20, 191, 153, 187, 99, 75, 9, 46, 236, 179, 225, 45, 246, 248, 146, 255, 119, 138, 46, 43, 221, 63, 135, 239, 95, 134, 112, 53, 88, 132, 63, 46]



## UTXO transactions

![img](img/utxo.png)

## Example transaction

- Alice has 100 tokens and wants to pay Bob 60
- with the UTXO model Alice will use her input _vi0 = 100_ to pay herself the output _vo0 = 40_ and Bob the output _vo1 = 60_
- no transactions fees apply
- in order to not generate money out of nothing, the inputs must equal the ouputs

<div align="center">_vi0 = vo0 + vo1_</div>


```Rust
let zeros: [u8;32] = [0u8;32];

let mut vi0 = zeros.clone();
vi0[0] = 100u8;
let vi0 = Scalar::from_bytes_mod_order(vi0);

let mut vo0 = zeros.clone();
vo0[0] = 40u8;
let vo0 = Scalar::from_bytes_mod_order(vo0);

let mut vo1 = zeros.clone();
vo1[0] = 60u8;
let vo1 = Scalar::from_bytes_mod_order(vo1);

//check whether input equals output
assert_eq!(vi0,vo0+vo1);

vi0
```




    Scalar{
    	bytes: [100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    }



## Hiding

- in order to obscure the values of the transaction, one can multiply every term by the point _H_ on an elliptic curve, this yields

<div align="center">_vi0\*H = vo0\* H + vo1\*H_</div>

- similar to the dlog problem, for people not knowing _vi0, vo0, vo1_ it is almost impossible to obtain them now
- however, the inputs must still equal the outputs


```Rust
//get point on the curve, it is important that the relation between G and H is unknown
let H = RistrettoPoint::random(&mut rng);

assert_eq!(vi0*H,vo0*H+vo1*H);

(vi0*H).compress()
```




    CompressedRistretto: [148, 138, 75, 242, 132, 118, 243, 252, 172, 167, 45, 58, 43, 109, 27, 219, 79, 196, 98, 124, 250, 28, 122, 169, 176, 46, 76, 113, 172, 125, 71, 121]



## Blinding

- the problem now is that, the people that transacted with you know the value of the transactions values and it gets easy for them to deduce your following transactions (if they know you have 100, they can try every combination below 100 to see what you spend on your next output)
- the aim is to replace every input and output by its corresponding pedersen commitment

<div align="center">_v\*H -> r\*G + v\*H_</div>

- where _r_ is called blinding factor and _G_ is another point on the curve
- every input and ouput has its own blinding factor
- in the context of mimblewimble _r_ can be thought of as a private key to the corresponding output and it is only known by the owner of that output

## Main idea:

- each participant uses the sum of his pedersen commitments for the outputs minus the sum of the pedersen commitments for the inputs as his public key

<div align="center">_U1 = (ro0\*G + vo0\*H) - (ri0\*G + vi0\*H)_</div>

<div align="center">_U2 = (ro1\*G + vo1*H)_</div>

- the private key for each participant is then the sum of the blinding factors of the outputs minus the inputs

<div align="center">_r1 = (ro0 - ri0)_</div>

<div align="center">_r2 = ro1_</div>

## Validating transactions

- public key for sender is sum of pedersen commitments (output - input)

<div align="center">_U1 = (ro0 - ri0)\*G + (vo0 - vi0)\*H_</div>

- public key of reciever is sum of pedersen commitments (output - input)

<div align="center">_U2 = ro1\*G + vo1\*H_</div>

- both generate random nonces _rt1,rt2_ and compute commitments to the nonces

<div align="center">_Ut1 = rt1\*G,&nbsp; &nbsp; Ut2 = rt2\*G_</div>

- using challenge _c=H(m,Ut1+Ut2,U1+U2)_ signers compute

<div align="center">_rz1 = rt1 + c\*(ro0 - ri0),&nbsp; &nbsp; rz2 = rt2 + c\*ro1 _</div>

- signers send _(Ut1,rz1),(Ut2,rz2)_ to verifier
- verifier checks

<div align="center">_(rz1 + rz2)\*G = (Ut1 + Ut2) + c\*(U1 + U2)_</div>

- which is equal to 

<div align="center">_(rz1 + rz2)\*G = (Ut1 + Ut2) + c\*((ro0 - ri0)\*G + (vo0 - vi0)\*H + ro1\*G + vo1\*H)_</div>

- if the following condition holds

<div align="center">_0 = vo0\* H - vi0\*H + vo1\*H_</div>

- this can be simplified to the valid aggregate schnorr signature

<div align="center">_(rz1 + rz2)\*G = (rt1\*G + rt2\*G) + c\*((ro0 - ri0)\*G + ro1\*G)_</div>

- vice versa, a valid signature means that the inputs and outputs cancel out


```Rust
//initialize the blinding factors

let mut ri0 = zeros.clone();
ri0[0] = 10u8;
let ri0 = Scalar::from_bytes_mod_order(ri0);

let mut ro0 = zeros.clone();
ro0[0] = 20u8;
let ro0 = Scalar::from_bytes_mod_order(ro0);

let mut ro1 = zeros.clone();
ro1[0] = 30u8;
let ro1 = Scalar::from_bytes_mod_order(ro1);

//compute public key
let U1 = (ro0 - ri0)*G + (vo0 - vi0)*H;
let U2 = ro1*G + vo1*H;

//generate random nonces, has to be different every time
let mut temp: [u8;32] = [0u8;32];
temp.copy_from_slice((0..32).map(|x| rng.gen()).collect::<Vec<u8>>().as_slice());
let rt1 = Scalar::from_bytes_mod_order(temp);

let mut temp: [u8;32] = [0u8;32];
temp.copy_from_slice((0..32).map(|x| rng.gen()).collect::<Vec<u8>>().as_slice());
let rt2 = Scalar::from_bytes_mod_order(temp);

//calculate commitment to nonce
let Ut1 = rt1*G;
let Ut2 = rt2*G;

//generate challenge from hashfunction
let mut hasher = Sha256::new();
hasher.input("message".as_bytes());
hasher.input((Ut1+Ut2).compress().to_bytes());
hasher.input((U1+U2).compress().to_bytes());
temp.copy_from_slice(hasher.result().as_slice());
let c = Scalar::from_bytes_mod_order(temp);

let rz1 = rt1 + c*(ro0 - ri0);
let rz2 = rt2 + c*ro1;

let U = U1 + U2;
let rz = rz1 + rz2;
let Ut = Ut1 + Ut2;

//check whether signature is valid
assert_eq!(rz*G,Ut+c*U);

(rz*G).compress()
```




    CompressedRistretto: [80, 4, 253, 149, 37, 77, 34, 116, 159, 148, 142, 149, 228, 18, 226, 140, 193, 58, 114, 40, 56, 236, 154, 53, 229, 69, 85, 228, 63, 255, 154, 50]

