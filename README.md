We provide two ways to deploy and run our system. The first one uses Docker to run our system where you can pull our image mengling333666/meng:escrow, and then you can directly run our system without installing OpenSSL and compiling our code. The second one provides the detailed steps for you to directly deploy our system to your OS.

## Docker
1. Install Docker. Official guideline (https://docs.docker.com/get-docker/)
2. Pull our image.
```
    docker pull mengling333666/meng:escrow
```
4. Run the container.
```
    docker run -it mengling333666/meng:escrow /bin/bash
```
6. Run our protocol.
```
    cd /home/Escrow-protocol/PGC_openssl/build
    ./test_escrow_protocol
```
## Direct Deployent 

### Specifications

- OS: Linux x64, MAC OS x64

- Language: C++

- Requires: OpenSSL

- The default elliptic curve is "NID_secp256k1"


### Installation

The current implementation is based on OpenSSL library. See the installment instructions of OpenSSL as below:  

1. Clone the code [openssl-master](https://github.com/openssl/openssl.git)

```
    git clone https://github.com/openssl/openssl.git
```

2. install openssl on your machine

```
    ./config --prefix=/usr/local/ssl shared
    make 
    sudo make install
    export OPENSSL_ROOT_DIR=/usr/local/ssl/
```


### Testing


To compile and test the system, do the following: 

```
  $ cd {PATH}/Escrow-protocol/PGC_openssl/
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ ./test_escrow_protocol
```



