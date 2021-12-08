# SDWS
A Secure Distributed Watchtower Scheme Based on Schnorr Threshold Signature
using muduo for network and crypro++ for encryption and signature

- install muduo
  git clone git@github.com:chenshuo/muduo.git
  cd muduo
  ./build.sh
  sudo cp ../build/release-cpp11/lib/libmuduo_base.a /usr/local/lib
  sudo cp ../build/release-cpp11/lib/libmuduo_net.a /usr/local/lib
  sudo cp -rf ./muduo /usr/local/include
- install cryptopp
  git clone git@github.com:weidai11/cryptopp.git
  cd cryptopp
  make libcryptopp.a
  sudo make install PREFIX=/usr/local
- build project
  make

### execute example

- ./server ip_port n k
  ./server 12358 10 3

- ./client server_ip server_ip_port

  ./client 127.0.0.1 12358
