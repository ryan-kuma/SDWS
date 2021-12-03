#include "integer.h"
#include "eccrypto.h"
#include "osrng.h"
#include "oids.h"

#include <iostream>
#include <iomanip>

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    typedef DL_GroupParameters_EC<ECP> GroupParameters;
    typedef DL_GroupParameters_EC<ECP>::Element Element;

    AutoSeededRandomPool prng;    
    GroupParameters group;
    group.Initialize(ASN1::secp256k1());

    // private key
    Integer x(prng, Integer::One(), group.GetMaxExponent());
    Integer x1(prng, Integer::One(), group.GetMaxExponent());

    std::cout << "Private exponent:" << std::endl;
    std::cout << "  " << std::hex << x << std::endl;
    std::cout << "  " << std::hex << x1 << std::endl;
    
    // public key
    Element y = group.ExponentiateBase(x);
    Element y2 = group.ExponentiateBase(x);
	Integer yx = y.x;
	Integer yy = y.y;

    std::cout << "Public element:" << std::endl;
    std::cout << "  " << std::hex << yx << std::endl;
    std::cout << "  " << std::hex << yy << std::endl;
    std::cout << "  " << std::hex << y2.y << std::endl;
    
    // element addition
    Element u = group.GetCurve().Add(y, ECP::Point(2,3));

    std::cout << "Add:" << std::endl;
    std::cout << "  " << std::hex << u.x << std::endl;
    std::cout << "  " << std::hex << u.y << std::endl;

    // scalar multiplication
    Element v = group.GetCurve().ScalarMultiply(u, Integer::Two());

    std::cout << "Mult:" << std::endl;
    std::cout << "  " << std::hex << v.x << std::endl;
    std::cout << "  " << std::hex << v.y << std::endl;

    return 0;
}

