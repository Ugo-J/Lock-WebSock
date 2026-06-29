#ifndef LOCKWS_MAIN_HEADER_HPP
#define LOCKWS_MAIN_HEADER_HPP

#ifdef USE_WOLFSSL
    // If the compiled with -DWOLFSSL, route to the wolfSSL variant
    #include "wolfssl/lockws.hpp"
#else
    // default fallback variant using standard openSSL
    #include "openssl/lockws.hpp"
#endif

#endif
