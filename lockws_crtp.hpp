#ifndef LOCKWS_MAIN_HEADER_HPP
#define LOCKWS_MAIN_HEADER_HPP

#ifdef USE_WOLFSSL
    // If the compiled with -DUSE_WOLFSSL, route to the wolfSSL variant
    #include "wolfssl/lockws_crtp.hpp"
#else
    // default fallback variant using standard openSSL
    #include "openssl/lockws_crtp.hpp"
#endif

#endif

