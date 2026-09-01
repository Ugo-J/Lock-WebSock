#ifndef LOCKWS_PM_CRTP_MAIN_HEADER_HPP
#define LOCKWS_PM_CRTP_MAIN_HEADER_HPP

#ifdef USE_WOLFSSL
    // If the compiled with -DUSE_WOLFSSL, route to the wolfSSL variant
    #include "wolfssl/lockws_pm_crtp.hpp"
#else
    // default fallback variant using standard openSSL
    #include "openssl/lockws_pm_crtp.hpp"
#endif

#endif
