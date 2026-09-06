#pragma once

#include "lockws_pm_headers.hpp"
#include "lockws_structure_pm.hpp"

// use the following pragma declaration to suppress the shift overflow warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"

// constructor with url string
lock_client_pm::lock_client_pm(std::string_view url, int core, int read_chunk, int read_buffer_size){

    // initialisation of class wide variables
    if(!wolfssl_init){

        if(wolfSSL_Init() != WOLFSSL_SUCCESS){

            strncpy(error_buffer, "Failed to initialize wolfSSL core runtime.", error_buffer_array_length);
                
            error.store(true, std::memory_order_release);

        }
        
        if(!error.load(std::memory_order_acquire)){

            // we initialise our ssl ctx
            ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());

            if(!ssl_ctx){

                strncpy(error_buffer, "Context creation failed.", error_buffer_array_length);
                    
                error.store(true, std::memory_order_release);

            }

            // we load our system certificates
            int ca_ret = wolfSSL_CTX_load_system_CA_certs(ssl_ctx);

            if(ca_ret != WOLFSSL_SUCCESS){

                strncpy(error_buffer, "Failed to load system CA bundle.", error_buffer_array_length);

                error.store(true, std::memory_order_release);
            }

            // we pre allocate memory for io & general operations so we don't allocate during operations
            crypto_memory_pool = new(std::nothrow) unsigned char[CRYPTO_ARENA_SIZE];
            general_memory_pool = new(std::nothrow) unsigned char[CRYPTO_ARENA_SIZE];

            // now we set aside our static memory for our wolfssl ctx to use for io operations for ssl objects - we set the max number of session objects drawing from this pool to 1 in our last parameter
            if(crypto_memory_pool != nullptr){

                wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, crypto_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_IO_POOL, 1);

            }

            // load the general memory pool
            if(general_memory_pool != nullptr){

                wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, general_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_GENERAL, 1);

            }
            
            // seed the random number generator
            srand(std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch()).count());

            // we generate the static mask the library uses
            int upper_bound = 255;
                
            for(int j = 0; j<mask_array_len; j++){
            
                mask[j] = (unsigned char)(rand() % upper_bound);

            }

            // we only update our read buffer size if the supplied size is > our default buffer size and is a power of 2 else we leave the default read buffer size
            if(read_buffer_size > READ_BUFFER_SIZE && ((read_buffer_size & (read_buffer_size - 1)) == 0)) READ_BUFFER_SIZE = read_buffer_size;

            // we only update our read chunk if it is > our default read chunk
            if(read_chunk > READ_CHUNK_SIZE) READ_CHUNK_SIZE = read_chunk;

            // we allocate our read buffer
            read_buffer = new(std::nothrow) unsigned char[READ_BUFFER_SIZE];

            // we check that our read buffer was successfully allocated if it wasn't we set our error flag
            if(read_buffer != nullptr){

                // getting here our read buffer was successfully allocated so we start our poll_thread
                poll_thread = std::thread(&lock_client_pm::poll_read, this, core);

                // we wait till the poll thread sets its init flag before we continue because then we can check the error flag to know if the poll thread encountered any error while setting up
                while(!poll_init.load(std::memory_order_acquire));

            }
            else{

                // getting here our allocation of our read buffer was unsuccessful so we set our error flag to true
                strcpy(error_buffer, "Error Allocating Poll Read Buffer.");

                error.store(true, std::memory_order_release);

            }

        }
        
        wolfssl_init = true;
        
    }

    if(!error.load(std::memory_order_acquire)){
    
        // check if url is a wss:// endpoint, check case insensitively - for thw wolfssl client we only implement the wss client
        
        if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
        
            int protocol_prefix_len = strlen("wss://");

            // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
            size_t base_url_end_index = url.find('/', protocol_prefix_len);

            int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any
            
            // size of required memory in bytes to store the base url and the port number if it would be appended
            int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url

            // we create our ssl object
            c_ssl = wolfSSL_new(ssl_ctx);
        
            if(!error.load(std::memory_order_acquire)){ // the constructor continues only if there was no error fetching the ssl pointer

                // URL copy 
                if(req_mem < url_static_array_length){ // static memory large enough
                
                    url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
                
                    c_url_static[base_url_length] = '\0'; // null-terminate the string
                
                    c_url = c_url_static;
                
                }
                else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
                    
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
                
                    c_url_new[base_url_length] = '\0'; // null-terminate the string
                
                    c_url = c_url_new;
                    
                
                }
                else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
                    
                    if(c_url_new == NULL){ // memory has not yet been allocated
                        
                        c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                    
                        if(c_url_new == NULL){
                            
                            strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                            
                            error.store(true, std::memory_order_release);
                            
                        }
                        else{
                            
                            size_of_allocated_url_memory = req_mem;    
                                
                            url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                            c_url_new[base_url_length] = '\0';
                
                            c_url = c_url_new;
                        
                        }
                
                    }
                    else{ // memory has been allocated but still isn't large enough
                        
                        delete [] c_url_new; // delete the already allocated memory
                        
                        // heap memory allocation for urls larger than the static array length
                        c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                    
                        if(c_url_new == NULL){
                            
                            strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                            
                            error.store(true, std::memory_order_release);
                            
                        }
                        else{
                            
                            size_of_allocated_url_memory = req_mem;    
                                
                            url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                    
                            c_url_new[base_url_length] = '\0';

                            c_url = c_url_new;
                        
                        }
                    
                    }

                }
                
                if(!error.load(std::memory_order_acquire)){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error
                    
                    // we check if the supplied url has the port number appended if not we append it
                    if(strchr(c_url, ':') == NULL){
                        strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                    }
            
                }
            
            }
        
        }
        else{ // not a valid/supported websocket endpoint
            
            strncpy(error_buffer, "Supplied URL parameter is not a valid/supported WebSocket endpoint", error_buffer_array_length);
                    
            error.store(true, std::memory_order_release);
            
        }
        
        if(!error.load(std::memory_order_acquire)){ // only continue if no error
            
            int search_start_index = 6; // we store the index where we would begin the host name search from, we start searching from after the wss:// protocol prefix

            // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
            size_t host_name_end_index = url.find_first_of(":/", search_start_index); // we start searching at the search_start_index - index 6 to bypass the wss:// protocol prefix length
            
            int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - search_start_index : (int)host_name_end_index - search_start_index;

            if(host_name_len < host_static_array_length){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, search_start_index);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if(host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
                url.copy(c_host_new, host_name_len, search_start_index);
            
                c_host_new[host_name_len] = '\0';
            
                c_host = c_host_new;
                
            }
            else{ // neither static or already allocated memory is large enough, we test the two possible cases
                
                if(c_host_new == NULL){ // memory has not been allocated yet 
                
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error.store(true, std::memory_order_release);    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, search_start_index);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;
            
                    }
                
                }
                else{ // memory has been allocated but it still isn't sufficient
                    
                    delete [] c_host_new; // delete the previously allocated memory
                    
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                    if(c_host_new == NULL){

                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error.store(true, std::memory_order_release);    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, search_start_index);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;

            
                    }
                
                }
                
            }
            
            if(!error.load(std::memory_order_acquire)){ // only continue if no error
            
                // we set the host name we wish to connect to for server name identification(SNI) if the websocket address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
                if(c_ssl != NULL){
                    
                    if(!wolfSSL_UseSNI(c_ssl, WOLFSSL_SNI_HOST_NAME, c_host, host_name_len)){
                    // we test the return value. wolfSSL_UseSNI returns 0 on error and 1 on success
                        
                        strncpy(error_buffer, "Error setting up Lock client for SNI TLS extension", error_buffer_array_length);
                            
                        error.store(true, std::memory_order_release);
                    
                    }
                    
                }
                
                if(!error.load(std::memory_order_acquire)){
                // only continue if no error
                
                    // we store the start index of the path from the supplied url - we search for the next forward slash after the last colon, that is the start of the path in the supplied url string view
                    size_t path_start_index = url.find('/', search_start_index);
                    
                    // we check if a forward slash was found after the last colon, if none was we connect to the default root path else the forward slash till the end of the url string is the path
                    std::string_view path = (path_start_index != std::string_view::npos) ? url.substr(path_start_index) : "/";

                    // copy the channel path parameter into the channel path array
                    int path_string_len = path.size();
                    
                    if(path_string_len < path_static_array_length){ // we can store the path in the static array if this condition is true
                        
                        path.copy(c_path_static, path_string_len); // copy the path into the static array
                        c_path_static[path_string_len] = '\0'; // null-terminate the array
                        
                        c_path = c_path_static;
                        
                    }
                    else if(path_string_len < size_of_allocated_path_memory){ // allocated memory is large enough
                        
                        path.copy(c_path_new, path_string_len); // copy the path into the allocated array
                        c_path_new[path_string_len] = '\0'; // null-terminate the array
                        
                        c_path = c_path_new;
                        
                    }
                    else{ // neither static or already allocated memory is large enough, we test the two possible cases 
                        
                        if(c_path_new == NULL){ //memory has not been allocated yet
                        
                            c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                        
                            if(c_path_new == NULL){
                            
                                strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                                
                                error.store(true, std::memory_order_release);
                                
                            }
                            else{ 
                                
                                size_of_allocated_path_memory = path_string_len + 1;
                                
                                path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                        
                                c_path_new[path_string_len] = '\0'; // null-terminate the array
                        
                                c_path = c_path_new;
                        
                            }
                            
                        }
                        else{ // memory has been allocated but is still not sufficient
                            
                            delete [] c_path_new; // delete already allocated memory
                            
                            c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                        
                            if(c_path_new == NULL){
                            
                                strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                                
                                error.store(true, std::memory_order_release);
                                
                            }
                            else{ 
                                
                                size_of_allocated_path_memory = path_string_len + 1;
                                
                                path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                        
                                c_path_new[path_string_len] = '\0'; // null-terminate the array
                        
                                c_path = c_path_new;
                        
                            }
                            
                        }
                        
                    }
                    
                    if(!error.load(std::memory_order_acquire)){ // only continue if no error

                        // we create a local char array to hold the port extracted from the url
                        const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
                        char c_port[MAX_CHAR_FOR_PORT];

                        // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

                        // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
                        std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

                        // we now copy the derived port into char array
                        int num_of_chars_copied = port.copy(c_port, port.size());

                        // we null terminate the c_port array
                        c_port[num_of_chars_copied] = '\0';

                        // we call our connect to server function with the interface parameters set to null
                        int sockfd = connect_to_server(c_host, c_port, nullptr, nullptr);
                        
                        if(!error.load(std::memory_order_acquire)){ // only continue if no error

                            // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                            wolfSSL_set_fd(c_ssl, sockfd);

                            // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                            int len;

                            while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                                
                                // we get the error message
                                int err = wolfSSL_get_error(c_ssl, len);

                                // we check if the wolfssl handle is still expecting a read or a write
                                if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                    continue;

                                }
                                else{

                                    // getting here we got a actual error so we set our error flag
                                    strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                                
                                    error.store(true, std::memory_order_release);

                                    // we break out of this loop
                                    break;

                                }

                            }

                            // upgrade the connection to websocket
                            
                            // fill the random bytes array with 16 random bytes between 0 and 255
                            int upper_bound = 255;
                            for(int i = 0; i < rand_byte_array_len; i++){
                                
                                rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                            }
                            
                            // we store our nonce array len in a local variable because we pass it to base 64 encode as a pointer and the function updates it
                            unsigned int tmp_array_len = nonce_array_len;
                            
                            // get the Base-64 encoding of the random number to give the value of the nonce
                            Base64_Encode_NoNl(rand_bytes, rand_byte_array_len, base64_encoded_nonce, &tmp_array_len);
                        
                            // request connection upgrade
                            int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                            char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                            int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                            
                            if(upgrade_request_len < upgrade_request_array_length){ // static array is large enough
                                
                                // build the upgrade request
                                strcpy(upgrade_request_static, "GET ");
                                strcat(upgrade_request_static, c_path);
                                strcat(upgrade_request_static, " HTTP/1.1\n");
                                strcat(upgrade_request_static, "Host: ");
                                strcat(upgrade_request_static, c_host);
                                strcat(upgrade_request_static, "\n");
                                strcat(upgrade_request_static, "Connection: Upgrade\n");
                                strcat(upgrade_request_static, "Pragma: no-cache\n");
                                strcat(upgrade_request_static, "Upgrade: websocket\n");
                                strcat(upgrade_request_static, "Sec-WebSocket-Version: 13\n");
                                strcat(upgrade_request_static, "Sec-WebSocket-Key: ");
                                strcat(upgrade_request_static, (const char*)base64_encoded_nonce);
                                strcat(upgrade_request_static, "\n\n");
                                // upgrade request build end 
                                
                                upgrade_request = upgrade_request_static;
                                
                            }
                            else if(upgrade_request_len < size_of_allocated_upgrade_request_memory){ // allocated memory large enough
                            
                                // build the upgrade request
                                strcpy(upgrade_request_new, "GET ");
                                strcat(upgrade_request_new, c_path);
                                strcat(upgrade_request_new, " HTTP/1.1\n");
                                strcat(upgrade_request_new, "Host: ");
                                strcat(upgrade_request_new, c_host);
                                strcat(upgrade_request_new, "\n");
                                strcat(upgrade_request_new, "Connection: Upgrade\n");
                                strcat(upgrade_request_new, "Pragma: no-cache\n");
                                strcat(upgrade_request_new, "Upgrade: websocket\n");
                                strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                strcat(upgrade_request_new, "\n\n");
                                // upgrade request build end 
                                
                                upgrade_request = upgrade_request_new;
                                
                            }
                            else{ // neither static nor allocated memory is large enough, we test both cases
                            
                                if(upgrade_request_new == NULL){ // memory has not been allocated yet
                                
                                    upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                                
                                    if(upgrade_request_new == NULL){
                                    
                                        strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                                        
                                        error.store(true, std::memory_order_release);
                                        
                                        reset(); // disconnect the underlying wolfssl object
                                        
                                    }
                                    else{
                                        
                                        size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                                        
                                        // build the upgrade request
                                        strcpy(upgrade_request_new, "GET ");
                                        strcat(upgrade_request_new, c_path);
                                        strcat(upgrade_request_new, " HTTP/1.1\n");
                                        strcat(upgrade_request_new, "Host: ");
                                        strcat(upgrade_request_new, c_host);
                                        strcat(upgrade_request_new, "\n");
                                        strcat(upgrade_request_new, "Connection: Upgrade\n");
                                        strcat(upgrade_request_new, "Pragma: no-cache\n");
                                        strcat(upgrade_request_new, "Upgrade: websocket\n");
                                        strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                        strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                        strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                        strcat(upgrade_request_new, "\n\n");
                                        // upgrade request build end 
                                
                                        upgrade_request = upgrade_request_new;
                                    
                                    }
                            
                                }
                                else{ // memory has previously been allocated for an upgrade request but it still isn't sufficient
                                    
                                    delete [] upgrade_request_new; // delete the previously allocated memory
                                    
                                    upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                            
                                    if(upgrade_request_new == NULL){
                                
                                        strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                                    
                                        error.store(true, std::memory_order_release);
                                        
                                        reset(); // disconnect the underlying wolfssl object
                                    
                                    }
                                    else{ 
                                    
                                        size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                                    
                                        // build the upgrade request
                                        strcpy(upgrade_request_new, "GET ");
                                        strcat(upgrade_request_new, c_path);
                                        strcat(upgrade_request_new, " HTTP/1.1\n");
                                        strcat(upgrade_request_new, "Host: ");
                                        strcat(upgrade_request_new, c_host);
                                        strcat(upgrade_request_new, "\n");
                                        strcat(upgrade_request_new, "Connection: Upgrade\n");
                                        strcat(upgrade_request_new, "Pragma: no-cache\n");
                                        strcat(upgrade_request_new, "Upgrade: websocket\n");
                                        strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                        strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                        strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                        strcat(upgrade_request_new, "\n\n");
                                        // upgrade request build end 
                            
                                        upgrade_request = upgrade_request_new;
                                
                                    }
                                    
                                }
                            
                            }
                        
                            if(!error.load(std::memory_order_acquire)){ // only continue if no error
                                
                                data_array = data_array_static;

                                // we send our upgrade request
                                while((len = wolfSSL_write(c_ssl, reinterpret_cast<const void*>(upgrade_request), strlen(upgrade_request))) <= 0){
                                
                                    // we get the error message
                                    int err = wolfSSL_get_error(c_ssl, len);

                                    // we check if the wolfssl handle is still expecting a write
                                    if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                                        continue;

                                    }
                                    else{

                                        // getting here we got a actual error so we set our error flag
                                        strncpy(error_buffer, "Error sending websocket upgrade request ", error_buffer_array_length);
                                    
                                        error.store(true, std::memory_order_release);

                                        // we break out of this loop
                                        break;

                                    }

                                }
                                
                                if(!error.load(std::memory_order_acquire)){

                                    // non blocking call to wolfssl read
                                    while((len = wolfSSL_read(c_ssl, data_array, static_data_array_length)) <= 0){
                                
                                        // we get the error message
                                        int err = wolfSSL_get_error(c_ssl, len);

                                        // we check if the wolfssl handle is still expecting a read
                                        if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                            continue;

                                        }
                                        else{

                                            // getting here we got a actual error so we set our error flag
                                            strncpy(error_buffer, "Error reading websocket upgrade response ", error_buffer_array_length);
                                        
                                            error.store(true, std::memory_order_release);

                                            // we break out of this loop
                                            break;

                                        }

                                    }

                                    if(!error.load(std::memory_order_acquire)){

                                        data_array[len] = '\0'; // null terminate the received bytes

                                        // test for the switching protocol header to confirm that the connection upgrade was successful
                                        char success_response[] = "HTTP/1.1 101 Switching Protocols";
                                        
                                        if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful

                                            // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                                            
                                            // build the SHA1 parameter
                                            strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                                            strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                                            // SHA1 parameter build end 
                                            
                                            // we create a sha context for computing our sha1 hash
                                            wc_Sha sha_context;

                                            // sha context init
                                            wc_InitSha(&sha_context);

                                            // we update our sha context with the data to be hashed
                                            wc_ShaUpdate(&sha_context, reinterpret_cast<const byte*>(SHA1_parameter), strlen(SHA1_parameter));

                                            wc_ShaFinal(&sha_context, SHA1_digest);

                                            // we store a copy of our local sec key array len
                                            tmp_array_len = local_sec_ws_accept_key_array_len;

                                            // base64 encode the SHA1 digest
                                            Base64_Encode_NoNl(SHA1_digest, size_of_SHA1_digest, reinterpret_cast<byte*>(local_sec_ws_accept_key), &tmp_array_len);
                                            
                                            // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                                            char key[] = "Sec";
                                            char* cursor = strtok(NULL, "\n");
                                            
                                            while(cursor != NULL){
                                            // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                                                
                                                // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                                                if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                                        
                                                    cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                                    
                                                    // compare server's response with our calculation
                                                    if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                                        
                                                        // we set our last read index and last write index to 0 so the poll thread ignores any messages from a previous connection and starts polling for messages from this connection
                                                        last_read.store(0, std::memory_order_release);
                                                        last_write.store(0, std::memory_order_release);

                                                        client_state.store(OPEN, std::memory_order_release);

                                                        break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                                            
                                                    }
                                                    else{
                                                        
                                                        strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                                            
                                                        reset(); // reset session and disconnect the underlying connection
                                                            
                                                        error.store(true, std::memory_order_release);
                                                            
                                                        break;
                                                            
                                                    }
                                                    
                                                }
                                                
                                                cursor = strtok(NULL, "\n");
                                                
                                            }
                                            
                                            if(cursor == NULL){
                                                
                                                // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                                                strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                                                
                                                reset(); // reset session and disconnect the underlying connection
                                                
                                                error.store(true, std::memory_order_release);
                                            
                                            }
                                            
                                        }
                                        else{ // upgrade unsuccessful
                                            
                                            strncpy(error_buffer, "Connection upgrade failed. Invalid path or url supplied", error_buffer_array_length);
                                            
                                            reset(); // reset session and disconnect the underlying connection
                                            
                                            error.store(true, std::memory_order_release);
                                            
                                        }
                                                            
                                        memset(data_array, '\0', len); // zero out the data array

                                        memset(upgrade_request, '\0', upgrade_request_len); // zero out the upgrade request array
                                        
                                    }
                                    
                                }
                        
                            }
                        
                        }
                    
                    }
        
                }
        
            }
        
        }

    }

}

// constructor that binds to a network interface
lock_client_pm::lock_client_pm(std::string_view url, in_addr* interface_address, char* interface_name, int core, int read_chunk, int read_buffer_size){

    // initialisation of class wide variables
    if(!wolfssl_init){

        if(wolfSSL_Init() != WOLFSSL_SUCCESS){

            strncpy(error_buffer, "Failed to initialize wolfSSL core runtime.", error_buffer_array_length);
                
            error.store(true, std::memory_order_release);

        }
        
        if(!error.load(std::memory_order_acquire)){

            // we initialise our ssl ctx
            ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());

            if(!ssl_ctx){

                strncpy(error_buffer, "Context creation failed.", error_buffer_array_length);
                    
                error.store(true, std::memory_order_release);

            }

            // we load our system certificates
            int ca_ret = wolfSSL_CTX_load_system_CA_certs(ssl_ctx);

            if(ca_ret != WOLFSSL_SUCCESS){

                strncpy(error_buffer, "Failed to load system CA bundle.", error_buffer_array_length);

                error.store(true, std::memory_order_release);
            }

            // we pre allocate memory for io & general operations so we don't allocate during operations
            crypto_memory_pool = new(std::nothrow) unsigned char[CRYPTO_ARENA_SIZE];
            general_memory_pool = new(std::nothrow) unsigned char[CRYPTO_ARENA_SIZE];

            // now we set aside our static memory for our wolfssl ctx to use for io operations for ssl objects - we set the max number of session objects drawing from this pool to 1 in our last parameter
            if(crypto_memory_pool != nullptr){

                wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, crypto_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_IO_POOL, 1);

            }

            // load the general memory pool
            if(general_memory_pool != nullptr){

                wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, general_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_GENERAL, 1);

            }
            
            // seed the random number generator
            srand(std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch()).count());

            // we generate the static mask the library uses
            int upper_bound = 255;
                
            for(int j = 0; j<mask_array_len; j++){
            
                mask[j] = (unsigned char)(rand() % upper_bound);

            }

            // we only update our read buffer size if the supplied size is > our default buffer size and is a power of 2 else we leave the default read buffer size
            if(read_buffer_size > READ_BUFFER_SIZE && ((read_buffer_size & (read_buffer_size - 1)) == 0)) READ_BUFFER_SIZE = read_buffer_size;

            // we only update our read chunk if it is > our default read chunk
            if(read_chunk > READ_CHUNK_SIZE) READ_CHUNK_SIZE = read_chunk;

            // we allocate our read buffer
            read_buffer = new(std::nothrow) unsigned char[READ_BUFFER_SIZE];

            // we check that our read buffer was successfully allocated if it wasn't we set our error flag
            if(read_buffer != nullptr){

                // getting here our read buffer was successfully allocated so we start our poll_thread
                poll_thread = std::thread(&lock_client_pm::poll_read, this, core);

                // we wait till the poll thread sets its init flag before we continue because then we can check the error flag to know if the poll thread encountered any error while setting up
                while(!poll_init.load(std::memory_order_acquire));

            }
            else{

                // getting here our allocation of our read buffer was unsuccessful so we set our error flag to true
                strcpy(error_buffer, "Error Allocating Poll Read Buffer.");

                error.store(true, std::memory_order_release);

            }

        }
        
        wolfssl_init = true;
        
    }
    
    if(!error.load(std::memory_order_acquire)){

        // check if url is a wss:// endpoint, check case insensitively

        if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
        
            int protocol_prefix_len = strlen("wss://");

            // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
            size_t base_url_end_index = url.find('/', protocol_prefix_len);

            int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any

            // size of required memory in bytes to store the base url and the port number if it would be appended
            int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url
            
            // URL copy 
            if(req_mem < url_static_array_length){ // static memory large enough
            
                url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
            
                c_url_static[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_static;
            
            }
            else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
            
                url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
            
                c_url_new[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_new;
                
            
            }
            else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not
                
                if(c_url_new == NULL){ // memory has not yet been allocated
                    
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error.store(true, std::memory_order_release);
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                        c_url_new[base_url_length] = '\0';
            
                        c_url = c_url_new;
                    
                    }
            
                }
                else{ // memory has been allocated but still isn't large enough
                    
                    delete [] c_url_new; // delete the already allocated memory
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error.store(true, std::memory_order_release);
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                        c_url_new[base_url_length] = '\0';

                        c_url = c_url_new;
                    
                    }
                
                }

            }

            if(!error.load(std::memory_order_acquire)){

                // we check if the supplied url has the port number appended if not we append it
                if(strchr(c_url, ':') == NULL){
                    strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                }

                // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
                size_t host_name_end_index = url.find_first_of(":/", protocol_prefix_len); // we start searching at the protocol_prefix_len - index 6 to bypass the wss:// protocol prefix length
                
                int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - protocol_prefix_len : (int)host_name_end_index - protocol_prefix_len;

                if(host_name_len < host_static_array_length){ // static array is large enough
                
                    url.copy(c_host_static, host_name_len, protocol_prefix_len);
                
                    c_host_static[host_name_len] = '\0';
                
                    c_host = c_host_static;
                
                }
                else if(host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                    
                    url.copy(c_host_new, host_name_len, protocol_prefix_len);
                
                    c_host_new[host_name_len] = '\0';
                
                    c_host = c_host_new;
                    
                }
                else{ // neither static or already allocated memory is large enough, we test the two possible cases
                    
                    if(c_host_new == NULL){ // memory has not been allocated yet 
                    
                        c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                        if(c_host_new == NULL){
                    
                            strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                        
                            error.store(true, std::memory_order_release);    
                    
                        }
                        else{
                            
                            size_of_allocated_host_memory = host_name_len + 1;
                            
                            url.copy(c_host_new, host_name_len, protocol_prefix_len);
                
                            c_host_new[host_name_len] = '\0';
                
                            c_host = c_host_new;
                
                        }
                    
                    }
                    else{ // memory has been allocated but it still isn't sufficient
                        
                        delete [] c_host_new; // delete the previously allocated memory
                        
                        c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail

                        if(c_host_new == NULL){
                    
                            strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                        
                            error.store(true, std::memory_order_release);    
                    
                        }
                        else{
                            
                            size_of_allocated_host_memory = host_name_len + 1;
                            
                            url.copy(c_host_new, host_name_len, protocol_prefix_len);
                
                            c_host_new[host_name_len] = '\0';
                
                            c_host = c_host_new;
                
                        }
                    
                    }
                    
                }

                // we create a local char array to hold the port extracted from the url
                const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
                char c_port[MAX_CHAR_FOR_PORT];

                // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

                // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
                std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

                // we now copy the derived port into char array
                int num_of_chars_copied = port.copy(c_port, port.size());

                // we null terminate the c_port array
                c_port[num_of_chars_copied] = '\0';

                // now we can call the connect to server function that would return the configured socket file descriptor
                int sockfd = connect_to_server(c_host, c_port, interface_address, interface_name);

                if(!error.load(std::memory_order_acquire)){ // only continue if no error

                    // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                    wolfSSL_set_fd(c_ssl, sockfd);

                    // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                    int len;

                    while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                        
                        // we get the error message
                        int err = wolfSSL_get_error(c_ssl, len);

                        // we check if the wolfssl handle is still expecting a read or a write
                        if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                            continue;

                        }
                        else{

                            // getting here we got a actual error so we set our error flag
                            strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                        
                            error.store(true, std::memory_order_release);

                            // we break out of this loop
                            break;

                        }

                    }

                    // upgrade the connection to websocket
                    
                    // fill the random bytes array with 16 random bytes between 0 and 255
                    int upper_bound = 255;
                    for(int i = 0; i < rand_byte_array_len; i++){
                        
                        rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                    }
                    
                    // we store our nonce array len in a local variable because we pass it to base 64 encode as a pointer and the function updates it
                    unsigned int tmp_array_len = nonce_array_len;
                    
                    // get the Base-64 encoding of the random number to give the value of the nonce
                    Base64_Encode_NoNl(rand_bytes, rand_byte_array_len, base64_encoded_nonce, &tmp_array_len);
                
                    // request connection upgrade
                    int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                    char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                    int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                    
                    if(upgrade_request_len < upgrade_request_array_length){ // static array is large enough
                        
                        // build the upgrade request
                        strcpy(upgrade_request_static, "GET ");
                        strcat(upgrade_request_static, c_path);
                        strcat(upgrade_request_static, " HTTP/1.1\n");
                        strcat(upgrade_request_static, "Host: ");
                        strcat(upgrade_request_static, c_host);
                        strcat(upgrade_request_static, "\n");
                        strcat(upgrade_request_static, "Connection: Upgrade\n");
                        strcat(upgrade_request_static, "Pragma: no-cache\n");
                        strcat(upgrade_request_static, "Upgrade: websocket\n");
                        strcat(upgrade_request_static, "Sec-WebSocket-Version: 13\n");
                        strcat(upgrade_request_static, "Sec-WebSocket-Key: ");
                        strcat(upgrade_request_static, (const char*)base64_encoded_nonce);
                        strcat(upgrade_request_static, "\n\n");
                        // upgrade request build end 
                        
                        upgrade_request = upgrade_request_static;
                        
                    }
                    else if(upgrade_request_len < size_of_allocated_upgrade_request_memory){ // allocated memory large enough
                    
                        // build the upgrade request
                        strcpy(upgrade_request_new, "GET ");
                        strcat(upgrade_request_new, c_path);
                        strcat(upgrade_request_new, " HTTP/1.1\n");
                        strcat(upgrade_request_new, "Host: ");
                        strcat(upgrade_request_new, c_host);
                        strcat(upgrade_request_new, "\n");
                        strcat(upgrade_request_new, "Connection: Upgrade\n");
                        strcat(upgrade_request_new, "Pragma: no-cache\n");
                        strcat(upgrade_request_new, "Upgrade: websocket\n");
                        strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                        strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                        strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                        strcat(upgrade_request_new, "\n\n");
                        // upgrade request build end 
                        
                        upgrade_request = upgrade_request_new;
                        
                    }
                    else{ // neither static nor allocated memory is large enough, we test both cases
                    
                        if(upgrade_request_new == NULL){ // memory has not been allocated yet
                        
                            upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                        
                            if(upgrade_request_new == NULL){
                            
                                strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                                
                                error.store(true, std::memory_order_release);
                                
                                reset(); // disconnect the underlying wolfssl object
                                
                            }
                            else{
                                
                                size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                                
                                // build the upgrade request
                                strcpy(upgrade_request_new, "GET ");
                                strcat(upgrade_request_new, c_path);
                                strcat(upgrade_request_new, " HTTP/1.1\n");
                                strcat(upgrade_request_new, "Host: ");
                                strcat(upgrade_request_new, c_host);
                                strcat(upgrade_request_new, "\n");
                                strcat(upgrade_request_new, "Connection: Upgrade\n");
                                strcat(upgrade_request_new, "Pragma: no-cache\n");
                                strcat(upgrade_request_new, "Upgrade: websocket\n");
                                strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                strcat(upgrade_request_new, "\n\n");
                                // upgrade request build end 
                        
                                upgrade_request = upgrade_request_new;
                            
                            }
                    
                        }
                        else{ // memory has previously been allocated for an upgrade request but it still isn't sufficient
                            
                            delete [] upgrade_request_new; // delete the previously allocated memory
                            
                            upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                    
                            if(upgrade_request_new == NULL){
                        
                                strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                            
                                error.store(true, std::memory_order_release);
                                
                                reset(); // disconnect the underlying wolfssl object
                            
                            }
                            else{ 
                            
                                size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                            
                                // build the upgrade request
                                strcpy(upgrade_request_new, "GET ");
                                strcat(upgrade_request_new, c_path);
                                strcat(upgrade_request_new, " HTTP/1.1\n");
                                strcat(upgrade_request_new, "Host: ");
                                strcat(upgrade_request_new, c_host);
                                strcat(upgrade_request_new, "\n");
                                strcat(upgrade_request_new, "Connection: Upgrade\n");
                                strcat(upgrade_request_new, "Pragma: no-cache\n");
                                strcat(upgrade_request_new, "Upgrade: websocket\n");
                                strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                strcat(upgrade_request_new, "\n\n");
                                // upgrade request build end 
                    
                                upgrade_request = upgrade_request_new;
                        
                            }
                            
                        }
                    
                    }
                
                    if(!error.load(std::memory_order_acquire)){ // only continue if no error
                        
                        data_array = data_array_static;

                        // we send our upgrade request
                        while((len = wolfSSL_write(c_ssl, reinterpret_cast<const void*>(upgrade_request), strlen(upgrade_request))) <= 0){
                        
                            // we get the error message
                            int err = wolfSSL_get_error(c_ssl, len);

                            // we check if the wolfssl handle is still expecting a write
                            if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                                continue;

                            }
                            else{

                                // getting here we got a actual error so we set our error flag
                                strncpy(error_buffer, "Error sending websocket upgrade request ", error_buffer_array_length);
                            
                                error.store(true, std::memory_order_release);

                                // we break out of this loop
                                break;

                            }

                        }
                        
                        if(!error.load(std::memory_order_acquire)){

                            // non blocking call to wolfssl read
                            while((len = wolfSSL_read(c_ssl, data_array, static_data_array_length)) <= 0){
                        
                                // we get the error message
                                int err = wolfSSL_get_error(c_ssl, len);

                                // we check if the wolfssl handle is still expecting a read
                                if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                    continue;

                                }
                                else{

                                    // getting here we got a actual error so we set our error flag
                                    strncpy(error_buffer, "Error reading websocket upgrade response ", error_buffer_array_length);
                                
                                    error.store(true, std::memory_order_release);

                                    // we break out of this loop
                                    break;

                                }

                            }

                            if(!error.load(std::memory_order_acquire)){

                                data_array[len] = '\0'; // null terminate the received bytes

                                // test for the switching protocol header to confirm that the connection upgrade was successful
                                char success_response[] = "HTTP/1.1 101 Switching Protocols";
                                
                                if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful

                                    // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                                    
                                    // build the SHA1 parameter
                                    strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                                    strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                                    // SHA1 parameter build end 
                                    
                                    // we create a sha context for computing our sha1 hash
                                    wc_Sha sha_context;

                                    // sha context init
                                    wc_InitSha(&sha_context);

                                    // we update our sha context with the data to be hashed
                                    wc_ShaUpdate(&sha_context, reinterpret_cast<const byte*>(SHA1_parameter), strlen(SHA1_parameter));

                                    wc_ShaFinal(&sha_context, SHA1_digest);

                                    // we store a copy of our local sec key array len
                                    tmp_array_len = local_sec_ws_accept_key_array_len;

                                    // base64 encode the SHA1 digest
                                    Base64_Encode_NoNl(SHA1_digest, size_of_SHA1_digest, reinterpret_cast<byte*>(local_sec_ws_accept_key), &tmp_array_len);
                                    
                                    // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                                    char key[] = "Sec";
                                    char* cursor = strtok(NULL, "\n");
                                    
                                    while(cursor != NULL){
                                    // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                                        
                                        // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                                        if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                                
                                            cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                            
                                            // compare server's response with our calculation
                                            if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                                
                                                // we set our last read index and last write index to 0 so the poll thread ignores any messages from a previous connection and starts polling for messages from this connection
                                                last_read.store(0, std::memory_order_release);
                                                last_write.store(0, std::memory_order_release);

                                                client_state.store(OPEN, std::memory_order_release);

                                                break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                                    
                                            }
                                            else{
                                                
                                                strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                                    
                                                reset(); // reset session and disconnect the underlying connection
                                                    
                                                error.store(true, std::memory_order_release);
                                                    
                                                break;
                                                    
                                            }
                                            
                                        }
                                        
                                        cursor = strtok(NULL, "\n");
                                        
                                    }
                                    
                                    if(cursor == NULL){
                                        
                                        // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                                        strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                                        
                                        reset(); // reset session and disconnect the underlying connection
                                        
                                        error.store(true, std::memory_order_release);
                                    
                                    }
                                    
                                }
                                else{ // upgrade unsuccessful
                                    
                                    strncpy(error_buffer, "Connection upgrade failed. Invalid path or url supplied", error_buffer_array_length);
                                    
                                    reset(); // reset session and disconnect the underlying connection
                                    
                                    error.store(true, std::memory_order_release);
                                    
                                }
                                                    
                                memset(data_array, '\0', len); // zero out the data array

                                memset(upgrade_request, '\0', upgrade_request_len); // zero out the upgrade request array
                                
                            }
                            
                        }
                
                    }
                
                }
            }
        }
        else{ // not a valid/supported websocket endpoint
            
            strncpy(error_buffer, "Supplied URL parameter is not a valid/supported WebSocket endpoint", error_buffer_array_length);
                    
            error.store(true, std::memory_order_release);
            
        }

    }

}

// basic constructor
lock_client_pm::lock_client_pm(int core, int read_chunk, int read_buffer_size){
    
    // initialisation of class wide variables
    if(!wolfssl_init){

        if(wolfSSL_Init() != WOLFSSL_SUCCESS){

            strcpy(error_buffer, "Failed to initialize wolfSSL core runtime.");
                
            error.store(true, std::memory_order_release);

        }
        
        if(!error.load(std::memory_order_acquire)){

            // we initialise our ssl ctx
            ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());

            if(!ssl_ctx){

                strncpy(error_buffer, "Context creation failed.", error_buffer_array_length);
                    
                error.store(true, std::memory_order_release);

            }

            // we load our system certificates
            int ca_ret = wolfSSL_CTX_load_system_CA_certs(ssl_ctx);

            if(ca_ret != WOLFSSL_SUCCESS){

                strncpy(error_buffer, "Failed to load system CA bundle.", error_buffer_array_length);

                error.store(true, std::memory_order_release);
            }

            // we pre allocate memory for io & general operations so we don't allocate during operations
            crypto_memory_pool = new(std::nothrow) unsigned char[CRYPTO_ARENA_SIZE];
            general_memory_pool = new(std::nothrow) unsigned char[CRYPTO_ARENA_SIZE];

            // now we set aside our static memory for our wolfssl ctx to use for io operations for ssl objects - we set the max number of session objects drawing from this pool to 1 in our last parameter
            if(crypto_memory_pool != nullptr){

                wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, crypto_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_IO_POOL, 1);

            }

            // load the general memory pool
            if(general_memory_pool != nullptr){

                wolfSSL_CTX_load_static_memory(&ssl_ctx, NULL, general_memory_pool, CRYPTO_ARENA_SIZE, WOLFMEM_GENERAL, 1);

            }
            
            // seed the random number generator
            srand(std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch()).count());

            // we generate the static mask the library uses
            int upper_bound = 255;
                
            for(int j = 0; j<mask_array_len; j++){
            
                mask[j] = (unsigned char)(rand() % upper_bound);

            }

            // we only update our read buffer size if the supplied size is > our default buffer size and is a power of 2 else we leave the default read buffer size
            if(read_buffer_size > READ_BUFFER_SIZE && ((read_buffer_size & (read_buffer_size - 1)) == 0)) READ_BUFFER_SIZE = read_buffer_size;

            // we only update our read chunk if it is > our default read chunk
            if(read_chunk > READ_CHUNK_SIZE) READ_CHUNK_SIZE = read_chunk;

            // we allocate our read buffer
            read_buffer = new(std::nothrow) unsigned char[READ_BUFFER_SIZE];

            // we check that our read buffer was successfully allocated if it wasn't we set our error flag
            if(read_buffer != nullptr){

                // getting here our read buffer was successfully allocated so we start our poll_thread
                poll_thread = std::thread(&lock_client_pm::poll_read, this, core);

                // we wait till the poll thread sets its init flag before we continue because then we can check the error flag to know if the poll thread encountered any error while setting up
                while(!poll_init.load(std::memory_order_acquire));

            }
            else{

                // getting here our allocation of our read buffer was unsuccessful so we set our error flag to true
                strcpy(error_buffer, "Error Allocating Poll Read Buffer.");

                std::cout<<error_buffer<<std::endl;

                error.store(true, std::memory_order_release);

            }

        }
        
        wolfssl_init = true;
        
    }
    
}

// destructor
lock_client_pm::~lock_client_pm(){

    // we set our stop poll flag to stop the poll thread
    stop_poll.store(true, std::memory_order_release);
    
    // close the websocket connection if any
    if(client_state.load(std::memory_order_acquire) == OPEN){
        
        close();

    }

    // we join our poll thread if it is joinable
    if(poll_thread.joinable()) { poll_thread.join(); }
    
    // free url heap memory - this only runs if dynamic memory allocation is used to store the url
    if(c_url_new != NULL){
        
        delete [] c_url_new;
        
    }
    
    // free path heap memory if the path string was stored in dynamic memory
    if(c_path_new != NULL){
        
        delete [] c_path_new;
        
    }
    
    // free host heap memory if host string was stored in dynamic memory
    if(c_host_new != NULL){
        
        delete [] c_host_new;
        
    }
    
    // free upgrade request string heap memory if upgrade request string was stored in dynamic memory
    if(upgrade_request_new != NULL){
        
        delete [] upgrade_request_new;
        
    }
    
    if(c_ssl != NULL && c_url != NULL){
        
        wolfSSL_free(c_ssl); // frees the wolfssl object
    }
    
    if(send_data_new != NULL){
        
        delete [] send_data_new; // free the memory used if the send string is stored on the heap
        
    }
    
    if(data_array_new != NULL){
        
        delete [] data_array_new; // free the memory used to receive data
        
    }

    if(crypto_memory_pool != NULL){

        delete [] crypto_memory_pool;

    }

    if(general_memory_pool != NULL){

        delete [] general_memory_pool;

    }

    if(read_buffer != NULL){

        delete [] read_buffer;

    }
    
}

inline bool lock_client_pm::status(){ // returns the error status of a lock_client instance
    
    return error.load(std::memory_order_acquire);
    
}

inline char* lock_client_pm::get_error_message(){ // returns the error message: the reason why a lock_client instance's error flag is set
    
    return error_buffer;
    
}

inline bool lock_client_pm::is_open(){

    return client_state.load(std::memory_order_acquire) == OPEN ? true : false;
    
}

bool lock_client_pm::ping(){ // sends a ping on an established websocket connection
    
    if(!error.load(std::memory_order_acquire)){ // only continue if no error
        
        // we use memory order relaxed to check the client state because only the main thread can set the client state
        if(client_state.load(std::memory_order_relaxed) == OPEN){ // continue if client is in open state
            
            int i = 0; // variable for traversing the send data array
            
            send_data = (char*)send_data_static; // the send static array is always large enough to hold a ping frame
            
            send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | PING);
            i++;
            
            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)0x00); // ping frames usually have no data so the frame length is set to 0  
            i++;
                
            for(int j = 0; j<mask_array_len; j++){
                
                send_data[i] = mask[j]; // store the mask in the send data array
                    
                i++;
                    
            }
            // mask storing end 
            
            // block SIGPIPE signal before attempting to send data, just incase the connection is closed
            block_sigpipe_signal();
            
            int64_t len = 0;

            // keep polling till we have sent the entire frame
            while(len < i){

                int64_t local_len = wolfSSL_write(c_ssl, send_data, i - len);

                if(local_len > 0){

                    len += local_len;
                            
                    send_data += local_len;

                }
                else{

                    // we get the error message
                    int err = wolfSSL_get_error(c_ssl, local_len);

                    if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                        continue;

                    }
                    else{

                        // here wolfssl_read couldn't fetch any extra data
                        strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                        error.store(true, std::memory_order_release);
                        
                        unblock_sigpipe_signal();

                        fail_ws_connection(GOING_AWAY);
                        
                        // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                        // we return from this function
                        return error.load(std::memory_order_acquire);
                        
                    }

                }

            }

            // getting here all ping data has been sent

            unblock_sigpipe_signal();
            
        }
        else{ // set the error flag if lock client is not in open state
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
                
            error.store(true, std::memory_order_release);
            
        }
        
    }
    
    return error.load(std::memory_order_acquire);
    
}

bool lock_client_pm::pong(int ping_data_len){ // sends out a pong frame unsolicited or in response to a received ping frame
    
    if(!error.load(std::memory_order_acquire)){ // only continue if no error
        
        // we use memory order relaxed to check the client state because only the main thread can set the client state
        if(client_state.load(std::memory_order_relaxed) == OPEN){ // continue if client is in open state
            
            int i = 0; // variable for traversing the send data array
            
            send_data = (char*)send_data_static; // the send static array is always large enough to hold a ping frame
            
            send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | PONG);
            i++;
            
            send_data[i] = MASK_BIT_SET | ((unsigned char)ping_data_len); // pong frames usually have no data but if the ping frame has application data, identical data should be sent along with the pong frame
            i++;
                
            for(int j = 0; j<mask_array_len; j++){
            
                send_data[i] = mask[j]; // store the mask in the send data array
                    
                i++;

            }
            // mask storing end 
            
            // mask the pong application data if any and send as the pong application data
            int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
                
            for(int j = 0; j<ping_data_len; j++){
            
                k = j % 4;
                    
                send_data[i] = upgrade_request_static[j] ^ mask[k]; // received ping data if any, is stored in the upgrade request static array
                    
                i++;
                    
            }
            
            // block SIGPIPE signal before attempting to send data, just incase the connection is closed
            block_sigpipe_signal();
            
            int64_t len = 0;

            // keep polling till we have sent the entire frame
            while(len < i){

                int64_t local_len = wolfSSL_write(c_ssl, send_data, i - len);

                if(local_len > 0){

                    len += local_len;
                            
                    send_data += local_len;

                }
                else{

                    // we get the error message
                    int err = wolfSSL_get_error(c_ssl, local_len);

                    if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                        continue;

                    }
                    else{

                        // here wolfssl_read couldn't fetch any extra data
                        strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                        error.store(true, std::memory_order_release);
                        
                        unblock_sigpipe_signal();

                        fail_ws_connection(GOING_AWAY);
                        
                        // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                        // we return from this function
                        return error.load(std::memory_order_acquire);
                        
                    }

                }

            }

            // getting here the pong request send succeeds

            // we unblock the sigpipe signal
            unblock_sigpipe_signal();

            // we set the num_of_pings_received back to 0
            num_of_pings_received = 0;

            // zero out the upgrade request static array
            memset(upgrade_request_static, '\0', ping_data_len);
            
        }
        else{
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
                
            error.store(true, std::memory_order_release);
            
        }
        
    }
    
    return error.load(std::memory_order_acquire);
    
}

inline bool lock_client_pm::set_ping_backlog(int backlog_num){
    
    if(!error.load(std::memory_order_acquire)){ // only continue if no error
        
        // this can be set with a client in closed state
        ping_backlog = backlog_num;
        
    }
    
    return error.load(std::memory_order_acquire);
    
}

inline bool lock_client_pm::clear(){ // clear the error flag of a lock client in open state

    // we use memory order relaxed to check the client state because only the main thread can set the client state
    if(client_state.load(std::memory_order_relaxed) == OPEN){
    
        memset(error_buffer, '\0', strlen(error_buffer));
            
        error.store(false, std::memory_order_release);
            
    }
        
    return error.load(std::memory_order_acquire);
    
}

bool lock_client_pm::send(std::string_view payload_data){ // sends data passed as parameter along an established websocket connection

    if(!error.load(std::memory_order_acquire)){ // only continue if no error
        
        // we use memory order relaxed to check the client state because only the main thread can set the client state
        if(client_state.load(std::memory_order_relaxed) == OPEN){ // only continue if client is in open state
        
            int64_t payload_data_len = payload_data.size();
            int i = 0; // variable for traversing the send data array
            
            if((payload_data_len + biggest_header_len) < send_data_array_len){ // static array is large enough
                
                send_data = (char*)send_data_static;
                
                // set the first byte
                send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME);
                i++;
                
                // set the second byte
                if(payload_data_len < 126){ // if payload data length is less than 126 the next 7 bits represent the payload length
                
                    send_data[i] = MASK_BIT_SET | (unsigned char)payload_data_len;
                    i++;
                    
                }
                else if( (payload_data_len > 125) && (payload_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                    i++;
                    
                    send_data[i] = (0xFF00 & payload_data_len) >> 8;
                    i++;
                    
                    send_data[i] = 0x00FF & payload_data_len;
                    i++;
                    
                }
                else if( (payload_data_len > (MAX_2BYTE_INT - 1)) && (payload_data_len < (MAX_8BYTE_INT - 1)) ){
                // next byte stores the value 127 and he next 8 bytes store the payload length
                
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                    i++;
                    
                    send_data[i] = (0xFF00000000000000 & payload_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                    i++;
                    
                    send_data[i] = (0x00FF000000000000 & payload_data_len) >> 48;
                    i++;
                    
                    send_data[i] = (0x0000FF0000000000 & payload_data_len) >> 40;
                    i++;
                    
                    send_data[i] = (0x000000FF00000000 & payload_data_len) >> 32;
                    i++;
                    
                    send_data[i] = (0x00000000FF000000 & payload_data_len) >> 24;
                    i++;
                    
                    send_data[i] = (0x0000000000FF0000 & payload_data_len) >> 16;
                    i++;
                    
                    send_data[i] = (0x000000000000FF00 & payload_data_len) >> 8;
                    i++;
                    
                    send_data[i] = (0x00000000000000FF & payload_data_len); // no shift required
                    i++;
                    
                    
                }
                else{ // ERROR!! Data length too large - execution never gets here normally because the static send data array is only a few kilobytes long and the payload data would have to be > 2^64 bytes in length to get here which would already fail the outer if statement for being > static send data array, the code is just added for completeness
                
                    strncpy(error_buffer, "Send data length too large", error_buffer_array_length);
                    
                    error.store(true, std::memory_order_release);
                    
                }

                if(!error.load(std::memory_order_acquire)){ // only continue if no error
                    
                    for(int j = 0; j<mask_array_len; j++){
                    
                        send_data[i] = mask[j]; // store the mask in the send data array
                        
                        i++;
                        
                    }
                    // mask storing end 
                    
                    // mask the data and store the masked data in the send data array 
                    int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
                    
                    for(int j = 0; j<payload_data_len; j++){
                    
                        k = j % 4;
                        
                        send_data[i] = payload_data[j] ^ mask[k];
                        
                        i++;
                        
                    }
                    
                    // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                    block_sigpipe_signal();
                    
                    int64_t len = 0;

                    // keep polling till we have sent the entire frame
                    while(len < i){

                        int64_t local_len = wolfSSL_write(c_ssl, send_data, i - len);

                        if(local_len > 0){

                            len += local_len;
                                    
                            send_data += local_len;

                        }
                        else{

                            // we get the error message
                            int err = wolfSSL_get_error(c_ssl, local_len);

                            if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                                continue;

                            }
                            else{

                                // here wolfssl_read couldn't fetch any extra data
                                strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                                error.store(true, std::memory_order_release);
                                
                                unblock_sigpipe_signal();

                                fail_ws_connection(GOING_AWAY);
                                
                                // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                                // we return from this function
                                return error.load(std::memory_order_acquire);
                                
                            }

                        }

                    }

                    // getting here the send request succeeds

                    // we unblock the sigpipe signal
                    unblock_sigpipe_signal();
                
                }
                  
            }
            else{
            // here the payload data is larger than the size of the send data array so we send the data out with multiple frames

                send_data = (char*)send_data_static;
                
                // set the first byte stating that this is a multiframe data payload
                send_data[i] = FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME;
                i++;

                // we store the frame length of the frame - we set the frame length of the individual frames to send_data_array_len - biggest_header_len so the frame can be fit into the static array irrespective of the websocket header length
                int64_t frame_data_len = send_data_array_len - biggest_header_len;

                // this variable holds the index of the payload data that the sending continues from after each frame
                int64_t continuation_index = 0;
                
                // set the second byte
                if(frame_data_len < 126){ // if frame data length is less than 126 the next 7 bits represent the frame length
                
                    send_data[i] = MASK_BIT_SET | (unsigned char)frame_data_len;
                    i++;
                    
                }
                else if( (frame_data_len > 125) && (frame_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                    i++;
                    
                    send_data[i] = (0xFF00 & frame_data_len) >> 8;
                    i++;
                    
                    send_data[i] = (0x00FF & frame_data_len);
                    i++;
                    
                }
                else if( (frame_data_len > (MAX_2BYTE_INT - 1)) && (frame_data_len < (MAX_8BYTE_INT - 1)) ){
                // next byte stores the value 127 and he next 8 bytes store the payload length
                
                    send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                    i++;
                    
                    send_data[i] = (0xFF00000000000000 & frame_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                    i++;
                    
                    send_data[i] = (0x00FF000000000000 & frame_data_len) >> 48;
                    i++;
                    
                    send_data[i] = (0x0000FF0000000000 & frame_data_len) >> 40;
                    i++;
                    
                    send_data[i] = (0x000000FF00000000 & frame_data_len) >> 32;
                    i++;
                    
                    send_data[i] = (0x00000000FF000000 & frame_data_len) >> 24;
                    i++;
                    
                    send_data[i] = (0x0000000000FF0000 & frame_data_len) >> 16;
                    i++;
                    
                    send_data[i] = (0x000000000000FF00 & frame_data_len) >> 8;
                    i++;
                    
                    send_data[i] = (0x00000000000000FF & frame_data_len); // no shift required
                    i++;
                    
                    
                }
                
                for(int j = 0; j<mask_array_len; j++){
                
                    send_data[i] = mask[j]; // store the mask in the send data array
                    
                    i++;
                    
                }
                // mask storing end 
                
                // mask the data and store the masked data in the send data array 
                int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
                
                for(int64_t j = 0; j<frame_data_len; j++){

                    k = j % 4;
                    
                    send_data[i] = payload_data[j] ^ mask[k];
                    
                    i++;
                    
                }

                // increment the continuation index by frame data len
                continuation_index += frame_data_len;

                // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                block_sigpipe_signal();
                
                int64_t len = 0;

                // keep polling till we have sent the entire frame
                while(len < i){

                    int64_t local_len = wolfSSL_write(c_ssl, send_data, i - len);

                    if(local_len > 0){

                        len += local_len;
                                
                        send_data += local_len;

                    }
                    else{

                        // we get the error message
                        int err = wolfSSL_get_error(c_ssl, local_len);

                        if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                            continue;

                        }
                        else{

                            // here wolfssl_read couldn't fetch any extra data
                            strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                            error.store(true, std::memory_order_release);
                            
                            unblock_sigpipe_signal();

                            fail_ws_connection(GOING_AWAY);
                            
                            // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                            // we return from this function
                            return error.load(std::memory_order_acquire);
                            
                        }

                    }

                }

                // getting here the send request for this frame succeeds

                // we unblock the sigpipe signal
                unblock_sigpipe_signal();

                // we now build up the continuation frames

                // we loop till the continuation index equals the payload data len
                while(continuation_index < payload_data_len){

                    // we test if the unsent portion of the data can be sent out as a single frame now
                    if(payload_data_len - continuation_index <= send_data_array_len - biggest_header_len){
                    // we send out this frame with the fin bit set

                        // we set our iterator i back to 0
                        i = 0;

                        // we set our frame data len to payload_data_len - continution index as that would be the length of the remaining data to be sent
                        frame_data_len = payload_data_len - continuation_index;
                        
                        // set the first byte
                        send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME);
                        i++;

                        // set the second byte
                        if(frame_data_len < 126){ // if payload data length is less than 126 the next 7 bits represent the payload length
                        
                            send_data[i] = MASK_BIT_SET | (unsigned char)frame_data_len;
                            i++;
                            
                        }
                        else if( (frame_data_len > 125) && (frame_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                        
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                            i++;
                            
                            send_data[i] = (0xFF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00FF & frame_data_len);
                            i++;
                            
                        }
                        else if( (frame_data_len > (MAX_2BYTE_INT - 1)) && (frame_data_len < (MAX_8BYTE_INT - 1)) ){
                        // next byte stores the value 127 and he next 8 bytes store the payload length
                        
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                            i++;
                            
                            send_data[i] = (0xFF00000000000000 & frame_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                            i++;
                            
                            send_data[i] = (0x00FF000000000000 & frame_data_len) >> 48;
                            i++;
                            
                            send_data[i] = (0x0000FF0000000000 & frame_data_len) >> 40;
                            i++;
                            
                            send_data[i] = (0x000000FF00000000 & frame_data_len) >> 32;
                            i++;
                            
                            send_data[i] = (0x00000000FF000000 & frame_data_len) >> 24;
                            i++;
                            
                            send_data[i] = (0x0000000000FF0000 & frame_data_len) >> 16;
                            i++;
                            
                            send_data[i] = (0x000000000000FF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00000000000000FF & frame_data_len); // no shift required
                            i++;
                            
                            
                        }
            
                        // we reuse the already generated mask to save computation
                        for(int j = 0; j<mask_array_len; j++){
                        
                            send_data[i] = mask[j]; // store the mask in the send data array
                            
                            i++;
                            
                        }

                        // mask the data and store the masked data in the send data array 
                        k = 0; // we reuse the variable used to store the mask index of the exact byte in the mask array to mask with
                        
                        // since this is the last frame we use continuation_index < payload_data_len as the conditional for this for loop
                        for(int64_t j = continuation_index; j<payload_data_len; j++){

                            send_data[i] = payload_data[j] ^ mask[k];

                            k = ++k % 4;
                            
                            i++;
                            
                        }

                        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                        block_sigpipe_signal();
                        
                        int64_t len = 0;

                        // keep polling till we have sent the entire frame
                        while(len < i){

                            int64_t local_len = wolfSSL_write(c_ssl, send_data, i - len);

                            if(local_len > 0){

                                len += local_len;
                                        
                                send_data += local_len;

                            }
                            else{

                                // we get the error message
                                int err = wolfSSL_get_error(c_ssl, local_len);

                                if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                                    continue;

                                }
                                else{

                                    // here wolfssl_read couldn't fetch any extra data
                                    strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                                    error.store(true, std::memory_order_release);
                                    
                                    unblock_sigpipe_signal();

                                    fail_ws_connection(GOING_AWAY);
                                    
                                    // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                                    // we return from this function
                                    return error.load(std::memory_order_acquire);
                                    
                                }

                            }

                        }

                        // getting here the pong request send succeeds

                        // we unblock the sigpipe signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // we send out this frame with the fin bit not set - we do not alter the frame data len in this case as it would still be set to send_data_array_len - biggest_header_len

                        // we set our iterator i back to 0
                        i = 0;
                        
                        // we get our copy boundary index where our frame data for this frame stops
                        int64_t copy_bound = continuation_index + frame_data_len;

                        // set the first byte
                        send_data[i] = FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME;
                        i++;

                        // set the second byte
                        if(frame_data_len < 126){ // if payload data length is less than 126 the next 7 bits represent the payload length
                        
                            send_data[i] = MASK_BIT_SET | (unsigned char)frame_data_len;
                            i++;
                            
                        }
                        else if( (frame_data_len > 125) && (frame_data_len < MAX_2BYTE_INT) ){ // next byte stores the value 126 and the next two bytes store the payload length
                        
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)126);
                            i++;
                            
                            send_data[i] = (0xFF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00FF & frame_data_len);
                            i++;
                            
                        }
                        else if( (frame_data_len > (MAX_2BYTE_INT - 1)) && (frame_data_len < (MAX_8BYTE_INT - 1)) ){
                        // next byte stores the value 127 and he next 8 bytes store the payload length
                        
                            send_data[i] = (unsigned char)(MASK_BIT_SET | (unsigned char)127);
                            i++;
                            
                            send_data[i] = (0xFF00000000000000 & frame_data_len) >> 56 ; // the most significant bit cannot be 1 since we have the MAX_8BYTE_INT range test before executing this part of the code
                            i++;
                            
                            send_data[i] = (0x00FF000000000000 & frame_data_len) >> 48;
                            i++;
                            
                            send_data[i] = (0x0000FF0000000000 & frame_data_len) >> 40;
                            i++;
                            
                            send_data[i] = (0x000000FF00000000 & frame_data_len) >> 32;
                            i++;
                            
                            send_data[i] = (0x00000000FF000000 & frame_data_len) >> 24;
                            i++;
                            
                            send_data[i] = (0x0000000000FF0000 & frame_data_len) >> 16;
                            i++;
                            
                            send_data[i] = (0x000000000000FF00 & frame_data_len) >> 8;
                            i++;
                            
                            send_data[i] = (0x00000000000000FF & frame_data_len); // no shift required
                            i++;
                            
                            
                        }
            
                        // we reuse the already generated mask to save computation
                        for(int j = 0; j<mask_array_len; j++){
                        
                            send_data[i] = mask[j]; // store the mask in the send data array
                            
                            i++;
                            
                        }

                        // mask the data and store the masked data in the send data array 
                        k = 0; // we reuse the variable used to store the mask index of the exact byte in the mask array to mask with
                        
                        for(int64_t j = continuation_index; j<copy_bound; j++){

                            send_data[i] = payload_data[j] ^ mask[k];

                            k = ++k % 4;
                            
                            i++;
                            
                        }

                        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                        block_sigpipe_signal();
                        
                        int64_t len = 0;

                        // keep polling till we have sent the entire frame
                        while(len < i){

                            int64_t local_len = wolfSSL_write(c_ssl, send_data, i - len);

                            if(local_len > 0){

                                len += local_len;
                                        
                                send_data += local_len;

                            }
                            else{

                                // we get the error message
                                int err = wolfSSL_get_error(c_ssl, local_len);

                                if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                                    continue;

                                }
                                else{

                                    // here wolfssl_read couldn't fetch any extra data
                                    strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                                    error.store(true, std::memory_order_release);
                                    
                                    unblock_sigpipe_signal();

                                    fail_ws_connection(GOING_AWAY);
                                    
                                    // the connection getting lost isn't in itself an error it just puts the lock client in a closed state

                                    // we return from this function
                                    return error.load(std::memory_order_acquire);
                                    
                                }

                            }

                        }

                        // getting here the send request succeeds

                        // we unblock the sigpipe signal
                        unblock_sigpipe_signal();

                    }

                    // increment the continuation index by frame data len
                    continuation_index += frame_data_len;

                }

            }   

        }
        else{ // lock client in closed state
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
            
            error.store(true, std::memory_order_release);
            
        }
    
    }
        
    return error.load(std::memory_order_acquire);
    
}
    
inline int lock_client_pm::default_receive(char* data_array, int length_of_array_data, int length_of_array){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
    
}

inline int lock_client_pm::default_pong_receive(char* data_array, int length_of_array_data, int length_of_array){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
    
}

void lock_client_pm::set_receive_function(lock_function fn){
    
    recv_data = std::move(fn);
    
}

void lock_client_pm::set_pong_function(lock_function fn){
    
    recv_pong = std::move(fn);
    
}

bool lock_client_pm::data_available(){

    // we use memory order relaxed for loading last read because data available is called by the main thread that updates last read
    return last_write.load(std::memory_order_acquire) - last_read.load(std::memory_order_relaxed) > 0 ? true : false;

}

bool lock_client_pm::poll_read(int core){

    // we increase this thread priority
    bool thread_priori_error = increase_thread_priority();

    // if the increase thread priority error encounters an error we set our poll init and return
    if(thread_priori_error){

        // we set our poll init flag to true
        poll_init.store(true, std::memory_order_release);

        return error.load(std::memory_order_acquire);

    }

    // we set this thread cpu affinity
    bool cpu_affinity_error = set_cpu_affinity(core);

    // we set our poll init flag to true to indicate that that this thread is setup to run the read poll
    poll_init.store(true, std::memory_order_release);

    // we check if the set cpu affinity function encountered an error, if it did we return from the poll read function ending the poll thread - the poll init flag is already set after running the set cpu affinity function so we don't need to set it before returning
    if(cpu_affinity_error) return error.load(std::memory_order_acquire);

    // getting here the poll thread encountered no issue setting up so we set our poll thread running flag to true
    poll_thread_running.store(true, std::memory_order_release);

    // we keep polling till our stop poll flag is set
    while(!stop_poll.load(std::memory_order_acquire)){

        // we check that the client has no error
        if(!error.load(std::memory_order_acquire)){

            // we check that the client has an open websocket connection
            if(client_state.load(std::memory_order_acquire) == OPEN){

                // we fetch our last read and last write index - we use memory order relaxed for fetching the last write variable because it is only the poll thread that updates it
                int loc_last_read = last_read.load(std::memory_order_acquire);
                int loc_last_write = last_write.load(std::memory_order_relaxed);

                // we fetch how much free space we have in our read buffer - free space here means how much empty spaces or spaces with data already consumed do we have
                int free_space = READ_BUFFER_SIZE - (loc_last_write - loc_last_read);

                // we simply continue if we have no free space in our read buffer
                if(free_space == 0) continue;

                // we fetch our write start index
                int start_index = loc_last_write & (READ_BUFFER_SIZE - 1);

                // now we compute how much contiguous memory we have because wolfssl read ca only be called to populate contiguous memory
                int contiguous_space = READ_BUFFER_SIZE - start_index;

                // now we compute our data size to read. our data size to read is the minimum of 3 values - our free space, our contiguous space and our read chunk size
                int data_sz_to_read = std::min({free_space, contiguous_space, READ_CHUNK_SIZE});

                // block SIGPIPE signal before attempting to read data, just incase the connection is closed
                block_sigpipe_signal_pm();

                // we read our data using our wolfssl read
                int data_size_read = wolfSSL_read(c_ssl, read_buffer + start_index, data_sz_to_read);

                // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                unblock_sigpipe_signal_pm();

                // we increment our write index if we successfully fetched more data
                if(data_size_read > 0){

                    last_write.store(loc_last_write + data_size_read, std::memory_order_release);

                }
                else{

                    // we fetch the wolfssl error
                    int err = wolfSSL_get_error(c_ssl, data_size_read);

                    if(err != WOLFSSL_ERROR_WANT_READ){

                        // we copy our error message to our error buffer
                        strcpy(error_buffer, "Poll Error: Can't Fetch data from remote host: Check network connection");

                        error.store(true, std::memory_order_release);
                        
                        // we don't break out from this loop we let it continue, the error flag set would prevent the poll thread from reading any more data till the main thread reconnects and clears the error flag

                    }

                }

            }

        }

    }

    return error.load(std::memory_order_acquire);

}

int lock_client_pm::fetch_data(unsigned char* dest, int sz){

    // first we check if the supplied sz is <=0 in which case we simply return 0
    if(sz <= 0) return 0;

    // we fetch our local last read and last write - we use memory order relaxed to acquire our last read variable because it is updated by only the main thread that calls this fetch data function
    int loc_last_read = last_read.load(std::memory_order_acquire);
    int loc_last_write = last_write.load(std::memory_order_relaxed);

    // we compute our available data
    int available_data = loc_last_write - loc_last_read;

    // we check if there is any available data if not we return retry
    if(available_data <= 0) return RETRY;

    // getting here there is available data so we compute the size to copy
    int data_sz_to_copy = available_data < sz ? available_data : sz;

    // now we fetch the start index our read would start from
    int start_index = loc_last_read & (READ_BUFFER_SIZE - 1);

    // now because we use bit masks to get our effective index and we need to know explicitly when to wrap around we check how much contiguous data there is to the end of the read buffer because we can only fetch ontiguous memory data with each memcpy call
    int contiguous_data_sz = READ_BUFFER_SIZE - start_index;

    // we check if our contiguous data sz is < our data sz to copy in which case we can fetch the available data in one memcpy call else we have to fetch our data sz to copy in two memcpy call
    if(data_sz_to_copy <= contiguous_data_sz){

        memcpy(dest, read_buffer + start_index, data_sz_to_copy);

    }
    else{

        // getting here the available data is not contiguous so we fetch it in two memcpy calls
        memcpy(dest, read_buffer + start_index, contiguous_data_sz);

        // this second memcpy wraps around and copies from the start of the read buffer
        memcpy(dest + contiguous_data_sz, read_buffer, data_sz_to_copy - contiguous_data_sz);

    }

    // we update our last read atomic variable
    last_read.store(loc_last_read + data_sz_to_copy, std::memory_order_release);

    return data_sz_to_copy;

}

bool lock_client_pm::basic_read(){

    if(!error.load(std::memory_order_acquire) || data_available()){ // only continue if no error or data available
        
        // we use memory order relaxed to check the client state because only the main thread can set the client state
        if(client_state.load(std::memory_order_relaxed) == OPEN){ // only continue if client is in open state
        
            int64_t frame_data_len = 0; // stores the length of the data frame received

            // attempt to read the first two bytes to test the FIN bit, the opcode and the size of the frame. We use the rand bytes array because it is not in use by the program at this point

            // we set our bytes to read variable to the number of bytes we are trying to read
            int bytes_to_read = 2;

            // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array wolfSSL_read should write to
            int total_read_bytes = 0;

            // we initialise our read bytes to 0, read bytes keeps track of how many bytes were read in each wolfSSL_read call
            int read_bytes = 0;

            // we keep reading till we have our total bytes to read
            while(total_read_bytes < bytes_to_read){

                // we call fetch data function to attempt to read the bytes into the buffer
                read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                if(read_bytes <= 0){

                    // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                    // we check if we still expects more reads or if the poll thread encountered an error
                    if(read_bytes == RETRY){

                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                        // getting here fetch data returned RETRY so we check if any data has been fetched in this basic read call
                        if(total_read_bytes > 0){
                        // getting here data has been gotten in this current basic read call so we continue the loop till the entire data is fetched

                            continue;

                        }
                        else{
                        // getting here no data has been fetched in this basic read call so we simply exit

                            // we return error at this point because it is still 0 and it signals that basic read didn't fail there just is no data to read - so we use memory order relaxed here to load the error flag
                            return error.load(std::memory_order_relaxed);

                        }


                    }

                }

                // we increment our total read bytes
                total_read_bytes += read_bytes;

            }

            
            if( (rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME)) || (rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | BINARY_FRAME)) ){ // this is the only frame of a text or binary frame data stream. We do not differentiate between text and binary frames since data copy happens the same way
                
                // test the frame length. No need testing the mask bit as server to client frames are always unmasked
                if(rand_bytes[1] < 126){ // this is the length
                    
                    frame_data_len = rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 126){ // next two bytes store the data length

                    // read the next 2 bytes to get the length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 2;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }
                    
                    frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 127){ // this would mean that the next 8 bytes is our length

                    // read the next 8 bytes to get our length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 8;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }

                    // getting here the frame length was successfully read
                
                    if((rand_bytes[0] & 128) != 0){

                        // most significant bit of most significant byte is set which is against protocol rules
                        
                        strcpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set");
                        
                        error.store(true, std::memory_order_release);
                        
                        // fail the websocket connection
                        fail_ws_connection(PROTOCOL_ERROR);

                        return error.load(std::memory_order_relaxed);
                        
                    }

                    // geting here everything is fine
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strcpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ");
                    
                    error.store(true, std::memory_order_release);
                    
                    // fail the websocket connection
                    fail_ws_connection(PROTOCOL_ERROR);

                    return error.load(std::memory_order_relaxed);
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned.
                
                int64_t length_of_array_data = 0;
                
                // test that the size of data to be received can fit into the static data array
                if(frame_data_len < static_data_array_length){ // static data array would be sufficient
                    
                    data_array = data_array_static;
                    cursor = data_array;
                    length_of_array = static_data_array_length;
                    length_of_array_data = frame_data_len;

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                    
                    memset(data_array, '\0', frame_data_len); // zero out the data array
                    
                    cursor = data_array; // set the cursor back to point to the array pointed at by data array
                
                }
                else if(frame_data_len < size_of_allocated_data_memory){ // we use allocated heap memory to store the received data
                    
                    data_array = data_array_new;
                    cursor = data_array;
                    length_of_array = size_of_allocated_data_memory;
                    length_of_array_data = frame_data_len;
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                    
                    memset(data_array, '\0', frame_data_len); // zero out the data array
                    
                    cursor = data_array; // set the cursor back to point to the array pointed at by data array
                    
                }
                else{ // neither static nor already allocated memory is sufficient, so we check if memory has been allocated or not 
                    
                    if(data_array_new == NULL){ // memory has not been allocated
                        
                        data_array_new = new(std::nothrow) char[frame_data_len + 1024]; // we allocate 1KB more memory than is needed to store the frame so we could avoid some future memory allocations
            
                        if(data_array_new == NULL){
                            
                            close(FRAME_TOO_LARGE); // close the WebSocket connection with a frame too large error
                            
                            // no need to memset as no data has been written to the array at this point
                            
                            strcpy(error_buffer, "Error allocating heap memory for receiving single frame data...frame too large ");
                    
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            length_of_array_data = frame_data_len;
                        
                            // SIGPIPE signal is still blocked

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                        
                            (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                            
                            memset(data_array, '\0', frame_data_len); // zero out the data array
                            
                            cursor = data_array; // set the cursor back to point to the array pointed at by data array
                    
                        }
                        
                    }
                    else{ // there is already allocated memory but it is not sufficient
                        
                        delete [] data_array_new; //delete already allocated memory
                        
                        data_array_new = new(std::nothrow) char[frame_data_len + 1024]; // we allocate 1KB more memory than the data frame length just to get some extra spacing and avoid some memory allocation for future data frames
                
                        if(data_array_new == NULL){
                            
                            close(FRAME_TOO_LARGE); // close the WebSocket connection with a frame too large error
                                
                            // no need to memset as no data has been written to the array at this point
                            
                            strcpy(error_buffer, "Error allocating heap memory for receiving single frame data after deleting previously allocated memory...frame too large");
                        
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                        
                        }
                        else{
                            
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            length_of_array_data = frame_data_len;
                        
                            // SIGPIPE signal is still blocked

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                        
                            (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                            
                            memset(data_array, '\0', frame_data_len); // zero out the data array
                            
                            cursor = data_array; // set the cursor back to point to the array pointed at by data array
                    
                        }
                
                    }
                
                }
            
            }
            else if( (rand_bytes[0] == (FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME)) || (rand_bytes[0] == (FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | BINARY_FRAME)) ){ // this data frame is an incomplete part of a larger whole
                
                // test the frame length. No need testing the mask bit as server to client frames are always unmasked
                if(rand_bytes[1] < 126){ // this is the length
                    
                    frame_data_len = rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 126){ // next two bytes store the data length

                    // read the next 2 bytes to get the length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 2;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }
                    
                    frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 127){ // this would mean that the next 8 bytes is our length

                    // read the next 8 bytes to get our length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 8;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }

                    // getting here the frame length was successfully read
                
                    if((rand_bytes[0] & 128) != 0){

                        // most significant bit of most significant byte is set which is against protocol rules
                        
                        strcpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set");
                        
                        error.store(true, std::memory_order_release);
                        
                        // fail the websocket connection
                        fail_ws_connection(PROTOCOL_ERROR);

                        return error.load(std::memory_order_relaxed);
                        
                    }

                    // geting here everything is fine
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strcpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ");
                    
                    error.store(true, std::memory_order_release);
                    
                    // fail the websocket connection
                    fail_ws_connection(PROTOCOL_ERROR);

                    return error.load(std::memory_order_relaxed);
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned.
                
                // test that the size of data to be received can fit into the static data array
                if(frame_data_len < static_data_array_length){ // static data array would be sufficient
                    
                    data_array = data_array_static;
                    cursor = data_array;
                    length_of_array = static_data_array_length;

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    // we don't call user's receive function here because the data is still incomplete
                    
                    // we do not zero out the data array because the data isn't yet complete
                
                }
                else if(frame_data_len < size_of_allocated_data_memory){ // we use allocated heap memory to store the received data
                    
                    data_array = data_array_new;
                    cursor = data_array;
                    length_of_array = size_of_allocated_data_memory;

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    // we don't call user's receive function here because the data is still incomplete
                    
                    // we do not zero out the data array because the data isn't yet complete
                    
                }
                else{ // neither static nor already allocated memory is sufficient, so we check if memory has been allocated or not
                    
                    if(data_array_new == NULL){ // memory has not been allocated
                        
                        data_array_new = new(std::nothrow) char[frame_data_len + 1024]; // we allocate 1KB more memory than is needed to store the frame so we could avoid some future memory allocations
            
                        if(data_array_new == NULL){
                            
                            close(FRAME_TOO_LARGE); // close the WebSocket connection with a frame too large error
                            
                            // no need to memset as no data has been written to the array at this point
                            
                            strcpy(error_buffer, "Error allocating heap memory for receiving single frame data...frame too large ");
                    
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                        
                            // we don't call user's receive function here because the data is still incomplete
                    
                            // we do not zero out the data array because the data isn't yet complete
                    
                        }
                        
                    }
                    else{ // there is already allocated memory but it is not sufficient
                        
                        delete [] data_array_new; // delete already allocated memory
                        
                        data_array_new = new(std::nothrow) char[frame_data_len + 1024]; // we allocate 1KB more memory than the data frame length just to get some extra spacing and avoid some memory allocation for future data frames
                
                        if(data_array_new == NULL){
                            
                            close(FRAME_TOO_LARGE); // close the WebSocket connection with a frame too large error
                                
                            // no need to memset as no data has been written to the array at this point
                            
                            strcpy(error_buffer, "Error allocating heap memory for receiving single frame data after deleting previously allocated memory...frame too large");
                        
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                        
                        }
                        else{
                            
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;

                            int64_t len = 0; // we initialise our len variable to 0

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                        
                            // we don't call user's receive function here because the data is still incomplete
                    
                            // we do not zero out the data array because the data isn't yet complete
                    
                        }
                
                    }
                
                }
                
            }
            else if(rand_bytes[0] == (FIN_BIT_NOT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME) ){
                
                // test the frame length. No need testing the mask bit as server to client frames are always unmasked
                if(rand_bytes[1] < 126){ // this is the length
                    
                    frame_data_len = rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 126){ // next two bytes store the data length

                    // read the next 2 bytes to get the length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 2;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }
                    
                    frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 127){ // this would mean that the next 8 bytes is our length

                    // read the next 8 bytes to get our length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 8;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }

                    // getting here the frame length was successfully read
                
                    if((rand_bytes[0] & 128) != 0){

                        // most significant bit of most significant byte is set which is against protocol rules
                        
                        strcpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set");
                        
                        error.store(true, std::memory_order_release);
                        
                        // fail the websocket connection
                        fail_ws_connection(PROTOCOL_ERROR);

                        return error.load(std::memory_order_relaxed);
                        
                    }

                    // geting here everything is fine
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strcpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ");
                    
                    error.store(true, std::memory_order_release);
                    
                    // fail the websocket connection
                    fail_ws_connection(PROTOCOL_ERROR);

                    return error.load(std::memory_order_relaxed);
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned.
                
                int64_t length_of_array_data = cursor - data_array; // this is used to store the length of data that the data array currently holds
                
                if(frame_data_len < (length_of_array - length_of_array_data) ){ // array in use is large enough for incoming frame

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    // we don't call user's receive function here because the data is still incomplete
                    
                    // we do not zero out the data array because the data isn't yet complete
                        
                    
                }
                else if( (data_array == data_array_static) && ( (length_of_array_data + frame_data_len) < size_of_allocated_data_memory) ){ // already allocated memory is large enough
                    
                    data_array = data_array_new; // reassign the data array pointer to point to the allocated memory
                    cursor = data_array;
                    length_of_array = size_of_allocated_data_memory;
                    
                    memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the heap memory
                    
                    memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                    
                    cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    // we don't call user's receive function here because the data is still incomplete
                    
                    // we do not zero out the data array because the data isn't yet complete
                    
                }
                else if( (data_array == data_array_static) && ( (length_of_array_data + frame_data_len) > size_of_allocated_data_memory) ){ // there are two parts to this condition, either memory has been allocated of memory has not been allocated
                    
                    if(data_array_new == NULL){ // memory has not been allocated
                        
                        data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // allocate memory 1KB bigger than the length of array data + the length of the incoming continuation frame
            
                        if(data_array_new == NULL){
                            
                            memset(data_array, '\0', length_of_array_data); // zero out already received data
                    
                            cursor = data_array; // set cursor to point back to data array 
                            
                            close(FRAME_TOO_LARGE); // we close the websocket connection with a frame too large error
                            
                            strcpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ");
                    
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = length_of_array_data + frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            
                            memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the allocated memory
                            
                            memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                            
                            cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                            
                            // we don't call user's receive function here because the data is still incomplete
                            
                            // we do not zero out the data array because the data isn't yet complete
                    
                        }
                        
                    }
                    else{ // there is already allocated memory but it is not sufficient
                        
                        delete [] data_array_new; // delete already allocated memory
                        
                        data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // make the new array 1KB bigger than the previous array length + the incoming continuaton frame length
                        
                        if(data_array_new == NULL){
                    
                            memset(data_array, '\0', length_of_array_data); // zero out already received data
                        
                            cursor = data_array; // set cursor to point back to data array 
                                
                            close(FRAME_TOO_LARGE); // we close the websocket connection with a frame too large error
                                
                            strcpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ");
                        
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                        
                        }
                        else{
                            
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = length_of_array_data + frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            
                            memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the allocated memory
                            
                            memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                            
                            cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                            
                            // we don't call user's receive function here because the data is still incomplete
                            
                            // we do not zero out the data array because the data isn't yet complete
                    
                        }
                    
                    }
                    
                }
                else{ // dynamic memory already in use but it is not sufficient for incoming continuation frame
                    
                    char* local_data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // make the new array 1KB bigger than the previous array size + the incoming continuation frame
                    
                    if(local_data_array_new == NULL){
                
                        memset(data_array, '\0', length_of_array_data); // zero out already received data
                    
                        cursor = data_array; // set cursor to point back to data array 
                            
                        close(FRAME_TOO_LARGE); // we close the websocket connection with a frame too large error
                            
                        strcpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ");
                    
                        error.store(true, std::memory_order_release);

                        return error.load(std::memory_order_relaxed);
                    
                    }
                    else{
                        
                        memcpy(local_data_array_new, data_array_new, length_of_array_data); // we first copy the previously received data to the newly allocated memory before deleting the previously allocated memory
                        
                        delete [] data_array_new; // delete previously allocated memory
                        
                        data_array_new = local_data_array_new; // assign the local_data_array_new to data_array_new
                        data_array = data_array_new;
                        cursor = data_array;
                        size_of_allocated_data_memory = length_of_array_data + frame_data_len + 1024;
                        length_of_array = size_of_allocated_data_memory;
                        
                        cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 

                        int64_t len = 0; // we initialise our len variable

                        // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                        while(len < frame_data_len){
                        
                            int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                            
                            if(extra_bytes_read > 0){
                            // fetch data fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // fetch data didn't fetch more data

                                if(extra_bytes_read == RETRY){
                                // no data available yet

                                    // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                    if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                    continue;

                                }

                            }

                        }
                        
                        // we don't call user's receive function here because the data is still incomplete
                        
                        // we do not zero out the data array because the data isn't yet complete
                    
                    }
                
                }
                
            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME) ){
                
                // test the frame length. No need testing the mask bit as server to client frames are always unmasked
                if(rand_bytes[1] < 126){ // this is the length
                    
                    frame_data_len = rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 126){ // next two bytes store the data length

                    // read the next 2 bytes to get the length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 2;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }
                    
                    frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];
                    
                }
                else if(rand_bytes[1] == 127){ // this would mean that the next 8 bytes is our length

                    // read the next 8 bytes to get our length

                    // we set our bytes to read variable to the number of bytes we are trying to read
                    bytes_to_read = 8;

                    // the total read bytes shows how many bytes have been read in total out of the number of bytes to be read - this also indicates where next in the rand bytes array fetch data should write to
                    total_read_bytes = 0;

                    // we reset our read bytes to 0, read bytes keeps track of how many bytes were read in each fetch data call
                    read_bytes = 0;

                    // we keep reading till we have our total bytes to read
                    while(total_read_bytes < bytes_to_read){

                        // we call fetch data function to attempt to read the bytes into the buffer
                        read_bytes = fetch_data(&rand_bytes[total_read_bytes], bytes_to_read - total_read_bytes);

                        // if wolfssl_read returns a value <= 0 we check if there is data available to be read
                        if(read_bytes <= 0){

                            // for clarification fetch data returns either 0 or RETRY which is a negative number. 0 is returned when the supplied size parameter is invalid and retry when the read buffer has no new data

                            // we check if we still expects more reads or if the poll thread encountered an error
                            if(read_bytes == RETRY){

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                // getting here since there is no error from the poll thread and we haven't fetched the entire data yet we just continue the loop
                                continue;


                            }

                        }

                        // we increment our total read bytes
                        total_read_bytes += read_bytes;

                    }

                    // getting here the frame length was successfully read
                
                    if((rand_bytes[0] & 128) != 0){

                        // most significant bit of most significant byte is set which is against protocol rules
                        
                        strcpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set");
                        
                        error.store(true, std::memory_order_release);
                        
                        // fail the websocket connection
                        fail_ws_connection(PROTOCOL_ERROR);

                        return error.load(std::memory_order_relaxed);
                        
                    }

                    // geting here everything is fine
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strcpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ");
                    
                    error.store(true, std::memory_order_release);
                    
                    // fail the websocket connection
                    fail_ws_connection(PROTOCOL_ERROR);

                    return error.load(std::memory_order_relaxed);
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned.
                
                int64_t length_of_array_data = cursor - data_array; // this is used to store the length of data that the data array currently holds
                
                if(frame_data_len < (length_of_array - length_of_array_data) ){ // array in use is large enough for incoming frame
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    // getting here would mean we did not encounter any error in receiving the frame data because if we did the websocket connection would have been failed

                    // update the array data length
                    length_of_array_data += frame_data_len;
                    
                    (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                        
                    memset(data_array, '\0', length_of_array_data); // zero out the data array
                        
                    cursor = data_array; // set the cursor back to point to the array pointed at by data array
                        
                }
                else if( (data_array == data_array_static) && ( (length_of_array_data + frame_data_len) < size_of_allocated_data_memory) ){ // already allocated memory is large enough
                    
                    data_array = data_array_new; // reassign the data array pointer to point to the allocated memory
                    cursor = data_array;
                    length_of_array = size_of_allocated_data_memory;
                    
                    memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the heap memory
                    
                    memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                    
                    cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array

                    int64_t len = 0; // we initialise our len variable

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }
                    
                    // getting here would mean we did not encounter any error in receiving the frame data because if we did the websocket connection would have been failed
                    
                    // update the array data length
                    length_of_array_data += frame_data_len;
                    
                    (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                    
                    memset(data_array, '\0', length_of_array_data); // zero out the data array
                    
                    cursor = data_array; // set the cursor back to point to the array pointed at by data array
                    
                }
                else if( (data_array == data_array_static) && ( (length_of_array_data + frame_data_len) > size_of_allocated_data_memory) ){ // there are two parts to this condition, either memory has been allocated of memory has not been allocated 
                    
                    if(data_array_new == NULL){ // memory has not been allocated
                        
                        data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // allocate memory 1KB bigger than the length of array data + the length of the incoming continuation frame
            
                        if(data_array_new == NULL){
                            
                            memset(data_array, '\0', length_of_array_data); // zero out already received data
                    
                            cursor = data_array; // set cursor to point back to data array 
                            
                            close(FRAME_TOO_LARGE);
                            
                            strcpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ");
                    
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = length_of_array_data + frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            
                            memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the allocated memory
                            
                            memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                            
                            cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 
                            
                            // SIGPIPE signal is still blocked

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }
                            
                            // getting here would mean we did not encounter any error in receiving the frame data because if we did the websocket connection would have been failed
                            
                            // update the array data length
                            length_of_array_data += frame_data_len;
                            
                            (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                        
                            memset(data_array, '\0', length_of_array_data); // zero out the data array
                            
                            cursor = data_array; // set the cursor back to point to the array pointed at by data array
                            
                        }
                        
                    }
                    else{ // there is already allocated memory but it is not sufficient
                        
                        delete [] data_array_new; //delete already allocated memory
                        
                        data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // make the new array 1KB bigger than the previous array length + the incoming continuaton frame length
                        
                        if(data_array_new == NULL){
                    
                            memset(data_array, '\0', length_of_array_data); // zero out already received data
                        
                            cursor = data_array; // set cursor to point back to data array 
                                
                            close(FRAME_TOO_LARGE);
                                
                            strcpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...total frame too large ");
                        
                            error.store(true, std::memory_order_release);

                            return error.load(std::memory_order_relaxed);
                        
                        }
                        else{
                            
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = length_of_array_data + frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            
                            memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the allocated memory
                            
                            memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                            
                            cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array

                            int64_t len = 0; // we initialise our len variable

                            // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                            while(len < frame_data_len){
                            
                                int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                                
                                if(extra_bytes_read > 0){
                                // fetch data fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // fetch data didn't fetch more data

                                    if(extra_bytes_read == RETRY){
                                    // no data available yet

                                        // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                        if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                        continue;

                                    }

                                }

                            }

                            // getting here would mean we did not encounter any error in receiving the frame data because if we did the websocket connection would have been failed
                            
                            // update the array data length
                            length_of_array_data += frame_data_len;
                            
                            (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                            
                            memset(data_array, '\0', length_of_array_data); // zero out the data array
                            
                            cursor = data_array; // set the cursor back to point to the array pointed at by data array
                        
                        }
                    
                    }
                    
                }
                else{ // dynamic memory already in use but it is not sufficient for incoming continuation frame
                    
                    char* local_data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // make the new array 1KB bigger than the previous array size + the incoming continuation frame
                    
                    if(local_data_array_new == NULL){
                
                        memset(data_array, '\0', length_of_array_data); // zero out already received data
                    
                        cursor = data_array; // set cursor to point back to data array 
                            
                        close(FRAME_TOO_LARGE);
                            
                        strcpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...total frame too large ");
                    
                        error.store(true, std::memory_order_release);

                        return error.load(std::memory_order_relaxed);
                    
                    }
                    else{
                        
                        memcpy(local_data_array_new, data_array_new, length_of_array_data); // we first copy the previously received data to the newly allocated memory before deleting the previously allocated memory
                        
                        delete [] data_array_new; // delete previously allocated memory
                        
                        data_array_new = local_data_array_new; // assign the local_data_array_new to data_array_new
                        data_array = data_array_new;
                        cursor = data_array;
                        size_of_allocated_data_memory = length_of_array_data + frame_data_len + 1024;
                        length_of_array = size_of_allocated_data_memory;
                        
                        cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 
                        
                        // SIGPIPE signal is still blocked

                        int64_t len = 0; // we initialise our len variable

                        // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                        while(len < frame_data_len){
                        
                            int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                            
                            if(extra_bytes_read > 0){
                            // fetch data fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // fetch data didn't fetch more data

                                if(extra_bytes_read == RETRY){
                                // no data available yet

                                    // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                    if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                    continue;

                                }

                            }

                        }
                        
                        // getting here would mean we did not encounter any error in receiving the frame data because if we did the websocket connection would have been failed
                        
                        // update the array data length
                        length_of_array_data += frame_data_len;
                        
                        (void)recv_data(data_array, length_of_array_data, length_of_array); // call the receive function to handle the received data
                        
                        memset(data_array, '\0', length_of_array_data); // zero out the data array
                        
                        cursor = data_array; // set the cursor back to point to the array pointed at by data array
                
                    }
                
                }

            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | PING) ){
                
                if( !(++num_of_pings_received < ping_backlog) ){ // the ping backlog delays sending a pong frame till a number of pings specified by the ping backlog has been received
                    
                    if(rand_bytes[1] > 125){ // protocol error as the frame length of control frames should not be more than 125
                    
                        strcpy(error_buffer, "Protocol error: Ping frame received with length greater than 125 bytes");
                    
                        error.store(true, std::memory_order_release);
                        
                        memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the faulty ping frame is received when a fragmented message is still being transmitted.
                        
                        cursor = data_array; // set cursor to point back to data array
                        
                        fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                        return error.load(std::memory_order_relaxed);
                
                    }
                
                    // getting here would mean that no error was encountered
                    
                    frame_data_len = rand_bytes[1];
                    
                    int64_t len = 0; // we initialise our len variable

                    // point the upgrade request pointer to the upgrade request static array
                    upgrade_request = upgrade_request_static;

                    // read in the ping frame data, we use the upgrade request static array because it isn't currently in use by the program

                    // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                    while(len < frame_data_len){
                    
                        int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                        
                        if(extra_bytes_read > 0){
                        // fetch data fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // fetch data didn't fetch more data

                            if(extra_bytes_read == RETRY){
                            // no data available yet

                                // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                                if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                                continue;

                            }

                        }

                    }

                    // getting here the ping frame payload data has been fetched
                
                    // send a pong frame response - the num_of_pings_received variable is set back to 0 in the pong function
                    pong(frame_data_len);

                }
                
            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONNECTION_CLOSE) ){
                
                if((cursor != NULL) && (data_array != NULL)){
                
                    memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the close frame is received when a fragmented message is still being transmitted.
                    
                    cursor = data_array; // set cursor to point back to data array
                
                }
                
                if(rand_bytes[1] > 125){ // protocol error as the frame length should not be more than 125
                    
                    strcpy(error_buffer, "Protocol error: Close frame received with length greater than 125 bytes");
                    
                    error.store(true, std::memory_order_release);
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error.load(std::memory_order_relaxed);
                
                }
                
                frame_data_len = rand_bytes[1]; // store the close frame response length which would be the same as the close frame received
                data_array = data_array_static; // use the static array because it is always large enough to hold a close frame
                cursor = data_array;
                
                
                int i = 0; // variable for traversing the send array and building up the close data frame response

                int64_t len = 0; // we initialise our len variable

                // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                while(len < frame_data_len){
                
                    int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                    
                    if(extra_bytes_read > 0){
                    // fetch data fetched extra data

                        len += extra_bytes_read;
                        
                        cursor += extra_bytes_read;

                    }
                    else{
                    // fetch data didn't fetch more data

                        if(extra_bytes_read == RETRY){
                        // no data available yet

                            // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                            if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                            continue;

                        }

                    }

                }
            
                // build up the close frame response message
            
                send_data = (char*)send_data_static; // set the send data pointer to the send data static array
        
                send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONNECTION_CLOSE);
                i++;
        
                send_data[i] = MASK_BIT_SET | ((unsigned char)frame_data_len);
                i++;
            
                for(int j = 0; j<mask_array_len; j++){
                
                    send_data[i] = mask[j]; // store the mask in the send data array
                
                    i++;
                
                }
                // mask storing end 
            
                // mask the data and store the masked data in the send data array 
                int k = 0; // variable used to store the mask index of the exact byte in the max array to mask with
            
                for(int j = 0; j<frame_data_len; j++){
                
                    k = j % 4;
                
                    send_data[i] = data_array[j] ^ mask[k];  
                
                    i++;
                
                }
                
                // we block our SIGPIPE signal
                block_sigpipe_signal();

                // send the close frame response - we do not test the return code of wolfssl_read in this case neither do we poll to ensure it sends
                (void)wolfSSL_write(c_ssl, send_data, i);
                
                // unblock SIGPIPE signal
                unblock_sigpipe_signal();
                
                reset(); // close the existing connection and reset the wolfssl object

                // before we set the error flag for the unsolicited close frame we first check if the poll thread already set the error flag
                if(!error.load(std::memory_order_acquire)){
                
                    // getting here the error flag isn't set so we copy our error message to the error buffer

                    // set error flag to indicate that the lock client instance connection has been closed by foreign host
                    strcpy(error_buffer, "Lock client WebSocket connection mutually closed after instance received unsolicited close frame from foreign host");

                    // we set our error flag
                    error.store(true, std::memory_order_release);

                }
                else{

                    // getting here the error flag is set so we concatenate our error message to the error buffer

                    // set error flag to indicate that the lock client instance connection has been closed by foreign host
                    strcat(error_buffer, "\nClient Error: Lock client WebSocket connection mutually closed after instance received unsolicited close frame from foreign host");

                    // getting here our error flag is already set so we don't have to set it

                }

                // now the received close frame application data may contain a server reason for closing after the first 2 bytes which is the status code for the close frame, so we check if the application data length is > 2 if it is we append it to the error buffer
                    
                int server_reason = static_cast<int>(frame_data_len) - 2;

                // we check if there is a received close reason
                if(server_reason > 0){

                    // getting here there is a received close reason so we append this reason to the error buffer

                    // since this is a string within the received data we don't treat it as a null terminated string so we first fetch the index in the error buffer we would be copying this to - we first append our opening bracket and server reaon to the error buffer
                    strcat(error_buffer, " (Server reason: ");
                    
                    // we fetch the error buffer index to copy this data to
                    int error_buffer_index = strlen(error_buffer);

                    // we now copy the server reason to the error buffer starting at offset 2 to capture only the server reason
                    memcpy(&error_buffer[error_buffer_index], data_array + 2, server_reason);

                    // now we append the closing parentheses to error_buffer
                    memcpy(&error_buffer[error_buffer_index] + server_reason, ").", 3);

                }

                memset(data_array, '\0', frame_data_len); // zero out the data array
                
                cursor = data_array; // set cursor to point back to data array
                
                client_state.store(CLOSED, std::memory_order_release);
                
            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | PONG) ){
                
                if(rand_bytes[1] > 125){ // protocol error as the frame length of control frames should not be more than 125
                    
                    strcpy(error_buffer, "Protocol error: Pong frame received with length greater than 125 bytes");
                    
                    error.store(true, std::memory_order_release);
                    
                    memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if a faulty pong frame is received when a fragmented message is still being transmitted.
                    
                    cursor = data_array; // set cursor to point back to data array
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error.load(std::memory_order_relaxed);
                
                }
                
                // getting here would mean that no error in the protocol was encountered thus far
                
                frame_data_len = rand_bytes[1]; // read in the data length
                
                // we point the upgrade request pointer to the upgrade_request_static variable because it isn't used by the program at this point
                upgrade_request = upgrade_request_static;

                // SIGPIPE signal is still blocked

                int64_t len = 0;

                // we keep polling till we have read the entire frame - this case already handles instances where frame data len is 0, the while loop won't run
                while(len < frame_data_len){
                
                    int extra_bytes_read = fetch_data(reinterpret_cast<unsigned char*>(cursor), frame_data_len - len);
                    
                    if(extra_bytes_read > 0){
                    // fetch data fetched extra data

                        len += extra_bytes_read;
                        
                        cursor += extra_bytes_read;

                    }
                    else{
                    // fetch data didn't fetch more data

                        if(extra_bytes_read == RETRY){
                        // no data available yet

                            // getting a retry means that there is no data to read from the read buffer so we check if the error flag has been set in the poll thread in which case we would simply return here - we use memory order acquire to load the error flag in the if condition but use memory order relaxed to return in the if brace because the condition already loaded it
                            if(error.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

                            continue;

                        }

                    }

                }

                // getting here the pong frame payload data has been fetched
                
                (void)recv_pong(upgrade_request_static, frame_data_len, upgrade_request_array_length); // call te receive pong function
                
                memset(upgrade_request_static, '\0', frame_data_len);
                    
            }
            else{ // unrecognised protocol opcode received
                
                strcpy(error_buffer, "Unrecognised data frame received ");
                
                error.store(true, std::memory_order_release);
                
                memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the an unrecognised frame is received when a fragmented message is still being transmitted.
                
                cursor = data_array; // set cursor to point back to data array
                
                fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection
                
            }
            
        }
        else{

            strcpy(error_buffer, "Lock Client not connected yet");
                
            error.store(true, std::memory_order_release);
            
        }
        
    }

    // in order to accomodate the scenario where the poll thread sets the error flag to true but there is still data to read we check if data is still available and if so we return false masking the error till there is no more data available. this way calling basic read in a loop that checks if any error was encountered can run till all available data is exhausted
    return data_available() ? false : error.load(std::memory_order_relaxed);
        
}
       
bool lock_client_pm::connect(std::string_view url){ // this is used to connect to connect to the url passed as a parameter, it can be used when a lock client object was created without establishing a websocket connection by using the parameterless constructor, or to connect an already established websocket connection and lock client instance to a different websocket server, it can also be used to retry connecting an instance that encountered an error during connection

    // we check that the poll thread is running if it isn't we return our error flag which would be set already if the poll thread isn't running - we return the error with memory order relaxed because we have already loaded the poll thread running flag which was written to after the error flag so we should already have an updated error flag
    if(!poll_thread_running.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);
    
    // we close the websocket connection - if this handle was connected before, if it wasn't close is still a safe operation
    close(NORMAL_CLOSE);

    // erase any previous error message
    memset(error_buffer, '\0', strlen(error_buffer));

    // we set our error flag to false
    error.store(false, std::memory_order_release);
  
    // check if url is a wss:// endpoint, check case insensitively - for thw wolfssl client we only implement the wss client
        
    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocol_prefix_len = strlen("wss://");

        // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
        size_t base_url_end_index = url.find('/', protocol_prefix_len);

        int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any
        
        // size of required memory in bytes to store the base url and the port number if it would be appended
        int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url

        // we create our ssl object - we call close before calling wolfssl new and close frees the previous wolfssl object so for every connect call we create a new wolfssl object
        c_ssl = wolfSSL_new(ssl_ctx);
    
        if(!error.load(std::memory_order_acquire)){ // the constructor continues only if there was no error fetching the ssl pointer

            // URL copy 
            if(req_mem < url_static_array_length){ // static memory large enough
            
                url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
            
                c_url_static[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_static;
            
            }
            else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
                
                url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
            
                c_url_new[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_new;
                
            
            }
            else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
                
                if(c_url_new == NULL){ // memory has not yet been allocated
                    
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error.store(true, std::memory_order_release);
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                        c_url_new[base_url_length] = '\0';
            
                        c_url = c_url_new;
                    
                    }
            
                }
                else{ // memory has been allocated but still isn't large enough
                    
                    delete [] c_url_new; // delete the already allocated memory
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error.store(true, std::memory_order_release);
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = req_mem;    
                            
                        url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                        c_url_new[base_url_length] = '\0';

                        c_url = c_url_new;
                    
                    }
                
                }

            }
            
            if(!error.load(std::memory_order_acquire)){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error 
                
                // we check if the supplied url has the port number appended if not we append it
                if(strchr(c_url, ':') == NULL){
                    strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
                }
        
            }
        
        }
    
    }
    else{ // not a valid/supported websocket endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid/supported WebSocket endpoint", error_buffer_array_length);
                
        error.store(true, std::memory_order_release);
        
    }
    
    if(!error.load(std::memory_order_acquire)){ // only continue if no error
        
        int search_start_index = 6; // we store the index where we would begin the host name search from, we start searching from after the wss:// protocol prefix

        // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
        size_t host_name_end_index = url.find_first_of(":/", search_start_index); // we start searching at the search_start_index - index 6 to bypass the wss:// protocol prefix length
        
        int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - search_start_index : (int)host_name_end_index - search_start_index;

        if(host_name_len < host_static_array_length){ // static array is large enough
        
            url.copy(c_host_static, host_name_len, search_start_index);
        
            c_host_static[host_name_len] = '\0';
        
            c_host = c_host_static;
        
        }
        else if(host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
            
            url.copy(c_host_new, host_name_len, search_start_index);
        
            c_host_new[host_name_len] = '\0';
        
            c_host = c_host_new;
            
        }
        else{ // neither static or already allocated memory is large enough, we test the two possible cases
            
            if(c_host_new == NULL){ // memory has not been allocated yet 
            
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
                if(c_host_new == NULL){
            
                    strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                
                    error.store(true, std::memory_order_release);    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, search_start_index);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;
        
                }
            
            }
            else{ // memory has been allocated but it still isn't sufficient
                
                delete [] c_host_new; // delete the previously allocated memory
                
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
                if(c_host_new == NULL){
            
                    strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                
                    error.store(true, std::memory_order_release);    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, search_start_index);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;
        
                }
            
            }
            
        }
        
        if(!error.load(std::memory_order_acquire)){ // only continue if no error
        
            // we set the host name we wish to connect to for server name identification(SNI) if the websocket address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
            if(c_ssl != NULL){
                
                if(!wolfSSL_UseSNI(c_ssl, WOLFSSL_SNI_HOST_NAME, c_host, host_name_len)){
                // we test the return value. wolfSSL_UseSNI returns 0 on error and 1 on success
                    
                    strncpy(error_buffer, "Error setting up Lock client for SNI TLS extension", error_buffer_array_length);
                        
                    error.store(true, std::memory_order_release);
                
                }
                
            }
            
            if(!error.load(std::memory_order_acquire)){
            // only continue if no error
            
                // we store the start index of the path from the supplied url - we search for the next forward slash after the last colon, that is the start of the path in the supplied url string view
                size_t path_start_index = url.find('/', search_start_index);
                
                // we check if a forward slash was found after the last colon, if none was we connect to the default root path else the forward slash till the end of the url string is the path
                std::string_view path = (path_start_index != std::string_view::npos) ? url.substr(path_start_index) : "/";

                // copy the channel path parameter into the channel path array
                int path_string_len = path.size();
                
                if(path_string_len < path_static_array_length){ // we can store the path in the static array if this condition is true
                    
                    path.copy(c_path_static, path_string_len); // copy the path into the static array
                    c_path_static[path_string_len] = '\0'; // null-terminate the array
                    
                    c_path = c_path_static;
                    
                }
                else if(path_string_len < size_of_allocated_path_memory){ // allocated memory is large enough
                    
                    path.copy(c_path_new, path_string_len); // copy the path into the allocated array
                    c_path_new[path_string_len] = '\0'; // null-terminate the array
                    
                    c_path = c_path_new;
                    
                }
                else{ // neither static or already allocated memory is large enough, we test the two possible cases 
                    
                    if(c_path_new == NULL){ //memory has not been allocated yet
                    
                        c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                    
                        if(c_path_new == NULL){
                        
                            strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                            
                            error.store(true, std::memory_order_release);
                            
                        }
                        else{ 
                            
                            size_of_allocated_path_memory = path_string_len + 1;
                            
                            path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                    
                            c_path_new[path_string_len] = '\0'; // null-terminate the array
                    
                            c_path = c_path_new;
                    
                        }
                        
                    }
                    else{ // memory has been allocated but is still not sufficient
                        
                        delete [] c_path_new; // delete already allocated memory
                        
                        c_path_new = new(std::nothrow) char[path_string_len + 1]; // allocate memory for the path string with the std::nothrow parameter so C++ throws no exceptons even if memory allocation fails. We check for this below
                    
                        if(c_path_new == NULL){
                        
                            strncpy(error_buffer, "Error allocating heap memory for lock_client channel path ", error_buffer_array_length);
                            
                            error.store(true, std::memory_order_release);
                            
                        }
                        else{ 
                            
                            size_of_allocated_path_memory = path_string_len + 1;
                            
                            path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                    
                            c_path_new[path_string_len] = '\0'; // null-terminate the array
                    
                            c_path = c_path_new;
                    
                        }
                        
                    }
                    
                }
                
                if(!error.load(std::memory_order_acquire)){ // only continue if no error

                    // we create a local char array to hold the port extracted from the url
                    const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
                    char c_port[MAX_CHAR_FOR_PORT];

                    // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

                    // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
                    std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

                    // we now copy the derived port into char array
                    int num_of_chars_copied = port.copy(c_port, port.size());

                    // we null terminate the c_port array
                    c_port[num_of_chars_copied] = '\0';

                    // we call our connect to server function with the interface parameters set to null
                    int sockfd = connect_to_server(c_host, c_port, nullptr, nullptr);
                    
                    if(!error.load(std::memory_order_acquire)){ // only continue if no error

                        // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                        wolfSSL_set_fd(c_ssl, sockfd);

                        // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                        int len;

                        while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                            
                            // we get the error message
                            int err = wolfSSL_get_error(c_ssl, len);

                            // we check if the wolfssl handle is still expecting a read or a write
                            if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                continue;

                            }
                            else{

                                // getting here we got a actual error so we set our error flag
                                strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                            
                                error.store(true, std::memory_order_release);

                                // we break out of this loop
                                break;

                            }

                        }

                        // upgrade the connection to websocket
                        
                        // fill the random bytes array with 16 random bytes between 0 and 255
                        int upper_bound = 255;
                        for(int i = 0; i < rand_byte_array_len; i++){
                            
                            rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                        }
                        
                        // we store our nonce array len in a local variable because we pass it to base 64 encode as a pointer and the function updates it
                        unsigned int tmp_array_len = nonce_array_len;
                        
                        // get the Base-64 encoding of the random number to give the value of the nonce
                        Base64_Encode_NoNl(rand_bytes, rand_byte_array_len, base64_encoded_nonce, &tmp_array_len);
                    
                        // request connection upgrade
                        int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                        char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                        int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                        
                        if(upgrade_request_len < upgrade_request_array_length){ // static array is large enough
                            
                            // build the upgrade request
                            strcpy(upgrade_request_static, "GET ");
                            strcat(upgrade_request_static, c_path);
                            strcat(upgrade_request_static, " HTTP/1.1\n");
                            strcat(upgrade_request_static, "Host: ");
                            strcat(upgrade_request_static, c_host);
                            strcat(upgrade_request_static, "\n");
                            strcat(upgrade_request_static, "Connection: Upgrade\n");
                            strcat(upgrade_request_static, "Pragma: no-cache\n");
                            strcat(upgrade_request_static, "Upgrade: websocket\n");
                            strcat(upgrade_request_static, "Sec-WebSocket-Version: 13\n");
                            strcat(upgrade_request_static, "Sec-WebSocket-Key: ");
                            strcat(upgrade_request_static, (const char*)base64_encoded_nonce);
                            strcat(upgrade_request_static, "\n\n");
                            // upgrade request build end 
                            
                            upgrade_request = upgrade_request_static;
                            
                        }
                        else if(upgrade_request_len < size_of_allocated_upgrade_request_memory){ // allocated memory large enough
                        
                            // build the upgrade request
                            strcpy(upgrade_request_new, "GET ");
                            strcat(upgrade_request_new, c_path);
                            strcat(upgrade_request_new, " HTTP/1.1\n");
                            strcat(upgrade_request_new, "Host: ");
                            strcat(upgrade_request_new, c_host);
                            strcat(upgrade_request_new, "\n");
                            strcat(upgrade_request_new, "Connection: Upgrade\n");
                            strcat(upgrade_request_new, "Pragma: no-cache\n");
                            strcat(upgrade_request_new, "Upgrade: websocket\n");
                            strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                            strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                            strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                            strcat(upgrade_request_new, "\n\n");
                            // upgrade request build end 
                            
                            upgrade_request = upgrade_request_new;
                            
                        }
                        else{ // neither static nor allocated memory is large enough, we test both cases
                        
                            if(upgrade_request_new == NULL){ // memory has not been allocated yet
                            
                                upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                            
                                if(upgrade_request_new == NULL){
                                
                                    strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                                    
                                    error.store(true, std::memory_order_release);
                                    
                                    reset(); // disconnect the underlying wolfssl object
                                    
                                }
                                else{
                                    
                                    size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                                    
                                    // build the upgrade request
                                    strcpy(upgrade_request_new, "GET ");
                                    strcat(upgrade_request_new, c_path);
                                    strcat(upgrade_request_new, " HTTP/1.1\n");
                                    strcat(upgrade_request_new, "Host: ");
                                    strcat(upgrade_request_new, c_host);
                                    strcat(upgrade_request_new, "\n");
                                    strcat(upgrade_request_new, "Connection: Upgrade\n");
                                    strcat(upgrade_request_new, "Pragma: no-cache\n");
                                    strcat(upgrade_request_new, "Upgrade: websocket\n");
                                    strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                    strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                    strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                    strcat(upgrade_request_new, "\n\n");
                                    // upgrade request build end 
                            
                                    upgrade_request = upgrade_request_new;
                                
                                }
                        
                            }
                            else{ // memory has previously been allocated for an upgrade request but it still isn't sufficient
                                
                                delete [] upgrade_request_new; // delete the previously allocated memory
                                
                                upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                        
                                if(upgrade_request_new == NULL){
                            
                                    strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                                
                                    error.store(true, std::memory_order_release);
                                    
                                    reset(); // disconnect the underlying wolfssl object
                                
                                }
                                else{ 
                                
                                    size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                                
                                    // build the upgrade request
                                    strcpy(upgrade_request_new, "GET ");
                                    strcat(upgrade_request_new, c_path);
                                    strcat(upgrade_request_new, " HTTP/1.1\n");
                                    strcat(upgrade_request_new, "Host: ");
                                    strcat(upgrade_request_new, c_host);
                                    strcat(upgrade_request_new, "\n");
                                    strcat(upgrade_request_new, "Connection: Upgrade\n");
                                    strcat(upgrade_request_new, "Pragma: no-cache\n");
                                    strcat(upgrade_request_new, "Upgrade: websocket\n");
                                    strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                                    strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                                    strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                                    strcat(upgrade_request_new, "\n\n");
                                    // upgrade request build end 
                        
                                    upgrade_request = upgrade_request_new;
                            
                                }
                                
                            }
                        
                        }
                    
                        if(!error.load(std::memory_order_acquire)){ // only continue if no error
                            
                            data_array = data_array_static;

                            // we send our upgrade request
                            while((len = wolfSSL_write(c_ssl, reinterpret_cast<const void*>(upgrade_request), strlen(upgrade_request))) <= 0){
                            
                                // we get the error message
                                int err = wolfSSL_get_error(c_ssl, len);

                                // we check if the wolfssl handle is still expecting a write
                                if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                                    continue;

                                }
                                else{

                                    // getting here we got a actual error so we set our error flag
                                    strncpy(error_buffer, "Error sending websocket upgrade request ", error_buffer_array_length);
                                
                                    error.store(true, std::memory_order_release);

                                    // we break out of this loop
                                    break;

                                }

                            }
                            
                            if(!error.load(std::memory_order_acquire)){

                                // non blocking call to wolfssl read
                                while((len = wolfSSL_read(c_ssl, data_array, static_data_array_length)) <= 0){
                            
                                    // we get the error message
                                    int err = wolfSSL_get_error(c_ssl, len);

                                    // we check if the wolfssl handle is still expecting a read
                                    if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                        continue;

                                    }
                                    else{

                                        // getting here we got a actual error so we set our error flag
                                        strncpy(error_buffer, "Error reading websocket upgrade response ", error_buffer_array_length);
                                    
                                        error.store(true, std::memory_order_release);

                                        // we break out of this loop
                                        break;

                                    }

                                }

                                if(!error.load(std::memory_order_acquire)){

                                    data_array[len] = '\0'; // null terminate the received bytes

                                    // test for the switching protocol header to confirm that the connection upgrade was successful
                                    char success_response[] = "HTTP/1.1 101 Switching Protocols";
                                    
                                    if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful

                                        // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                                        
                                        // build the SHA1 parameter
                                        strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                                        strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                                        // SHA1 parameter build end 
                                        
                                        // we create a sha context for computing our sha1 hash
                                        wc_Sha sha_context;

                                        // sha context init
                                        wc_InitSha(&sha_context);

                                        // we update our sha context with the data to be hashed
                                        wc_ShaUpdate(&sha_context, reinterpret_cast<const byte*>(SHA1_parameter), strlen(SHA1_parameter));

                                        wc_ShaFinal(&sha_context, SHA1_digest);

                                        // we store a copy of our local sec key array len
                                        tmp_array_len = local_sec_ws_accept_key_array_len;

                                        // base64 encode the SHA1 digest
                                        Base64_Encode_NoNl(SHA1_digest, size_of_SHA1_digest, reinterpret_cast<byte*>(local_sec_ws_accept_key), &tmp_array_len);
                                        
                                        // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                                        char key[] = "Sec";
                                        char* cursor = strtok(NULL, "\n");
                                        
                                        while(cursor != NULL){
                                        // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                                            
                                            // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                                            if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                                    
                                                cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                                
                                                // compare server's response with our calculation
                                                if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                                    
                                                    // we set our last read index and last write index to 0 so the poll thread ignores any messages from a previous connection and starts polling for messages from this connection
                                                    last_read.store(0, std::memory_order_release);
                                                    last_write.store(0, std::memory_order_release);

                                                    client_state.store(OPEN, std::memory_order_release);

                                                    break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                                        
                                                }
                                                else{
                                                    
                                                    strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                                        
                                                    reset(); // reset session and disconnect the underlying connection
                                                        
                                                    error.store(true, std::memory_order_release);
                                                        
                                                    break;
                                                        
                                                }
                                                
                                            }
                                            
                                            cursor = strtok(NULL, "\n");
                                            
                                        }
                                        
                                        if(cursor == NULL){
                                            
                                            // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                                            strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                                            
                                            reset(); // reset session and disconnect the underlying connection
                                            
                                            error.store(true, std::memory_order_release);
                                        
                                        }
                                        
                                    }
                                    else{ // upgrade unsuccessful
                                        
                                        strncpy(error_buffer, "Connection upgrade failed. Invalid path or url supplied", error_buffer_array_length);
                                        
                                        reset(); // reset session and disconnect the underlying connection
                                        
                                        error.store(true, std::memory_order_release);
                                        
                                    }
                                                        
                                    memset(data_array, '\0', len); // zero out the data array

                                    memset(upgrade_request, '\0', upgrade_request_len); // zero out the upgrade request array
                                    
                                }
                                
                            }
                    
                        }
                    
                    }
                
                }
    
            }
    
        }
    
    }

    return error.load(std::memory_order_acquire);
        
}

bool lock_client_pm::interface_connect(std::string_view url, in_addr* interface_address, char* interface_name){
    
    // we check that the poll thread is running if it isn't we return our error flag which would be set already if the poll thread isn't running - we return the error with memory order relaxed because we have already loaded the poll thread running flag which was written to after the error flag so we should already have an updated error flag
    if(!poll_thread_running.load(std::memory_order_acquire)) return error.load(std::memory_order_relaxed);

    // we close the websocket connection - if this handle was connected before, if it wasn't close is still a safe operation
    close(NORMAL_CLOSE);

    // erase any previous error message
    memset(error_buffer, '\0', strlen(error_buffer));

    // we set our error flag to false
    error.store(false, std::memory_order_release);

    // check if url is a wss:// endpoint, check case insensitively

    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocol_prefix_len = strlen("wss://");

        // we fetch the url length without the wss:// prefix and any path appended to the url, we do this by finding the next '/' character after the initial wss://
        size_t base_url_end_index = url.find('/', protocol_prefix_len);

        int base_url_length = (base_url_end_index != std::string_view::npos) ? (int)base_url_end_index - protocol_prefix_len : url.size() - protocol_prefix_len; // saves the length of the url without the wss:// prefix and the path if any

        // size of required memory in bytes to store the base url and the port number if it would be appended
        int req_mem = base_url_length + 5; // we add an extra 5 bytes to the base url length to accomodate for the chance that this url was supplied without a port number so we have enough room to append port :443 to the base url
        
        // URL copy 
        if(req_mem < url_static_array_length){ // static memory large enough
        
            url.copy(c_url_static, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
        
            c_url_static[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_static;
        
        }
        else if(req_mem < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocol_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
        
            c_url_new[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_new;
            
        
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not
            
            if(c_url_new == NULL){ // memory has not yet been allocated
                
                c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                if(c_url_new == NULL){
                    
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                    
                    error.store(true, std::memory_order_release);
                    
                }
                else{
                    
                    size_of_allocated_url_memory = req_mem;    
                        
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
        
                    c_url_new[base_url_length] = '\0';
        
                    c_url = c_url_new;
                
                }
        
            }
            else{ // memory has been allocated but still isn't large enough
                
                delete [] c_url_new; // delete the already allocated memory
                
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[req_mem]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                if(c_url_new == NULL){
                    
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                    
                    error.store(true, std::memory_order_release);
                    
                }
                else{
                    
                    size_of_allocated_url_memory = req_mem;    
                        
                    url.copy(c_url_new, base_url_length, protocol_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                    c_url_new[base_url_length] = '\0';

                    c_url = c_url_new;
                
                }
            
            }

        }

        if(!error.load(std::memory_order_acquire)){

            // we check if the supplied url has the port number appended if not we append it
            if(strchr(c_url, ':') == NULL){
                strcat(c_url, ":443"); // we use strcat here because the array length check already checks that we have enough space in the array to accomodate for the port number
            }

            // we search for the colon to indicate the start of the port number if any or the forward slash to indicate the start of the path if appended whichever comes first as that would indicate the end of the host name
            size_t host_name_end_index = url.find_first_of(":/", protocol_prefix_len); // we start searching at the protocol_prefix_len - index 6 to bypass the wss:// protocol prefix length
            
            int host_name_len = (host_name_end_index == std::string_view::npos) ? url.size() - protocol_prefix_len : (int)host_name_end_index - protocol_prefix_len;

            if(host_name_len < host_static_array_length ){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, protocol_prefix_len);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
                url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                c_host_new[host_name_len] = '\0';
            
                c_host = c_host_new;
                
            }
            else{ // neither static or already allocated memory is large enough, we test the two possible cases
                
                if(c_host_new == NULL){ // memory has not been allocated yet 
                
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error.store(true, std::memory_order_release);    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;
            
                    }
                
                }
                else{ // memory has been allocated but it still isn't sufficient
                    
                    delete [] c_host_new; // delete the previously allocated memory
                    
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error.store(true, std::memory_order_release);    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, protocol_prefix_len);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;

            
                    }
                
                }
                
            }

            // we create a local char array to hold the port extracted from the url
            const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
            char c_port[MAX_CHAR_FOR_PORT];

            // since the host_name_end_index already finds the first character out of : and / after the host name we use it to find the port number location if any

            // we first check if the host name end index was either std::string_view::npos or / in which case we know the host wasn't supplied so we store 443 as the host, but if the : character was found then the host was supplied so we just create a sub string view from after the : character to either the / starting the path if supplied, but if not supplied till std::string_view::npos - host_name_end_index - 1 which would be a very large number the copy takes the rest of the url string_view
            std::string_view port = (host_name_end_index == std::string_view::npos || url[host_name_end_index] == '/') ? "443" : url.substr(host_name_end_index + 1, url.find('/', host_name_end_index) - host_name_end_index - 1);

            // we now copy the derived port into char array
            int num_of_chars_copied = port.copy(c_port, port.size());

            // we null terminate the c_port array
            c_port[num_of_chars_copied] = '\0';

            // now we can call the connect to server function that would return the configured socket file descriptor
            int sockfd = connect_to_server(c_host, c_port, interface_address, interface_name);

            if(!error.load(std::memory_order_acquire)){ // only continue if no error

                // getting here the connect to server function returned successfully so now we bind the returned socket fd to our c_ssl object
                wolfSSL_set_fd(c_ssl, sockfd);

                // we perform our tls handshake - since this is a non blocking socket we loop till our handshake is complete
                int len;

                while((len = wolfSSL_connect(c_ssl)) != WOLFSSL_SUCCESS){
                    
                    // we get the error message
                    int err = wolfSSL_get_error(c_ssl, len);

                    // we check if the wolfssl handle is still expecting a read or a write
                    if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                        continue;

                    }
                    else{

                        // getting here we got a actual error so we set our error flag
                        strncpy(error_buffer, "Error performing tls handshake ", error_buffer_array_length);
                    
                        error.store(true, std::memory_order_release);

                        // we break out of this loop
                        break;

                    }

                }

                // upgrade the connection to websocket
                
                // fill the random bytes array with 16 random bytes between 0 and 255
                int upper_bound = 255;
                for(int i = 0; i < rand_byte_array_len; i++){
                    
                    rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                }
                
                // we store our nonce array len in a local variable because we pass it to base 64 encode as a pointer and the function updates it
                unsigned int tmp_array_len = nonce_array_len;
                
                // get the Base-64 encoding of the random number to give the value of the nonce
                Base64_Encode_NoNl(rand_bytes, rand_byte_array_len, base64_encoded_nonce, &tmp_array_len);
            
                // request connection upgrade
                int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                
                if(upgrade_request_len < upgrade_request_array_length){ // static array is large enough
                    
                    // build the upgrade request
                    strcpy(upgrade_request_static, "GET ");
                    strcat(upgrade_request_static, c_path);
                    strcat(upgrade_request_static, " HTTP/1.1\n");
                    strcat(upgrade_request_static, "Host: ");
                    strcat(upgrade_request_static, c_host);
                    strcat(upgrade_request_static, "\n");
                    strcat(upgrade_request_static, "Connection: Upgrade\n");
                    strcat(upgrade_request_static, "Pragma: no-cache\n");
                    strcat(upgrade_request_static, "Upgrade: websocket\n");
                    strcat(upgrade_request_static, "Sec-WebSocket-Version: 13\n");
                    strcat(upgrade_request_static, "Sec-WebSocket-Key: ");
                    strcat(upgrade_request_static, (const char*)base64_encoded_nonce);
                    strcat(upgrade_request_static, "\n\n");
                    // upgrade request build end 
                    
                    upgrade_request = upgrade_request_static;
                    
                }
                else if(upgrade_request_len < size_of_allocated_upgrade_request_memory){ // allocated memory large enough
                
                    // build the upgrade request
                    strcpy(upgrade_request_new, "GET ");
                    strcat(upgrade_request_new, c_path);
                    strcat(upgrade_request_new, " HTTP/1.1\n");
                    strcat(upgrade_request_new, "Host: ");
                    strcat(upgrade_request_new, c_host);
                    strcat(upgrade_request_new, "\n");
                    strcat(upgrade_request_new, "Connection: Upgrade\n");
                    strcat(upgrade_request_new, "Pragma: no-cache\n");
                    strcat(upgrade_request_new, "Upgrade: websocket\n");
                    strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                    strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                    strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                    strcat(upgrade_request_new, "\n\n");
                    // upgrade request build end 
                    
                    upgrade_request = upgrade_request_new;
                    
                }
                else{ // neither static nor allocated memory is large enough, we test both cases
                
                    if(upgrade_request_new == NULL){ // memory has not been allocated yet
                    
                        upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                    
                        if(upgrade_request_new == NULL){
                        
                            strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                            
                            error.store(true, std::memory_order_release);
                            
                            reset(); // disconnect the underlying wolfssl object
                            
                        }
                        else{
                            
                            size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                            
                            // build the upgrade request
                            strcpy(upgrade_request_new, "GET ");
                            strcat(upgrade_request_new, c_path);
                            strcat(upgrade_request_new, " HTTP/1.1\n");
                            strcat(upgrade_request_new, "Host: ");
                            strcat(upgrade_request_new, c_host);
                            strcat(upgrade_request_new, "\n");
                            strcat(upgrade_request_new, "Connection: Upgrade\n");
                            strcat(upgrade_request_new, "Pragma: no-cache\n");
                            strcat(upgrade_request_new, "Upgrade: websocket\n");
                            strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                            strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                            strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                            strcat(upgrade_request_new, "\n\n");
                            // upgrade request build end 
                    
                            upgrade_request = upgrade_request_new;
                        
                        }
                
                    }
                    else{ // memory has previously been allocated for an upgrade request but it still isn't sufficient
                        
                        delete [] upgrade_request_new; // delete the previously allocated memory
                        
                        upgrade_request_new = new(std::nothrow) char[upgrade_request_len + 1]; // allocate memory for the upgrade request with the std::nothrow parameter stops the C++ runtime from throwing an error should the allocation request fail
                
                        if(upgrade_request_new == NULL){
                    
                            strncpy(error_buffer, "Error allocating heap memory for upgrade request string, supplied URL or channel path too long  ", error_buffer_array_length);
                        
                            error.store(true, std::memory_order_release);
                            
                            reset(); // disconnect the underlying wolfssl object
                        
                        }
                        else{ 
                        
                            size_of_allocated_upgrade_request_memory = upgrade_request_len + 1;
                        
                            // build the upgrade request
                            strcpy(upgrade_request_new, "GET ");
                            strcat(upgrade_request_new, c_path);
                            strcat(upgrade_request_new, " HTTP/1.1\n");
                            strcat(upgrade_request_new, "Host: ");
                            strcat(upgrade_request_new, c_host);
                            strcat(upgrade_request_new, "\n");
                            strcat(upgrade_request_new, "Connection: Upgrade\n");
                            strcat(upgrade_request_new, "Pragma: no-cache\n");
                            strcat(upgrade_request_new, "Upgrade: websocket\n");
                            strcat(upgrade_request_new, "Sec-WebSocket-Version: 13\n");
                            strcat(upgrade_request_new, "Sec-WebSocket-Key: ");
                            strcat(upgrade_request_new, (const char*)base64_encoded_nonce);
                            strcat(upgrade_request_new, "\n\n");
                            // upgrade request build end 
                
                            upgrade_request = upgrade_request_new;
                    
                        }
                        
                    }
                
                }
            
                if(!error.load(std::memory_order_acquire)){ // only continue if no error
                    
                    data_array = data_array_static;

                    // we send our upgrade request
                    while((len = wolfSSL_write(c_ssl, reinterpret_cast<const void*>(upgrade_request), strlen(upgrade_request))) <= 0){
                    
                        // we get the error message
                        int err = wolfSSL_get_error(c_ssl, len);

                        // we check if the wolfssl handle is still expecting a write
                        if(err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ){

                            continue;

                        }
                        else{

                            // getting here we got a actual error so we set our error flag
                            strncpy(error_buffer, "Error sending websocket upgrade request ", error_buffer_array_length);
                        
                            error.store(true, std::memory_order_release);

                            // we break out of this loop
                            break;

                        }

                    }
                    
                    if(!error.load(std::memory_order_acquire)){

                        // non blocking call to wolfssl read
                        while((len = wolfSSL_read(c_ssl, data_array, static_data_array_length)) <= 0){
                    
                            // we get the error message
                            int err = wolfSSL_get_error(c_ssl, len);

                            // we check if the wolfssl handle is still expecting a read
                            if(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE){

                                continue;

                            }
                            else{

                                // getting here we got a actual error so we set our error flag
                                strncpy(error_buffer, "Error reading websocket upgrade response ", error_buffer_array_length);
                            
                                error.store(true, std::memory_order_release);

                                // we break out of this loop
                                break;

                            }

                        }

                        if(!error.load(std::memory_order_acquire)){

                            data_array[len] = '\0'; // null terminate the received bytes

                            // test for the switching protocol header to confirm that the connection upgrade was successful
                            char success_response[] = "HTTP/1.1 101 Switching Protocols";
                            
                            if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful

                                // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                                
                                // build the SHA1 parameter
                                strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                                strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                                // SHA1 parameter build end 
                                
                                // we create a sha context for computing our sha1 hash
                                wc_Sha sha_context;

                                // sha context init
                                wc_InitSha(&sha_context);

                                // we update our sha context with the data to be hashed
                                wc_ShaUpdate(&sha_context, reinterpret_cast<const byte*>(SHA1_parameter), strlen(SHA1_parameter));

                                wc_ShaFinal(&sha_context, SHA1_digest);

                                // we store a copy of our local sec key array len
                                tmp_array_len = local_sec_ws_accept_key_array_len;

                                // base64 encode the SHA1 digest
                                Base64_Encode_NoNl(SHA1_digest, size_of_SHA1_digest, reinterpret_cast<byte*>(local_sec_ws_accept_key), &tmp_array_len);
                                
                                // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                                char key[] = "Sec";
                                char* cursor = strtok(NULL, "\n");
                                
                                while(cursor != NULL){
                                // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                                    
                                    // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                                    if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                            
                                        cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                        
                                        // compare server's response with our calculation
                                        if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                            
                                            // we set our last read index and last write index to 0 so the poll thread ignores any messages from a previous connection and starts polling for messages from this connection
                                            last_read.store(0, std::memory_order_release);
                                            last_write.store(0, std::memory_order_release);

                                            client_state.store(OPEN, std::memory_order_release);

                                            break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                                
                                        }
                                        else{
                                            
                                            strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                                
                                            reset(); // reset session and disconnect the underlying connection
                                                
                                            error.store(true, std::memory_order_release);
                                                
                                            break;
                                                
                                        }
                                        
                                    }
                                    
                                    cursor = strtok(NULL, "\n");
                                    
                                }
                                
                                if(cursor == NULL){
                                    
                                    // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                                    strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                                    
                                    reset(); // reset session and disconnect the underlying connection
                                    
                                    error.store(true, std::memory_order_release);
                                
                                }
                                
                            }
                            else{ // upgrade unsuccessful
                                
                                strncpy(error_buffer, "Connection upgrade failed. Invalid path or url supplied", error_buffer_array_length);
                                
                                reset(); // reset session and disconnect the underlying connection
                                
                                error.store(true, std::memory_order_release);
                                
                            }
                                                
                            memset(data_array, '\0', len); // zero out the data array

                            memset(upgrade_request, '\0', upgrade_request_len); // zero out the upgrade request array
                            
                        }
                        
                    }
            
                }
            
            }
        }
    }
    else{ // not a valid/supported websocket endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid/supported WebSocket endpoint", error_buffer_array_length);
                
        error.store(true, std::memory_order_release);
        
    }


    return error.load(std::memory_order_acquire);
}

int lock_client_pm::connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name){

    struct addrinfo hints, *res = NULL, *p = NULL;

    // we create the socket the ssl structure would use
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        std::cout<<"Error creating socket"<<std::endl;
        strncpy(error_buffer, "Error creating socket", error_buffer_array_length);          
        error.store(true, std::memory_order_release);
        return -1;
    }

    // we bind to the supplied interface if any
    if(interface_name != nullptr){

        // Bind to a specific device
        if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0){
            std::cout<<"Error binding socket to device"<<std::endl;
            perror("setsockopt(SO_BINDTODEVICE)");
            strncpy(error_buffer, "Error binding socket to device", error_buffer_array_length);          
            error.store(true, std::memory_order_release);
            ::close(sock);
            return -1;
        }
        else{
            std::cout<<"Successfully bound socket to device "<<interface_name<<std::endl;
        }

    }

    // we bind to the supplied interface address if any
    if(interface_address != nullptr){

        // Set up local address structure
        struct sockaddr_in localaddr;
        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_addr.s_addr = interface_address->s_addr;
        localaddr.sin_port = 0;  // Lets the system choose port

        // Bind socket to specific interface
        if(bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0){
            // if the binding fails the library does not set the error flag to true it just prints the error message, ignores the specified interface and attempts to make the connection with whatever network interface is available
            std::cout<<"Lockws Error: Binding To Supplied Interface Address Failed...Connection Will Be Attempted With The Default Network Interface Address..."<<std::endl;
        }

    }

    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // IPv4 (use AF_UNSPEC for both IPv4 and IPv6)
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    // Perform DNS resolution
    if(getaddrinfo(hostname, port, &hints, &res) != 0){
        std::cout<<"Error resolving hostname: "<<hostname<<std::endl;
        strncpy(error_buffer, "Error resolving hostname", error_buffer_array_length);          
        error.store(true, std::memory_order_release);
        return -1;
    }

    // Iterate over results and try to connect
    for(p = res; p != NULL; p = p->ai_next){

        // Try to connect
        if(::connect(sock, p->ai_addr, p->ai_addrlen) == 0){
            std::cout<<"Connected to "<<hostname<<std::endl;
            break; // Connected successfully
        }

        perror("connect");
        ::close(sock);
        sock = -1;
    }

    if(res != NULL)
        freeaddrinfo(res); // Free the addrinfo structure if non null

    if(sock < 0){
        std::cout<<"Failed to connect to "<<hostname<<':'<<port<<std::endl;
        strncpy(error_buffer, "Failed to connect to host", error_buffer_array_length);          
        error.store(true, std::memory_order_release);
        return -1;
    }

    // set the socket to non blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock; // Return the connected socket
}

int lock_client_pm::reset(){

    if(!c_ssl) return 0;

    // we fetch the active socket fd
    int sockfd = wolfSSL_get_fd(c_ssl);

    // if a valid socket is bound, we first close it effectively disconnecting it
    if(sockfd >= 0) ::close(sockfd);

    // we free our wolfssl object
    wolfSSL_free(c_ssl);

    // we set our c_ssl pointer to null
    c_ssl = nullptr;

    return 0;

}

void lock_client_pm::block_sigpipe_signal(){

    sigemptyset(&newset);
    sigemptyset(&oldset);
    sigaddset(&newset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &newset, &oldset);
    
}

void lock_client_pm::unblock_sigpipe_signal(){

    // clear out any SIGPIPE signal that came in while we blocked it
    while(sigtimedwait(&newset, &si, &ts) >= 0 || errno != EAGAIN);
    
    // restore the previous signal mask of the calling thread
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    
    
}

void lock_client_pm::block_sigpipe_signal_pm(){

    sigemptyset(&newset_pm);
    sigemptyset(&oldset_pm);
    sigaddset(&newset_pm, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &newset_pm, &oldset_pm);
    
}

void lock_client_pm::unblock_sigpipe_signal_pm(){

    // clear out any SIGPIPE signal that came in while we blocked it
    while(sigtimedwait(&newset_pm, &si_pm, &ts_pm) >= 0 || errno != EAGAIN);
    
    // restore the previous signal mask of the calling thread
    pthread_sigmask(SIG_SETMASK, &oldset_pm, NULL);
    
    
}

void lock_client_pm::fail_ws_connection(unsigned short status_code){

    if(cursor != NULL && data_array != NULL){
        
        memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the fail_ws_connection is called when a fragmented message was being transmitted.
            
        cursor = data_array; // set cursor to point back to data array
        
    }
        
    int i = 0; // variable for traversing the send array and building up the close data frame
    unsigned short frame_len = (unsigned short)2; // holds the length of the close data frame - sizeof unsigned short
    unsigned char close_payload[2]; // hods the close payload data which is basically the status code in network byte order
        
    send_data = (char*)send_data_static; // set the send data pointer to the send data static array
        
    send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONNECTION_CLOSE);
    close_payload[i] = (unsigned char)(status_code >> 8); // store the high byte of the status code
    i++;
        
    send_data[i] = MASK_BIT_SET | ((unsigned char)frame_len);
    close_payload[i] = (unsigned char)(0x00FF & status_code); // store the low byte of the status code
    i++;
            
    for(int j = 0; j<mask_array_len; j++){
                
        send_data[i] = mask[j]; // store the mask in the send data array
                
        i++;

    }
    // mask storing end 
            
    // mask the data and store the masked data in the send data array 
    int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
            
    for(int j = 0; j<frame_len; j++){
                
        k = j % 4;
                
        send_data[i] = close_payload[j] ^ mask[k];  
                
        i++;
                
    }
            
    // block SIGPIPE signal before attempting to send data, just incase the connection is closed
    block_sigpipe_signal();
            
    // send the close frame
    (void)wolfSSL_write(c_ssl, send_data, i); // no need checking whether it was successfully sent through we close the connection nonetheless
            
    unblock_sigpipe_signal();
            
    // close the underlying connection, don't wait for server response
    reset();
            
    client_state.store(CLOSED, std::memory_order_release); // sets the client state back to closed

    if(!error.load(std::memory_order_acquire)){
    // we only set the error message and error flag if the error flag was not set already

        // we set the lock client error variable
        strcpy(error_buffer, "Websocket Connection Lost");
                    
        error.store(true, std::memory_order_release);

    }
    
}

bool lock_client_pm::set_cpu_affinity(int core){
    
    // thread id structure used to identify the calling thread
    pthread_t thread_id = pthread_self();
    
    // cpu affinity variables
    cpu_set_t cpuset;
    
    // zero out our cpu set
    CPU_ZERO(&cpuset);
    
    // set in the cpuset struct to pin the thread to the specific core in the parameter
    CPU_SET(core, &cpuset);
    
    // now set the cpu affinity to the core specified above
    int set_affinity_error = pthread_setaffinity_np(thread_id, sizeof(cpuset), &cpuset);
    
    // we check if there was any error setting thr cpu affinity, we set our error flag if there was an error setting thr cpu affinity
    if(set_affinity_error != 0){   

        strcpy(error_buffer, "Error Pinning Thread To CPU Core ");

        // we convert our core number to a char, store it in our error buffer and null terminate our error buffer
        *(std::to_chars(error_buffer + strlen(error_buffer), error_buffer + error_buffer_array_length - 1, core).ptr) = '\0';

        // we set our error flag to true
        error.store(true, std::memory_order_release);

    }
    
    return error;
}

bool lock_client_pm::increase_thread_priority(int p_policy, int priority){
    
    // local variables used by the increase priority function
    pthread_t thread_id = pthread_self();
    int policy = 0;
    sched_param param;
    
    // the policy will now be set to the value of policy and its priority set to the value of priority, understand that policies for which priorities can be set - SCHED_FIFO and SCHED_RR have a max priority of 99 and a min priority of 0
    
    // we set our local policy variable to the p_policy parameter passed
    policy = p_policy;
    
    // we set our scheduling priority to the parameter passed
    param.sched_priority = priority;
    
    // we change our scheduling policy to scheduling policy supplied, the default is SCHED_FIFO and the default priority is 90
    int sched_error = pthread_setschedparam(thread_id, policy, &param);
    
    if(sched_error != 0) [[unlikely]] {
        
        if(sched_error == ESRCH){
        
            strcpy(error_buffer, "No Thread With The Thread ID Could Be Found In Setting Scheduling Parameters\n");

        }
        else if(sched_error == EINVAL){
            
            strcpy(error_buffer, "Invalid Scheduling Policy\n");

        }
        else if(sched_error == EPERM){

            strcpy(error_buffer, "Permission Denied For Setting Scheduling Parameters\n");

        }

        // we set our error flag to true
        error.store(true, std::memory_order_release);
        
    }
    
    return error.load(std::memory_order_acquire);

}

bool lock_client_pm::close(unsigned short status_code){ // this closes an established websocket connection although the object itself still exists till it goes out of scope, the object can be connected to a different or the same websocket server using the connect function
    
    if(client_state.load(std::memory_order_acquire) == OPEN){ // only continue if client is in open state
    
        int i = 0; // variable for traversing the send array and building up the close data frame
        unsigned short frame_len = (unsigned short)2; // holds the length of the close data frame - sizeof unsigned short
        unsigned char close_payload[2]; // holds the close payload data which is basically the status code in network byte order
        
        send_data = (char*)send_data_static; // set the send data pointer to the send data static array
        
        send_data[i] = (unsigned char)(FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONNECTION_CLOSE);
        close_payload[i] = (unsigned char)(status_code >> 8); // store the high byte of the status code
        i++;
        
        send_data[i] = MASK_BIT_SET | ((unsigned char)frame_len);
        close_payload[i] = (unsigned char)(0x00FF & status_code); // store the low byte of the status code
        i++;

        for(int j = 0; j<mask_array_len; j++){

            send_data[i] = mask[j]; // store the mask in the send data array
                
            i++;
                
        }
        // mask storing end 
            
        // mask the data and store the masked data in the send data array 
        int k = 0; // variable used to store the mask index of the exact byte in the mask array to mask with
            
        for(int j = 0; j<frame_len; j++){

            k = j % 4;
                
            send_data[i] = close_payload[j] ^ mask[k];  
                
            i++;
                
        }
            
        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
        block_sigpipe_signal();
            
        // send the close frame
        (void)wolfSSL_write(c_ssl, send_data, i); // no need checking whether it was successfully sent through we close the connection nonetheless
        
        // unblock SIGPIPE signal
        unblock_sigpipe_signal();
    
    }
    
    // we disconnect our underlying connection
    reset();

    client_state.store(CLOSED, std::memory_order_release);
    
    return error.load(std::memory_order_acquire);
}

#pragma GCC diagnostic pop