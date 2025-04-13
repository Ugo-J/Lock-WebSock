#include "lockws_headers.hpp"
#include "lockws_structure.hpp"

// lock client constructor
lock_client::lock_client(std::string_view url, std::string_view path = "/"){

    // initialisation of class wide variables
    if(!openssl_init){
        
        ssl_ctx = SSL_CTX_new(TLS_client_method()); // initialises the SSL_CTX pointer with method TLS, this SSL_CTX structure is shared among all lock_client instance
        
        // seed the random number generator
        srand(std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch()).count());

        // we generate the static mask the library uses
        int upper_bound = 255;
            
        for(int j = 0; j<mask_array_len; j++){
                
            mask[j] = (unsigned char)(rand() % upper_bound);

        }
        
        openssl_init = true;
        
    }
    
    // set the screen output bio
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE); // sets the out bio to print to stdout
    
    // sets the mem bio 
    c_mem_base64 = BIO_new(BIO_s_mem());
    
    // sets the base64 bio 
    c_base64 = BIO_new(BIO_f_base64()); // initialise the base64 BIO structure
    
    // set the no newline option on the base64 bio to prevent it from adding superfluous newlines to output
    BIO_set_flags(c_base64, BIO_FLAGS_BASE64_NO_NL);
    
    // chain base64 and mem bio 
    BIO_push(c_base64, c_mem_base64);
    
    
    // check if url is a ws:// or wss:// endpoint, check case insensitively
    
    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocal_prefix_len = strlen("wss://");    
        int base_url_length = url.size() - protocal_prefix_len; // saves the length of the url without the wss:// prefix 
            
        // SSL members initialisations
        c_bio = BIO_new_ssl_connect(ssl_ctx); // creates a new bio ssl object
        BIO_get_ssl(c_bio, &c_ssl); // get the SSL structure component of the ssl bio for per instance SSL settings
        if(c_ssl == NULL){
            
            strncpy(error_buffer, "Error fetching SSL structure pointer ", error_buffer_array_length);
                    
            error = true;
            
        }
    
        if(!error){ // the constructor continues only if there was no error fetching the ssl pointer
        
            // URL copy 
            if(base_url_length < url_static_array_length){ // static memory large enough
            
                url.copy(c_url_static, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
            
                c_url_static[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_static;
            
            }
            else if(base_url_length < size_of_allocated_url_memory){ // store in already allocated dynamic memory
                
                url.copy(c_url_new, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
            
                c_url_new[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_new;
                
            
            }
            else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
                
                if(c_url_new == NULL){ // memory has not yet been allocated
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = base_url_length + 1;    
                            
                        url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                        c_url_new[base_url_length] = '\0';
            
                        c_url = c_url_new;
                    
                    }
            
                }
                else{ // memory has been allocated but still isn't large enough
                    
                    delete [] c_url_new; // delete the already allocated memory
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = base_url_length + 1;    
                            
                        url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                        c_url_new[base_url_length] = '\0';

                        c_url = c_url_new;
                    
                    }
                
                }

            }
            
            if(!error){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error 
                
                // set the websocket url(port included)
                BIO_set_conn_hostname(c_bio, c_url);
                
                // set SSL mode to retry automatically should SSL connection fail
                SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);
        
            }
        
        }
    
    }
    
    else if( (url.compare(0, 5, "ws://") == 0) || (url.compare(0, 5, "Ws://") == 0) || (url.compare(0, 5, "wS://") == 0) || (url.compare(0, 5, "WS://") == 0)){ // ws:// endpoint, we test the 4 possible combinations of uppercase and lowercase lettering. The second parameter to the std::string_view compare function is the length of the protocol prefix which we test for the presence of
    
        int protocal_prefix_len = strlen("ws://");    
        int base_url_length = url.size() - protocal_prefix_len; // saves the length of the url without the wss:// prefix 
    
        // URL copy 
        if(base_url_length < url_static_array_length){ // static array is sufficient
    
            url.copy(c_url_static, base_url_length, protocal_prefix_len); // protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
    
            c_url_static[base_url_length] = '\0'; // null-terminate the string
    
            c_url = c_url_static;
    
        }
        else if(base_url_length < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
    
            c_url_new[base_url_length] = '\0'; // null-terminate the string
    
            c_url = c_url_new;
        
    
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
        
            if(c_url_new == NULL){ // memory has not yet been allocated
            
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
           
                if(c_url_new == NULL){
                
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                
                    error = true;
                
                }
                else{
                
                    size_of_allocated_url_memory = base_url_length + 1;    
                    
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
       
                    c_url_new[base_url_length] = '\0';
    
                    c_url = c_url_new;
            
                }
    
            }
            else{ // memory has been allocated but still isn't large enough
            
                delete [] c_url_new; // delete the already allocated memory
            
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
           
                if(c_url_new == NULL){
                
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                
                    error = true;
                
                }
                else{
                
                    size_of_allocated_url_memory = base_url_length + 1;    
                    
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
       
                    c_url_new[base_url_length] = '\0';
    
                    c_url = c_url_new;
            
                }
            
            }
    
        }
    
        if(!error){ // this only runs if the preceding code executed without the error flag being set, meaning all is good
            
            //Non-ssl BIO structure creation
            c_bio = BIO_new_connect(c_url); // creates the non-ssl bio object with the url supplied
     
        }
    
    }
    else{ // not a valid websocket endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid WebSocket endpoint", error_buffer_array_length);
                
        error = true;
        
    }
    // initialisation of BIO and SSL structures end
    
    if(!error){ // only continue if no error
        
        // get the host name out of the stored url
        int last_colon = url.rfind(":"); // get location of last colon
        int last_f_slash = url.rfind("/"); // get location of last forward slash
        
        if(last_colon < last_f_slash){ // This condition checks that the last colon being considered is the colon before the port number and not the colon immediately after the protocol name (wss:// for instance), we do not need to check that a colon and forward slash were found because that part is already checked by the code that checks the endpoint protocol and all protocol names contained in urls have a colon and a forward slash character in them, so so long as execution got here the supplied url has both a colon and a forward slash 
            
            strncpy(error_buffer, "Supplied URL parameter does not conform to the LockWebSocket endpoint convention", error_buffer_array_length);
                    
            error = true;
        
        }
        
        if(!error){ // only continue if no error
            
            int host_name_len = last_colon - last_f_slash - 1;
        
            if( host_name_len < host_static_array_length ){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, last_f_slash + 1);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
                url.copy(c_host_new, host_name_len, last_f_slash + 1);
            
                c_host_new[host_name_len] = '\0';
            
                c_host = c_host_new;
                
            }
            else{ // neither static or already allocated memory is large enough, we test the two possible cases
                
                if(c_host_new == NULL){ // memory has not been allocated yet 
                
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, last_f_slash + 1);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;
            
                    }
                
                }
                else{ // memory has been allocated but it still isn't sufficient
                    
                    delete [] c_host_new; // delete the previously allocated memory
                    
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, last_f_slash + 1);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;

            
                    }
                
                }
                
            }
            
            if(!error){ // only continue if no error
            
                // we set the host name we wish to connect to for server name identification(SNI) if the websocket address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
                if(!(c_ssl == NULL)){
                    
                    if(!SSL_set_tlsext_host_name(c_ssl, c_host)){
                    // we test the return value. SSL_set_tlsext_host_name returns 0 on error and 1 on success
                        
                        strncpy(error_buffer, "Error setting up Lock client for SNI TLS extension", error_buffer_array_length);
                            
                        error = true;
                    
                    }    
                    
                }
                
                if(!error){
                // only continue if no error
                
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
                                
                                error = true;
                                
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
                                
                                error = true;
                                
                            }
                            else{ 
                                
                                size_of_allocated_path_memory = path_string_len + 1;
                                
                                path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                        
                                c_path_new[path_string_len] = '\0'; // null-terminate the array
                        
                                c_path = c_path_new;
                        
                            }
                            
                        }
                        
                    }
                    
                    if(!error){ // only continue if no error

                        // make the connection
                        if(BIO_do_connect(c_bio) <= 0){
                            
                            strncpy(error_buffer, "Error connecting to WebSocket host ", error_buffer_array_length);
                            
                            error = true;
                        
                        }
                        
                        // upgrade the connection to websocket
                        if(!error){ // only continue if no error
                            
                            // fill the random bytes array with 16 random bytes between 0 and 255
                            int upper_bound = 255;
                            for(int i = 0; i < rand_byte_array_len; i++){
                                
                                rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                            }
                            
                            // get the Base-64 encoding of the random number to give the value of the nonce
                            BIO_write(c_base64, rand_bytes, rand_byte_array_len);
                            BIO_flush(c_base64); 
                            BIO_read(c_mem_base64, base64_encoded_nonce, nonce_array_len);
                        
                            // request connection upgrade
                            int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                            char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                            int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                            
                            if( upgrade_request_len < upgrade_request_array_length ){ // static array is large enough
                                
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
                                        
                                        error = true;
                                        
                                        BIO_reset(c_bio); // disconnect the underlying bio
                                        
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
                                    
                                        error = true;
                                        
                                        BIO_reset(c_bio); // disconnect the underlying bio
                                    
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
                        
                            if(!error){ // only continue if no error
                                
                                data_array = data_array_static;
                                BIO_puts(c_bio, upgrade_request);
                                
                                int len = BIO_read(c_bio, data_array, static_data_array_length); // this function call would block till there is data to read
                                data_array[len] = '\0'; // null terminate the received bytes

                                // test for the switching protocol header to confirm that the connection upgrade was successful
                                char success_response[] = "HTTP/1.1 101 Switching Protocols";
                                
                                if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful
                                    
                                    // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                                    
                                    // build the SHA1 parameter
                                    strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                                    strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                                    // SHA1 parameter build end 
                                    
                                    SHA1((const unsigned char*)SHA1_parameter, strlen(SHA1_parameter), SHA1_digest); // get the sha1 hash digest
                                    
                                    // base64 encode the SHA1_digest 
                                    BIO_write(c_base64, SHA1_digest, size_of_SHA1_digest);
                                    BIO_flush(c_base64); 
                                    BIO_read(c_mem_base64, local_sec_ws_accept_key, local_sec_ws_accept_key_array_len);
                                    // base64 encoding of SHA1 digest end 
                                    
                                    // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                                    char key[] = "Sec";
                                    char* cursor = strtok(NULL, "\n");
                                    
                                    while(!(cursor == NULL)){
                                    // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                                        
                                        // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                                        if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                                
                                            cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                            
                                            // compare server's response with our calculation
                                            if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                                
                                                client_state = OPEN;
                                                
                                                break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                                    
                                            }
                                            else{
                                                
                                                strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                                    
                                                BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                                    
                                                error = true;
                                                    
                                                break;
                                                    
                                            }
                                            
                                        }
                                        
                                        cursor = strtok(NULL, "\n");
                                        
                                    }
                                    
                                    if(cursor == NULL){
                                        
                                        // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                                        strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                                        
                                        BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                        
                                        error = true;
                                    
                                    }
                                    
                                }
                                else{ // upgrade unsuccessful
                                    
                                    strncpy(error_buffer, "Connection upgrade failed. Invalid path supplied", error_buffer_array_length);
                                    
                                    BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                    
                                    error = true;
                                    
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

lock_client::lock_client(std::string_view url, std::string_view path = "/", in_addr* interface_address = NULL, char* interface_name = NULL){
}

// lock client parameterless constructor
lock_client::lock_client(){
    
    // initialisation of class wide variables
    if(!openssl_init){
        
        ssl_ctx = SSL_CTX_new(TLS_client_method()); // initialises the SSL_CTX pointer with method TLS, this SSL_CTX structure is shared among all lock_client instance
        
        // seed the random number generator
        srand(std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch()).count());

        // we generate the static mask the library uses
        int upper_bound = 255;
            
        for(int j = 0; j<mask_array_len; j++){
                
            mask[j] = (unsigned char)(rand() % upper_bound);

        }
        
        openssl_init = true;
        
    }
    
    // set the screen output bio
    out_bio = BIO_new_fp(stdout, BIO_NOCLOSE); // sets the out bio to print to stdout
    
    // sets the mem bio 
    c_mem_base64 = BIO_new(BIO_s_mem());
    
    // sets the base64 bio 
    c_base64 = BIO_new(BIO_f_base64()); // initialise the base64 BIO structure
    
    // set the no newline option on the base64 bio to prevent it from adding superfluous newlines to output
    BIO_set_flags(c_base64, BIO_FLAGS_BASE64_NO_NL);
    
    // chain base64 and mem bio 
    BIO_push(c_base64, c_mem_base64);
    
    
}

// lock client destructor
lock_client::~lock_client(){
    
    // close the websocket connection if any
    if(client_state == OPEN){
        
        close();
        
    }
    
    // free url heap memory - this only runs if dynamic memory allocation is used to store the url
    if(!(c_url_new == NULL)){
        
        delete [] c_url_new;
        
    }
    
    // free path heap memory if the path string was stored in dynamic memory
    if(!(c_path_new == NULL)){
        
        delete [] c_path_new;
        
    }
    
    // free host heap memory if host string was stored in dynamic memory
    if(!(c_host_new == NULL)){
        
        delete [] c_host_new;
        
    }
    
    // free upgrade request string heap memory if upgrade request string was stored in dynamic memory
    if(!(upgrade_request_new == NULL)){
        
        delete [] upgrade_request_new;
        
    }
    
    if(c_ssl == NULL && c_url != NULL){// this would mean that this object is not an ssl BIO hence a regular free is sufficient
        
        BIO_free(c_bio);
    }
    else if(c_ssl != NULL && c_url != NULL){// this would mean that the object is an ssl bio
        
        BIO_free_all(c_bio); // frees the ssl bio chain
    }
    
    if(c_base64 != NULL){
        
        BIO_free(c_base64); // free the base64 bio chain
        
    }
    
    if(c_mem_base64 != NULL){
        
        BIO_free(c_mem_base64); // free the mem bio structure
        
    }
    
    if(send_data_new != NULL){
        
        delete [] send_data_new; // free the memory used if the send string is stored on the heap
        
    }
    
    if (data_array_new != NULL){
        
        delete [] data_array_new; // free the memory used to receive data
        
    }
    
    BIO_free(out_bio); // frees the output printing bio
    
}

inline bool lock_client::status(){ // returns the error status of a lock_client instance
    
    return error;
    
}

inline char* lock_client::get_error_message(){ // returns the error message: the reason why a lock_client instance's error flag is set
    
    return error_buffer;
    
}

inline bool lock_client::is_open(){

    if(client_state == OPEN)
        return true;
    else
        return false;
    
}

bool lock_client::ping(){ // sends a ping on an established websocket connection
    
    if(!error){ // only continue if no error
        
        if(client_state == OPEN){ // continue if client is in open state 
            
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
            
            // send out the ping frame
            if(BIO_write(c_bio, send_data, i) <= 0){
                
                // we unblock the sigpipe signal because the fail_ws_connection function blocks it internally
                unblock_sigpipe_signal();

                // here bio_read couldn't fetch any extra data
                strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                error = true;
                
                fail_ws_connection(GOING_AWAY);
                
                // the connection getting lost isn't in itself an error it just puts the lock client in a closed state
                    
            }
            else 
            //we just unblock the SIGPIPE signal
                unblock_sigpipe_signal();
            
            
        }
        else{ // set the error flag if lock client is not in open state
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
                
            error = true;
            
        }
        
    }
    
    return error;
    
}

bool lock_client::pong(int ping_data_len){ // sends out a pong frame unsolicited or in response to a received ping frame
    
    if(!error){ // only continue if no error
        
        if(client_state == OPEN){ // continue if client is in open state
            
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
            
            // send out the pong frame
            if(BIO_write(c_bio, send_data, i) <= 0){
                
                // we unblock the sigpipe signal because the fail_ws_connection function blocks it internally
                unblock_sigpipe_signal();

                // here bio_read couldn't fetch any extra data
                strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                error = true;
                
                fail_ws_connection(GOING_AWAY);
                // the connection getting lost isn't in itself an error it just puts the lock client in a closed state
                    
            }
            else{
                
                //we just unblock the SIGPIPE signal
                unblock_sigpipe_signal();
            
                // we set the num_of_pings_received back to 0
                num_of_pings_received = 0;
                
            }
                
            // zero out the upgrade request static array
            memset(upgrade_request_static, '\0', ping_data_len);
            
        }
        else{
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
                
            error = true;
            
        }
        
    }
    
    return error;
    
}

inline bool lock_client::set_ping_backlog(int backlog_num){
    
    if(!error){ // only continue if no error
        
        // this can be set with a client in closed state
        ping_backlog = backlog_num;
        
    }
    
    return error;
    
}

inline bool lock_client::clear(){ // clear the error flag of a lock client in open state

    if(client_state == OPEN){
            
        memset(error_buffer, '\0', strlen(error_buffer));
            
        error = false;
            
    }
        
    return error;
    
}

bool lock_client::send(std::string_view payload_data){ // sends data passed as parameter along an established websocket connection

    if(!error){ // only continue if no error
        
        if(client_state == OPEN){ // only continue if client is in open state
        
            uint64_t payload_data_len = payload_data.size();
            int i = 0; // variable for traversing the send data array
            
            if( (payload_data_len + biggest_header_len) < send_data_array_len ){ // static array is large enough
                
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
                    
                    error = true;
                    
                    
                }

                if(!error){ // only continue if no error
                    
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
                    
                    // send the data
                    if(BIO_write(c_bio, send_data, i) <= 0){
                    
                        // we unblock the sigpipe signal because the fail_ws_connection function blocks it internally
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                        error = true;
                    
                        fail_ws_connection(GOING_AWAY);
                        // the connection getting lost isn't in itself an error it just puts the lock client in a closed state
                        
                    }
                    else 
                        //we just unblock the SIGPIPE signal
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
                uint64_t frame_data_len = send_data_array_len - biggest_header_len;

                // this variable holds the index of the payload data that the sending continues from after each frame
                uint64_t continuation_index = 0;
                
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
                
                for(uint64_t j = 0; j<frame_data_len; j++){

                    k = j % 4;
                    
                    send_data[i] = payload_data[j] ^ mask[k];
                    
                    i++;
                    
                }

                // increment the continuation index by frame data len
                continuation_index += frame_data_len;

                // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                block_sigpipe_signal();
                
                // send the data
                if(BIO_write(c_bio, send_data, i) <= 0){
                
                    // we unblock the sigpipe signal because the fail_ws_connection function blocks it internally
                    unblock_sigpipe_signal();

                    // here bio_read couldn't fetch any extra data
                    strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                    error = true;
                
                    fail_ws_connection(GOING_AWAY);
                    // the connection getting lost isn't in itself an error it just puts the lock client in a closed state
                    
                }
                else
                    //we just unblock the SIGPIPE signal
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
                        for(uint64_t j = continuation_index; j<payload_data_len; j++){

                            send_data[i] = payload_data[j] ^ mask[k];

                            k = ++k % 4;
                            
                            i++;
                            
                        }

                        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                        block_sigpipe_signal();
                        
                        // send the data
                        if(BIO_write(c_bio, send_data, i) <= 0){
                        
                            // we unblock the sigpipe signal because the fail_ws_connection function blocks it internally
                            unblock_sigpipe_signal();

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                            error = true;
                        
                            fail_ws_connection(GOING_AWAY);
                            // the connection getting lost isn't in itself an error it just puts the lock client in a closed state
                            
                        }
                        else 
                            //we just unblock the SIGPIPE signal
                            unblock_sigpipe_signal();

                    }
                    else{
                    // we send out this frame with the fin bit not set - we do not alter the frame data len in this case as it would still be set to send_data_array_len - biggest_header_len

                        // we set our iterator i back to 0
                        i = 0;
                        
                        // we get our copy boundary index where our frame data for this frame stops
                        uint64_t copy_bound = continuation_index + frame_data_len;

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
                        
                        for(uint64_t j = continuation_index; j<copy_bound; j++){

                            send_data[i] = payload_data[j] ^ mask[k];

                            k = ++k % 4;
                            
                            i++;
                            
                        }

                        // block SIGPIPE signal before attempting to send data, just incase the connection is closed
                        block_sigpipe_signal();
                        
                        // send the data
                        if(BIO_write(c_bio, send_data, i) <= 0){
                        
                            // we unblock the sigpipe signal because the fail_ws_connection function blocks it internally
                            unblock_sigpipe_signal();

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);

                            error = true;
                        
                            fail_ws_connection(GOING_AWAY);
                            // the connection getting lost isn't in itself an error it just puts the lock client in a closed state
                            
                        }
                        else 
                            //we just unblock the SIGPIPE signal
                            unblock_sigpipe_signal();

                    }

                    // increment the continuation index by frame data len
                    continuation_index += frame_data_len;

                }

            }   

        }
        else{ // lock client in closed state
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
            
            error = true;
            
        }
    
    }
        
    return error;
        
}
    
inline int lock_client::default_receive(char* data_array, int length_of_array_data, int length_of_array){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
        
}

inline int lock_client::default_pong_receive(char* data_array, int length_of_array_data, int length_of_array){
    
    std::cout<<data_array<<std::endl;
    
    return 1;
        
}

void lock_client::set_receive_function(lock_function fn){
    
    recv_data = std::move(fn);
    
}

void lock_client::set_pong_function(lock_function fn){
    
    recv_pong = std::move(fn);
    
}

bool lock_client::basic_read(){

    if(!error){ // only continue if no error
        
        if(client_state == OPEN){ // only continue if lock client is in open state
        
            uint64_t frame_data_len = 0; // stores the length of the data frame received
            
            // block SIGPIPE signal before attempting to read data, just incase the connection is closed
            block_sigpipe_signal();
            
            if(BIO_read(c_bio, rand_bytes, 2) <= 0){
            // attempt to read the first two bytes to test the FIN bit, the opcode and the size of the frame. We use the rand bytes array because it is not in use by the program at this point
                
                // here bio_read couldn't fetch any data
                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                error = true;

                // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                unblock_sigpipe_signal();
                
                fail_ws_connection(GOING_AWAY);
                // losing the network connection isn't in itself an error, it just puts the lock client back in closed state
                
                return error;
                
            }
            
            // SIGPIPE signal remains blocked   
            
            if( (rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | TEXT_FRAME)) || (rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | BINARY_FRAME)) ){ // this is the only frame of a text or binary frame data stream. We do not differentiate between text and binary frames since data copy happens the same way
                
                // test the frame length. No need testing the mask bit as server to client frames are always unmasked
                if(rand_bytes[1] < 126){ // this is the length
                    
                    frame_data_len = rand_bytes[1];
                    
                }
                else if( rand_bytes[1] == 126 ){ // next two bytes store the data length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 2 bytes from c_bio to get the length
                    if(BIO_read(c_bio, rand_bytes, 2) <= 0){

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    else{
                    
                        // SIGPIPE signal still remains blocked
                        
                        frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];

                    }
                    
                }
                else if( rand_bytes[1] == 127 ){ // this would mean that the next 8 bytes is our length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 8 bytes from c_bio to get our length

                    if(!(BIO_read(c_bio, rand_bytes, 8) <= 0)){
                    
                        if((rand_bytes[0] & 128) != 0){ // most significant bit of most significant byte is set which is against protocol rules
                            
                            strncpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set", error_buffer_array_length);
                            
                            error = true;

                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();
                            
                            fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                            return error;
                            
                        }
                        
                        // getting here the frame length was successfully read but the SIGPIPE signal still remains blocked

                    }
                    else{
                    // here bio_read couldn't fetch any extra data

                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strncpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ", error_buffer_array_length);
                    
                    error = true;

                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                    unblock_sigpipe_signal();
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error;
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned - SIGPIPE signal is still blocked
                
                uint64_t length_of_array_data = 0;
                
                // test that the size of data to be received can fit into the static data array
                if(frame_data_len < static_data_array_length){ // static data array would be sufficient
                    
                    data_array = data_array_static;
                    cursor = data_array;
                    length_of_array = static_data_array_length;
                    length_of_array_data = frame_data_len;
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

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

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

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
                            
                            strncpy(error_buffer, "Error allocating heap memory for receiving single frame data...frame too large ", error_buffer_array_length);
                    
                            error = true;

                            return error;
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            length_of_array_data = frame_data_len;
                        
                            // SIGPIPE signal is still blocked

                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

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
                            
                            strncpy(error_buffer, "Error allocating heap memory for receiving single frame data after deleting previously allocated memory...frame too large", error_buffer_array_length);
                        
                            error = true;

                            return error;
                        
                        }
                        else{
                            
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                            length_of_array_data = frame_data_len;
                        
                            // SIGPIPE signal is still blocked

                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

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
                else if( rand_bytes[1] == 126 ){ // next two bytes store the data length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 2 bytes from c_bio to get the length
                    if(BIO_read(c_bio, rand_bytes, 2) <= 0){

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    else{
                    
                        // SIGPIPE signal still remains blocked
                        
                        frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];

                    }
                    
                }
                else if( rand_bytes[1] == 127 ){ // this would mean that the next 8 bytes is our length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 8 bytes from c_bio to get our length

                    if(!(BIO_read(c_bio, rand_bytes, 8) <= 0)){
                    
                        if((rand_bytes[0] & 128) != 0){ // most significant bit of most significant byte is set which is against protocol rules
                            
                            strncpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set", error_buffer_array_length);
                            
                            error = true;

                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();
                            
                            fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                            return error;
                            
                        }
                        
                        // getting here the frame length was successfully read but the SIGPIPE signal still remains blocked

                    }
                    else{
                    // here bio_read couldn't fetch any extra data

                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strncpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ", error_buffer_array_length);
                    
                    error = true;

                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                    unblock_sigpipe_signal();
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error;
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned - SIGPIPE signal is still blocked
                
                // test that the size of data to be received can fit into the static data array
                if(frame_data_len < static_data_array_length){ // static data array would be sufficient
                    
                    data_array = data_array_static;
                    cursor = data_array;
                    length_of_array = static_data_array_length;
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

                    }
                    
                    // we don't call user's receive function here because the data is still incomplete
                    
                    // we do not zero out the data array because the data isn't yet complete
                
                }
                else if(frame_data_len < size_of_allocated_data_memory){ // we use allocated heap memory to store the received data
                    
                    data_array = data_array_new;
                    cursor = data_array;
                    length_of_array = size_of_allocated_data_memory;
                    
                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

                    }
                    
                    // we don't call user's receive function here because the data is still incomplete
                    
                    // we do not zero out the data array because the data isn't yet complete
                    
                }
                else{ // neither static nor already allocated memory is sufficient, so we check if memory has been allocated or not 
                    
                    if( data_array_new == NULL ){ // memory has not been allocated
                        
                        data_array_new = new(std::nothrow) char[frame_data_len + 1024]; // we allocate 1KB more than the frame length 
            
                        if(data_array_new == NULL){
                        
                            close(FRAME_TOO_LARGE);
                            
                            // no need to memset as no data has been copied at this point
                            
                            strncpy(error_buffer, "Error allocating heap memory for receiving first frame of continuous frame data...frame too large ", error_buffer_array_length);
                    
                            error = true;

                            return error;
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                    
                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            } 
                        
                            // we do not call user's receive function because data is still incomplete
                            
                            // we do not zero out the data array because the data isn't yet complete
                    
                        }
                        
                    }
                    else{ // there is already allocated memory but it is not sufficient
                    
                        delete [] data_array_new; //delete already allocated memory
                    
                        data_array_new = new(std::nothrow) char[frame_data_len + 1024]; // we allocate extra memory for future use
            
                        if(data_array_new == NULL){
                
                            close(FRAME_TOO_LARGE);
                            
                            // no need to memset as no data has been copied at this point
                            
                            strncpy(error_buffer, "Error allocating heap memory for receiving first frame of continuous frame data ", error_buffer_array_length);
                    
                            error = true;

                            return error;
                    
                        }
                        else{
                        
                            data_array = data_array_new;
                            cursor = data_array;
                            size_of_allocated_data_memory = frame_data_len + 1024;
                            length_of_array = size_of_allocated_data_memory;
                    
                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

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
                else if( rand_bytes[1] == 126 ){ // next two bytes store the data length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 2 bytes from c_bio to get the length
                    if(BIO_read(c_bio, rand_bytes, 2) <= 0){

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    else{
                    
                        // SIGPIPE signal still remains blocked
                        
                        frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];

                    }
                    
                }
                else if( rand_bytes[1] == 127 ){ // this would mean that the next 8 bytes is our length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 8 bytes from c_bio to get our length

                    if(!(BIO_read(c_bio, rand_bytes, 8) <= 0)){
                    
                        if((rand_bytes[0] & 128) != 0){ // most significant bit of most significant byte is set which is against protocol rules
                            
                            strncpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set", error_buffer_array_length);
                            
                            error = true;

                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();
                            
                            fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                            return error;
                            
                        }
                        
                        // getting here the frame length was successfully read but the SIGPIPE signal still remains blocked

                    }
                    else{
                    // here bio_read couldn't fetch any extra data

                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strncpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ", error_buffer_array_length);
                    
                    error = true;

                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                    unblock_sigpipe_signal();
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error;
                    
                }
                
                // reaching here means that we encountered no errors thus far because if we encountered an error the function would have returned - SIGPIPE signal is still blocked
                
                uint64_t length_of_array_data = cursor - data_array; // this is used to store the length of data that the data array currently holds
                
                if(frame_data_len < (length_of_array - length_of_array_data) ){ // array in use is large enough for incoming frame
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

                    }
                    
                    // Don't call user's receive function 
                        
                    
                }
                else if( (data_array == data_array_static) && ( (length_of_array_data + frame_data_len) < size_of_allocated_data_memory) ){ // already allocated memory is large enough
                    
                    data_array = data_array_new; // reassign the data array pointer to point to the allocated memory
                    cursor = data_array;
                    length_of_array = size_of_allocated_data_memory;
                    
                    memcpy(data_array_new, data_array_static, length_of_array_data); // copy the previously received data to the heap memory
                    
                    memset(data_array_static, '\0', length_of_array_data); // zero out the static memory since it is no longer in use
                    
                    cursor += length_of_array_data; // move the cursor forward to point to to the next empty location in the array 
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

                    }
                    
                    // we do not call user's receive function here
                    
                }
                else if( (data_array == data_array_static) && ( (length_of_array_data + frame_data_len) > size_of_allocated_data_memory) ){ // there are two parts to this condition, either memory has been allocated of memory has not been allocated 
                    
                    
                    if( data_array_new == NULL ){ // memory has not been allocated
                        
                        data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // allocate memory 1KB bigger than the length of array data + the length of the incoming continuation frame
            
                        if(data_array_new == NULL){
                            
                            memset(data_array, '\0', length_of_array_data); // zero out already received data
                    
                            cursor = data_array; // set cursor to point back to data array 
                            
                            close(FRAME_TOO_LARGE); // we close the websocket connection with a frame too large error
                            
                            strncpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ", error_buffer_array_length);
                    
                            error = true;

                            return error;
                    
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

                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                        
                            // we do not call the user's receive function here as the data isn't yet complete
                        
                            // we do not zero out the data array because the data isn't yet complete
                    
                        }
                        
                    }
                    else{ // there is already allocated memory but it is not sufficient
                        
                        delete [] data_array_new; //delete already allocated memory
                        
                        data_array_new = new(std::nothrow) char[length_of_array_data + frame_data_len + 1024]; // make the new array 1KB bigger than the previous array length + the incoming continuaton frame length
                        
                        if(data_array_new == NULL){
                    
                            memset(data_array, '\0', length_of_array_data); // zero out already received data
                        
                            cursor = data_array; // set cursor to point back to data array 
                                
                            close(FRAME_TOO_LARGE); // we close the websocket connection with a frame too large error
                                
                            strncpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ", error_buffer_array_length);
                        
                            error = true;

                            return error;
                        
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

                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                        
                            // we do not call user's receive function here
                            
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
                            
                        strncpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ", error_buffer_array_length);
                    
                        error = true;

                        return error;
                    
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

                        int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                        if(len > 0){
                        // bio_read fetched some extra bytes
                        
                            cursor += len;
                            
                            // test that all data was read in
                            while(len < frame_data_len){
                                
                                int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                
                                if(extra_bytes_read > 0){
                                // bio_read fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // bio_read couldn't fetch extra data

                                    // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                    unblock_sigpipe_signal();

                                    // here bio_read couldn't fetch any extra data
                                    strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                    error = true;

                                    fail_ws_connection(GOING_AWAY);

                                    return error;

                                }
                            
                            }

                            // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                            unblock_sigpipe_signal();

                        }
                        else{
                        // bio_read didn't fetch any more data so we fail the connection
                            
                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                            error = true;

                            fail_ws_connection(GOING_AWAY);

                            return error;

                        }
                    
                        // we do not call user's receive function here
                        
                        // we do not zero out the data array because the data isn't yet complete
                    
                    }
                
                }
                
            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONTINUATION_FRAME) ){
                
                // test the frame length. No need testing the mask bit as server to client frames are always unmasked
                if(rand_bytes[1] < 126){ // this is the length
                    
                    frame_data_len = rand_bytes[1];
                    
                }
                else if( rand_bytes[1] == 126 ){ // next two bytes store the data length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 2 bytes from c_bio to get the length
                    if(BIO_read(c_bio, rand_bytes, 2) <= 0){

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    else{
                    
                        // SIGPIPE signal still remains blocked
                        
                        frame_data_len = (rand_bytes[0] << 8) | rand_bytes[1];

                    }
                    
                }
                else if( rand_bytes[1] == 127 ){ // this would mean that the next 8 bytes is our length
                    
                    // getting here the SIGPIPE signal is still blocked

                    // read the next 8 bytes from c_bio to get our length

                    if(!(BIO_read(c_bio, rand_bytes, 8) <= 0)){
                    
                        if((rand_bytes[0] & 128) != 0){ // most significant bit of most significant byte is set which is against protocol rules
                            
                            strncpy(error_buffer, "Protocol error: Most significant bit of 64-bit frame length set", error_buffer_array_length);
                            
                            error = true;

                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();
                            
                            fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                            return error;
                            
                        }
                        
                        // getting here the frame length was successfully read but the SIGPIPE signal still remains blocked

                    }
                    else{
                    // here bio_read couldn't fetch any extra data

                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY); // fail the websocket connection

                        return error;

                    }
                    
                    
                    // getting here there was no error fetching the frame length so we store it
                    frame_data_len =  (rand_bytes[0] << 56) | (rand_bytes[1] << 48) | rand_bytes[2] << 40 | rand_bytes[3] << 32 | rand_bytes[4] << 24 | rand_bytes[5] << 16 | rand_bytes[6] << 8 | rand_bytes[7];
                    
                    
                }
                else{ // unrecognised data length received. This is possible because a malicious of wrongly configured WebSocket server could set the mask bit to 1 hence the library should be able to handle that
                    
                    strncpy(error_buffer, "Unrecognised data length received...WebSocket connection closed ", error_buffer_array_length);
                    
                    error = true;

                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                    unblock_sigpipe_signal();
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error;
                    
                }
                
                uint64_t length_of_array_data = cursor - data_array; // this is used to store the length of data that the data array currently holds
                
                if(frame_data_len < (length_of_array - length_of_array_data) ){ // array in use is large enough for incoming frame
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

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
                    
                    // SIGPIPE signal is still blocked

                    int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                    if(len > 0){
                    // bio_read fetched some extra bytes
                    
                        cursor += len;
                        
                        // test that all data was read in
                        while(len < frame_data_len){
                            
                            int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                            
                            if(extra_bytes_read > 0){
                            // bio_read fetched extra data

                                len += extra_bytes_read;
                                
                                cursor += extra_bytes_read;

                            }
                            else{
                            // bio_read couldn't fetch extra data

                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

                            }
                          
                        }

                        // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                        unblock_sigpipe_signal();

                    }
                    else{
                    // bio_read didn't fetch any more data so we fail the connection
                        
                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                        unblock_sigpipe_signal();

                        // here bio_read couldn't fetch any extra data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        fail_ws_connection(GOING_AWAY);

                        return error;

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
                            
                            strncpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...frame too large ", error_buffer_array_length);
                    
                            error = true;

                            return error;
                    
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

                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

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
                                
                            strncpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...total frame too large ", error_buffer_array_length);
                        
                            error = true;

                            return error;
                        
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

                            int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                            if(len > 0){
                            // bio_read fetched some extra bytes
                            
                                cursor += len;
                                
                                // test that all data was read in
                                while(len < frame_data_len){
                                    
                                    int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                    
                                    if(extra_bytes_read > 0){
                                    // bio_read fetched extra data

                                        len += extra_bytes_read;
                                        
                                        cursor += extra_bytes_read;

                                    }
                                    else{
                                    // bio_read couldn't fetch extra data

                                        // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                        unblock_sigpipe_signal();

                                        // here bio_read couldn't fetch any extra data
                                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                        error = true;

                                        fail_ws_connection(GOING_AWAY);

                                        return error;

                                    }
                                
                                }

                                // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                                unblock_sigpipe_signal();

                            }
                            else{
                            // bio_read didn't fetch any more data so we fail the connection
                                
                                // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                unblock_sigpipe_signal();

                                // here bio_read couldn't fetch any extra data
                                strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                error = true;

                                fail_ws_connection(GOING_AWAY);

                                return error;

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
                            
                        strncpy(error_buffer, "Error allocating heap memory for receiving non fin continuation frame data...total frame too large ", error_buffer_array_length);
                    
                        error = true;

                        return error;
                    
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

                        int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                        if(len > 0){
                        // bio_read fetched some extra bytes
                        
                            cursor += len;
                            
                            // test that all data was read in
                            while(len < frame_data_len){
                                
                                int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                                
                                if(extra_bytes_read > 0){
                                // bio_read fetched extra data

                                    len += extra_bytes_read;
                                    
                                    cursor += extra_bytes_read;

                                }
                                else{
                                // bio_read couldn't fetch extra data

                                    // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                                    unblock_sigpipe_signal();

                                    // here bio_read couldn't fetch any extra data
                                    strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                                    error = true;

                                    fail_ws_connection(GOING_AWAY);

                                    return error;

                                }
                            
                            }

                            // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                            unblock_sigpipe_signal();

                        }
                        else{
                        // bio_read didn't fetch any more data so we fail the connection
                            
                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                            error = true;

                            fail_ws_connection(GOING_AWAY);

                            return error;

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
                    
                        strncpy(error_buffer, "Protocol error: Ping frame received with length greater than 125 bytes", error_buffer_array_length);
                    
                        error = true;
                        
                        memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the faulty ping frame is received when a fragmented message is still being transmitted.
                        
                        cursor = data_array; // set cursor to point back to data array

                        // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                        return error;
                
                    }
                
                    // getting here would mean that no error was encountered
                    
                    frame_data_len = rand_bytes[1];

                    // read in the ping frame data, we use the upgrade request static array because it isn't currently in use by the program
                    if(BIO_read(c_bio, upgrade_request_static, frame_data_len) <= 0){
                    // there was an error reading in the ping frame data

                        // here bio_read couldn't fetch any data
                        strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                        error = true;

                        // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                        unblock_sigpipe_signal();
                        
                        fail_ws_connection(GOING_AWAY);
                        // losing the network connection isn't in itself an error, it just puts the lock client back in closed state
                        
                        return error;

                    }
                    else{
                    // no error reading the ping frame data so we send the response pong frame

                        // we unblock the SIGPIPE signal because the pong function internally blocks it
                        unblock_sigpipe_signal();
                    
                        // the num_of_pings_received variable is set back to 0 in the pong function
                        pong(frame_data_len);

                
                    }

                }
                
            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | CONNECTION_CLOSE) ){
                
                if((cursor != NULL) && (data_array != NULL)){
                
                    memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the close frame is received when a fragmented message is still being transmitted.
                    
                    cursor = data_array; // set cursor to point back to data array
                
                }
                
                if(rand_bytes[1] > 125){ // protocol error as the frame length should not be more than 125
                    
                    strncpy(error_buffer, "Protocol error: Close frame received with length greater than 125 bytes", error_buffer_array_length);
                    
                    error = true;

                    // we unblock the sigpipe signal because fail_ws_connection internally blocks it
                    unblock_sigpipe_signal();
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error;
                
                }
                
                frame_data_len = rand_bytes[1]; // store the close frame response length which would be the same as the close frame received
                data_array = data_array_static; // use the static array because it is always large enough to hold a close frame
                cursor = data_array;
                
                
                int i = 0; // variable for traversing the send array and building up the close data frame response
                
                // SIGPIPE signal is still blocked

                int64_t len = BIO_read(c_bio, cursor, frame_data_len);

                if(len > 0){
                // bio_read fetched some extra bytes
                
                    cursor += len;
                    
                    // test that all data was read in
                    while(len < frame_data_len){
                        
                        int64_t extra_bytes_read = BIO_read(c_bio, cursor, (frame_data_len - len) );
                        
                        if(extra_bytes_read > 0){
                        // bio_read fetched extra data

                            len += extra_bytes_read;
                            
                            cursor += extra_bytes_read;

                        }
                        else{
                        // bio_read couldn't fetch extra data

                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                            error = true;

                            fail_ws_connection(GOING_AWAY);

                            return error;

                        }
                        
                    }

                    // getting here all the frame data has been fetched so we leave the SIGPIPE signal blocked because we still have to send our response close frame

                }
                else{
                // bio_read didn't fetch any more data so we fail the connection
                    
                    // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                    unblock_sigpipe_signal();

                    // here bio_read couldn't fetch any extra data
                    strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                    error = true;

                    fail_ws_connection(GOING_AWAY);

                    return error;

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
                
                // send the close frame response - we do not test the return code of bio_read in this case
                (void)BIO_write(c_bio, send_data, i);
                
                // unblock SIGPIPE signal
                unblock_sigpipe_signal();
                
                BIO_reset(c_bio); // close the existing connection and reset the bio
                
                memset(data_array, '\0', frame_data_len); // zero out the data array
                
                cursor = data_array; // set cursor to point back to data array
                
                // set error flag to indicate that the lock client instance connection has been closed by foreign host
                strncpy(error_buffer, "Lock client WebSocket connection mutually closed after instance received unsolicited close frame from foreign host", error_buffer_array_length);
                
                error = true;
                
                client_state = CLOSED;
                
            }
            else if( rand_bytes[0] == (FIN_BIT_SET | RSV_BIT_UNSET_ALL | PONG) ){
                
                if(rand_bytes[1] > 125){ // protocol error as the frame length of control frames should not be more than 125
                    
                    strncpy(error_buffer, "Protocol error: Pong frame received with length greater than 125 bytes", error_buffer_array_length);
                    
                    error = true;
                    
                    memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if a faulty pong frame is received when a fragmented message is still being transmitted.
                    
                    cursor = data_array; // set cursor to point back to data array
                    
                    fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection

                    return error; 
                
                }
                
                // getting here would mean that no error in the protocol was encountered thus far
                
                frame_data_len = rand_bytes[1]; // read in the data length
                
                // we declare a local cursor with which we read the received ping data into the upgrade_request_static variable because it isn't used by the program at this point
                char* loc_cursor = upgrade_request_static;

                // SIGPIPE signal is still blocked

                int64_t len = BIO_read(c_bio, loc_cursor, frame_data_len);

                if(len > 0){
                // bio_read fetched some extra bytes
                
                    loc_cursor += len;
                    
                    // test that all data was read in
                    while(len < frame_data_len){
                        
                        int64_t extra_bytes_read = BIO_read(c_bio, loc_cursor, (frame_data_len - len) );
                        
                        if(extra_bytes_read > 0){
                        // bio_read fetched extra data

                            len += extra_bytes_read;
                            
                            loc_cursor += extra_bytes_read;

                        }
                        else{
                        // bio_read couldn't fetch extra data

                            // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                            unblock_sigpipe_signal();

                            // here bio_read couldn't fetch any extra data
                            strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                            error = true;

                            fail_ws_connection(GOING_AWAY);

                            return error;

                        }
                        
                    }

                    // getting here all the frame data has been fetched so we unblock the SIGPIPE signal
                    unblock_sigpipe_signal();

                }
                else{
                // bio_read didn't fetch any more data so we fail the connection
                    
                    // we unblock the SIGPIPE signal because the fail_ws_connection function internally blocks it
                    unblock_sigpipe_signal();

                    // here bio_read couldn't fetch any extra data
                    strncpy(error_buffer, "Can't Fetch data from remote host: Check network connection", error_buffer_array_length);

                    error = true;

                    fail_ws_connection(GOING_AWAY);

                    return error;

                }
                
                (void)recv_pong(upgrade_request_static, frame_data_len, upgrade_request_array_length); // call te receive pong function
                
                memset(upgrade_request_static, '\0', frame_data_len);
                    
            }
            else{ // unrecognised protocol opcode received
                
                strncpy(error_buffer, "Unrecognised data frame received ", error_buffer_array_length);
                
                error = true;
                
                memset(data_array, '\0', (cursor - data_array) ); // zero out the data possibly already written to the data array if the an unrecognised frame is received when a fragmented message is still being transmitted.
                
                cursor = data_array; // set cursor to point back to data array
                
                fail_ws_connection(PROTOCOL_ERROR); // fail the websocket connection
                
            }
            
        }
        else{
            
            strncpy(error_buffer, "Lock Client not connected yet", error_buffer_array_length);
                
            error = true;
            
        }
        
    }
        
    return error;
        
}
       
bool lock_client::connect(std::string_view url, std::string_view path = "/"){ // this is used to connect to connect to the url passed as a parameter, it can be used when a lock client object was created without establishing a websocket connection by using the parameterless constructor, or to connect an already established websocket connection and lock client instance to a different websocket server, it can also be used to retry connecting an instance that encountered an error during connection
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a websocket connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        if(close()) // close the open websocket connection 
            
            error = false; // if the close function disconnects the connection because an unrecognised length was received, we need to set the error flag to 0 so that the rest of the connect function can proceed without hitch.
          
            // no need to memset since an unclean close sets the error flag but writes nothing to the error buffer
            
    }
  
    // check if url is a ws:// or wss:// endpoint, check case insensitively
    
    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocal_prefix_len = strlen("wss://");    
        int base_url_length = url.size() - protocal_prefix_len; // saves the length of the url without the wss:// prefix 
            
        // SSL members initialisations
        c_bio = BIO_new_ssl_connect(ssl_ctx); // creates a new bio ssl object
        BIO_get_ssl(c_bio, &c_ssl); // get the SSL structure component of the ssl bio for per instance SSL settings
        if(c_ssl == NULL){
            
            strncpy(error_buffer, "Error fetching SSL structure pointer ", error_buffer_array_length);
                    
            error = true;
            
        }
    
        if(!error){ // the constructor continues only if there was no error fetching the ssl pointer
        
            // URL copy 
            if(base_url_length < url_static_array_length){ // static memory large enough
            
                url.copy(c_url_static, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
            
                c_url_static[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_static;
            
            }
            else if(base_url_length < size_of_allocated_url_memory){ // store in already allocated dynamic memory
                
                url.copy(c_url_new, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
            
                c_url_new[base_url_length] = '\0'; // null-terminate the string
            
                c_url = c_url_new;
                
            
            }
            else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
                
                if(c_url_new == NULL){ // memory has not yet been allocated
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = base_url_length + 1;    
                            
                        url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                        c_url_new[base_url_length] = '\0';
            
                        c_url = c_url_new;
                    
                    }
            
                }
                else{ // memory has been allocated but still isn't large enough
                    
                    delete [] c_url_new; // delete the already allocated memory
                    
                    // heap memory allocation for urls larger than the static array length
                    c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
                
                    
                    if(c_url_new == NULL){
                        
                        strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                        
                        error = true;
                        
                    }
                    else{
                        
                        size_of_allocated_url_memory = base_url_length + 1;    
                            
                        url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
                
                        c_url_new[base_url_length] = '\0';

                        c_url = c_url_new;
                    
                    }
                
                }

            }
            
            if(!error){ // checks if there was any error allocating memory, that is if that part of the code was executed. The constructor only continues if there was no error 
                
                // set the websocket url(port included)
                BIO_set_conn_hostname(c_bio, c_url);
                
                // set SSL mode to retry automatically should SSL connection fail
                SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);
        
            }
        
        }
    
    }
    
    else if( (url.compare(0, 5, "ws://") == 0) || (url.compare(0, 5, "Ws://") == 0) || (url.compare(0, 5, "wS://") == 0) || (url.compare(0, 5, "WS://") == 0)){ // ws:// endpoint, we test the 4 possible combinations of uppercase and lowercase lettering. The second parameter to the std::string_view compare function is the length of the protocol prefix which we test for the presence of
    
        int protocal_prefix_len = strlen("ws://");    
        int base_url_length = url.size() - protocal_prefix_len; // saves the length of the url without the wss:// prefix 
    
        // URL copy 
        if(base_url_length < url_static_array_length){ // static array is sufficient
    
            url.copy(c_url_static, base_url_length, protocal_prefix_len); // protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
    
            c_url_static[base_url_length] = '\0'; // null-terminate the string
    
            c_url = c_url_static;
    
        }
        else if(base_url_length < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
    
            c_url_new[base_url_length] = '\0'; // null-terminate the string
    
            c_url = c_url_new;
        
    
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
        
            if(c_url_new == NULL){ // memory has not yet been allocated
            
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
           
                if(c_url_new == NULL){
                
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                
                    error = true;
                
                }
                else{
                
                    size_of_allocated_url_memory = base_url_length + 1;    
                    
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
       
                    c_url_new[base_url_length] = '\0';
    
                    c_url = c_url_new;
            
                }
    
            }
            else{ // memory has been allocated but still isn't large enough
            
                delete [] c_url_new; // delete the already allocated memory
            
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
           
                if(c_url_new == NULL){
                
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                
                    error = true;
                
                }
                else{
                
                    size_of_allocated_url_memory = base_url_length + 1;    
                    
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
       
                    c_url_new[base_url_length] = '\0';
    
                    c_url = c_url_new;
            
                }
            
            }
    
        }
    
        if(!error){ // this only runs if the preceding code executed without the error flag being set, meaning all is good
            
            //Non-ssl BIO structure creation
            c_bio = BIO_new_connect(c_url); // creates the non-ssl bio object with the url supplied
     
        }
    
    }
    else{ // not a valid websocket endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid WebSocket endpoint", error_buffer_array_length);
                
        error = true;
        
    }
    // initialisation of BIO and SSL structures end
    
    if(!error){ // only continue if no error
        
        // get the host name out of the stored url
        int last_colon = url.rfind(":"); // get location of last colon
        int last_f_slash = url.rfind("/"); // get location of last forward slash
        
        if(last_colon < last_f_slash){ // This condition checks that the last colon being considered is the colon before the port number and not the colon immediately after the protocol name (wss:// for instance), we do not need to check that a colon and forward slash were found because that part is already checked by the code that checks the endpoint protocol and all protocol names contained in urls have a colon and a forward slash character in them, so so long as execution got here the supplied url has both a colon and a forward slash
            
            strncpy(error_buffer, "Supplied URL parameter does not conform to the LockWebSocket endpoint convention", error_buffer_array_length);
                    
            error = true;
        
        }
        
        if(!error){ // only continue if no error
            
            int host_name_len = last_colon - last_f_slash - 1;
        
            if( host_name_len < host_static_array_length ){ // static array is large enough
            
                url.copy(c_host_static, host_name_len, last_f_slash + 1);
            
                c_host_static[host_name_len] = '\0';
            
                c_host = c_host_static;
            
            }
            else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
                
                url.copy(c_host_new, host_name_len, last_f_slash + 1);
            
                c_host_new[host_name_len] = '\0';
            
                c_host = c_host_new;
                
            }
            else{ // neither static or already allocated memory is large enough, we test the two possible cases
                
                if(c_host_new == NULL){ // memory has not been allocated yet 
                
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, last_f_slash + 1);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;
            
                    }
                
                }
                else{ // memory has been allocated but it still isn't sufficient
                    
                    delete [] c_host_new; // delete the previously allocated memory
                    
                    c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                    if(c_host_new == NULL){
                
                        strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                    
                        error = true;    
                
                    }
                    else{
                        
                        size_of_allocated_host_memory = host_name_len + 1;
                        
                        url.copy(c_host_new, host_name_len, last_f_slash + 1);
            
                        c_host_new[host_name_len] = '\0';
            
                        c_host = c_host_new;

            
                    }
                
                }
                
            }
            
            if(!error){ // only continue if no error
            
                // we set the host name we wish to connect to for server name identification(SNI) if the websocket address passed is a wss:// address. We test this by checking that the c_ssl pointer is non-null
                if(!(c_ssl == NULL)){
                    
                    if(!SSL_set_tlsext_host_name(c_ssl, c_host)){
                    // we test the return value. SSL_set_tlsext_host_name returns 0 on error and 1 on success
                        
                        strncpy(error_buffer, "Error setting up Lock client for SNI TLS extension", error_buffer_array_length);
                            
                        error = true;
                    
                    } 
                    
                }
                
                if(!error){
                // only continue if no error
                
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
                                
                                error = true;
                                
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
                                
                                error = true;
                                
                            }
                            else{ 
                                
                                size_of_allocated_path_memory = path_string_len + 1;
                                
                                path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                        
                                c_path_new[path_string_len] = '\0'; // null-terminate the array
                        
                                c_path = c_path_new;
                        
                            }
                            
                        }
                        
                    }
                    
                    if(!error){ // only continue if no error

                        // make the connection
                        if(BIO_do_connect(c_bio) <= 0){
                            
                            strncpy(error_buffer, "Error connecting to WebSocket host ", error_buffer_array_length);
                            
                            error = true;
                        
                        }
                        
                        // upgrade the connection to websocket
                        if(!error){ // only continue if no error
                            
                            // fill the random bytes array with 16 random bytes between 0 and 255
                            int upper_bound = 255;
                            for(int i = 0; i < rand_byte_array_len; i++){
                                
                                rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                            }
                            
                            // get the Base-64 encoding of the random number to give the value of the nonce
                            BIO_write(c_base64, rand_bytes, rand_byte_array_len);
                            BIO_flush(c_base64); 
                            BIO_read(c_mem_base64, base64_encoded_nonce, nonce_array_len);
                        
                            // request connection upgrade
                            int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                            char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                            int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                            
                            if( upgrade_request_len < upgrade_request_array_length ){ // static array is large enough
                                
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
                                        
                                        error = true;
                                        
                                        BIO_reset(c_bio); // disconnect the underlying bio
                                        
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
                                    
                                        error = true;
                                        
                                        BIO_reset(c_bio); // disconnect the underlying bio
                                    
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
                        
                            if(!error){ // only continue if no error
                                
                                data_array = data_array_static;
                                BIO_puts(c_bio, upgrade_request);
                                
                                int len = BIO_read(c_bio, data_array, static_data_array_length); // this function call would block till there is data to read
                                data_array[len] = '\0'; // null terminate the received bytes

                                // test for the switching protocol header to confirm that the connection upgrade was successful
                                char success_response[] = "HTTP/1.1 101 Switching Protocols";
                                
                                if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful
                                    
                                    // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                                    
                                    // build the SHA1 parameter
                                    strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                                    strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                                    // SHA1 parameter build end 
                                    
                                    SHA1((const unsigned char*)SHA1_parameter, strlen(SHA1_parameter), SHA1_digest); // get the sha1 hash digest
                                    
                                    // base64 encode the SHA1_digest 
                                    BIO_write(c_base64, SHA1_digest, size_of_SHA1_digest);
                                    BIO_flush(c_base64); 
                                    BIO_read(c_mem_base64, local_sec_ws_accept_key, local_sec_ws_accept_key_array_len);
                                    // base64 encoding of SHA1 digest end 
                                    
                                    // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                                    char key[] = "Sec";
                                    char* cursor = strtok(NULL, "\n");
                                    
                                    while(!(cursor == NULL)){
                                    // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                                        
                                        // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                                        if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                                
                                            cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                            
                                            // compare server's response with our calculation
                                            if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                                
                                                client_state = OPEN;
                                                
                                                break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                                    
                                            }
                                            else{
                                                
                                                strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                                    
                                                BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                                    
                                                error = true;
                                                    
                                                break;
                                                    
                                            }
                                            
                                        }
                                        
                                        cursor = strtok(NULL, "\n");
                                        
                                    }
                                    
                                    if(cursor == NULL){
                                        
                                        // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                                        strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                                        
                                        BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                        
                                        error = true;
                                    
                                    }
                                    
                                }
                                else{ // upgrade unsuccessful
                                    
                                    strncpy(error_buffer, "Connection upgrade failed. Invalid path or url supplied", error_buffer_array_length);
                                    
                                    BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                    
                                    error = true;
                                    
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

    return error;
        
}

bool lock_client::interface_connect(std::string_view url, std::string_view path = "/", in_addr* interface_address = NULL, char* interface_name = NULL){
    
    if(client_state == CLOSED){
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase previous error message
        
        error = false;
        
    }
    else{ // the lock client instance has a websocket connection in open state
        
        memset(error_buffer, '\0', strlen(error_buffer)); // erase any previous error message
        
        error = false; // sets the error flag to false first so the close function can run 
        
        if(close()) // close the open websocket connection 
            
            error = false; // if the close function disconnects the connection because an unrecognised length was received, we need to set the error flag to 0 so that the rest of the connect function can proceed without hitch.
          
            // no need to memset since an unclean close sets the error flag but writes nothing to the error buffer
            
    }

    // check if url is a ws:// or wss:// endpoint, check case insensitively
    
    if( (url.compare(0, 6, "wss://") == 0) || (url.compare(0, 6, "Wss://") == 0) || (url.compare(0, 6, "WSs://") == 0) || (url.compare(0, 6, "WSS://") == 0) || (url.compare(0, 6, "WsS://") == 0) || (url.compare(0, 6, "wSS://") == 0) || (url.compare(0, 6, "wsS://") == 0) || (url.compare(0, 6, "wSs://") == 0) ){ // endpoint is a wss:// endpoint, the second parameter to the std::string_view compare function is 6 which is the length of the string "wss://" which we are testing for the presence of, we list out and compare the 8 possible combinations of uppercase and lowercase lettering that are valid
    
        int protocal_prefix_len = strlen("wss://");    
        int base_url_length = url.size() - protocal_prefix_len; // saves the length of the url without the wss:// prefix 
        
        // we copy the URL into the c_url array
        if(base_url_length < url_static_array_length){ // static memory large enough
        
            url.copy(c_url_static, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
        
            c_url_static[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_static;
        
        }
        else if(base_url_length < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
        
            c_url_new[base_url_length] = '\0'; // null-terminate the string
        
            c_url = c_url_new;
            
        
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
        
            if(c_url_new == NULL){ // memory has not yet been allocated
                
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
            
                if(c_url_new == NULL){
                    
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                    
                    error = true;
                    
                }
                else{
                    
                    size_of_allocated_url_memory = base_url_length + 1;    
                        
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
        
                    c_url_new[base_url_length] = '\0';
        
                    c_url = c_url_new;
                
                }
        
            }
            else{ // memory has been allocated but still isn't large enough
                
                delete [] c_url_new; // delete the already allocated memory
                
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
            
                
                if(c_url_new == NULL){
                    
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                    
                    error = true;
                    
                }
                else{
                    
                    size_of_allocated_url_memory = base_url_length + 1;    
                        
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
            
                    c_url_new[base_url_length] = '\0';

                    c_url = c_url_new;
                
                }
            
            }

        }

        // get the host name out of the stored url
        int last_colon = url.rfind(":"); // get location of last colon
        int last_f_slash = url.rfind("/"); // get location of last forward slash
        
        if(last_colon < last_f_slash){ // This condition checks that the last colon being considered is the colon before the port number and not the colon immediately after the protocol name (wss:// for instance), we do not need to check that a colon and forward slash were found because that part is already checked by the code that checks the endpoint protocol and all protocol names contained in urls have a colon and a forward slash character in them, so so long as execution got here the supplied url has both a colon and a forward slash
            
            strncpy(error_buffer, "Supplied URL parameter does not conform to the LockWebSocket endpoint convention", error_buffer_array_length);
                    
            error = true;
        
        }

        int host_name_len = last_colon - last_f_slash - 1;
        
        if( host_name_len < host_static_array_length ){ // static array is large enough
        
            url.copy(c_host_static, host_name_len, last_f_slash + 1);
        
            c_host_static[host_name_len] = '\0';
        
            c_host = c_host_static;
        
        }
        else if( host_name_len < size_of_allocated_host_memory){ // dynamic memory is large enough
            
            url.copy(c_host_new, host_name_len, last_f_slash + 1);
        
            c_host_new[host_name_len] = '\0';
        
            c_host = c_host_new;
            
        }
        else{ // neither static or already allocated memory is large enough, we test the two possible cases
            
            if(c_host_new == NULL){ // memory has not been allocated yet 
            
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
        
                if(c_host_new == NULL){
            
                    strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                
                    error = true;    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, last_f_slash + 1);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;
        
                }
            
            }
            else{ // memory has been allocated but it still isn't sufficient
                
                delete [] c_host_new; // delete the previously allocated memory
                
                c_host_new = new(std::nothrow) char[host_name_len + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
        
                if(c_host_new == NULL){
            
                    strncpy(error_buffer, "Error allocating heap memory for server host name ", error_buffer_array_length);
                
                    error = true;    
            
                }
                else{
                    
                    size_of_allocated_host_memory = host_name_len + 1;
                    
                    url.copy(c_host_new, host_name_len, last_f_slash + 1);
        
                    c_host_new[host_name_len] = '\0';
        
                    c_host = c_host_new;

        
                }
            
            }
            
        }

        // we create a local char array to hold the port extracted from the url
        const int MAX_CHAR_FOR_PORT = 8; // a port number can have a maximum of 5 characters because port numbers are 16 bit integers
        char c_port[MAX_CHAR_FOR_PORT];

        // we now copy the port from the url starting from the last colon
        int num_of_chars_copied = url.copy(c_port, MAX_CHAR_FOR_PORT, last_colon + 1);

        // we null terminate the c_port array
        c_port[num_of_chars_copied] = '\0';

        // now we can call the connect to server function that would return the configured socket file descriptor
        int sock = connect_to_server(c_host, c_port, interface_address, interface_name);

        if(error == false){
        // only continue if no error

            // we create an SSL object for this lock client instance
            SSL *c_ssl = SSL_new(ssl_ctx);
            if(c_ssl == NULL){
                
                strncpy(error_buffer, "Error creating SSL structure ", error_buffer_array_length);
                error = true;
                return error;
            }
        
            // Set SNI
            SSL_set_tlsext_host_name(c_ssl, c_host);

            // set SSL mode to retry automatically should SSL connection fail
            SSL_set_mode(c_ssl, SSL_MODE_AUTO_RETRY);

            // Create BIO for this socket
            BIO* sock_bio = BIO_new_socket(sock, BIO_NOCLOSE);
            if (!sock_bio) {
                SSL_free(c_ssl);
                close(sock);
                strncpy(error_buffer, "Error creating BIO structure from socket", error_buffer_array_length);          
                error = true;
                return error;
            }

            // now we create an SSL BIO
            BIO* ssl_bio = BIO_new(BIO_f_ssl());
            BIO_set_ssl(ssl_bio, c_ssl, BIO_CLOSE);

            // Chain ssl_bio and sock_bio together
            c_bio = BIO_push(ssl_bio, sock_bio);

            // Initialize SSL connection
            SSL_set_connect_state(c_ssl);  // Set as client

            // Perform handshake
            if (BIO_do_handshake(c_bio) <= 0) {
                std::cout << "SSL handshake failed"<< std::endl;
                BIO_free_all(c_bio); // this throws segmentation fault when called without any network connection
                strncpy(error_buffer, "SSL handshake failed", error_buffer_array_length);          
                error = true;
                return error;
            }
            else{
                std::cout << "SSL handshake successful"<< std::endl;
            }

            // we fetch the path for this connection

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
                        
                        error = true;
                        
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
                        
                        error = true;
                        
                    }
                    else{ 
                        
                        size_of_allocated_path_memory = path_string_len + 1;
                        
                        path.copy(c_path_new, path_string_len); // copy the path into the dynamically allocated array
                
                        c_path_new[path_string_len] = '\0'; // null-terminate the array
                
                        c_path = c_path_new;
                
                    }
                    
                }
                
            }
            
            // upgrade the connection to websocket
            if(!error){ // only continue if no error
                
                // fill the random bytes array with 16 random bytes between 0 and 255
                int upper_bound = 255;
                for(int i = 0; i < rand_byte_array_len; i++){
                    
                    rand_bytes[i] = (unsigned char)(rand() % upper_bound ); // we get a random byte between 0 and 255 and cast it into a one byte value

                }
                
                // get the Base-64 encoding of the random number to give the value of the nonce
                BIO_write(c_base64, rand_bytes, rand_byte_array_len);
                BIO_flush(c_base64); 
                BIO_read(c_mem_base64, base64_encoded_nonce, nonce_array_len);
            
                // request connection upgrade
                int length_of_supplied_data = strlen(c_path) + strlen( (const char*)base64_encoded_nonce) + strlen(c_host);
                char char_remaining[] = "GET  HTTP/1.1\nHost: \nConnection: Upgrade\nPragma: no-cache\nUpgrade: websocket\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: \n\n";
                int upgrade_request_len = strlen(char_remaining) + length_of_supplied_data;
                
                if( upgrade_request_len < upgrade_request_array_length ){ // static array is large enough
                    
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
                            
                            error = true;
                            
                            BIO_reset(c_bio); // disconnect the underlying bio
                            
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
                        
                            error = true;
                            
                            BIO_reset(c_bio); // disconnect the underlying bio
                        
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
            
                if(!error){ // only continue if no error
                    
                    data_array = data_array_static;
                    BIO_puts(c_bio, upgrade_request);
                    
                    int len = BIO_read(c_bio, data_array, static_data_array_length); // this function call would block till there is data to read
                    data_array[len] = '\0'; // null terminate the received bytes

                    // test for the switching protocol header to confirm that the connection upgrade was successful
                    char success_response[] = "HTTP/1.1 101 Switching Protocols";
                    
                    if(strncmp(success_response, strtok(data_array, "\n"), strlen(success_response)) == 0){ // upgrade successful
                        
                        // Authorise connection - confirm that the Sec-WebSocket-Accept is what it should be by calculating the key and comparing it with the server's
                        
                        // build the SHA1 parameter
                        strncpy(SHA1_parameter, (const char*)base64_encoded_nonce, SHA1_parameter_array_len);
                        strncat(SHA1_parameter, string_to_append, SHA1_parameter_array_len - strlen(SHA1_parameter));
                        // SHA1 parameter build end 
                        
                        SHA1((const unsigned char*)SHA1_parameter, strlen(SHA1_parameter), SHA1_digest); // get the sha1 hash digest
                        
                        // base64 encode the SHA1_digest 
                        BIO_write(c_base64, SHA1_digest, size_of_SHA1_digest);
                        BIO_flush(c_base64); 
                        BIO_read(c_mem_base64, local_sec_ws_accept_key, local_sec_ws_accept_key_array_len);
                        // base64 encoding of SHA1 digest end 
                        
                        // loop through the rest of the response string to find the Sec-WebSocket-Accept header
                        char key[] = "Sec";
                        char* cursor = strtok(NULL, "\n");
                        
                        while(!(cursor == NULL)){
                        // we keep looping through the HTTP upgrade request response till either cursor == NULL or we find our Sec-WebSocket-Key header
                            
                            // we use sizeof so we can get the length of key as a compile time constan, we subtract 1 from the result of sizeof() to account for the null byte that terminates the string
                            if((strncmp(key, cursor, sizeof(key) - 1) == 0) || (strncmp("sec", cursor, sizeof(key) - 1) == 0) || (strncmp("SEC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEc", cursor, sizeof(key) - 1) == 0) || (strncmp("seC", cursor, sizeof(key) - 1) == 0) || (strncmp("sEC", cursor, sizeof(key) - 1) == 0) || (strncmp("SEc", cursor, sizeof(key) - 1) == 0) || (strncmp("SeC", cursor, sizeof(key) - 1) == 0)){ // only the Sec-WebSocket-key response header would have "Sec" in it so we test all possible upper and lower case combinations of the key word "sec"
                                    
                                cursor += strlen("Sec-WebSocket-Accept: "); //move cursor foward to point to accept key value
                                
                                // compare server's response with our calculation
                                if(strncmp(local_sec_ws_accept_key, cursor, strlen(local_sec_ws_accept_key)) == 0){
                                    
                                    client_state = OPEN;
                                    
                                    break; // break if the server sec websocket key matches what we calculated. Connection authorised
                                        
                                }
                                else{
                                    
                                    strncpy(error_buffer, "Connection authorisation Failed", error_buffer_array_length);
                                        
                                    BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                                        
                                    error = true;
                                        
                                    break;
                                        
                                }
                                
                            }
                            
                            cursor = strtok(NULL, "\n");
                            
                        }
                        
                        if(cursor == NULL){
                            
                            // getting here means no Sec-Websocket-Key header was found before strtok returned a null value
                            strncpy(error_buffer, "Invalid Upgrade request response received", error_buffer_array_length);
                            
                            BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                            
                            error = true;
                        
                        }
                        
                    }
                    else{ // upgrade unsuccessful
                        
                        strncpy(error_buffer, "Connection upgrade failed. Invalid path supplied", error_buffer_array_length);
                        
                        BIO_reset(c_bio); // reset bio and disconnect the underlying connection
                        
                        error = true;
                        
                    }
                                        
                    memset(data_array, '\0', len); // zero out the data array

                    memset(upgrade_request, '\0', upgrade_request_len); // zero out the upgrade request array
            
                }
            
            }
        }
    }
    
    else if( (url.compare(0, 5, "ws://") == 0) || (url.compare(0, 5, "Ws://") == 0) || (url.compare(0, 5, "wS://") == 0) || (url.compare(0, 5, "WS://") == 0)){ // ws:// endpoint, we test the 4 possible combinations of uppercase and lowercase lettering. The second parameter to the std::string_view compare function is the length of the protocol prefix which we test for the presence of
    
        int protocal_prefix_len = strlen("ws://");    
        int base_url_length = url.size() - protocal_prefix_len; // saves the length of the url without the wss:// prefix 
    
        // URL copy 
        if(base_url_length < url_static_array_length){ // static array is sufficient
    
            url.copy(c_url_static, base_url_length, protocal_prefix_len); // protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the static character array
    
            c_url_static[base_url_length] = '\0'; // null-terminate the string
    
            c_url = c_url_static;
    
        }
        else if(base_url_length < size_of_allocated_url_memory){ // store in already allocated dynamic memory
        
            url.copy(c_url_new, base_url_length, protocal_prefix_len); // protocol prefix len specifies the starting point where the copy should begin, the url.copy copies the string view object into the already allocated character array
    
            c_url_new[base_url_length] = '\0'; // null-terminate the string
    
            c_url = c_url_new;
        
    
        }
        else{ // neither static or dynamic memory is large enough, we test whether memory has already been allocated or not 
        
            if(c_url_new == NULL){ // memory has not yet been allocated
            
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
           
                if(c_url_new == NULL){
                
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                
                    error = true;
                
                }
                else{
                
                    size_of_allocated_url_memory = base_url_length + 1;    
                    
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
       
                    c_url_new[base_url_length] = '\0';
    
                    c_url = c_url_new;
            
                }
    
            }
            else{ // memory has been allocated but still isn't large enough
            
                delete [] c_url_new; // delete the already allocated memory
            
                // heap memory allocation for urls larger than the static array length
                c_url_new = new(std::nothrow) char[base_url_length + 1]; // the nothrow parameter prevents an exception from being thrown by the C++ runtime should the heap allocation fail
        
           
                if(c_url_new == NULL){
                
                    strncpy(error_buffer, "Error allocating heap memory for lock_client url parameter ", error_buffer_array_length);
                
                    error = true;
                
                }
                else{
                
                    size_of_allocated_url_memory = base_url_length + 1;    
                    
                    url.copy(c_url_new, base_url_length, protocal_prefix_len); // the int protocol prefix specifies the starting point where the copy should begin, the url.copy copies the string view object into the allocated character array
       
                    c_url_new[base_url_length] = '\0';
    
                    c_url = c_url_new;
            
                }
            
            }
    
        }
    
        if(!error){ // this only runs if the preceding code executed without the error flag being set, meaning all is good
            
            //Non-ssl BIO structure creation
            c_bio = BIO_new_connect(c_url); // creates the non-ssl bio object with the url supplied
     
        }
    
    }
    else{ // not a valid websocket endpoint
        
        strncpy(error_buffer, "Supplied URL parameter is not a valid WebSocket endpoint", error_buffer_array_length);
                
        error = true;
        
    }

    return error;
}

int lock_client::connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name){
    struct addrinfo hints, *res = NULL, *p = NULL;

    // we create the socket the BIO structure would use
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cout<<"Error creating socket"<<std::endl;
        strncpy(error_buffer, "Error creating socket", error_buffer_array_length);          
        error = true;
        return -1;
    }

    // Bind to a specific device
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0) {
        std::cout<<"Error binding socket to device"<<std::endl;
        perror("setsockopt(SO_BINDTODEVICE)");
        strncpy(error_buffer, "Error binding socket to device", error_buffer_array_length);          
        error = true;
        close(sock);
        return -1;
    }
    else{
        std::cout<<"Successfully bound socket to device "<<interface_name<<std::endl;
    }

    // Set up local address structure
    struct sockaddr_in localaddr;
    memset(&localaddr, 0, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = interface_address->s_addr;
    localaddr.sin_port = 0;  // Lets the system choose port

    // Bind socket to specific interface
    if (bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0) {
        // if the binding fails the library does not set the error flag to true it just prints the error message, ignores the specified interface and attempts to make the connection with whatever network interface is available
        std::cout<<"Lockws Error: Binding To Supplied Interface Address Failed...Connection Will Be Attempted With The Default Network Interface Address..."<<std::endl;
    }

    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // IPv4 (use AF_UNSPEC for both IPv4 and IPv6)
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    // Perform DNS resolution
    if (getaddrinfo(hostname, port, &hints, &res) != 0) {
        std::cout<<"Error resolving hostname: "<<hostname<<std::endl;
        strncpy(error_buffer, "Error resolving hostname", error_buffer_array_length);          
        error = true;
        return -1;
    }

    // Iterate over results and try to connect
    for(p = res; p != NULL; p = p->ai_next) {

        // Try to connect
        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            std::cout<<"Connected to "<<hostname<<std::endl;
            break; // Connected successfully
        }

        perror("connect");
        close(sock);
        sock = -1;
    }

    if(res != NULL)
        freeaddrinfo(res); // Free the addrinfo structure if non null

    if (sock < 0) {
        std::cout<<"Failed to connect to "<<hostname<<':'<<port<<std::endl;
        strncpy(error_buffer, "Failed to connect to host", error_buffer_array_length);          
        error = true;
        return -1;
    }

    return sock; // Return the connected socket
}

void lock_client::block_sigpipe_signal(){

    sigemptyset(&newset);
    sigemptyset(&oldset);
    sigaddset(&newset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &newset, &oldset);
    
}

void lock_client::unblock_sigpipe_signal(){

    // clear out any SIGPIPE signal that came in while we blocked it
    while(sigtimedwait(&newset, &si, &ts) >= 0 || errno != EAGAIN);
    
    // restore the previous signal mask of the calling thread
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);
    
    
}

void lock_client::fail_ws_connection(unsigned short status_code){

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
    (void)BIO_write(c_bio, send_data, i); // no need checking whether it was successfully sent through we close the connection nonetheless
            
    unblock_sigpipe_signal();
            
    // close the underlying connection, don't wait for server response
    BIO_reset(c_bio);
            
    client_state = CLOSED; // sets the client state back to closed

    // we set the lock client error variable
    strncpy(error_buffer, "Websocket Connection Lost", error_buffer_array_length);
                
    error = true;
    
}
     
bool lock_client::close(unsigned short status_code){ // this closes an established websocket connection although the object itself still exists till it goes out of scope, the object can be connected to a different or the same websocket server using the connect function

    if(!error){ // only continue if no error
        
        if(client_state == OPEN){ // only continue if client is in open state
        
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
            BIO_write(c_bio, send_data, i);
            
            // unblock SIGPIPE signal
            unblock_sigpipe_signal();

            // after sending the close frame we do not attempt to read any more data from the server we just disconnect the underlying network connection
            BIO_reset(c_bio);
                
            client_state = CLOSED;
     
        }
        else{
            
            strncpy(error_buffer, "Lock Client not connected", error_buffer_array_length);
                
            error = true;
            
        }
                
    }
    
    return error; // returning an error of 1 from the close function just means that the close was not a clean one but it was successful nonetheless, and the close function does not write any message to the error buffer
        
}
