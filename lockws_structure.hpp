using lock_function = std::function<int(char*, int, int)>;

class lock_client {
    
public:
    
    //constructors
    lock_client(std::string_view url, std::string_view path);
    lock_client(std::string_view url, std::string_view path, in_addr* interface_address, char* interface_name); // constructor that binds to a particular interface before connection
    lock_client(); // parameterless constructor
    
    // destructor
    ~lock_client();

public:
    
    // public functions
    bool ping(); // ping function
    bool pong(int ping_data_len = 0); // pong function
    bool send(std::string_view); //send function
    bool connect(std::string_view, std::string_view path); // function to connect to a url
    bool connect(std::string_view url, std::string_view path, in_addr* interface_address, char* interface_name); // connect function that binds to a particular interface before connection
    bool close(unsigned short status_code = NORMAL_CLOSE); // closes an open connection of a lock_client instance
    bool status(); // checks the error status of a lock_client instance
    bool is_open();
    char* get_error_message();
    bool basic_read();
    bool set_ping_backlog(int backlog_num);
    bool clear(); // this function is used to clear the error flags of lock clients in open state, error flags of lock clients in closed state can only be cleared by calling the connect function
    inline static int default_pong_receive(char*, int, int); // default function for receiving pong frames
    inline static int default_receive(char*, int, int); // default receive function called by basic read
    void set_receive_function(lock_function fn);
    void set_pong_function(lock_function fn);
    
    

private:
// pointers to receive functions
    
    // receive function pointer
    lock_function recv_data = lock_client::default_receive;
    
    // receive pong function pointer
    lock_function recv_pong = lock_client::default_pong_receive;
    
// private class functions
private:
    
    inline void fail_ws_connection(unsigned short status_code); // function used internally to fail a websocket connection
    inline void block_sigpipe_signal(); // function to block sigpipe signals before any write or read
    void unblock_sigpipe_signal(); // function to unblock sigpipe signals after any write or read
    int connect_to_server(const char *hostname, const char *port, in_addr* interface_address, const char *interface_name); // function to connect to server when we manually configure the socket

// private signal handling variables
private: 
    
    sigset_t oldset; // sigset variable for holding the old signal mask
    sigset_t newset; // sigset variable for holding the signal mask of the signal(s) we wish to block
    siginfo_t si; // siginfo variable for storing the info of blocked signals
    timespec ts = {0}; // structure that stores the time wait for the sigtimedwait function to return, it is initialised to 0 meaning that we don't wait
    
// class wide variables    
private:    
    
    inline static bool openssl_init = false; // bool variable to test if openssl initialisations have been done
    inline static SSL_CTX* ssl_ctx = NULL;
    inline static const char string_to_append[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // this string is appended to the base64 encoded nonce to calculate the Sec-WebSocket-Accept header value and compare with the server's
    inline static const int size_of_SHA1_digest = 20;
    
// instance connection data variables     
private:
    
    static const int url_static_array_length = 1024;
    char c_url_static[url_static_array_length] = {'\0'}; // this url to which the connection is to be made is copied into this array
    uint64_t size_of_allocated_url_memory = 0;
    char* c_url_new = NULL;
    char* c_url = NULL;
    static const int path_static_array_length = 512; 
    char c_path_static[path_static_array_length] = {'\0'}; // static array for holding the channel path
    uint64_t size_of_allocated_path_memory = 0;
    char* c_path_new = NULL; 
    char* c_path = NULL;
    static const int host_static_array_length = 128;
    char c_host_static[host_static_array_length] = {'\0'}; // static array for holding the hostname
    uint64_t size_of_allocated_host_memory = 0;
    char* c_host_new = NULL;
    char* c_host = NULL;
    static const int upgrade_request_array_length = 1024;
    char upgrade_request_static[upgrade_request_array_length] = {'\0'}; // static array for holding the upgrade request
    uint64_t size_of_allocated_upgrade_request_memory = 0;
    char* upgrade_request_new = NULL;
    char* upgrade_request = NULL;
    static const int error_buffer_array_length = 256;
    char error_buffer[error_buffer_array_length] = {'\0'};
    bool error = false;
    unsigned char client_state = CLOSED; // this variable is used to store the lock client state, OPEN meaning there is an active websocket connection and CLOSED meaning that there isn't 
    
// Openssl Library instance variables    
private:
        
   BIO* c_bio = NULL; // sets the lock_client instance connection handle
   BIO* out_bio = NULL; // sets the bio instance used for screen output
   BIO* c_base64 = NULL; //  BIO structure for Base64 encoding
   BIO* c_mem_base64 = NULL; // mem bio that is chained to the base64 filter bio 
   SSL* c_ssl = NULL; // defines the ssl object that is used to set instance-specific openssl options  

// variables for upgrading to and maintaining WebSocket connection    
private:

    static const int rand_byte_array_len = 16; // the random bytes used to generate the nonce is required to be 16 bytes long by the WebSocket protocol 
    unsigned char rand_bytes[rand_byte_array_len] = {'\0'};
    static const int nonce_array_len = 256;
    unsigned char base64_encoded_nonce[nonce_array_len] = {'\0'};
    static const int SHA1_digest_array_len = 32;
    unsigned char SHA1_digest[SHA1_digest_array_len] = {'\0'};
    static const int SHA1_parameter_array_len = 256;
    char SHA1_parameter[SHA1_parameter_array_len] = {'\0'};
    static const int local_sec_ws_accept_key_array_len = 256;
    char local_sec_ws_accept_key[local_sec_ws_accept_key_array_len] = {'\0'};

// lock client states
private: 
    
    inline static const unsigned char OPEN = (unsigned char)0;
    inline static const unsigned char CLOSED = (unsigned char)1;
    
    
// websocket protocol opcodes
private: 
    
    inline static const unsigned char CONTINUATION_FRAME = (unsigned char)0x0;
    inline static const unsigned char TEXT_FRAME = (unsigned char)0x1;
    inline static const unsigned char BINARY_FRAME = (unsigned char)0x2;
    inline static const unsigned char RSV_NON_CONTROL1 = (unsigned char)0x3;
    inline static const unsigned char RSV_NON_CONTROL2 = (unsigned char)0x4;
    inline static const unsigned char RSV_NON_CONTROL3 = (unsigned char)0x5;
    inline static const unsigned char RSV_NON_CONTROL4 = (unsigned char)0x6;
    inline static const unsigned char RSV_NON_CONTROL5 = (unsigned char)0x7;
    inline static const unsigned char CONNECTION_CLOSE = (unsigned char)0x8;
    inline static const unsigned char PING = (unsigned char)0x9;
    inline static const unsigned char PONG = (unsigned char)0xA;
    inline static const unsigned char RSV_CONTROL1 = (unsigned char)0xB;
    inline static const unsigned char RSV_CONTROL2 = (unsigned char)0xC;
    inline static const unsigned char RSV_CONTROL3 = (unsigned char)0xD;
    inline static const unsigned char RSV_CONTROL4 = (unsigned char)0xE;
    inline static const unsigned char RSV_CONTROL5 = (unsigned char)0xF;

// websocket protocol control opcodes
private:

    inline static const unsigned char FIN_BIT_SET = (unsigned char)0x80;
    inline static const unsigned char FIN_BIT_NOT_SET = (unsigned char)0x00;
    inline static const unsigned char RSV_BIT_1_NOT_SET = (unsigned char)0x00;
    inline static const unsigned char RSV_BIT_1_SET = (unsigned char)0x40;
    inline static const unsigned char RSV_BIT_2_NOT_SET = (unsigned char)0x00;
    inline static const unsigned char RSV_BIT_2_SET = (unsigned char)0x20;
    inline static const unsigned char RSV_BIT_3_NOT_SET = (unsigned char)0x00;
    inline static const unsigned char RSV_BIT_3_SET = (unsigned char)0x10;
    inline static const unsigned char RSV_BIT_UNSET_ALL = (unsigned char)0x00;
    inline static const unsigned char MASK_BIT_SET = (unsigned char)0x80;
    inline static const unsigned char MASK_BIT_NOT_SET = (unsigned char)0x00;
    
// close frame status codes 
private:
    
    inline static const unsigned short NORMAL_CLOSE = (unsigned short)1000;
    inline static const unsigned short GOING_AWAY = (unsigned short)1001;
    inline static const unsigned short PROTOCOL_ERROR = (unsigned short)1002;
    inline static const unsigned short UNRECOGNISED_DATA = (unsigned short)1003;
    inline static const unsigned short RESERVED = (unsigned short)1004;
    inline static const unsigned short NO_STATUS_CODE = (unsigned short)1005; // DON'T USE!!
    inline static const unsigned short ABNORMAL_CLOSE = (unsigned short)1006; // DON'T USE!!
    inline static const unsigned short INCONSISTENT_MESSAGE = (unsigned short)1007;
    inline static const unsigned short POLICY_VIOLATION = (unsigned short)1008;
    inline static const unsigned short FRAME_TOO_LARGE = (unsigned short)1009;
    inline static const unsigned short NO_EXTENSION = (unsigned short)1010;
    inline static const unsigned short UNEXPECTED_CONDITION = (unsigned short)1011; // used by servers
    inline static const unsigned short TLS_HANDSHAKE_FAILURE = (unsigned short)1015; // DON'T USE!!
    
// class variables for sending data
private:

    static const int mask_array_len = 4; // used to create an array for storing the data mask
    inline static unsigned char mask[mask_array_len] = {'\0'}; // array to store the send data mask - it is defined to be inline and static because to increase performance the library generates a mask just once when the class is first instantiated and every subsequent lock_client object reuses that same mask to send out every masked frame
   
// instance variables for sending data
private:

    static const int send_data_array_len = 64 * 1024; // 64KB
    unsigned char send_data_static[send_data_array_len] = {'\0'};
    uint64_t size_of_allocated_send_data_memory = 0;
    char* send_data_new = NULL;
    char* send_data = NULL;
    inline static const int biggest_header_len = 14; // stores the highest possible length of a websocket header
    inline static const int MAX_2BYTE_INT = 65536; // this is the max value that can be held by a 2 byte int variable 
    inline static const uint64_t MAX_8BYTE_INT = 9.223372037e+18; // this is the maximum length of a data frame that can be sent with the WebSocket protocol without fragmentation

// instance variables for receiving data
private:
    
    inline static const int static_data_array_length = 64*1024; // received received data static array length 64KB
    char data_array_static[static_data_array_length] = {'\0'}; // static array for holding received data
    char* data_array_new = NULL;
    char* data_array = NULL;
    char* cursor = NULL; // this is used to keep track of and arrange fragmented messages in order
    uint64_t size_of_allocated_data_memory = 0L;
    uint64_t length_of_array = 0L;

// instance variables for handling ping backlogs
private:
    
    int ping_backlog = 0; // this variable sets the number of ping the lock_client instance would receive before sending out a pong response
    int num_of_pings_received = 0;
    
};
