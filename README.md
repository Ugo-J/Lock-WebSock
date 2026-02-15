This is a WebSocket client library for C++ 

The function that is used to receive the data collected by the websocket client has the prototype int fn(char*, int, int), where the char pointer is a pointer to the received data, the second int parameter is the length of the data received, while the third parameter is the length of the array in which the data as stored.

This function can be set with the lock websocket class member function set_receive_function. Although the function prototype specifies that an int return value is expected, it is not used by the library for anything and is just ignored regardless of what value was returned. This return value however can be used by the user supplied function to stop execution mid-way, for example when receiving data from the websocket endpoint and the user wishes to ignore certain data, once they test and confirm that this is indeed the data they wish to ignore, they could use the return statement "return 0;" or any integer they wish to halt further execution of the user supplied function, then the library moves on and delivers the next received data to the user defined function.

If this function is not set, the received data is simply printed to standard output.

Change log - 25-07-2023

The size of the send data static array was increased from 1024 bytes to 1024 * 1024 bytes

The server connection code was extended to accomodate server name identification(SNI) for instances where the lock client needs to make a secure connection to a server that shares its IP address among different hosted domain names

The test for the Sec-Websocket-Accept header was extended to search for every possible lower case and upper case combination of the key word "Sec"

31-07-2023

The send data function, the ping function and the pong function were corrected to now test the return value of BIO_write to ascertain that the send_data was sent successfully

the ping function and pong function were explicitly made non-inline since they contain for loops and the compiler would likely ignore the inline directive

01-08-2023

The lock client was given the functionaliy to be able to fail a websocket connection and set the client in close state if it tries to send a message through the connection and fails either due to the connection being closed by the websocket server or the underlying connection failing. This way a lock client can be put in close state not only when it receives a close frame from the server but also if it tries to send data and the underlying connection is already closed.

The lock client now blocks SIGPIPE signals before any internal calls to BIO_write or BIO_read, this stops the SIGPIPE signal from killing the program, instead if the lock client attempts to read an already closed connection an error is returned and the lock client is put in closed state

15-09-2023
Removed deprecated OpenSSL functions

17-09-2023
Called sigemptyset on the oldset sigset variable before passing it as a parameter to pthread_sigmask

All member functions interact with the error variable as a bool, no longer as an integer

Performed the static casting of all opcodes there in the source file rather than leaving it for the compilation stage

Corrected the length_of_array_data update in the instance of receiving the FIN frame from a series of already received Non-FIN frames

21-10-2023
The num_of_pings_receved variable is now reset in the pong function so that if the user decides to handle sending out pongs themselves the num_of_pings_receved is always reset after a pong frame is sent hence if sending out pong frames is properly timed it is guaranteed to not interfere with basic_read whenever it is called.

27-03-2024
Reduced the static send array and the static receive array sizes to 64KB each from 1MB and 3MB respectively to enable the library be able to fit in the address space of minimal RAM machines

29-03-2024
Enabled the send function to send fragmented messages if the message to be sent is > the static send buffer size
