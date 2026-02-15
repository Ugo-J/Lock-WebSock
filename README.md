# LockWebSocket

A lightweight, header-only WebSocket client library for C++ with support for both secure (WSS) and non-secure (WS) connections.

## Features

- Header-only library - just include and use
- Support for both `ws://` and `wss://` protocols
- Blocking (`lock_client`) and non-blocking (`lock_client_nb`) client implementations
- Built on OpenSSL for secure connections
- Custom receive function callbacks
- Ping/Pong support with configurable backlog
- Automatic message fragmentation for large payloads
- Interface binding support for multi-homed systems
- Memory-efficient with static buffers and dynamic allocation fallback

## Requirements

- C++17 or later
- OpenSSL library
- POSIX-compliant system (Linux, macOS, etc.)

## Installation

This is a header-only library. Simply include the necessary headers in your project:

```cpp
#include "lockws.hpp"
```

Make sure to link against OpenSSL when compiling:

```bash
g++ -std=c++17 your_program.cpp -lssl -lcrypto -o your_program
```

## Quick Start

### Basic Connection

```cpp
#include "lockws.hpp"

int main() {
    // Create a blocking WebSocket client
    lock_client client;
    
    // Connect to a WebSocket server
    if (client.connect("wss://example.com:443", "/ws")) {
        std::cout << "Error: " << client.get_error_message() << std::endl;
        return 1;
    }
    
    std::cout << "Connected successfully!" << std::endl;
    
    // Send a message
    client.send(R"({"type":"hello","data":"world"})");
    
    // Receive messages
    while (client.is_open()) {
        client.basic_read();
    }
    
    return 0;
}
```

### Non-Blocking Client

```cpp
#include "lockws.hpp"

int main() {
    lock_client_nb client;
    
    if (!client.connect("wss://stream.example.com:443", "/ws")) {
        // Send subscription message
        client.send(R"({"method":"SUBSCRIBE","params":["data@stream"]})");
        
        // Non-blocking read loop
        while (client.is_open()) {
            client.basic_read();
            // Do other work here
        }
    }
    
    return 0;
}
```

## API Reference

### Classes

#### `lock_client` (Blocking Client)

The main blocking WebSocket client class.

#### `lock_client_nb` (Non-Blocking Client)

Non-blocking variant of the WebSocket client.

Both classes share the same API:

### Constructors

```cpp
// Default constructor
lock_client();

// Connect during construction
lock_client(std::string_view url, std::string_view path = "/");

// Connect with specific network interface
lock_client(std::string_view url, std::string_view path, 
            in_addr* interface_address, char* interface_name);
```

### Connection Methods

#### `connect()`
```cpp
bool connect(std::string_view url, std::string_view path = "/");
```
Establishes a WebSocket connection to the specified URL.

- **Parameters:**
  - `url`: WebSocket URL (e.g., `"wss://example.com:443"` or `"ws://example.com:80"`)
  - `path`: WebSocket path (default: `"/"`)
- **Returns:** `true` on error, `false` on success
- **URL Format:** `ws://hostname:port` or `wss://hostname:port`

**Example:**
```cpp
if (client.connect("wss://echo.websocket.org:443", "/")) {
    std::cerr << "Connection failed: " << client.get_error_message() << std::endl;
}
```

#### `interface_connect()`
```cpp
bool interface_connect(std::string_view url, std::string_view path,
                      in_addr* interface_address, char* interface_name);
```
Connects to a WebSocket server using a specific network interface.

- **Parameters:**
  - `url`: WebSocket URL
  - `path`: WebSocket path
  - `interface_address`: Pointer to the interface IP address
  - `interface_name`: Name of the network interface
- **Returns:** `true` on error, `false` on success

**Example:**
```cpp
in_addr addr;
inet_pton(AF_INET, "192.168.1.100", &addr);
client.interface_connect("wss://example.com:443", "/ws", &addr, "eth0");
```

### Sending Data

#### `send()`
```cpp
bool send(std::string_view message);
```
Sends a text message over the WebSocket connection.

- **Parameters:**
  - `message`: The message to send
- **Returns:** `true` on error, `false` on success
- **Note:** Automatically handles message fragmentation for large payloads

**Example:**
```cpp
if (client.send(R"({"action":"subscribe","channel":"trades"})")) {
    std::cerr << "Send failed" << std::endl;
}
```

### Receiving Data

#### `basic_read()`
```cpp
bool basic_read();
```
Reads incoming WebSocket frames and dispatches them to the appropriate handler.

- **Returns:** `true` on error, `false` on success
- **Note:** Automatically handles ping/pong, close frames, and data frames

**Example:**
```cpp
while (client.is_open()) {
    if (client.basic_read()) {
        std::cerr << "Read error" << std::endl;
        break;
    }
}
```

#### `set_receive_function()`
```cpp
void set_receive_function(lock_function fn);
```
Sets a custom callback function for handling received data.

- **Parameters:**
  - `fn`: Function with signature `int(char* data, int length, int buffer_size)`
    - `data`: Pointer to received data
    - `length`: Length of received data
    - `buffer_size`: Size of the buffer containing the data
    - Return value is ignored by the library

**Example:**
```cpp
int my_receive_handler(char* data, int length, int buffer_size) {
    std::cout << "Received: " << std::string(data, length) << std::endl;
    return 0;
}

client.set_receive_function(my_receive_handler);
```

**Default Behavior:** If no custom function is set, received data is printed to stdout.

### Ping/Pong

#### `ping()`
```cpp
bool ping();
```
Sends a WebSocket ping frame.

- **Returns:** `true` on error, `false` on success

#### `pong()`
```cpp
bool pong(int ping_data_len = 0);
```
Sends a WebSocket pong frame.

- **Parameters:**
  - `ping_data_len`: Length of ping data to echo back (default: 0)
- **Returns:** `true` on error, `false` on success

#### `set_pong_function()`
```cpp
void set_pong_function(lock_function fn);
```
Sets a custom callback for handling received pong frames.

- **Parameters:**
  - `fn`: Function with signature `int(char* data, int length, int buffer_size)`

#### `set_ping_backlog()`
```cpp
bool set_ping_backlog(int backlog_num);
```
Configures how many ping frames to receive before automatically sending a pong.

- **Parameters:**
  - `backlog_num`: Number of pings to accumulate before responding
- **Returns:** `true` on error, `false` on success
- **Default:** Responds to every ping immediately

### Connection Management

#### `close()`
```cpp
bool close(unsigned short status_code = NORMAL_CLOSE);
```
Closes the WebSocket connection gracefully.

- **Parameters:**
  - `status_code`: WebSocket close status code (default: 1000 - Normal Closure)
- **Returns:** `true` on error, `false` on success

**Common Status Codes:**
- `1000` - Normal Closure
- `1001` - Going Away
- `1002` - Protocol Error
- `1003` - Unrecognised Data
- `1007` - Inconsistent Message
- `1008` - Policy Violation
- `1009` - Frame Too Large
- `1011` - Unexpected Condition

**Example:**
```cpp
client.close(1000); // Normal closure
```

#### `is_open()`
```cpp
bool is_open();
```
Checks if the WebSocket connection is currently open.

- **Returns:** `true` if connected, `false` otherwise

### Error Handling

#### `status()`
```cpp
bool status();
```
Checks the error status of the client.

- **Returns:** `true` if an error has occurred, `false` otherwise

#### `get_error_message()`
```cpp
char* get_error_message();
```
Retrieves the last error message.

- **Returns:** Pointer to error message string

**Example:**
```cpp
if (client.status()) {
    std::cerr << "Error: " << client.get_error_message() << std::endl;
}
```

#### `clear()`
```cpp
bool clear();
```
Clears error flags for clients in open state.

- **Returns:** `true` on error, `false` on success
- **Note:** For closed clients, errors can only be cleared by calling `connect()`

## Advanced Usage

### Custom Receive Handler

```cpp
#include "lockws.hpp"
#include <json/json.h> // Example JSON library

int handle_message(char* data, int length, int buffer_size) {
    std::string message(data, length);
    
    // Parse JSON
    Json::Value root;
    Json::Reader reader;
    if (reader.parse(message, root)) {
        std::cout << "Type: " << root["type"].asString() << std::endl;
    }
    
    return 0;
}

int main() {
    lock_client client;
    client.set_receive_function(handle_message);
    
    if (!client.connect("wss://api.example.com:443", "/stream")) {
        while (client.is_open()) {
            client.basic_read();
        }
    }
    
    return 0;
}
```

### Multiple Concurrent Connections

```cpp
#include "lockws.hpp"
#include <thread>

void handle_connection(const char* url, const char* path) {
    lock_client_nb client;
    
    if (!client.connect(url, path)) {
        while (client.is_open()) {
            client.basic_read();
        }
    }
}

int main() {
    std::thread t1(handle_connection, "wss://stream1.example.com:443", "/ws");
    std::thread t2(handle_connection, "wss://stream2.example.com:443", "/ws");
    
    t1.join();
    t2.join();
    
    return 0;
}
```

### Interface-Specific Connection

```cpp
#include "lockws.hpp"
#include <network_interface_handler.hpp>

int main() {
    net_interface_handler network_handler;
    network_handler.get_network_interfaces();
    
    std::cout << network_handler.num_of_network_interfaces 
              << " Network Interfaces Available" << std::endl;
    
    lock_client_nb client;
    
    // Connect using first available interface
    if (!client.interface_connect(
            "wss://stream.example.com:443", 
            "/ws",
            &(network_handler.interface_array[0].ip_addr),
            network_handler.interface_array[0].name)) {
        
        client.send(R"({"method":"SUBSCRIBE","params":["data@stream"]})");
        
        while (client.is_open()) {
            client.basic_read();
        }
    }
    
    return 0;
}
```

## Memory Management

The library uses a hybrid memory allocation strategy:

- **Static buffers** (64KB) for typical use cases - zero allocation overhead
- **Dynamic allocation** automatically kicks in for larger messages
- **Automatic fragmentation** for messages exceeding buffer limits
- **No memory leaks** - all resources cleaned up in destructor

## Thread Safety

- Each `lock_client` or `lock_client_nb` instance is **not thread-safe**
- Use separate instances per thread for concurrent connections
- Synchronize access if sharing an instance across threads

## Protocol Support

- **WebSocket Protocol:** RFC 6455
- **TLS/SSL:** Via OpenSSL (TLS 1.2+)
- **Message Types:** Text and binary frames
- **Extensions:** None (base protocol only)
- **Compression:** Not supported

## Changelog

### 29-03-2024
- Enabled send function to send fragmented messages if message size exceeds static send buffer

### 27-03-2024
- Reduced static send and receive buffer sizes from 1MB/3MB to 64KB each for better compatibility with low-memory systems

### 21-10-2023
- Fixed `num_of_pings_received` reset in pong function to prevent interference with `basic_read()`

### 17-09-2023
- Changed error variable handling from integer to boolean
- Added static casting for all opcodes
- Fixed `length_of_array_data` update for FIN frame reception
- Called `sigemptyset` on oldset before passing to `pthread_sigmask`

### 15-09-2023
- Removed deprecated OpenSSL functions

### 01-08-2023
- Added automatic connection failure detection on send errors
- Implemented SIGPIPE signal blocking to prevent program termination on closed connections

### 31-07-2023
- Fixed send, ping, and pong functions to verify BIO_write return values
- Made ping and pong functions explicitly non-inline

### 25-07-2023
- Increased send data static array from 1KB to 1MB
- Added Server Name Indication (SNI) support for shared-IP servers
- Extended Sec-WebSocket-Accept header parsing for case variations

## License

[Specify your license here]

## Contributing

[Specify contribution guidelines here]

## Support

For issues, questions, or contributions, please [specify contact method or issue tracker].
