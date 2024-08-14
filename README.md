# Network Applications Project

## Overview
This project is a collection of network utilities that provide essential networking functionalities, including a ping tool, traceroute utility, a simple web server, and a basic web proxy server. Each application can be executed from the command line, offering straightforward and effective network operations.

## Features

1. **Ping (`ping` or `p`)**: 
   - Sends ICMP Echo Request messages to a specified host to measure round-trip time (RTT).
   - Arguments:
     - `hostname` (required): The host to ping.
     - `--count` or `-c` (optional): Number of echo requests to send (default: 10).
     - `--timeout` or `-t` (optional): Timeout in seconds to wait for a response (default: 2 seconds).
  
2. **Traceroute (`traceroute` or `t`)**:
   - Traces the path packets take from your machine to a specified host, displaying each hop along the way.
   - Arguments:
     - `hostname` (required): The destination host to trace the route to.
     - `--timeout` or `-t` (optional): Timeout in seconds to wait for each hop (default: 2 seconds).
     - `--protocol` or `-p` (optional): Protocol to use (`icmp` or `udp`, default: `icmp`).

3. **Web Server (`web` or `w`)**:
   - A minimal HTTP server that serves files from the current directory.
   - Arguments:
     - `--port` or `-p` (optional): Port number to start the web server on (default: 8080).

4. **Proxy Server (`proxy` or `x`)**:
   - A simple web proxy server with caching capabilities, allowing for efficient web content retrieval.
   - Arguments:
     - `--port` or `-p` (optional): Port number to start the proxy server on (default: 8000).

## Prerequisites

- Python 3.x
- Administrator privileges to run the script (required for operations involving raw sockets, e.g., `ping` and `traceroute`).

## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   ```
2. Navigate to the project directory:
   ```bash
   cd <project_directory>
   ```

## Usage

To run any of the network applications, use the command line to execute the script with the desired command and arguments. Make sure to run the script with `sudo` if it requires raw socket access (such as for `ping` or `traceroute`).

### Examples:

- **Ping a host 5 times with a 3-second timeout:**
  ```bash
  sudo python3 main.py ping lancaster.ac.uk --count 5 --timeout 3
  ```

- **Perform a traceroute to a host using ICMP:**
  ```bash
  sudo python3 main.py traceroute google.com --protocol icmp --timeout 5
  ```

- **Start the web server on port 9090:**
  ```bash
  python3 main.py web --port 9090
  ```

- **Start the proxy server on port 8000:**
  ```bash
  python3 main.py proxy
  ```

### Command Line Arguments

- **Ping**: Measure the latency to a specific host by sending ICMP Echo Requests.
- **Traceroute**: Discover the route packets take to reach a host, identifying each hop along the way.
- **Web Server**: Serve files over HTTP from the current directory, ideal for quick testing or local development.
- **Proxy Server**: Act as an intermediary for web requests, with the added benefit of caching frequently requested content.

## Directory Structure

- **`main.py`**: The primary script that includes the argument parser and initializes the selected network application.
- **`cache/`**: Directory where cached files for the proxy server are stored. It is automatically created if it does not exist.

