[![progress-banner](https://backend.codecrafters.io/progress/bittorrent/72de9b75-e90d-4e57-947c-d6d0269f4e29)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

# C++ BitTorrent Client

A fully functional BitTorrent client written in C++ as part of the [CodeCrafters BitTorrent Challenge](https://codecrafters.io/challenges/bittorrent). 

This client is capable of parsing Bencoded data, interacting with HTTP trackers, communicating via the Peer Wire Protocol, and downloading files using both **.torrent files** and **Magnet links**. It also implements the **Extension Protocol (BEP 10)** to fetch metadata from peers directly.

## Features

- **BEncoding:** Robust decoder and encoder for the BitTorrent file format.
- **Torrent File Parsing:** Extracts announce URLs, info hashes, file lengths, and piece hashes.
- **Tracker Communication:** Connects to HTTP trackers to retrieve peer lists.
- **Peer Wire Protocol:**
  - Performs handshakes.
  - Manages peer states (choking/unchoking).
  - Pipelined block downloading.
  - SHA-1 integrity checking for downloaded pieces.
- **Magnet Link Support:**
  - Parses Magnet URIs.
  - Implements **BEP 9/10 (Extension Protocol)**.
  - Performs the Extension Handshake.
  - Retrieves `.torrent` metadata (Info Dictionary) from peers via `ut_metadata`.
  - Downloads files purely from an Info Hash without a starting `.torrent` file.

## Dependencies

To build and run this project, you need the following:

1.  **C++ Compiler**: GCC or Clang (supporting C++11 or later).
2.  **CMake**: Version 3.10 or higher.
3.  **OpenSSL**: Required for SHA-1 hashing.
    * *Debian/Ubuntu:* `sudo apt-get install libssl-dev`
    * *macOS:* `brew install openssl`
4.  **nlohmann/json**: Used for JSON manipulation (included in `lib/` or requires installation).

## Build Instructions

You can build the project using the provided helper script or standard CMake commands.

Usage

The application is run via the command line. Below are the supported commands.
1. BEncode Debugging

Decodes a Bencoded string and prints the JSON representation.
Bash

./your_program.sh decode <bencoded_string>
# Example:
./your_program.sh decode "d3:foo3:bare"

2. Torrent File Operations

Parse Torrent Info Prints the tracker URL, file length, info hash, and piece hashes.
Bash

./your_program.sh info <path_to_torrent_file>

Discover Peers Connects to the tracker defined in the torrent file and lists available peers (IP:Port).
Bash

./your_program.sh peers <path_to_torrent_file>

Peer Handshake Establishes a TCP connection with a specific peer and performs the BitTorrent handshake.
Bash

./your_program.sh handshake <path_to_torrent_file> <peer_ip>:<peer_port>

Download a Specific Piece Downloads a single piece from the torrent to a specified output path.
Bash

./your_program.sh download_piece <output_path> <path_to_torrent_file> <piece_index>

Download Full File Downloads the entire file specified in the torrent.
Bash

./your_program.sh download <output_path> <path_to_torrent_file>

3. Magnet Link Operations

Parse Magnet Link Extracts the Tracker URL and Info Hash from a magnet link.
Bash

./your_program.sh magnet_parse <magnet_link>

Magnet Handshake Connects to a peer from the magnet link and performs a handshake indicating support for extensions.
Bash

./your_program.sh magnet_handshake <magnet_link>

Fetch Metadata (Magnet Info) Connects to a peer, performs the extension handshake, and requests the Info Dictionary (metadata) via the ut_metadata extension. Prints file details.
Bash

./your_program.sh magnet_info <magnet_link>

Download Piece via Magnet Fetches metadata first, then downloads a specific piece using the magnet link.
Bash

./your_program.sh magnet_download_piece <output_path> <magnet_link> <piece_index>

Download Full File via Magnet Fetches metadata, calculates piece requirements, and downloads the entire file using the magnet link.
Bash

./your_program.sh magnet_download <output_path> <magnet_link>

Project Structure

    src/main.cpp: Contains the core logic, including:

        BEncoder class: Handles parsing and encoding of bencoded data.

        Network class: Manages TCP sockets, connections, and raw data transmission.

        Utils class: Helper functions for SHA1 hashing, Hex conversion, and URL encoding.

        Client class: High-level BitTorrent logic (Handshakes, Message parsing, Piece downloading, Extension protocol).

License

This project is based on the CodeCrafters BitTorrent challenge.
