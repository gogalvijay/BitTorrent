#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;


std::string url_encode(const unsigned char *d, size_t n) {
    std::ostringstream o;
    o << std::hex << std::uppercase;
    for (size_t i = 0; i < n; i++)
        o << '%' << std::setw(2) << std::setfill('0') << int(d[i]);
    return o.str();
}

std::string random_peer_id() {
    std::string s = "-CC0001-";
    std::random_device r;
    while (s.size() < 20) s += char('0' + (r() % 10));
    return s;
}





//--------------------------------encode---------------------------
std::string bencode(const json &j);

std::string bencode_int(long long x) {
    return "i" + std::to_string(x) + "e";
}

std::string bencode_string(const std::string &s) {
    return std::to_string(s.size()) + ":" + s;
}

std::string bencode_list(const json &j) {
    std::string out = "l";
    for (const auto &elem : j) {
        out += bencode(elem);
    }
    out += "e";
    return out;
}

std::string bencode_dict(const json &j) {
    std::string out = "d";

    std::vector<std::string> keys;
    for (auto it = j.begin(); it != j.end(); ++it) {
        keys.push_back(it.key());
    }
    sort(keys.begin(), keys.end());

    for (const auto &key : keys) {
        out += bencode_string(key);  
        out += bencode(j.at(key));   
    }

    out += "e";
    return out;
}

std::string bencode(const json &j) {
    if (j.is_number_integer()) {
        return bencode_int(j.get<long long>());
    }
    else if (j.is_string()) {
        return bencode_string(j.get<std::string>());
    }
    else if (j.is_array()) {
        return bencode_list(j);
    }
    else if (j.is_object()) {
        return bencode_dict(j);
    }

    throw std::runtime_error("Unsupported type in bencode");
}




//--------------------------------decode-----------------------

long long decode_integer(const std::string& s, int& l) {
    if (s[l] != 'i') throw std::runtime_error("Expected 'i' at integer start");
    l++; 
    bool minus = false;
    if (s[l] == '-') { minus = true; l++; }

    long long val = 0;
    while (std::isdigit(s[l])) {
        val = val * 10 + (s[l] - '0');
        l++;
    }
    if (s[l] != 'e') throw std::runtime_error("Expected 'e' at integer end");
    l++; 

    return minus ? -val : val;
}

// Decode a string at position l in the encoded string
std::string decode_string(const std::string& s, int& l) {
    int sz = 0;
    while (std::isdigit(s[l])) {
        sz = sz * 10 + (s[l] - '0');
        l++;
    }
    if (s[l] != ':') throw std::runtime_error("Expected ':' after string length");
    l++; 

    std::string result;
    for (int i = 0; i < sz; i++) {
        result += s[l++];
    }
    return result;
}

// Decode a list at position l in the encoded string
json decode_list(const std::string& s, int& l) {
    if (s[l] != 'l') throw std::runtime_error("Expected 'l' at list start");
    l++; 

    json result = json::array();
    while (s[l] != 'e') {
        if (std::isdigit(s[l])) { 
            result.push_back(decode_string(s, l));
        }
        else if (s[l] == 'i') { 
            result.push_back(decode_integer(s, l));
        }
        else if (s[l] == 'l') { 
            result.push_back(decode_list(s, l));
        }
        else {
            throw std::runtime_error("Unhandled encoded value: " + s.substr(l, 10));
        }
    }
    l++; 
    return result;
}

// Decode a dictionary at position l in the encoded string

json decode_dictionary(const std::string &s, int &l) {
    if (s[l] != 'd') throw std::runtime_error("Expected 'd' at dictionary start");
    l++; 

    json result = json::object();

    while (s[l] != 'e') {
       
        std::string key_string;
        long long key_int;

        if (std::isdigit(s[l])) {
            key_string = decode_string(s, l);
        } else if (s[l] == 'i') {
            key_int = decode_integer(s, l);
            key_string = std::to_string(key_int); 
        } else {
            throw std::runtime_error("Invalid key type in dictionary");
        }

        if (std::isdigit(s[l])) {
            result[key_string] = decode_string(s, l);
        } else if (s[l] == 'i') {
            result[key_string] = decode_integer(s, l);
        } else if (s[l] == 'l') {
            result[key_string] = decode_list(s, l);
        } else if (s[l] == 'd') {
            result[key_string] = decode_dictionary(s, l); 
        } else {
            throw std::runtime_error("Invalid value type in dictionary");
        }
    }

    l++; 
    return result;
}

	


// Decode any Bencoded value
json decode_bencoded_value(const std::string& s) {
    int pos = 0;
    if (std::isdigit(s[0])) { // string
        return decode_string(s, pos);
    }
    else if (s[0] == 'i') { // integer
        return decode_integer(s, pos);
    }
    else if (s[0] == 'l') { // list
        return decode_list(s, pos);
    }
    else if(s[0] == 'd'){//dictionary
    	 return decode_dictionary(s,pos);
    }
    else {
        throw std::runtime_error("Unhandled encoded value: " + s);
    }
}


std::ostringstream hex_converter( unsigned char *hash){

        std::ostringstream hex;
	for (int i = 0; i < 20; i++) {
	    	hex << std::hex
		<< std::setw(2)
		<< std::setfill('0')
		<< ((int)hash[i] & 0xff);
	    }
	return hex;
}


void recv_all(int sock, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(sock, buf + got, n - got, 0);
        if (r <= 0) exit(1);
        got += r;
    }
}

int parse_int(const std::string &s) {
    int result = 0;
    for (char c : s) {
        if (c >= '0' && c <= '9') {
            result = result * 10 + (c - '0');
        } else {
            std::cerr << "Invalid character in number: " << c << "\n";
            exit(1);
        }
    }
    return result;
}


bool verify_piece(const std::vector<uint8_t>& piece_data,const std::string& pieces,int piece_index) {
    unsigned char hash[20];
    SHA1(piece_data.data(), piece_data.size(), hash);

    for (int i = 0; i < 20; i++) {
        if ((unsigned char)pieces[piece_index * 20 + i] != hash[i])
            return false;
    }
    return true;
}


int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std::cerr << "Logs from your program will appear here!" << std::endl;

        // TODO: Uncomment the code below to pass the first stage
          std::string encoded_value = argv[2];
          json decoded_value = decode_bencoded_value(encoded_value);
          std::cout << decoded_value.dump() << std::endl;
    } 
    else if (command == "info") {
	    std::string file_name = argv[2];

	    std::ifstream in(file_name, std::ios::binary);
	    if (!in) {
		std::cerr << "Error opening file\n";
		return 1;
	    }

	    std::string file_content(
		(std::istreambuf_iterator<char>(in)),
		std::istreambuf_iterator<char>()
	    );

	    json decode_file = decode_bencoded_value(file_content);
	    
	    std::cout << "Tracker URL: " << decode_file["announce"].get<std::string>() << "\n";
	    //std::cout << "File Name: "  << decode_file["info"]["name"] << "\n";
	    std::cout << "Length: "     << decode_file["info"]["length"].get<int>() << "\n";
	    
	    //std::cerr<<decode_file<<'\n';
	    
	    auto info_content =decode_file["info"];
	    
	    auto encoded_content_hash=bencode(info_content);
	    
	    
	    unsigned char hash[20];
	    SHA1((unsigned char*)encoded_content_hash.data(),
                  encoded_content_hash.size(),
		  hash);

	   std::ostringstream hex=hex_converter(hash);  
	   std::cout << "Info Hash: " << hex.str() << "\n"; 
	   
	   
	   auto piece_len = decode_file["info"]["piece length"].get<int>();
	   auto pieces = decode_file["info"]["pieces"].get<std::string>();
	    

	   
	   std::cout<< "Piece Length: "<<piece_len<< "\n";
	   std::cout<<"Piece Hashes:"<<"\n";
	   
	   
	   
	   int j = 0;
	   for (size_t i = 0; i < pieces.size(); i++) {
	        hash[j++] = (unsigned char)pieces[i];

	        if (j == 20) {
		    std::ostringstream hex = hex_converter(hash);
		    std::cout << hex.str() << '\n';
		    j = 0;
	        }
	   }

 		
	   
	   
	   
    }
    
    else if (command == "peers") {
    std::string file_name = argv[2];

    std::ifstream in(file_name, std::ios::binary);
    if (!in) return 1;

    std::string file_content(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );

    json meta = decode_bencoded_value(file_content);
    json info = meta["info"];

    long long length = info["length"].get<long long>();

    std::string encoded_info = bencode(info);

    unsigned char info_hash[20];
    SHA1(
        (unsigned char *)encoded_info.data(),
        encoded_info.size(),
        info_hash
    );

    std::string peer_id =random_peer_id();

    std::string announce = meta["announce"].get<std::string>();
    std::string url = announce.substr(7);
    size_t slash = url.find('/');
    std::string hostport = url.substr(0, slash);
    std::string path = url.substr(slash);

    std::string host, port = "80";
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
    } else {
        host = hostport;
    }

    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return 1;

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) return 1;

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) return 1;
    freeaddrinfo(res);

    auto url_encode = [](const unsigned char *d, size_t n) {
        std::ostringstream o;
        o << std::hex << std::uppercase;
        for (size_t i = 0; i < n; i++)
            o << '%' << std::setw(2) << std::setfill('0') << int(d[i]);
        return o.str();
    };

    std::ostringstream req;
    req << "GET " << path
        << "?info_hash=" << url_encode(info_hash, 20)
        << "&peer_id=" << url_encode((unsigned char *)peer_id.data(), 20)
        << "&port=6881"
        << "&uploaded=0"
        << "&downloaded=0"
        << "&left=" << length
        << "&compact=1 HTTP/1.0\r\n"
        << "Host: " << host << "\r\n"
        << "Connection: close\r\n\r\n";

    std::string request = req.str();
    send(sockfd, request.data(), request.size(), 0);

    std::vector<uint8_t> response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sockfd, buf, sizeof(buf), 0)) > 0)
        response.insert(response.end(), buf, buf + n);

    close(sockfd);

    auto it = std::search(
        response.begin(),
        response.end(),
        "\r\n\r\n",
        "\r\n\r\n" + 4
    );

    if (it == response.end()) return 0;
    it += 4;

    std::string body(it, response.end());
    int pos = 0;
    json tracker = decode_dictionary(body, pos);

    if (!tracker.contains("peers")) return 0;

    std::string peers = tracker["peers"].get<std::string>();

    for (size_t i = 0; i + 6 <= peers.size(); i += 6) {
        uint8_t a = peers[i];
        uint8_t b = peers[i + 1];
        uint8_t c = peers[i + 2];
        uint8_t d = peers[i + 3];

        uint16_t p =
            ((uint8_t)peers[i + 4] << 8) |
            (uint8_t)peers[i + 5];

        std::cout
            << (int)a << "."
            << (int)b << "."
            << (int)c << "."
            << (int)d
            << ":" << p << "\n";
    }
  }
  
   else if (command == "handshake")
{
    std::string peer_info = argv[3];
    std::string peer_ip, peer_port;

    int i = 0;
    while (i < (int)peer_info.size() && peer_info[i] != ':')
        peer_ip += peer_info[i++];

    i++;
    while (i < (int)peer_info.size())
        peer_port += peer_info[i++];

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0)
        return 1;

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(stoi(peer_port));
    serverAddress.sin_addr.s_addr = inet_addr(peer_ip.c_str());

    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
        return 1;

    std::ifstream in(argv[2], std::ios::binary);
    if (!in)
        return 1;

    std::string file_content(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );

    json meta = decode_bencoded_value(file_content);
    json info = meta["info"];
    std::string encoded_info = bencode(info);

    unsigned char info_hash[20];
    SHA1(
        (unsigned char*)encoded_info.data(),
        encoded_info.size(),
        info_hash
    );

    std::vector<uint8_t> handshake;
    handshake.push_back(19);

    std::string proto = "BitTorrent protocol";
    handshake.insert(handshake.end(), proto.begin(), proto.end());

    handshake.insert(handshake.end(), 8, 0);
    handshake.insert(handshake.end(), info_hash, info_hash + 20);

    std::string peer_id = random_peer_id();
    handshake.insert(handshake.end(), peer_id.begin(), peer_id.end());

    send(clientSocket, handshake.data(), handshake.size(), 0);

    std::vector<uint8_t> response(68);
    int received = 0;
    while (received < 68) {
        int r = recv(clientSocket, response.data() + received, 68 - received, 0);
        if (r <= 0)
            return 1;
        received += r;
    }

    int offset = 1 + 19 + 8 + 20;
    std::cout << "Peer ID: ";
    for (int i = 0; i < 20; i++)
        printf("%02x", response[offset + i]);
    std::cout << "\n";
 }
 
 else if (command == "download_piece") {
       
        if (argc < 6) {
            std::cerr << "Usage: download_piece -o <output_path> <torrent_path> <piece_index>\n";
            return 1;
        }

        std::string output_path = argv[3];
        std::string torrent_path = argv[4];
        int piece_index = parse_int(argv[5]);

        std::ifstream in(torrent_path, std::ios::binary);
        if (!in) {
            std::cerr << "Failed to open torrent file\n";
            return 1;
        }

        std::string file_content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        json meta = decode_bencoded_value(file_content);
        json info = meta["info"];
        
        long long file_length = info["length"].get<long long>();
        int piece_length = info["piece length"].get<int>();
        std::string encoded_info = bencode(info);

        unsigned char info_hash[20];
        SHA1((unsigned char*)encoded_info.data(), encoded_info.size(), info_hash);

        
        std::string announce = meta["announce"].get<std::string>();
        std::string url = announce.substr(7);
        size_t slash = url.find('/');
        std::string hostport = url.substr(0, slash);
        std::string path = url.substr(slash);

        std::string host, port = "80";
        size_t colon = hostport.find(':');
        if (colon != std::string::npos) {
            host = hostport.substr(0, colon);
            port = hostport.substr(colon + 1);
        } else {
            host = hostport;
        }

        addrinfo hints{}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return 1;

        int trackerSock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (trackerSock < 0) return 1;
        if (connect(trackerSock, res->ai_addr, res->ai_addrlen) < 0) return 1;
        freeaddrinfo(res);

        std::string my_peer_id = random_peer_id();
        
       
        auto url_encode_local = [](const unsigned char *d, size_t n) {
            std::ostringstream o;
            o << std::hex << std::uppercase;
            for (size_t i = 0; i < n; i++) o << '%' << std::setw(2) << std::setfill('0') << int(d[i]);
            return o.str();
        };

        std::ostringstream req;
        req << "GET " << path
            << "?info_hash=" << url_encode_local(info_hash, 20)
            << "&peer_id=" << url_encode_local((unsigned char *)my_peer_id.data(), 20)
            << "&port=6881"
            << "&uploaded=0"
            << "&downloaded=0"
            << "&left=" << file_length
            << "&compact=1 HTTP/1.0\r\n"
            << "Host: " << host << "\r\n"
            << "Connection: close\r\n\r\n";

        std::string request = req.str();
        send(trackerSock, request.data(), request.size(), 0);

        std::vector<uint8_t> tracker_response;
        char buf[4096];
        ssize_t n;
        while ((n = recv(trackerSock, buf, sizeof(buf), 0)) > 0)
            tracker_response.insert(tracker_response.end(), buf, buf + n);
        close(trackerSock);

       
        auto it = std::search(tracker_response.begin(), tracker_response.end(), "\r\n\r\n", "\r\n\r\n" + 4);
        if (it == tracker_response.end()) return 1;
        std::string body(it + 4, tracker_response.end());
        int pos = 0;
        json tracker_dict = decode_dictionary(body, pos);
        std::string peers_bin = tracker_dict["peers"].get<std::string>();

        if (peers_bin.size() < 6) return 1;

  
        uint8_t a = peers_bin[0], b = peers_bin[1], c = peers_bin[2], d = peers_bin[3];
        uint16_t p = ((uint8_t)peers_bin[4] << 8) | (uint8_t)peers_bin[5];
        std::string peer_ip = std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d);
        int peer_port_num = p;

        std::cout << "Connecting to peer: " << peer_ip << ":" << peer_port_num << "\n";

        int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket < 0) return 1;

        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(peer_port_num);
        serverAddress.sin_addr.s_addr = inet_addr(peer_ip.c_str());

        if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) return 1;

        
        std::vector<uint8_t> handshake;
        handshake.push_back(19);
        std::string prot = "BitTorrent protocol";
        handshake.insert(handshake.end(), prot.begin(), prot.end());
        handshake.insert(handshake.end(), 8, 0);
        handshake.insert(handshake.end(), info_hash, info_hash + 20);
        handshake.insert(handshake.end(), my_peer_id.begin(), my_peer_id.end());

        send(clientSocket, handshake.data(), handshake.size(), 0);

        std::vector<uint8_t> response_handshake(68);
        recv_all(clientSocket, response_handshake.data(), 68);

       
        uint32_t len_interested = htonl(1);
        uint8_t id_interested = 2;
        send(clientSocket, &len_interested, 4, 0);
        send(clientSocket, &id_interested, 1, 0);

        while (true) {
            uint32_t msg_len;
            recv_all(clientSocket, (uint8_t*)&msg_len, 4);
            msg_len = ntohl(msg_len);
            if (msg_len == 0) continue;

            uint8_t msg_id;
            recv_all(clientSocket, &msg_id, 1);

            if (msg_id == 1) { 
                break;
            } else {
                std::vector<uint8_t> skip(msg_len - 1);
                recv_all(clientSocket, skip.data(), msg_len - 1);
            }
        }

      
        int current_piece_size = piece_length;
      
        int total_pieces = (file_length + piece_length - 1) / piece_length;
        if (piece_index == total_pieces - 1) {
            int remainder = file_length % piece_length;
            if (remainder != 0) current_piece_size = remainder;
        }

        int block_size = 16 * 1024; 
        int downloaded = 0;
        std::ofstream out(output_path, std::ios::binary);

        while (downloaded < current_piece_size) {
            int this_block_len = block_size;
            if (current_piece_size - downloaded < block_size) {
                this_block_len = current_piece_size - downloaded;
            }

           
            uint32_t msg_len_req = htonl(13);
            uint8_t msg_id_req = 6;
            uint32_t idx = htonl(piece_index);
            uint32_t begin = htonl(downloaded);
            uint32_t req_len = htonl(this_block_len);

            send(clientSocket, &msg_len_req, 4, 0);
            send(clientSocket, &msg_id_req, 1, 0);
            send(clientSocket, &idx, 4, 0);
            send(clientSocket, &begin, 4, 0);
            send(clientSocket, &req_len, 4, 0);

            
            uint32_t msg_len_resp;
            recv_all(clientSocket, (uint8_t*)&msg_len_resp, 4);
            msg_len_resp = ntohl(msg_len_resp);

            uint8_t msg_id_resp;
            recv_all(clientSocket, &msg_id_resp, 1);

            if (msg_id_resp != 7) return 1; 

            uint32_t recv_idx, recv_begin;
            recv_all(clientSocket, (uint8_t*)&recv_idx, 4);
            recv_all(clientSocket, (uint8_t*)&recv_begin, 4);

            int data_len = msg_len_resp - 9;
            std::vector<uint8_t> block_data(data_len);
            recv_all(clientSocket, block_data.data(), data_len);

            out.write((char*)block_data.data(), data_len);
            downloaded += data_len;
        }

        out.close();
        close(clientSocket);
        std::cout << "Piece " << piece_index << " downloaded to " << output_path << "\n";
    }
    
    else if (command == "download") {

    if (argc < 5) {
        std::cerr << "Usage: download -o <output_path> <torrent_path>\n";
        return 1;
    }

    std::string output_path = argv[3];
    std::string torrent_path = argv[4];

  
    std::ifstream in(torrent_path, std::ios::binary);
    if (!in) return 1;

    std::string file_content(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );

    json meta = decode_bencoded_value(file_content);
    json info = meta["info"];

    long long file_length = info["length"].get<long long>();
    int piece_length = info["piece length"].get<int>();
    std::string pieces = info["pieces"].get<std::string>();

    int total_pieces = (file_length + piece_length - 1) / piece_length;

    
    std::string encoded_info = bencode(info);
    unsigned char info_hash[20];
    SHA1((unsigned char*)encoded_info.data(), encoded_info.size(), info_hash);

    
    std::string announce = meta["announce"].get<std::string>();
    std::string url = announce.substr(7);
    size_t slash = url.find('/');
    std::string hostport = url.substr(0, slash);
    std::string path = url.substr(slash);

    std::string host, port = "80";
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
    } else host = hostport;

    addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo(host.c_str(), port.c_str(), &hints, &res);

    int trackerSock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(trackerSock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    std::string peer_id = random_peer_id();

    auto url_encode_local = [](const unsigned char *d, size_t n) {
        std::ostringstream o;
        o << std::hex << std::uppercase;
        for (size_t i = 0; i < n; i++)
            o << '%' << std::setw(2) << std::setfill('0') << int(d[i]);
        return o.str();
    };

    std::ostringstream req;
    req << "GET " << path
        << "?info_hash=" << url_encode_local(info_hash, 20)
        << "&peer_id=" << url_encode_local((unsigned char*)peer_id.data(), 20)
        << "&port=6881"
        << "&uploaded=0"
        << "&downloaded=0"
        << "&left=" << file_length
        << "&compact=1 HTTP/1.0\r\n"
        << "Host: " << host << "\r\n\r\n";

    send(trackerSock, req.str().data(), req.str().size(), 0);

    std::vector<uint8_t> tracker_resp;
    char buf[4096];
    int n;
    while ((n = recv(trackerSock, buf, sizeof(buf), 0)) > 0)
        tracker_resp.insert(tracker_resp.end(), buf, buf + n);
    close(trackerSock);

    auto it = std::search(
        tracker_resp.begin(), tracker_resp.end(),
        "\r\n\r\n", "\r\n\r\n" + 4
    );
    std::string body(it + 4, tracker_resp.end());
    int pos = 0;
    json tracker = decode_dictionary(body, pos);

    std::string peers_bin = tracker["peers"].get<std::string>();
    uint8_t a = peers_bin[0], b = peers_bin[1], c = peers_bin[2], d = peers_bin[3];
    uint16_t peer_port = ((uint8_t)peers_bin[4] << 8) | (uint8_t)peers_bin[5];

    std::string peer_ip =
        std::to_string(a) + "." + std::to_string(b) + "." +
        std::to_string(c) + "." + std::to_string(d);

   
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port);
    addr.sin_addr.s_addr = inet_addr(peer_ip.c_str());
    connect(sock, (sockaddr*)&addr, sizeof(addr));

    
    std::vector<uint8_t> hs;
    hs.push_back(19);
    std::string proto = "BitTorrent protocol";
    hs.insert(hs.end(), proto.begin(), proto.end());
    hs.insert(hs.end(), 8, 0);
    hs.insert(hs.end(), info_hash, info_hash + 20);
    hs.insert(hs.end(), peer_id.begin(), peer_id.end());
    send(sock, hs.data(), hs.size(), 0);

    std::vector<uint8_t> resp(68);
    recv_all(sock, resp.data(), 68);

    
    uint32_t len = htonl(1);
    uint8_t id = 2;
    send(sock, &len, 4, 0);
    send(sock, &id, 1, 0);

 
    while (true) {
        uint32_t l;
        recv_all(sock, (uint8_t*)&l, 4);
        l = ntohl(l);
        if (l == 0) continue;
        uint8_t mid;
        recv_all(sock, &mid, 1);
        if (mid == 1) break;
        std::vector<uint8_t> skip(l - 1);
        recv_all(sock, skip.data(), l - 1);
    }

   
    std::ofstream out(output_path, std::ios::binary);

    for (int piece = 0; piece < total_pieces; piece++) {

        int curr_size = piece_length;
        if (piece == total_pieces - 1 && file_length % piece_length)
            curr_size = file_length % piece_length;

        std::vector<uint8_t> piece_data;
        int downloaded = 0;

        while (downloaded < curr_size) {
            int req_len = std::min(16 * 1024, curr_size - downloaded);

            uint32_t mlen = htonl(13);
            uint8_t mid = 6;
            uint32_t idx = htonl(piece);
            uint32_t begin = htonl(downloaded);
            uint32_t rlen = htonl(req_len);

            send(sock, &mlen, 4, 0);
            send(sock, &mid, 1, 0);
            send(sock, &idx, 4, 0);
            send(sock, &begin, 4, 0);
            send(sock, &rlen, 4, 0);

            uint32_t resp_len;
            recv_all(sock, (uint8_t*)&resp_len, 4);
            resp_len = ntohl(resp_len);

            uint8_t rid;
            recv_all(sock, &rid, 1);

            recv_all(sock, (uint8_t*)&idx, 4);
            recv_all(sock, (uint8_t*)&begin, 4);

            int data_len = resp_len - 9;
            std::vector<uint8_t> block(data_len);
            recv_all(sock, block.data(), data_len);

            piece_data.insert(piece_data.end(), block.begin(), block.end());
            downloaded += data_len;
        }

        unsigned char h[20];
        SHA1(piece_data.data(), piece_data.size(), h);

        for (int i = 0; i < 20; i++) {
            if ((unsigned char)pieces[piece * 20 + i] != h[i]) {
                std::cerr << "Piece hash mismatch\n";
                return 1;
            }
        }

        out.write((char*)piece_data.data(), piece_data.size());
        std::cout << "Downloaded piece " << piece << "\n";
    }

    out.close();


shutdown(sock, SHUT_RDWR);
close(sock);

std::cout << "Download complete\n";
return 0;   
}

  
    
   
 else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

