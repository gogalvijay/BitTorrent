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


    else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

