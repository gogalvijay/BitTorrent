#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include<fstream>
#include <openssl/sha.h>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;




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

	   std::ostringstream hex;
	    for (int i = 0; i < 20; i++) {
	    	hex << std::hex
		<< std::setw(2)
		<< std::setfill('0')
		<< ((int)hash[i] & 0xff);
	    }

	    std::cout << "Info Hash: " << hex.str() << "\n"; 
    }

    else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
