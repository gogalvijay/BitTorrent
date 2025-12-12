#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;




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
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
