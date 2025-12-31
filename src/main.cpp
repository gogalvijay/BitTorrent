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
#include <stdexcept>
#include <map>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

namespace BitTorrent {

    static const int BLOCK_SIZE = 16 * 1024;
    static const int PIECE_HASH_LEN = 20;
    static const int HANDSHAKE_LEN = 68;

    struct TorrentInfo {
        std::string announce;
        long long length;
        long long piece_length;
        std::string pieces;
        std::string name;
        std::string info_hash_str;
        std::vector<uint8_t> info_hash_raw;
    };

    struct PeerAddress {
        std::string ip;
        uint16_t port;
    };

    class Utils {
    public:
        static std::string ToHex(const unsigned char* hash, size_t len) {
            std::ostringstream hex;
            hex << std::hex << std::setfill('0');
            for (size_t i = 0; i < len; i++) {
                hex << std::setw(2) << (static_cast<int>(hash[i]) & 0xff);
            }
            return hex.str();
        }

        static std::string UrlEncode(const std::vector<uint8_t>& data) {
            std::ostringstream o;
            o << std::hex << std::uppercase;
            for (unsigned char c : data) {
                o << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }
            return o.str();
        }

        static std::string GeneratePeerId() {
            std::string s = "-CC0001-";
            std::random_device r;
            std::uniform_int_distribution<int> dist(0, 9);
            while (s.size() < 20) s += std::to_string(dist(r));
            return s;
        }

        static std::vector<uint8_t> CalculateSHA1(const std::string& input) {
            std::vector<uint8_t> hash(20);
            SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data());
            return hash;
        }

        static std::vector<uint8_t> CalculateSHA1(const std::vector<uint8_t>& input) {
            std::vector<uint8_t> hash(20);
            SHA1(input.data(), input.size(), hash.data());
            return hash;
        }
        
        static std::string UrlDecode(const std::string& str) {
            std::string ret;
            for (size_t i = 0; i < str.length(); i++) {
                if (str[i] == '%' && i + 2 < str.length()) {
                    std::string hex = str.substr(i + 1, 2);
                    char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
                    ret += ch;
                    i += 2;
                } else {
                    ret += str[i];
                }
            }
            return ret;
        }
        
        static std::vector<uint8_t> HexToBytes(const std::string& hex) {
            std::vector<uint8_t> bytes;
            for (unsigned int i = 0; i < hex.length(); i += 2) {
                std::string byteString = hex.substr(i, 2);
                uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
                bytes.push_back(byte);
            }
            return bytes;
        }
    };

    class BEncoder {
    public:
        static std::string Encode(const json& j) {
            if (j.is_number_integer()) return "i" + std::to_string(j.get<long long>()) + "e";
            if (j.is_string()) {
                std::string s = j.get<std::string>();
                return std::to_string(s.size()) + ":" + s;
            }
            if (j.is_array()) {
                std::string out = "l";
                for (const auto& elem : j) out += Encode(elem);
                return out + "e";
            }
            if (j.is_object()) {
                std::string out = "d";
                std::vector<std::string> keys;
                for (auto& el : j.items()) keys.push_back(el.key());
                std::sort(keys.begin(), keys.end());
                for (const auto& key : keys) {
                    out += Encode(key) + Encode(j.at(key));
                }
                return out + "e";
            }
            throw std::runtime_error("Unsupported type for BEncoding");
        }

        static json Decode(const std::string& s) {
            int pos = 0;
            return ParseValue(s, pos);
        }

        static json Decode(const std::string& s, int& out_pos) {
            out_pos = 0;
            return ParseValue(s, out_pos);
        }

    private:
        static json ParseValue(const std::string& s, int& i) {
            if (isdigit(s[i])) return ParseString(s, i);
            if (s[i] == 'i') return ParseInt(s, i);
            if (s[i] == 'l') return ParseList(s, i);
            if (s[i] == 'd') return ParseDict(s, i);
            throw std::runtime_error("Invalid bencoded string");
        }

        static long long ParseInt(const std::string& s, int& i) {
            i++; 
            size_t end = s.find('e', i);
            if (end == std::string::npos) throw std::runtime_error("Unterminated integer");
            long long val = std::stoll(s.substr(i, end - i));
            i = end + 1;
            return val;
        }

        static std::string ParseString(const std::string& s, int& i) {
            size_t colon = s.find(':', i);
            if (colon == std::string::npos) throw std::runtime_error("Invalid string length");
            long long len = std::stoll(s.substr(i, colon - i));
            i = colon + 1;
            std::string val = s.substr(i, len);
            i += len;
            return val;
        }

        static json ParseList(const std::string& s, int& i) {
            i++; 
            json list = json::array();
            while (s[i] != 'e') list.push_back(ParseValue(s, i));
            i++;
            return list;
        }

        static json ParseDict(const std::string& s, int& i) {
            i++; 
            json dict = json::object();
            while (s[i] != 'e') {
                std::string key = ParseString(s, i);
                dict[key] = ParseValue(s, i);
            }
            i++;
            return dict;
        }
    };

    class Network {
    public:
       static int Connect(const std::string& ip, uint16_t port) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) throw std::runtime_error("Socket creation failed");

        
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(ip.c_str());

            if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
                close(sock);
                return -1;
            }
            return sock;
        }


        static int ConnectHostname(const std::string& hostname, const std::string& port) {
            addrinfo hints{}, *res;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            
            if (getaddrinfo(hostname.c_str(), port.c_str(), &hints, &res) != 0) return -1;

            int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (sock < 0) {
                freeaddrinfo(res);
                return -1;
            }

            if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
                close(sock);
                freeaddrinfo(res);
                return -1;
            }
            freeaddrinfo(res);
            return sock;
        }

        static void SendAll(int sock, const void* data, size_t len) {
            if (send(sock, data, len, 0) < 0) throw std::runtime_error("Send failed");
        }

        static void RecvAll(int sock, void* buffer, size_t len) {
            size_t received = 0;
            uint8_t* ptr = static_cast<uint8_t*>(buffer);
            while (received < len) {
                ssize_t r = recv(sock, ptr + received, len - received, 0);
                if (r <= 0) throw std::runtime_error("Receive failed or connection closed");
                received += r;
            }
        }
        
        static std::vector<uint8_t> RecvUntilClosed(int sock) {
            std::vector<uint8_t> data;
            char buf[4096];
            ssize_t n;
            while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
                data.insert(data.end(), buf, buf + n);
            }
            return data;
        }
    };

    class Client {
    public:
        static TorrentInfo LoadTorrent(const std::string& path) {
            std::ifstream in(path, std::ios::binary);
            if (!in) throw std::runtime_error("Cannot open file");
            
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            json root = BEncoder::Decode(content);
            json info = root["info"];

            TorrentInfo t;
            t.announce = root["announce"].get<std::string>();
            t.length = info["length"].get<long long>();
            t.piece_length = info["piece length"].get<long long>();
            t.pieces = info["pieces"].get<std::string>();
            t.name = info["name"].get<std::string>(); 
            
            std::string encoded_info = BEncoder::Encode(info);
            t.info_hash_raw = Utils::CalculateSHA1(encoded_info);
            t.info_hash_str = Utils::ToHex(t.info_hash_raw.data(), 20);

            return t;
        }

        static std::vector<PeerAddress> GetPeers(const TorrentInfo& t) {
            std::string url = t.announce;
            if (url.substr(0, 7) == "http://") url = url.substr(7);
            
            size_t slash = url.find('/');
            std::string hostport = url.substr(0, slash);
            std::string path = url.substr(slash);
            std::string port = "80";
            std::string host = hostport;

            size_t colon = hostport.find(':');
            if (colon != std::string::npos) {
                host = hostport.substr(0, colon);
                port = hostport.substr(colon + 1);
            }

            std::string peer_id = Utils::GeneratePeerId();
            std::vector<uint8_t> pid_vec(peer_id.begin(), peer_id.end());

            std::ostringstream req;
            req << "GET " << path 
                << "?info_hash=" << Utils::UrlEncode(t.info_hash_raw)
                << "&peer_id=" << Utils::UrlEncode(pid_vec)
                << "&port=6881&uploaded=0&downloaded=0&compact=1"
                << "&left=" << t.length 
                << " HTTP/1.0\r\nHost: " << host << "\r\nConnection: close\r\n\r\n";

            int sock = Network::ConnectHostname(host, port);
            if (sock < 0) throw std::runtime_error("Tracker connection failed");

            std::string request = req.str();
            Network::SendAll(sock, request.data(), request.size());
            
            std::vector<uint8_t> resp = Network::RecvUntilClosed(sock);
            close(sock);

            std::string resp_str(resp.begin(), resp.end());
            size_t header_end = resp_str.find("\r\n\r\n");
            if (header_end == std::string::npos) throw std::runtime_error("Invalid HTTP response");

            std::string body = resp_str.substr(header_end + 4);
            json tracker_resp = BEncoder::Decode(body);
            std::string peers_bin = tracker_resp["peers"].get<std::string>();

            std::vector<PeerAddress> peers;
            for (size_t i = 0; i + 6 <= peers_bin.size(); i += 6) {
                uint8_t a = peers_bin[i];
                uint8_t b = peers_bin[i+1];
                uint8_t c = peers_bin[i+2];
                uint8_t d = peers_bin[i+3];
                uint16_t p = (static_cast<uint8_t>(peers_bin[i+4]) << 8) | static_cast<uint8_t>(peers_bin[i+5]);
                
                std::string ip = std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d);
                peers.push_back({ip, p});
            }
            return peers;
        }

        static int PerformHandshake(const std::string& ip, uint16_t port, const TorrentInfo& t, std::vector<uint8_t>& out_peer_id, bool& out_peer_supports_ext, bool support_extensions = false) {
            int sock = Network::Connect(ip, port);
            if (sock < 0) throw std::runtime_error("Connection to peer failed");

            std::vector<uint8_t> handshake;
            handshake.push_back(19);
            std::string protocol = "BitTorrent protocol";
            handshake.insert(handshake.end(), protocol.begin(), protocol.end());

            std::vector<uint8_t> reserved(8, 0);
            if (support_extensions) {
                reserved[5] |= 0x10; 
            }
            handshake.insert(handshake.end(), reserved.begin(), reserved.end()); 
            
            handshake.insert(handshake.end(), t.info_hash_raw.begin(), t.info_hash_raw.end());
            std::string my_id = Utils::GeneratePeerId();
            handshake.insert(handshake.end(), my_id.begin(), my_id.end());

            Network::SendAll(sock, handshake.data(), handshake.size());

            std::vector<uint8_t> response(HANDSHAKE_LEN);
            Network::RecvAll(sock, response.data(), HANDSHAKE_LEN);

            out_peer_id.assign(response.begin() + 48, response.end());

            if ((response[25] & 0x10) != 0) {
                out_peer_supports_ext = true;
            } else {
                out_peer_supports_ext = false;
            }

            return sock;
        }

       
        static void ReadMessage(int sock, std::vector<uint8_t>& buffer) {
             uint32_t len;
             Network::RecvAll(sock, &len, 4);
             len = ntohl(len);
             if (len > 0) {
                 buffer.resize(len);
                 Network::RecvAll(sock, buffer.data(), len);
             } else {
                 buffer.clear(); 
             }
        }

        static void SendExtensionHandshake(int sock) {
            json handshake_payload;
            handshake_payload["m"]["ut_metadata"] = 1;

            std::string bencoded = BEncoder::Encode(handshake_payload);

            uint32_t len = htonl(1 + 1 + bencoded.size());
            
            std::vector<uint8_t> msg;
            msg.resize(4);
            std::memcpy(msg.data(), &len, 4);
            msg.push_back(20); 
            msg.push_back(0); 
            msg.insert(msg.end(), bencoded.begin(), bencoded.end());

            Network::SendAll(sock, msg.data(), msg.size());
        }

        
        static int ReceiveExtensionHandshake(int sock) {
            while (true) {
                std::vector<uint8_t> msg;
                ReadMessage(sock, msg);

                if (msg.empty()) continue; 

              
                if (msg[0] == 20) {
                    if (msg.size() < 2) continue; 
                    
                    if (msg[1] == 0) { 
                        std::string payload(msg.begin() + 2, msg.end());
                        json decoded = BEncoder::Decode(payload);

                        if (decoded.contains("m") && decoded["m"].contains("ut_metadata")) {
                            return decoded["m"]["ut_metadata"].get<int>();
                        }
                        throw std::runtime_error("Peer does not support ut_metadata");
                    }
                }
               
            }
        }

       
       static void SendMetadataRequest(int sock, int ext_id, int piece_index) {
            json payload;
            payload["msg_type"] = 0;
            payload["piece"] = piece_index;
            std::string bencoded_payload = BEncoder::Encode(payload);

        
            uint32_t msg_length = 1 + 1 + bencoded_payload.size();
            uint32_t len = htonl(msg_length);
            uint8_t msg_id = 20;
            uint8_t extension_id = static_cast<uint8_t>(ext_id);

            std::vector<uint8_t> packet;
            packet.resize(4);
            std::memcpy(packet.data(), &len, 4);
            packet.push_back(msg_id);
            packet.push_back(extension_id);
            packet.insert(packet.end(), bencoded_payload.begin(), bencoded_payload.end());

            Network::SendAll(sock, packet.data(), packet.size());
        }

        
       static std::vector<uint8_t> ReceiveMetadataResponse(int sock, int ext_id) {
            while (true) {
                uint32_t len;
            
            
                ssize_t n = recv(sock, &len, 4, 0);
                
                
                if (n == 0) {
                    throw std::runtime_error("Peer closed connection");
                }
                if (n < 0) {
                    throw std::runtime_error("recv() error");
                }
                if (n < 4) {
                
                    size_t received = n;
                    while (received < 4) {
                        n = recv(sock, ((char*)&len) + received, 4 - received, 0);
                        if (n <= 0) throw std::runtime_error("Connection closed during length read");
                        received += n;
                    }
                }
                
                len = ntohl(len);
                
                
                if (len == 0) {
                
                    continue;
                }
                
                if (len > 1000000) {
                    throw std::runtime_error("Message too large");
                }
                
                std::vector<uint8_t> msg(len);
                Network::RecvAll(sock, msg.data(), len);
                
            
                uint8_t msg_id = msg[0];
                if (msg_id != 20) {
                
                    continue;
                }
                
                if (msg.size() < 2) continue;
                
                uint8_t received_ext_id = msg[1];
            
                if (received_ext_id != ext_id) continue;
                
                std::string payload_str(msg.begin() + 2, msg.end());
                
                int dict_end_pos = 0;
                json dict = BEncoder::Decode(payload_str, dict_end_pos);
                
                
                
                if (!dict.contains("msg_type")) continue;
                
                int msg_type = dict["msg_type"].get<int>();
            
                
                if (msg_type == 1) {
                    std::vector<uint8_t> metadata;
                    size_t raw_data_start = 2 + dict_end_pos;
                    if (raw_data_start < msg.size()) {
                        metadata.assign(msg.begin() + raw_data_start, msg.end());
                    }
                    return metadata;
                } else if (msg_type == 2) {
                    throw std::runtime_error("Peer rejected metadata request");
                }
            }
        }

       
        static void WaitForUnchoke(int sock) {
            uint32_t len = htonl(1);
            uint8_t id = 2; 
            Network::SendAll(sock, &len, 4);
            Network::SendAll(sock, &id, 1);

            while (true) {
                uint32_t msg_len;
                Network::RecvAll(sock, &msg_len, 4);
                msg_len = ntohl(msg_len);
                if (msg_len == 0) continue;

                uint8_t msg_id;
                Network::RecvAll(sock, &msg_id, 1);

                if (msg_id == 1) return; 

                std::vector<uint8_t> ignore(msg_len - 1);
                Network::RecvAll(sock, ignore.data(), msg_len - 1);
            }
        }

        static std::vector<uint8_t> DownloadPiece(int sock, const TorrentInfo& t, int piece_idx) {
            long long total_pieces = (t.length + t.piece_length - 1) / t.piece_length;
            long long current_piece_size = t.piece_length;
            if (piece_idx == total_pieces - 1) {
                long long rem = t.length % t.piece_length;
                if (rem != 0) current_piece_size = rem;
            }

            int block_count = (current_piece_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

            for (int i = 0; i < block_count; i++) {
                int begin = i * BLOCK_SIZE;
                int len = BLOCK_SIZE;
                if (begin + len > current_piece_size) len = current_piece_size - begin;

                uint32_t msg_len = htonl(13);
                uint8_t id = 6; 
                uint32_t idx = htonl(piece_idx);
                uint32_t b = htonl(begin);
                uint32_t l = htonl(len);

                uint8_t req_buf[17];
                std::memcpy(req_buf, &msg_len, 4);
                std::memcpy(req_buf + 4, &id, 1);
                std::memcpy(req_buf + 5, &idx, 4);
                std::memcpy(req_buf + 9, &b, 4);
                std::memcpy(req_buf + 13, &l, 4);

                Network::SendAll(sock, req_buf, 17);
            }
            
            std::vector<uint8_t> piece_data(current_piece_size);
            long long downloaded = 0;

            while (downloaded < current_piece_size) {
                uint32_t msg_len;
                Network::RecvAll(sock, &msg_len, 4);
                msg_len = ntohl(msg_len);

                if (msg_len == 0) continue; 

                uint8_t msg_id;
                Network::RecvAll(sock, &msg_id, 1);

                if (msg_id == 7) { 
                    uint32_t idx, begin;
                    Network::RecvAll(sock, &idx, 4);
                    Network::RecvAll(sock, &begin, 4);
                    idx = ntohl(idx);
                    begin = ntohl(begin);

                    int data_len = msg_len - 9; 
                    std::vector<uint8_t> block(data_len);
                    Network::RecvAll(sock, block.data(), data_len);

                    if (begin + data_len <= current_piece_size) {
                        std::memcpy(piece_data.data() + begin, block.data(), data_len);
                        downloaded += data_len;
                    }
                } else {
                    std::vector<uint8_t> ignore(msg_len - 1);
                    Network::RecvAll(sock, ignore.data(), msg_len - 1);
                }
            }

            std::vector<uint8_t> hash = Utils::CalculateSHA1(piece_data);
            std::string expected_hash_str = t.pieces.substr(piece_idx * 20, 20);
            
            for(int i=0; i<20; i++) {
                if(hash[i] != (unsigned char)expected_hash_str[i]) 
                    throw std::runtime_error("Piece hash mismatch");
            }

            return piece_data;
        }
    };
}

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> [args...]\n";
        return 1;
    }

    std::string cmd = argv[1];

    try {
        if (cmd == "decode") {
            if (argc < 3) return 1;
            json j = BitTorrent::BEncoder::Decode(argv[2]);
            std::cout << j.dump() << std::endl;
        } 
        else if (cmd == "info") {
            if (argc < 3) return 1;
            auto t = BitTorrent::Client::LoadTorrent(argv[2]);
            std::cout << "Tracker URL: " << t.announce << "\n";
            std::cout << "Length: " << t.length << "\n";
            std::cout << "Info Hash: " << t.info_hash_str << "\n";
            std::cout << "Piece Length: " << t.piece_length << "\n";
            std::cout << "Piece Hashes:\n";
            for (size_t i = 0; i < t.pieces.size(); i += 20) {
                std::cout << BitTorrent::Utils::ToHex((const unsigned char*)t.pieces.data() + i, 20) << "\n";
            }
        } 
        else if (cmd == "peers") {
            if (argc < 3) return 1;
            auto t = BitTorrent::Client::LoadTorrent(argv[2]);
            auto peers = BitTorrent::Client::GetPeers(t);
            for (const auto& p : peers) {
                std::cout << p.ip << ":" << p.port << "\n";
            }
        } 
        else if (cmd == "handshake") {
            if (argc < 4) return 1;
            auto t = BitTorrent::Client::LoadTorrent(argv[2]);
            std::string peer_str = argv[3];
            size_t colon = peer_str.find(':');
            std::string ip = peer_str.substr(0, colon);
            uint16_t port = std::stoi(peer_str.substr(colon + 1));
            
            std::vector<uint8_t> peer_id;
            bool supports_ext;
            int sock = BitTorrent::Client::PerformHandshake(ip, port, t, peer_id, supports_ext);
            close(sock);
            
            std::cout << "Peer ID: " << BitTorrent::Utils::ToHex(peer_id.data(), 20) << "\n";
        } 
        else if (cmd == "download_piece") {
            if (argc < 6) return 1;
            std::string output = argv[3];
            std::string torrent = argv[4];
            int idx = std::stoi(argv[5]);

            auto t = BitTorrent::Client::LoadTorrent(torrent);
            auto peers = BitTorrent::Client::GetPeers(t);
            if (peers.empty()) return 1;

            std::vector<uint8_t> pid;
            bool supports_ext;
            int sock = BitTorrent::Client::PerformHandshake(peers[0].ip, peers[0].port, t, pid, supports_ext);
            BitTorrent::Client::WaitForUnchoke(sock);
            auto data = BitTorrent::Client::DownloadPiece(sock, t, idx);
            close(sock);

            std::ofstream out(output, std::ios::binary);
            out.write((char*)data.data(), data.size());
            std::cout << "Piece " << idx << " downloaded to " << output << "\n";
        }
        else if (cmd == "download") {
            if (argc < 5) return 1;
            std::string output = argv[3];
            std::string torrent = argv[4];

            auto t = BitTorrent::Client::LoadTorrent(torrent);
            auto peers = BitTorrent::Client::GetPeers(t);
            if (peers.empty()) return 1;

            std::vector<uint8_t> pid;
            bool supports_ext;
            int sock = BitTorrent::Client::PerformHandshake(peers[0].ip, peers[0].port, t, pid, supports_ext);
            BitTorrent::Client::WaitForUnchoke(sock);

            std::ofstream out(output, std::ios::binary);
            int total = (t.length + t.piece_length - 1) / t.piece_length;
            
            for (int i = 0; i < total; i++) {
                auto data = BitTorrent::Client::DownloadPiece(sock, t, i);
                out.write((char*)data.data(), data.size());
                std::cout << "Downloaded piece " << i << "\n";
            }
            close(sock);
            std::cout << "Download complete\n";
        } 
        else if(cmd == "magnet_parse"){
            if (argc < 3) return 1;
            std::string magnet_link = argv[2];
            
            std::string prefix = "magnet:?";
            if (magnet_link.find(prefix) == 0) {
                magnet_link = magnet_link.substr(prefix.length());
            }

            std::string tracker_url;
            std::string info_hash;

            std::stringstream ss(magnet_link);
            std::string segment;

            while (std::getline(ss, segment, '&')) {
                size_t split_pos = segment.find('=');
                if (split_pos == std::string::npos) continue;

                std::string key = segment.substr(0, split_pos);
                std::string val = segment.substr(split_pos + 1);

                if (key == "xt") {
                    
                    size_t pos = val.rfind(':');
                    if (pos != std::string::npos) {
                        info_hash = val.substr(pos + 1);
                    } else {
                        info_hash = val;
                    }
                } 
                else if (key == "tr") {
                    tracker_url = BitTorrent::Utils::UrlDecode(val);
                }
            }

            std::cout << "Tracker URL: " << tracker_url << "\n";
            std::cout << "Info Hash: " << info_hash << "\n";
        }
        else if (cmd == "magnet_handshake") {
            if (argc < 3) return 1;
            std::string magnet_link = argv[2];
            
            std::string prefix = "magnet:?";
            if (magnet_link.find(prefix) == 0) {
                magnet_link = magnet_link.substr(prefix.length());
            }

            std::string tracker_url;
            std::string info_hash_hex;

            std::stringstream ss(magnet_link);
            std::string segment;

            while (std::getline(ss, segment, '&')) {
                size_t split_pos = segment.find('=');
                if (split_pos == std::string::npos) continue;

                std::string key = segment.substr(0, split_pos);
                std::string val = segment.substr(split_pos + 1);

                if (key == "xt") {
                    size_t pos = val.rfind(':');
                    if (pos != std::string::npos) {
                        info_hash_hex = val.substr(pos + 1);
                    } else {
                        info_hash_hex = val;
                    }
                } else if (key == "tr") {
                    tracker_url = BitTorrent::Utils::UrlDecode(val);
                }
            }

            if (tracker_url.empty() || info_hash_hex.empty()) {
                std::cerr << "Invalid magnet link\n";
                return 1;
            }

            BitTorrent::TorrentInfo t;
            t.announce = tracker_url;
            t.info_hash_raw = BitTorrent::Utils::HexToBytes(info_hash_hex);
            t.length = 999; 

            auto peers = BitTorrent::Client::GetPeers(t);
            if (peers.empty()) return 1;

            std::vector<uint8_t> peer_id;
            bool peer_supports_ext = false;
            
            int sock = BitTorrent::Client::PerformHandshake(peers[0].ip, peers[0].port, t, peer_id, peer_supports_ext, true);
            
            std::cout << "Peer ID: " << BitTorrent::Utils::ToHex(peer_id.data(), 20) << "\n";

            if (peer_supports_ext) {
                BitTorrent::Client::SendExtensionHandshake(sock);
                int ext_id = BitTorrent::Client::ReceiveExtensionHandshake(sock);
                std::cout << "Peer Metadata Extension ID: " << ext_id << "\n";
            }

            close(sock);
        }
        else if (cmd == "magnet_info") {
            if (argc < 3) return 1;
            std::string magnet_link = argv[2];
            
            std::string prefix = "magnet:?";
            if (magnet_link.find(prefix) == 0) {
                magnet_link = magnet_link.substr(prefix.length());
            }

            std::string tracker_url;
            std::string info_hash_hex;

            std::stringstream ss(magnet_link);
            std::string segment;

            while (std::getline(ss, segment, '&')) {
                size_t split_pos = segment.find('=');
                if (split_pos == std::string::npos) continue;

                std::string key = segment.substr(0, split_pos);
                std::string val = segment.substr(split_pos + 1);

                if (key == "xt") {
                    size_t pos = val.rfind(':');
                    if (pos != std::string::npos) {
                        info_hash_hex = val.substr(pos + 1);
                    } else {
                        info_hash_hex = val;
                    }
                } else if (key == "tr") {
                    tracker_url = BitTorrent::Utils::UrlDecode(val);
                }
            }

            if (tracker_url.empty() || info_hash_hex.empty()) {
                std::cerr << "Invalid magnet link\n";
                return 1;
            }

            std::cout << "Tracker URL: " << tracker_url << "\n";

            BitTorrent::TorrentInfo t;
            t.announce = tracker_url;
            t.info_hash_raw = BitTorrent::Utils::HexToBytes(info_hash_hex);
            t.length = 999;

            auto peers = BitTorrent::Client::GetPeers(t);
            if (peers.empty()) {
                std::cerr << "No peers found\n";
                return 1;
            }

            for (const auto& peer : peers) {
                int sock = -1;
                try {
                    std::vector<uint8_t> peer_id;
                    bool peer_supports_ext = false;
                    
                    sock = BitTorrent::Client::PerformHandshake(peer.ip, peer.port, t, peer_id, peer_supports_ext, true);
                    
                    if (!peer_supports_ext) {
                        close(sock);
                        continue;
                    }

                    BitTorrent::Client::SendExtensionHandshake(sock);
                    int peer_ext_id = BitTorrent::Client::ReceiveExtensionHandshake(sock);
                
                    BitTorrent::Client::SendMetadataRequest(sock, peer_ext_id, 0);
                    
                
                    std::vector<uint8_t> metadata_raw = BitTorrent::Client::ReceiveMetadataResponse(sock, 1);
                    
                    std::string metadata_str(metadata_raw.begin(), metadata_raw.end());
                    json info = BitTorrent::BEncoder::Decode(metadata_str);
                    
                    std::cout << "Length: " << info["length"] << "\n";
                    std::cout << "Info Hash: " << info_hash_hex << "\n";
                    std::cout << "Piece Length: " << info["piece length"] << "\n";
                    std::cout << "Piece Hashes:\n";
                    
                    std::string pieces = info["pieces"].get<std::string>();
                    for (size_t i = 0; i < pieces.size(); i += 20) {
                        std::cout << BitTorrent::Utils::ToHex((const unsigned char*)pieces.data() + i, 20) << "\n";
                    }
                    
                    close(sock);
                    return 0;
                    
                } catch (const std::exception& e) {
                    if (sock >= 0) close(sock);
                    continue;
                }
            }
            
            std::cerr << "Failed to retrieve metadata from any peer\n";
            return 1;
        }
        else if (cmd == "magnet_download_piece") {
            if (argc < 6) return 1;
            std::string output = argv[3];
            std::string magnet_link = argv[4];
            int idx = std::stoi(argv[5]);
            
            std::string prefix = "magnet:?";
            if (magnet_link.find(prefix) == 0) {
                magnet_link = magnet_link.substr(prefix.length());
            }

            std::string tracker_url;
            std::string info_hash_hex;

            std::stringstream ss(magnet_link);
            std::string segment;

            while (std::getline(ss, segment, '&')) {
                size_t split_pos = segment.find('=');
                if (split_pos == std::string::npos) continue;

                std::string key = segment.substr(0, split_pos);
                std::string val = segment.substr(split_pos + 1);

                if (key == "xt") {
                    size_t pos = val.rfind(':');
                    if (pos != std::string::npos) {
                        info_hash_hex = val.substr(pos + 1);
                    } else {
                        info_hash_hex = val;
                    }
                } else if (key == "tr") {
                    tracker_url = BitTorrent::Utils::UrlDecode(val);
                }
            }

            if (tracker_url.empty() || info_hash_hex.empty()) {
                std::cerr << "Invalid magnet link\n";
                return 1;
            }

            BitTorrent::TorrentInfo t;
            t.announce = tracker_url;
            t.info_hash_raw = BitTorrent::Utils::HexToBytes(info_hash_hex);
            t.length = 999; 

            auto peers = BitTorrent::Client::GetPeers(t);
            if (peers.empty()) {
                std::cerr << "No peers found\n";
                return 1;
            }

            for (const auto& peer : peers) {
                int sock = -1;
                try {
                    std::vector<uint8_t> peer_id;
                    bool peer_supports_ext = false;
                    
                    sock = BitTorrent::Client::PerformHandshake(peer.ip, peer.port, t, peer_id, peer_supports_ext, true);
                    
                    if (!peer_supports_ext) {
                        close(sock);
                        continue;
                    }

                    BitTorrent::Client::SendExtensionHandshake(sock);
                    int peer_ext_id = BitTorrent::Client::ReceiveExtensionHandshake(sock);
                
                    BitTorrent::Client::SendMetadataRequest(sock, peer_ext_id, 0);
                    
                    std::vector<uint8_t> metadata_raw = BitTorrent::Client::ReceiveMetadataResponse(sock, 1);
                    
                    std::string metadata_str(metadata_raw.begin(), metadata_raw.end());
                    json info = BitTorrent::BEncoder::Decode(metadata_str);
                    
                    t.length = info["length"].get<long long>();
                    t.piece_length = info["piece length"].get<long long>();
                    t.pieces = info["pieces"].get<std::string>();
                    if (info.contains("name")) {
                        t.name = info["name"].get<std::string>();
                    }
                    t.info_hash_str = info_hash_hex;

                    BitTorrent::Client::WaitForUnchoke(sock);
                    
                    auto data = BitTorrent::Client::DownloadPiece(sock, t, idx);
                    
                    std::ofstream out(output, std::ios::binary);
                    out.write((char*)data.data(), data.size());
                    std::cout << "Piece " << idx << " downloaded to " << output << "\n";
                    
                    close(sock);
                    return 0;
                    
                } catch (const std::exception& e) {
                    if (sock >= 0) close(sock);
                    continue;
                }
            }
            std::cerr << "Failed to download piece from any peer\n";
            return 1;
        }
        else if (cmd == "magnet_download") {
            if (argc < 5) return 1;
            std::string output = argv[3];
            std::string magnet_link = argv[4];

            std::string prefix = "magnet:?";
            if (magnet_link.find(prefix) == 0) {
                magnet_link = magnet_link.substr(prefix.length());
            }

            std::string tracker_url;
            std::string info_hash_hex;

            std::stringstream ss(magnet_link);
            std::string segment;

            while (std::getline(ss, segment, '&')) {
                size_t split_pos = segment.find('=');
                if (split_pos == std::string::npos) continue;

                std::string key = segment.substr(0, split_pos);
                std::string val = segment.substr(split_pos + 1);

                if (key == "xt") {
                    size_t pos = val.rfind(':');
                    if (pos != std::string::npos) {
                        info_hash_hex = val.substr(pos + 1);
                    } else {
                        info_hash_hex = val;
                    }
                } else if (key == "tr") {
                    tracker_url = BitTorrent::Utils::UrlDecode(val);
                }
            }

            if (tracker_url.empty() || info_hash_hex.empty()) {
                std::cerr << "Invalid magnet link\n";
                return 1;
            }

            BitTorrent::TorrentInfo t;
            t.announce = tracker_url;
            t.info_hash_raw = BitTorrent::Utils::HexToBytes(info_hash_hex);
            t.length = 999; 

            auto peers = BitTorrent::Client::GetPeers(t);
            if (peers.empty()) {
                std::cerr << "No peers found\n";
                return 1;
            }

            for (const auto& peer : peers) {
                int sock = -1;
                try {
                    std::vector<uint8_t> peer_id;
                    bool peer_supports_ext = false;
                    
                    sock = BitTorrent::Client::PerformHandshake(peer.ip, peer.port, t, peer_id, peer_supports_ext, true);
                    
                    if (!peer_supports_ext) {
                        close(sock);
                        continue;
                    }

                    BitTorrent::Client::SendExtensionHandshake(sock);
                    int peer_ext_id = BitTorrent::Client::ReceiveExtensionHandshake(sock);
                
                    BitTorrent::Client::SendMetadataRequest(sock, peer_ext_id, 0);
                    
                    std::vector<uint8_t> metadata_raw = BitTorrent::Client::ReceiveMetadataResponse(sock, 1);
                    
                    std::string metadata_str(metadata_raw.begin(), metadata_raw.end());
                    json info = BitTorrent::BEncoder::Decode(metadata_str);
                    
                    t.length = info["length"].get<long long>();
                    t.piece_length = info["piece length"].get<long long>();
                    t.pieces = info["pieces"].get<std::string>();
                    if (info.contains("name")) {
                        t.name = info["name"].get<std::string>();
                    }
                    t.info_hash_str = info_hash_hex;

                    BitTorrent::Client::WaitForUnchoke(sock);
                    
                    std::ofstream out(output, std::ios::binary);
                    int total_pieces = (t.length + t.piece_length - 1) / t.piece_length;

                    for (int i = 0; i < total_pieces; i++) {
                        auto data = BitTorrent::Client::DownloadPiece(sock, t, i);
                        out.write((char*)data.data(), data.size());
                        std::cout << "Downloaded piece " << i << "\n";
                    }
                    
                    close(sock);
                    std::cout << "Download complete\n";
                    return 0;
                    
                } catch (const std::exception& e) {
                    if (sock >= 0) close(sock);
                    continue;
                }
            }
            std::cerr << "Failed to download file from any peer\n";
            return 1;
        }
        else {
            std::cerr << "Unknown command: " << cmd << "\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
