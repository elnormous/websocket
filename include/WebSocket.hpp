#ifndef WEBSOCKET_HPP
#define WEBSOCKET_HPP

#include <iostream>
#include <random>
#include "base64.hpp"
#include "sha1.hpp"
#include "Socket.hpp"

static const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static const std::vector<uint8_t> clrf = {'\r', '\n'};

class WebSocket
{
public:
    enum class Opcode
    {
        CONTINUATION_FRAME = 0x00,
        TEXT_FRAME = 0x01,
        BINARY_FRAME = 0x02,
        CLOSE = 0x08,
        PING = 0x09,
        PONG = 0x0A
    };

    static std::string toString(Opcode opcode)
    {
        switch (opcode)
        {
            case Opcode::CONTINUATION_FRAME: return "CONTINUATION_FRAME";
            case Opcode::TEXT_FRAME: return "TEXT_FRAME";
            case Opcode::BINARY_FRAME: return "BINARY_FRAME";
            case Opcode::CLOSE: return "CLOSE";
            case Opcode::PING: return "PING";
            case Opcode::PONG: return "PONG";
            default: return "unknown";
        }
    }

    WebSocket(cppsocket::Network& network):
        socket(network), dist(0, 255)
    {
    }

    WebSocket(cppsocket::Socket&& initSocket,
              const std::function<void(const std::vector<uint8_t>&)>& initFrameHandler):
        socket(std::forward<cppsocket::Socket>(initSocket)),
        frameHandler(initFrameHandler)
    {
        socket.setReadCallback(std::bind(&WebSocket::readCallback, this, std::placeholders::_1, std::placeholders::_2));
    }

    WebSocket(const WebSocket&) = delete;
    WebSocket(WebSocket&& other):
        socket(std::move(other.socket)),
        frameHandler(std::move(other.frameHandler)),
        firstLine(other.firstLine),
        handshakeDone(other.handshakeDone),
        clientData(other.clientData),
        headers(other.headers)
    {
        socket.setReadCallback(std::bind(&WebSocket::readCallback, this, std::placeholders::_1, std::placeholders::_2));
        other.firstLine = true;
        other.handshakeDone = false;
    }

    WebSocket& operator=(const WebSocket&) = delete;

    WebSocket& operator=(WebSocket&& other)
    {
        if (&other != this)
        {
            socket = std::move(other.socket);
            socket.setReadCallback(std::bind(&WebSocket::readCallback, this, std::placeholders::_1, std::placeholders::_2));
            frameHandler = std::move(other.frameHandler);
            firstLine = other.firstLine;
            handshakeDone = other.handshakeDone;
            clientData = other.clientData;
            headers = other.headers;

            other.firstLine = true;
            other.handshakeDone = false;
        }

        return *this;
    }

    void handleFrame(const std::vector<uint8_t>& payload,
                     Opcode opcode)
    {
        frameHandler(payload);
    }

    void sendFrame(const std::vector<uint8_t>& payload,
                   Opcode opcode = Opcode::TEXT_FRAME,
                   bool masked = false)
    {
        if (handshakeDone)
        {
            // response
            std::vector<uint8_t> data;
            data.push_back((1 << 7) | static_cast<uint8_t>(opcode)); // final fragment, opcode

            if (payload.size() < 126)
                data.push_back(((masked ? 1 : 0) << 7) | (payload.size() & 0x7F)); // masked, payload length
            else if (payload.size() < 65535)
            {
                data.push_back(((masked ? 1 : 0) << 7) | 126); // masked, payload length
                data.push_back((payload.size() >> 8) & 0xFF);
                data.push_back(payload.size() & 0xFF);
            }
            else
            {
                data.push_back(((masked ? 1 : 0) << 7) | 127); // masked, payload length
                data.push_back((payload.size() >> 56) & 0xFF);
                data.push_back((payload.size() >> 48) & 0xFF);
                data.push_back((payload.size() >> 40) & 0xFF);
                data.push_back((payload.size() >> 32) & 0xFF);
                data.push_back((payload.size() >> 24) & 0xFF);
                data.push_back((payload.size() >> 16) & 0xFF);
                data.push_back((payload.size() >> 8) & 0xFF);
                data.push_back(payload.size() & 0xFF);
            }

            if (masked)
            {
                uint8_t mask[4];
                for (uint8_t& c : mask)
                    data.push_back(c = dist(rng));

                for (int i = 0; i < payload.size(); ++i)
                    data.push_back(payload[i] ^ mask[i % 4]);
            }
            else
                for (uint8_t c : payload)
                    data.push_back(c);

            socket.send(data);
        }
    }

private:
    void readCallback(cppsocket::Socket& s, const std::vector<uint8_t>& data)
    {
        static constexpr const char* digits = "0123456789ABCDEF";
        std::cout << "Client received " << data.size() << " bytes:";
        for (uint8_t c : data)
            std::cout << " " << digits[(c >> 4) & 0x0F] << digits[c & 0x0F];
        std::cout << std::endl;

        clientData.insert(clientData.end(), data.begin(), data.end());

        for (;;)
        {
            if (!handshakeDone)
            {
                std::vector<uint8_t>::iterator i = std::search(clientData.begin(), clientData.end(), clrf.begin(), clrf.end());

                // didn't find a newline
                if (i == clientData.end()) break;

                std::string line(clientData.begin(), i);
                clientData.erase(clientData.begin(), i + 2);

                // empty line indicates the end of the header section
                if (line.empty())
                {
                    handshakeDone = true;
                    std::string key;

                    for (const std::string& header : headers)
                    {
                        std::string::size_type pos = header.find(':');

                        if (pos != std::string::npos)
                        {
                            std::string headerName = header.substr(0, pos);
                            std::string headerValue = header.substr(pos + 1);

                            // ltrim
                            headerValue.erase(headerValue.begin(),
                                              std::find_if(headerValue.begin(), headerValue.end(),
                                                           std::not1(std::ptr_fun<int, int>(std::isspace))));

                            // rtrim
                            headerValue.erase(std::find_if(headerValue.rbegin(), headerValue.rend(),
                                                           std::not1(std::ptr_fun<int, int>(std::isspace))).base(),
                                              headerValue.end());

                            if (headerName == "Sec-WebSocket-Key")
                                key = headerValue;
                        }
                    }

                    std::cout << "Key: " << key << std::endl;

                    std::vector<uint8_t> hash = sha1::hash(key + magic);
                    std::string base64Hash = base64::encode(hash);

                    std::string responseStr = "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: " + base64Hash + "\r\n\r\n";

                    std::vector<uint8_t> response(responseStr.begin(), responseStr.end());
                    s.send(response);

                    break;
                }
                else if (firstLine) // first line
                {
                    firstLine = false;

                    std::string::size_type pos, lastPos = 0, length = line.length();
                    std::vector<std::string> parts;

                    // tokenize first line
                    while (lastPos < length + 1)
                    {
                        pos = line.find(' ', lastPos);
                        if (pos == std::string::npos) pos = length;

                        if (pos != lastPos)
                            parts.push_back(std::string(line.data() + lastPos,
                                                        static_cast<std::vector<std::string>::size_type>(pos) - lastPos));

                        lastPos = pos + 1;
                    }

                    if (parts.size() < 2)
                        throw std::runtime_error("Not enought parameters");

                    if (parts[0] != "GET")
                        throw std::runtime_error("Invalid request type");

                    if (parts[1] != "/")
                        throw std::runtime_error("Invalid path");
                }
                else // headers
                    headers.push_back(line);
            }
            else // handle data frame
            {
                if (clientData.size() < 2) break;

                uint32_t offset = 0;

                uint8_t finalFragment = (clientData[offset] >> 7) & 0x01; // bit 0
                Opcode opcode = static_cast<Opcode>(clientData[offset] & 0x0F); // bits 4-7
                ++offset;

                uint8_t masked = (clientData[offset] >> 7) & 0x01; // bit 8
                uint64_t payloadLength = clientData[offset] & 0x7F; // bits 9-15
                ++offset;

                if (payloadLength == 126)
                {
                    if (clientData.size() - offset < 2) break;

                    payloadLength = (clientData[offset] << 8) |
                    clientData[offset + 1];
                    offset += 2;
                }
                else if (payloadLength == 127)
                {
                    if (clientData.size() - offset < 8) break;

                    payloadLength = (static_cast<uint64_t>(clientData[offset]) << 56) |
                        (static_cast<uint64_t>(clientData[offset + 1]) << 48) |
                        (static_cast<uint64_t>(clientData[offset + 2]) << 40) |
                        (static_cast<uint64_t>(clientData[offset + 3]) << 32) |
                        (clientData[offset + 4] << 24) |
                        (clientData[offset + 5] << 16) |
                        (clientData[offset + 6] << 8) |
                        clientData[offset + 7];

                    offset += 8;
                }

                uint8_t mask[4];
                if (masked)
                {
                    if (clientData.size() - offset < 4) break;

                    std::copy(clientData.begin() + offset, clientData.begin() + offset + sizeof(mask), std::begin(mask));
                    offset += sizeof(mask);
                }

                if (clientData.size() - offset < payloadLength) break;

                std::vector<uint8_t> payload(payloadLength);
                std::copy(clientData.begin() + offset, clientData.begin() + offset + payloadLength, payload.begin());
                offset += payloadLength;

                if (masked)
                    for (int i = 0; i < payload.size(); ++i)
                        payload[i] = payload[i] ^ mask[i % 4];

                clientData.erase(clientData.begin(), clientData.begin() + offset);

                std::cout << "Final fragment: " << (finalFragment & 0xFF) << ", opcode: " << toString(opcode)  <<
                    ", masked: " << (masked & 0xFF) << ", payload length: " << (payloadLength & 0xFF) << ", payload:";

                if (opcode == Opcode::CLOSE)
                    s.close();
                else if (opcode == Opcode::PING)
                    sendFrame({}, Opcode::PONG);
                else if (opcode == Opcode::TEXT_FRAME)
                    std::cout << " " << std::string(payload.begin(), payload.end());
                else if (opcode == Opcode::BINARY_FRAME)
                    for (uint8_t b : payload)
                        std::cout << " " << (b & 0xFF);

                std::cout << std::endl;

                if (opcode == Opcode::TEXT_FRAME ||
                    opcode == Opcode::BINARY_FRAME)
                    handleFrame(payload, opcode);
            }
        }
    }

    std::mt19937 rng;
    std::uniform_int_distribution<uint8_t> dist;

    cppsocket::Socket socket;
    std::function<void(const std::vector<uint8_t>&)> frameHandler;
    bool firstLine = true;
    bool handshakeDone = false;
    std::vector<uint8_t> clientData;
    std::vector<std::string> headers;
};

#endif // WEBSOCKET_HPP
