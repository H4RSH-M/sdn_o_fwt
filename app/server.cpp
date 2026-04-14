#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    //socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std :: cerr << "[!] Socket creation failed broski.." << std :: endl;
        return 1;
    }

    //force attach to port so we dont get address in use errors
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std :: cerr << "[!] setsockopt failed bruh.." << std :: endl;
        return 1;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    //bind the socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std :: cerr << "[!] Bind failed damn.." << std :: endl;
        return 1;
    }

    //start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        std :: cerr << "[!] Listen failed.. nobody's here" << std :: endl;
        return 1;
    }
    
    std :: cout << "[+] SERVER INITIALIZED BROSKI" << std :: endl;
    std :: cout << "[+] listening on tcp port " << PORT << "..." << std :: endl;

    //accept the incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        std :: cerr << "[!] Accept failed bruh.." << std :: endl;
        return 1;
    }

    std :: cout << "[!] homie connected. incoming connection accepted." << std :: endl;

    //open file to dump the incoming binary data
    std :: ofstream outfile("received_payload.bin", std :: ios :: binary);
    if (!outfile) {
        std :: cerr << "[!] Error opening file for writing.. check permissions" << std :: endl;
        return 1;
    }

    //receive loop to get the file chunks
    int bytesRead;
    std :: cout << "[>] receiving file..." << std :: endl;
    while ((bytesRead = recv(new_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        outfile.write(buffer, bytesRead);
    }

    std :: cout << "[+] transfer complete. connection closed." << std :: endl;

    //cleanup
    outfile.close();
    close(new_socket);
    close(server_fd);
    return 0;
}