#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]) {
    //check if args are right
    if (argc != 3) {
        std :: cerr << "Usage: " << argv[0] << " <Server_IP> <File_To_Send> broski" << std :: endl;
        return 1;
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    //create socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std :: cerr << "[!] Socket creation error bruh.." << std :: endl;
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    //convert ip addresses from text to binary form
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        std :: cerr << "[!] Invalid address broski / not supported" << std :: endl;
        return 1;
    }

    //connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std :: cerr << "[!] Connection failed damn.. is the server even up?" << std :: endl;
        return 1;
    }

    std :: cout << "[+] connected to server at " << argv[1] << ":" << PORT << std :: endl;

    //open the file we wanna send
    std :: ifstream infile(argv[2], std :: ios :: binary);
    if (!infile) {
        std :: cerr << "[!] Error opening file bruh.. u sure it exists?" << std :: endl;
        return 1;
    }

    //read and send loop
    std :: cout << "[>] sending file: " << argv[2] << "..." << std :: endl;
    while (infile.read(buffer, BUFFER_SIZE) || infile.gcount() > 0) {
        send(sock, buffer, infile.gcount(), 0);
    }

    std :: cout << "[+] file sent successfully annayya." << std :: endl;

    //cleanup
    infile.close();
    close(sock);
    return 0;
}