
#define DEFAULT_PORT 1337
#define DEFAULT_MODE 00775
#define USERNAME_MAX_LEN 25
#define PASSWORD_MAX_LEN 25
#define MAX_USERS 15
#define MAX_FILES_PER_USER 15
#define MAX_FILE_SIZE 512
#define MAX_FILENAME 50
#define MAX_PATH_LEN 50
#define MAX_MESSAGE_SIZE 100
#define FILE_BULK_SIZE 256
#define DEFAULT_HOSTNAME "localhost"
#define MESSAGE_FILE_NAME "Messages_received_offline.txt"
#define END_OF_OFLINE_MESSAGES "ZZZ"


// commands codes to send from client to server
//TODO  - maybe unused so remove!!

#define CHECK_CREDENTIALS "C"
#define QUIT_COMMAND "Q"
#define LIST_OF_FILES_COMMAND "L"
#define DELETE_FILE_COMMAND "D"
#define ADD_FILE_COMMAND "A"
#define GET_FILE_COMMAND "G"
#define USERS_ONLINE_COMMAND "U"
#define MSG_COMMAND "M"
#define READ_MSG_COMMAND "R"
#define CLIENT_INTERACTION_NOTIFICATION "N"

#define COMMAND_MSG_LEN 1
#define IS_AUTHORIZED 1
#define USERNAME_MSG_LEN 5 // derived from len(USERNAME_MAX_LEN)
#define PASSWORD_MSG_LEN 5 // derived from len(PASSWORD_MAX_LEN)
#define NUMBER_OF_FILES_MSG_LEN 3 // derived from len(MAX_FILES_PER_USER)
#define LIST_OF_FILES_MSG_LEN 10 // derived from len(MAX_FILES_PER_USER * MAX_FILENAME)
#define DELETE_FILE_MSG_LEN 1
#define ADD_FILE_MSG_LEN 1
#define GET_FILE_MSG_LEN 1
#define USERS_ONLINE_MSG_LEN 9 // derived from len(USERNAME_MAX_LEN * MAX_USERS)
#define MSG_MSG_LEN 1
#define FILENAME_MSG_LEN 8 // derived from len(MAX_FILENAME)
#define FILE_SIZE_MSG_LEN 12 // derived from len(MAX_FILE_SIZE)
#define MESSAGE_SIZE_LEN 7 // derived from len(MAX_MESSAGE_SIZE)
#define CLIENT_INTERACTION_LEN 14 // derived from len(USERNAME_MSG_LEN) + len(MESSAGE_SIZE_LEN)
#define OFFLINE_MESSAGE_LEN 7 // derived from len(USERNAME_MAX_LEN + MAX_MESSAGE_SIZE + 3)
#define LINE_MAX_LEN 1024

// this is a helper func' for send data.
// this method recives the length of the message we want to send and transforms it to a binary represantation of fixed size acording to the command
void padding(int messege_len, int final_len, char *padded);

// this method in charge of sending the data in buf between client and server
// returns #of byts sent ; -1 on network error
int send_data(int socket_fd, char *buf, int total_len);

// this method recieves data in buf from between client and server 
// returns number of bytes recieved or -1 for error
// returns -2 when the other side closes the socket so the server will know to close the connection
int recv_data(int socket_fd, void *buf, int total_len);

// this method gets as input socket fd and full path to a file. it writes the content transfered from the socket to the file specified
// returns 0 on success; 1 on error regarding file operations; 2 on network errors
int recieve_file(int socket_fd, char *full_path);

// this method gets as input socket fd and full path to a file and sends file's content to using the socket
// returns 0 on success; 1 on error regarding file operations; 2 on network errors
int send_file(int socket_fd, char *full_path);
