#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <limits.h>
#include <fcntl.h>
#include <sys/time.h>

#include "utils.h"

#define STDIN 0 // fd for standard input

// this method sends the user name and the password to the server for authorization
// if authorized, prints number of files in the server
// return 1 on success and -1 on failure
int send_user_and_possword_for_autintication(int socket_fd){
	
	char *us, *ps, *ptr_for_strtol, *temp, *prefix;
	char userInput[USERNAME_MAX_LEN + 10], passwordInput[PASSWORD_MAX_LEN + 10], serverReply[IS_AUTHORIZED]; 
	char num_of_files_in_binary[NUMBER_OF_FILES_MSG_LEN]; 
	char user[USERNAME_MAX_LEN], password[PASSWORD_MAX_LEN];
	char padded_user_msg[USERNAME_MSG_LEN], padded_password_msg[PASSWORD_MSG_LEN], num_of_files_as_string[10];	
	int num_of_files, keep_trying=1, is_valid;
	long long_num_of_files;
		
	// the client writes "USER: " and it's username. same for password according to http://moodle.tau.ac.il/mod/forum/discuss.php?d=7819s
	// check format
	while(keep_trying){
		userInput[0] = '\0';
		temp = fgets(userInput, USERNAME_MAX_LEN + 10, stdin);
		if(temp==NULL){
			printf("Error in reading\n");
			return -1;
		}
		userInput[strlen(userInput)-1]='\0';
		user[0] = '\0';
		prefix = strtok(userInput, " ");
		if(strcmp(prefix, "User:") != 0){
			printf("username prefix should be 'User: *your username* - try again'\n");
			continue;
		}		
		us = strtok(NULL, " ");
		strncpy(user, us, strlen(us));
		user[strlen(us)]='\0';
	
		passwordInput[0] = '\0';
		temp = fgets(passwordInput, PASSWORD_MAX_LEN + 10, stdin);
		if(temp==NULL){
			printf("Error in reading\n");
			return -1;
		}

		passwordInput[strlen(passwordInput)-1]='\0';
		password[0] = '\0';
		prefix = strtok(passwordInput, " ");
		if(strcmp(prefix, "Password:") != 0){
			printf("Password prefix should be 'Password: *your password* - try again'\n");
			continue;
		}
		ps = strtok(NULL, " ");
		strncpy(password, ps, strlen(ps));
		password[strlen(ps)]='\0';

		is_valid = send_data(socket_fd, CHECK_CREDENTIALS, COMMAND_MSG_LEN);
		if(is_valid < 0){
			printf("Failed to send credentials to the server\n");
			return -1;
		}
		padded_user_msg[0]='\0';
		padding(strlen(user), USERNAME_MSG_LEN, padded_user_msg);
		is_valid = send_data(socket_fd, padded_user_msg, USERNAME_MSG_LEN);
		if(is_valid < 0){
			printf("Failed to send credentials to the server\n");
			return -1;
		}
		is_valid = send_data(socket_fd, user, strlen(user));
		if(is_valid < 0){
			printf("Failed to send credentials to the server\n");
			return -1;
		}
		padded_password_msg[0]='\0';
		padding(strlen(password), PASSWORD_MSG_LEN, padded_password_msg);

		is_valid = send_data(socket_fd, padded_password_msg, PASSWORD_MSG_LEN);
		if(is_valid < 0){
			printf("Failed to send credentials to the server\n");
			return -1;
		}
		is_valid = send_data(socket_fd, password, strlen(password));
		if(is_valid < 0){
			printf("Failed to send credentials to the server\n");
			return -1;
		}
		
		is_valid = recv_data(socket_fd, serverReply, IS_AUTHORIZED);
		if(is_valid < 0){
			printf("Failed to send information to the server\n");
			return -1;
		}
		serverReply[1]='\0';

		if(strcmp(serverReply,"1")==0){ // i.e. authorized
			keep_trying = 0;
		}
		else{
			printf("Wrong credentials - try again\n");
		}
	}
	
	// receiving number of files
	num_of_files_in_binary[0]='\0';
	is_valid = recv_data(socket_fd, num_of_files_in_binary, NUMBER_OF_FILES_MSG_LEN);
	if(is_valid < 0){
		printf("Failed to receive # of files from server\n");
		return -1;
	}
	num_of_files_in_binary[NUMBER_OF_FILES_MSG_LEN]='\0';
	num_of_files = strtol(num_of_files_in_binary, &ptr_for_strtol, 2);
	sprintf(num_of_files_as_string, "%d", num_of_files);
	long_num_of_files = strtol(num_of_files_as_string,&ptr_for_strtol,10);
	if (long_num_of_files == LONG_MAX || long_num_of_files == LONG_MIN){
		printf("Error in converting the port to short, %s\n",strerror(errno));
		return -1;
	}
	printf("Hi %s, you have %d files stored.\n", user, num_of_files);
	return 1;
}

// this method sends the command name and its arguments to the server
// return 1 on success and -1 on failure
int send_command_and_params(int socket_fd, char* command_code, char* arg1){
	
	int arg1_len, is_valid, num_of_args;
	char padded_filename[FILENAME_MSG_LEN], padded_msg[CLIENT_INTERACTION_LEN];
	padded_filename[0] = '\0'; padded_msg[0] = '\0';
	
	// first, send the command code to the server
    is_valid = send_data(socket_fd, command_code, COMMAND_MSG_LEN);
    if(is_valid < 0){
    	// no need to print since print happened in send_data
    	return -1;	
    }

    // according to protocol, the list_of_files and quit do not have arguments to send. delete_file, get_file, add_file have 1 to send.
    if(strcmp(command_code, LIST_OF_FILES_COMMAND) == 0 || strcmp(command_code, QUIT_COMMAND) == 0 
		|| strcmp(command_code, READ_MSG_COMMAND) == 0 || strcmp(command_code, USERS_ONLINE_COMMAND) == 0)
	{
    	num_of_args = 0;
    }
    if(strcmp(command_code, DELETE_FILE_COMMAND) == 0 || strcmp(command_code, ADD_FILE_COMMAND) == 0 
		|| strcmp(command_code, GET_FILE_COMMAND) == 0 || strcmp(command_code, MSG_COMMAND) == 0)
	{
    	num_of_args = 1;
    	arg1_len = strlen(arg1);
    }

    // then, send length of the first argument. afterwards sends the argument 
    if(num_of_args > 0){
		//printf("send param, args >1\n");
		if(strcmp(command_code, MSG_COMMAND) == 0){
			padding(arg1_len, CLIENT_INTERACTION_LEN, padded_msg);
			//printf("send param, MSG command, arg1: %s, arg1_len: %d, padded_msg: %s\n", arg1, arg1_len, padded_msg);
			is_valid = send_data(socket_fd, padded_msg, CLIENT_INTERACTION_LEN);
	    	if(is_valid < 0){
	    		// no need to print since print happened in send_data
	    		return -1;	
	    	}
		}
		else{
			//printf("send param, add/get/del command\n");
			padding(arg1_len, FILENAME_MSG_LEN, padded_filename);
			is_valid = send_data(socket_fd, padded_filename, FILENAME_MSG_LEN);
	    	if(is_valid < 0){
	    		// no need to print since print happened in send_data
	    		return -1;	
	    	}
		}

		//printf("send param2, args >1\n");
	    is_valid = send_data(socket_fd, arg1, arg1_len);
	    //printf("send param3, args >1\n");
	    if(is_valid < 0){
	    	// no need to print since print happened in send_data
	    	return -1;	
	    }
    }
    return 1;
}

// this method is called when there is a msg for the client
// if there is a message, it is printed and 1 is returned
// in case of failure, -1 is returned
int get_messages(int socket_fd){

	int message_len, is_valid;
	long int long_message_len;
	char *ptr_for_strtol;
	char message[USERNAME_MAX_LEN + MAX_MESSAGE_SIZE + 2]; // 2 is for ": " between username and message
	char message_len_bin[CLIENT_INTERACTION_LEN], command_code[COMMAND_MSG_LEN+1];
	

	command_code[0] = '\0';
	is_valid = recv_data(socket_fd, command_code, COMMAND_MSG_LEN);
	if (is_valid < 0){
		// no need to print since printing happens in recv_data
		return -1;
	}
	command_code[COMMAND_MSG_LEN] = '\0';
	printf("command_code: %s\n", command_code);
	if (strcmp(command_code, CLIENT_INTERACTION_NOTIFICATION) != 0){
		printf("unknown transmission from server\n");
		return -1;
	}
	message_len_bin[0] = '\0';
	is_valid = recv_data(socket_fd, message_len_bin, CLIENT_INTERACTION_LEN);
	if (is_valid < 0){
		// no need to print since printing happens in recv_data
		return -1;
	}
	long_message_len = strtol(message_len_bin, &ptr_for_strtol, 2);
	// check conversion went good
	if (long_message_len == LONG_MAX || long_message_len == LONG_MIN){
		printf("Error in converting the port to short, %s\n",strerror(errno));
		return -1;
	}
	message_len = (int)long_message_len;
	message[0] = '\0';
	is_valid = recv_data(socket_fd, message, message_len);
	if (is_valid < 0){
		// no need to print since printing happens in recv_data
		return -1;
	}
	message[message_len] = '\0';
	printf("%s", message);

	is_valid = send_data(socket_fd, CLIENT_INTERACTION_NOTIFICATION, COMMAND_MSG_LEN);
	if (is_valid < 0){
		// no need to print since printing happens in recv_data
		return -1;
	}
	
	return 1;
}


int main(int argc, char *argv[]){

	int is_valid, socket_fd, keep_running, max_socket_fd_for_select; 
	short port;
	long int long_port, long_message_len;
	struct addrinfo hint, *res;
    char *ptr_for_strtol, *server_name, *temp;
    
    // check input arguments
    if(argc > 3){
    	printf("Wrong number of parameters!\n");
    	return -1;
    }

    else if(argc == 1){
    	// no parameters given
    	port = DEFAULT_PORT;
    	server_name = (char*)DEFAULT_HOSTNAME;
    }
   
    else if(argc == 2){
    	server_name = argv[1];
        port = DEFAULT_PORT;
    }

    else if(argc == 3){
        server_name = argv[1];
    	long_port = strtol(argv[2],&ptr_for_strtol,10); 
    	if (long_port == LONG_MAX || long_port == LONG_MIN){
    		printf("Error in converting the port to short, %s\n",strerror(errno));
	    	return -1;
    	}
    	port = (short)long_port;
	}	
    
    // create the TCP socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0); // use 0, the default value since TCP is default protocol
    if(socket_fd == -1){
    	printf("Error while creating socket for client. %s\n",strerror(errno));
    	return -1;
    }
    
    // create data structure to bind client to server
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_flags = AI_PASSIVE;
    hint.ai_socktype = SOCK_STREAM;

    char port_as_string[5];
    sprintf(port_as_string, "%d", (int)port);
    is_valid = getaddrinfo(server_name, port_as_string, &hint, &res);
    if(is_valid < 0){
    	printf("could not get server ip, %s\n",gai_strerror(is_valid));
	return -1;
    }

    // connect the socket to server
    is_valid = connect(socket_fd, res->ai_addr, res->ai_addrlen);
    if(is_valid == -1){
    	printf("Error while connecting client to server. %s\n", strerror(errno));
    	freeaddrinfo(res);
    	return -1;
    }

    // print hello msg to the client
    printf("Welcome! Please log in.\n");
	
	// ########################################################## //
	// send user & password to server for authorization:
	// ########################################################## //	
	is_valid = send_user_and_possword_for_autintication(socket_fd);
	if(is_valid == -1){
		printf("Error while trying to get authorization from server. %s\n", strerror(errno));
		freeaddrinfo(res);
		close(socket_fd);
		return -1;
    }

	// if we are here, it means the client connected successfully to the server and provided valid user and password
	// and we have printed the number of files it has

	// ########################################################## //
	// running the commands:
	// ########################################################## //
	// Command interface:
	char *command, *argument1, *argument2;
	char userInput[LINE_MAX_LEN];
	keep_running = 1;
	printf("Please enter your command: ");
	fflush(NULL);
    while(keep_running){
    	// choose whether to get client's command input or message from other client
    	fd_set read_fds;
	
		FD_ZERO(&read_fds);
		FD_SET(socket_fd, &read_fds);
		FD_SET(STDIN, &read_fds);
		if (socket_fd > STDIN){
			max_socket_fd_for_select = socket_fd + 1;
		}
		else{
			max_socket_fd_for_select = STDIN + 1;
		}

		// wait for input, rather client or msg
		//printf("check_messages - before select\n");
		is_valid = select(max_socket_fd_for_select, &read_fds, NULL, NULL, NULL);
	    if (is_valid == -1){
	    	printf("error while checking if there is a message. %s\n", strerror(errno));
	    	freeaddrinfo(res);
	    	close(socket_fd);
	    	return -1;
	    }
	    //printf("check_messages - after select\n");

	    // check who is ready for recv
	    if (FD_ISSET(socket_fd, &read_fds)){
	    	// incoming msg
	    	is_valid = get_messages(socket_fd);
	    	if (is_valid == -1){
	    		printf("Error in get msg from other client\n");
	    		freeaddrinfo(res);
	    		close(socket_fd);
	    		return -1;
	    	}
	    }

	    if (FD_ISSET(STDIN, &read_fds)){
	    	// input is from client - handle command

			//userInput[0] = '\0';
			temp = fgets(userInput, LINE_MAX_LEN, stdin);
			if(temp==NULL){
				printf("Error in reading command\n");
				return -1;
			}
			userInput[strlen(userInput)-1] = '\0';
			command = strtok(userInput, " ");
			argument1 = strtok(NULL, " ");
			//argument2 = strtok(NULL, " ");
			argument2 = strtok(NULL, "\n"); // made a change here....

			// Quit Command
			if(strcmp(command,"quit") == 0){
				// sending command and params to server
				is_valid = send_command_and_params(socket_fd, QUIT_COMMAND, NULL);
				// since the command is quit there is no real need in checking the result because we are quiting anyway..
				keep_running =0;
			}
			
			// List of Files Command
			else if(strcmp(command,"list_of_files") == 0){
				// sending command and params to server
				int message_len;
				char serverReply[MAX_FILES_PER_USER*MAX_FILENAME], binary_message_len[LIST_OF_FILES_MSG_LEN];
				
				is_valid = send_command_and_params(socket_fd, LIST_OF_FILES_COMMAND, NULL);
				if(is_valid < 0){
					// no need to print since printing in send_command_and_params
					break; 
				}

				binary_message_len[0] = '\0';
				is_valid = recv_data(socket_fd, binary_message_len, LIST_OF_FILES_MSG_LEN);
				if(is_valid < 0){
					// no need to print since printing in recv_data
					break;
				}
				binary_message_len[LIST_OF_FILES_MSG_LEN] = '\0';
				long_message_len = strtol(binary_message_len, &ptr_for_strtol, 2);
				// check conversion went good
				if(long_message_len == LONG_MAX || long_message_len == LONG_MIN){
					printf("Error in converting the msg len to short, %s\n",strerror(errno));
					return -1;
				}
				message_len = (int)long_message_len;
				if(message_len > 0){
					serverReply[0] = '\0';
					is_valid = recv_data(socket_fd, serverReply, message_len);
					if(is_valid < 0){
						// no need to print since printing in recv_data
						break;
					}
					serverReply[message_len] = '\0';
				}
				else{
					strcat(serverReply, "You have no files stored\n");
				}
				printf("%s",serverReply);
			}

			// Delete File Command		
			else if(strcmp(command,"delete_file") == 0){
				// sending command and params to server
				is_valid = send_command_and_params(socket_fd, DELETE_FILE_COMMAND, argument1);
				if(is_valid < 0){
					printf("Failed to send command\n");
					break; 
				}
				char serverReply[DELETE_FILE_MSG_LEN];
				is_valid = recv_data(socket_fd, serverReply, DELETE_FILE_MSG_LEN);
				if(is_valid < 0){
					printf("No response from the server\n");
					break;
				}
				serverReply[DELETE_FILE_MSG_LEN]='\0';

				if(strcmp(serverReply, "0") == 0){
					printf("No such file exists!\n");
				}
				else if(strcmp(serverReply, "1") == 0){
					printf("File removed\n");
				}
				else{
					//unknown answer.. quit
					printf("Unknown answer from server: %s\n", serverReply);
					break;
				}
			}
			
			// Add File Command
			else if(strcmp(command,"add_file") == 0){
				// sending command and params to server - it only needs the second argument, the end file location

				is_valid = open(argument1, O_RDONLY);
				if(is_valid == -1 && (errno == EACCES || errno == ENOENT)){ // file doesn't exist
					printf("The File doesn't exist\n");
				}
				else{
					is_valid = send_command_and_params(socket_fd, ADD_FILE_COMMAND, argument2);
					if(is_valid < 0){
						printf("Failed to send command\n");
						break; 
					}

					is_valid = send_file(socket_fd, argument1);
					if(is_valid > 0){
						// no need to print since prints happen in send_file
						break;
					}

					char serverReply[ADD_FILE_MSG_LEN];
					is_valid = recv_data(socket_fd, serverReply, ADD_FILE_MSG_LEN);
					if(is_valid < 0){
						printf("No response from the server\n");
						break;
					}
					serverReply[ADD_FILE_MSG_LEN] = '\0';

					if(strcmp(serverReply, "0") == 0){
						printf("File added\n");
					}
					else if(strcmp(serverReply, "1") == 0){
						printf("There was a file operation error\n");
					}
					else if(strcmp(serverReply, "2") == 0){
						printf("There was a network error\n");
					}
					else{
						//unknown answer.. quit
						printf("Unknown answer from server: %s\n", serverReply);
						break;
					}
				}
			}
			
			// Get File Command
			else if(strcmp(command,"get_file") == 0){
				// sending command and params to server. It only needs the first argument, to know what to send
				char serverReply[GET_FILE_MSG_LEN];

				//printf("get-file - before send command\n");
				is_valid = send_command_and_params(socket_fd, GET_FILE_COMMAND, argument1);
				//printf("get-file - after send command\n");
				if(is_valid < 0){
					// no need to print since prints happen in send_command_and_params
					break; 
				}

				serverReply[0] = '\0';
				is_valid = recv_data(socket_fd, serverReply, GET_FILE_MSG_LEN);
				if (is_valid < 0){
		        	// no need to print since printing in recv_data
		        	break;
		        }
		        //printf("get-file1\n");
		        serverReply[GET_FILE_MSG_LEN] = '\0';
				if(strcmp(serverReply, "0") == 0){
					printf("file doesn't exist\n");
				}
				else{
					is_valid = recieve_file(socket_fd, argument2);
					if(is_valid == 1){
						printf("There was a file operation error\n");
					}
					else if(is_valid == 2){
						printf("There was a network error\n");
					}
					else { // (is_valid > 2)
						printf("File received\n");
					}
				}
			}

			// Users On-line Command
			else if(strcmp(command, "users_online") == 0){

				int message_len;
				char serverReply[USERNAME_MAX_LEN*MAX_USERS], binary_message_len[USERS_ONLINE_MSG_LEN];

				// sending command and params to server
				is_valid = send_command_and_params(socket_fd, USERS_ONLINE_COMMAND, NULL);
				if(is_valid < 0){
					// no need to print since prints happen in send_command_and_params
					break; 
				}

				binary_message_len[0] = '\0';
				is_valid = recv_data(socket_fd, binary_message_len, USERS_ONLINE_MSG_LEN);
				if(is_valid < 0){
					// no need to print since printing in recv_data
					break;
				}

				binary_message_len[USERS_ONLINE_MSG_LEN]='\0';
				long_message_len = strtol(binary_message_len, &ptr_for_strtol, 2);
				// check convertaions went good
				if(long_message_len == LONG_MAX || long_message_len == LONG_MIN){
					printf("Error in converting the msg len to short, %s\n",strerror(errno));
					return -1;
				}

				message_len = (int)long_message_len;
				serverReply[0] = '\0';
				is_valid = recv_data(socket_fd, serverReply, message_len);
				if(is_valid < 0){
					// no need to print since printing in recv_data
					break;
				}
				serverReply[message_len] = '\0';
				printf("%s",serverReply);

			}

			// Msg Command
			else if(strcmp(command, "msg") == 0){
				
				char username_and_message[USERNAME_MSG_LEN + MESSAGE_SIZE_LEN + 2], msg_serverReply[MSG_MSG_LEN+1];
				username_and_message[0] = '\0'; msg_serverReply[0] = '\0';
				strcat(username_and_message, argument1);
				username_and_message[strlen(argument1)-1] = '\0'; // omit ':' that was passed by the client
				strcat(username_and_message,  "_");
				strcat(username_and_message, argument2);
				//printf("msg1, username_and_message: %s\n", username_and_message);
				// sending command and params to server
				is_valid = send_command_and_params(socket_fd, MSG_COMMAND, username_and_message);
				if(is_valid < 0){
					// no need to print since prints happen in send_command_and_params
					break; 
				}
				//printf("msg2 - after send command\n");
				
				// get reply from the server
				is_valid = recv_data(socket_fd, msg_serverReply, MSG_MSG_LEN);
				if(is_valid < 0){
					printf("No response from the server\n");
					break;
				}
				msg_serverReply[MSG_MSG_LEN] = '\0';
				//printf("msg3 - msg_serverReply: %s\n", msg_serverReply);
				if(strcmp(msg_serverReply, "0") == 0){
					printf("Client name passed doesn't exist\n");
				}
				else if(strcmp(msg_serverReply, "1") == 0){
					printf("Message was received by the recipient client\n");
				}
				else if(strcmp(msg_serverReply, "2") == 0){
					printf("Client isn't on-line, message was saved on the server\n");
				}
				else if(strcmp(msg_serverReply, "3") == 0){
					printf("There was a network error\n");
					break;
				}
				else{
					printf("Unknown answer from server: %s\n", msg_serverReply); //unknown answer.. quit
					break;
				}
			}

			// Read Msg Command
			else if(strcmp(command, "read_msgs") == 0){
				
				int message_len, msg_counter = 0;
				char serverReply[USERNAME_MAX_LEN + MAX_MESSAGE_SIZE + 3], binary_message_len[OFFLINE_MESSAGE_LEN];
				serverReply[0] = '\0'; binary_message_len[0] = '\0';

				// sending command and params to server
				is_valid = send_command_and_params(socket_fd, READ_MSG_COMMAND, NULL);
				if(is_valid < 0){
					// no need to print since prints happen in send_command_and_params
					break; 
				}

				while(strcmp(serverReply, END_OF_OFLINE_MESSAGES) != 0){

					binary_message_len[0] = '\0';
					is_valid = recv_data(socket_fd, binary_message_len, OFFLINE_MESSAGE_LEN);
					if(is_valid < 0){
						// no need to print since printing in recv_data
						break;
					}
					binary_message_len[OFFLINE_MESSAGE_LEN] = '\0';
					long_message_len = strtol(binary_message_len, &ptr_for_strtol, 2);
					// check conversion went good
					if(long_message_len == LONG_MAX || long_message_len == LONG_MIN){
						printf("Error in converting the msg len to short, %s\n",strerror(errno));
						return -1;
					}
					message_len = (int)long_message_len;
					serverReply[0] = '\0';
					is_valid = recv_data(socket_fd, serverReply, message_len);
					if(is_valid < 0){
						// no need to print since printing in recv_data
						break;
					}
					serverReply[message_len] = '\0';
					if(strcmp(serverReply, END_OF_OFLINE_MESSAGES) != 0){
						printf("%s\n", serverReply);
						msg_counter++;
					}
				}
				if(msg_counter == 0){
					printf("You have no message\n");
				}
			}

			else{
				printf("non-recognizable command. try again\n");
			}
		}

		if(keep_running != 0){
			printf("Please enter the next command: ");
			fflush(NULL);
		}
    }

    //after command loop. Exiting gracefully
    freeaddrinfo(res);
	close(socket_fd);
	if(keep_running == 1){
		// left the loop because of an error
		return -1;
	}
	else{
		return 0;
	}
}
