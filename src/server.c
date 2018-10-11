#include <sys/socket.h>
#include <sys/types.h>
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
#include <fcntl.h> // for open flags
#include <dirent.h> // for dealing with directories
#include <sys/select.h>
#include <sys/time.h>

#include "utils.h"


struct user_password_struct{
	char username[USERNAME_MAX_LEN];
	char password[PASSWORD_MAX_LEN];
	char user_dir[USERNAME_MAX_LEN + MAX_PATH_LEN + 2];
	int num_of_files;
	int is_connected;
	int user_socket_fd;
};


// this method creates an array of users from the given users_file for the purpose of authentication of the clients.
// we decided it's better to do the authentication with an array instead of opening and reading the file each time.
// return 1 on success and -1 in case of failure
int create_user_password_database(struct user_password_struct listed_users[], char* file_path, char* server_dir, int *real_num_of_users){
	int file_fd, total_users = 0, in_user = 1, user_loc =0, pass_loc = 0, need_to_add_tab = 0;
	char data_read[1];
	char curr_user[USERNAME_MAX_LEN], curr_pass[PASSWORD_MAX_LEN];

	file_fd = open(file_path, O_RDONLY);
	if(file_fd < 0){
		return -1;
	}

	// check if server_dir ends with '/' or do we need to add it
	if (server_dir[strlen(server_dir) - 1] =='/'){
		need_to_add_tab = 0;
	}
	else{
		need_to_add_tab = 1;
	}

	data_read[0] = '\0'; curr_user[0]= '\0'; curr_pass[0]= '\0';
	while(read(file_fd, data_read, 1) > 0){
		if(strncmp(data_read, "\t", 1) == 0){
			// finished username data. enter to struct
			in_user = 0;
			pass_loc = 0;
			curr_user[user_loc] = '\0';
			strcpy(listed_users[total_users].username, curr_user);
			

			// enter the dir of the user
			
			strcpy(listed_users[total_users].user_dir, server_dir);
			if (need_to_add_tab == 1){
				listed_users[total_users].user_dir[strlen(server_dir)] =  '/';
			}
			listed_users[total_users].user_dir[strlen(server_dir) + need_to_add_tab] = '\0'; // for the user insertion
			
			strcat(listed_users[total_users].user_dir, curr_user);
			strcat(listed_users[total_users].user_dir, "/");
			
			// enter is connected status
			listed_users[total_users].is_connected = 0;
			listed_users[total_users].user_socket_fd = -1;
			//printf("inserted username: - %s\n", listed_users[total_users].username);
			//printf("inserted user dir: - %s\n", listed_users[total_users].user_dir);
			curr_user[0] = '\0';
			continue;
		}
		
		if(strncmp(data_read, "\n",1) == 0){
			in_user = 1;
			user_loc = 0;
			curr_pass[pass_loc] = '\0';
			listed_users[total_users].num_of_files = 0;
			strcpy(listed_users[total_users].password, curr_pass);
			//printf("inserted password: - %s, len is %d\n", listed_users[total_users].password, pas_len);
			curr_pass[0] = '\0';
			total_users += 1;
			continue;
		}

		if (in_user){
			strncpy(curr_user + user_loc,data_read, 1);
			user_loc += 1;
			curr_user[user_loc]= '\0';
		}
		else{ // in password
			strncpy(curr_pass + pass_loc,data_read, 1);
			pass_loc += 1;
			curr_pass[pass_loc]= '\0';
		}
		data_read[0] = '\0';
	}
	*real_num_of_users = total_users;
	close(file_fd);
	return 0;
}

// a helper func to "get_and_validate_user_password_data".
// gets the given by client user-name and password, and checks in the database if there is a match
// returns -1 if not authorized; int>=0, number of file in users directory if authorized
int check_credentials(char* username, char* password, struct user_password_struct listed_users[], int real_num_of_users){

	for (int i=0; i<real_num_of_users ;i++){
		if (strcmp(username, listed_users[i].username)==0 && strcmp(password, listed_users[i].password)==0){
			return i;
		}
	}
	return -1;
}

// this method checks for every user if it has a directory in provided homerdir.
// if not, it creates one.
// return 1 on success and -1 in case of failure
int create_directories(struct user_password_struct listed_users[], int real_num_of_users){

	int is_valid, i = 0;
	int file_count, offline_file_fd;
	DIR * dirp;
	struct dirent * entry;

	for (i = 0; i < real_num_of_users; i++){
		file_count = 0;

		char new_dir[strlen(listed_users[i].user_dir)];
		strcpy(new_dir, listed_users[i].user_dir);
		is_valid = mkdir(new_dir, DEFAULT_MODE);
		if (is_valid == -1){
			if (errno == EEXIST){
				dirp = opendir(new_dir); // the dir exists so i'm not checking the return value
				if(dirp == NULL){
					printf("Error in opening existing directory, %s\n",strerror(errno));
					return -1;
				}
				
				while ((entry = readdir(dirp)) != NULL) {
					if (entry->d_type == DT_REG) { // DT_REG = regular file [http://man7.org/linux/man-pages/man3/readdir.3.html]
						file_count++;
					}
				}
				closedir(dirp);
				listed_users[i].num_of_files = file_count - 1; // -1 because of the off-line file
				continue;
			}
			else{
				printf("Error in creating new directory, %s\n",strerror(errno));
	    		return -1;
			}
		}
		else{ // directory just created - need to create off-line message file
			// check if off-line file exists - if not, create it
			char full_offline_file_path[strlen(new_dir) + strlen(MESSAGE_FILE_NAME) + 2];
			strcpy(full_offline_file_path, new_dir);
			strcat(full_offline_file_path, "/");
			strcat(full_offline_file_path, MESSAGE_FILE_NAME);
			full_offline_file_path[strlen(new_dir) + strlen(MESSAGE_FILE_NAME) + 1] = '\0';

			offline_file_fd = open(full_offline_file_path, O_RDWR | O_CREAT, DEFAULT_MODE);
			if (offline_file_fd < 0){
				printf("Error when creating off-line msg file.%s\n",strerror(errno));
				return -1;
			}

			close(offline_file_fd);
		}
	}
	return 1;
}

// receives from the client user-name and password, and checks if this client is registered
// the func, also sends to the client the number of files he has stored
// return 1 - if authorized; 0 - if not authorized; in case the error is in inner function returns its value, -1 in other failure
int get_and_validate_user_password_data(int socket_fd, int* user_idx, struct user_password_struct listed_users[], int real_num_of_users){
	
	int is_valid, message_len, num_of_files;
	long int long_message_len;
	char command_code[COMMAND_MSG_LEN], user[USERNAME_MAX_LEN], password[PASSWORD_MAX_LEN];
	char *ptr_for_strtol, username_binary_len[USERNAME_MSG_LEN+1], password_binary_len[PASSWORD_MSG_LEN+1], num_of_files_in_binary[NUMBER_OF_FILES_MSG_LEN];
	
	//printf("get_and_validate 1\n");
	is_valid = recv_data(socket_fd, command_code, COMMAND_MSG_LEN);
	if (is_valid < 0){
        // no need to print since printing happens in recv_data
        return is_valid;
	}
	//printf("get_and_validate 2\n");
	command_code[1]='\0';
	if (strcmp(command_code, CHECK_CREDENTIALS) == 0){
		// get the user-name
		//printf("get_and_validate 3\n");
		username_binary_len[0]='\0';
		is_valid = recv_data(socket_fd, username_binary_len, USERNAME_MSG_LEN);
		if (is_valid < 0){
			// no need to print since printing happens in recv_data
			return is_valid;
		}
		username_binary_len[USERNAME_MSG_LEN]='\0';
		//printf("get_and_validate 4, username_binary_len: %s\n", username_binary_len);
		long_message_len = strtol(username_binary_len, &ptr_for_strtol, 2);
		// check conversion went good
		if (long_message_len == LONG_MAX || long_message_len == LONG_MIN){
			printf("Error in converting the port to short, %s\n",strerror(errno));
			return -1;
		}
		message_len = (int)long_message_len;
		//printf("get_and_validate 4.5 - message_len: %d, long_message_len: %ld\n", message_len, long_message_len);
		is_valid = recv_data(socket_fd, user, message_len);
		if (is_valid < 0){
			// no need to print since printing happens in recv_data
			return is_valid;
		}
		//printf("get_and_validate 5\n");
		user[message_len]='\0';
		//printf("user name from client: %s, len is %d\n", user, strlen(user));

		// get the user password
		password_binary_len[0]='\0';
		is_valid = recv_data(socket_fd, password_binary_len, PASSWORD_MSG_LEN);
		if (is_valid < 0){
			// no need to print since printing happens in recv_data
			return is_valid;
		}
		password_binary_len[PASSWORD_MSG_LEN]='\0';
		//printf("get_and_validate 6, password_binary_len: %s\n", password_binary_len);
		long_message_len = strtol(password_binary_len, &ptr_for_strtol, 2);
		// check conversion went good
		if (long_message_len == LONG_MAX || long_message_len == LONG_MIN){
			printf("Error in converting the port to short, %s\n",strerror(errno));
			return -1;
		}
		message_len = (int)long_message_len;
		//printf("get_and_validate 6.5 - message_len: %d, long_message_len: %ld\n", message_len, long_message_len);
		is_valid = recv_data(socket_fd, password, message_len);
		if (is_valid < 0){
			// no need to print since printing happens in recv_data
			return is_valid;
		}
		//printf("get_and_validate 7\n");
		password[message_len]='\0';
		//printf("password from client: %s, len is: %d\n", password, strlen(password));
		
		// check if the user-name + password exists in the database, if they do return the idx for it in the DB
		//printf("get_and_validate - before check_credentials command\n");
		*user_idx = check_credentials(user, password, listed_users, real_num_of_users);
		//printf("get_and_validate 8 - after check_credentials command, idx: %d\n", *user_idx);
		if (*user_idx < 0){ // i.e. not authorized
			is_valid = send_data(socket_fd, "0", 1);
			if (is_valid < 0){
				// no need to print since printing happens in recv_data
				return -1;
			}
			//printf("get_and_validate 8.1\n");

			return 0;
		}
		else{ //if(check_credentials()>=0)  // i.e. authorized
			is_valid = send_data(socket_fd, "1", IS_AUTHORIZED); 
			if(is_valid < 0){
				// no need to print since printing happens in recv_data
				return -1;
			}
			//printf("get_and_validate 8.2\n");
			num_of_files = listed_users[*user_idx].num_of_files;
			//printf("get_and_validate - num_of_files: %d\n", num_of_files);
			padding(num_of_files, NUMBER_OF_FILES_MSG_LEN, num_of_files_in_binary);
			is_valid = send_data(socket_fd, num_of_files_in_binary, NUMBER_OF_FILES_MSG_LEN); // send client number of files
			if (is_valid < 0){
				// no need to print since printing happens in recv_data
				return -1;
			}
			//printf("get_and_validate 8.3\n");
			return 1;
		}
	}
	else{
		printf("Received wrong command code from client\n");
		return 0;
	}
}

// this method is called when the server got an error and shuts down. So it closes all active connections before.
void close_all_connections(int socket_fd, struct user_password_struct listed_users[], int real_num_of_users){
	
	int i;
	
	for (i = 0; i < real_num_of_users; i++){
		if (listed_users[i].is_connected == 1){
			close(listed_users[i].user_socket_fd);
			listed_users[i].is_connected = 0;
			listed_users[i].user_socket_fd = -1;
		}
	}
	close(socket_fd);
}

// this method is called when the server got an error of client closed connection, it closes the session gracefully.
void close_specific_connection(struct user_password_struct listed_users[], int connection_idx_to_close){
		
	if (listed_users[connection_idx_to_close].is_connected == 1){
		close(listed_users[connection_idx_to_close].user_socket_fd);
		listed_users[connection_idx_to_close].is_connected = 0;
		listed_users[connection_idx_to_close].user_socket_fd = -1;
	}		
}

// this method is called when a client wants to send a message to another client.
// gets the given by client user-name of the recipient client, and checks in the database if a client with this user-name exists.
// returns -1 if not authorized; int>=0, index of the recipient client in users database
int is_a_client(char* username, struct user_password_struct listed_users[], int real_num_of_users){
	
	for (int i=0; i<real_num_of_users ;i++){
		if (strcmp(username, listed_users[i].username)==0){
			return i;
		}
	}
	return -1;
}

int main(int argc, char *argv[]){

	short port;
	long int long_port, long_arg1_len;
	char *users_file_path, *dir_path, *ptr_for_strtol;
	char command_code[COMMAND_MSG_LEN], command_result[COMMAND_MSG_LEN + 1];
	char full_path[USERNAME_MAX_LEN + MAX_PATH_LEN + 2];
	struct user_password_struct listed_users[MAX_USERS];
	int is_valid, socket_fd, conn_fd, num_of_args, user_idx = 0, i, j;
	int arg1_len, full_path_len, real_num_of_users = 0, keep_trying, keep_running, list_len, max_socket_fd_for_select;
	struct sockaddr_in serv_addr, peer_addr;  
	socklen_t addrsize;
	
	// check input data
	if (argc < 3 || argc > 4){
		printf("Wrong number of parameters!\n");
    	return -1;
	}
	
	// valid number of parameters
	users_file_path = argv[1];
	dir_path = argv[2];
	if (argc == 4){
		// port is provided	
		long_port = strtol(argv[3],&ptr_for_strtol,10); 
		 // check conversion went good
	    if (long_port == LONG_MAX || long_port == LONG_MIN){
	    	printf("Error in converting the port to short, %s\n",strerror(errno));
	    	return -1;
    	}
    	port = (short) long_port;
	}
	else{
		port = DEFAULT_PORT;
	}

	//printf("after vars - %d\n", argc);

	//printf("after mkdir - %s\n", dir_path);

	// read the users_file and create a registered-clients-database (contains user+password) for future authentication of clients
	is_valid = create_user_password_database(listed_users, users_file_path, dir_path, &real_num_of_users);
	if (is_valid == -1){
		printf("Error in creating user & password database, %s\n",strerror(errno));
		return -1;
	}

	// check if dir_path exists. if not - creates it
	is_valid = mkdir(dir_path, DEFAULT_MODE);
	if (is_valid == -1){
		if (errno != EEXIST){
			printf("Error in creating home directory. %s\n", strerror(errno));
			return -1;
		}
	}
	
	//printf("after db creation - real_num_of_users: %d\n", real_num_of_users);

	// create directories for registered clients
	is_valid = create_directories(listed_users, real_num_of_users);
	if (is_valid == -1){
		// no printing since the print happened in the function
		return -1;
	}

	//printf("after dir creation\n");
	// create server side TCP socket
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1){
    	printf("Error while creating socket for server. %s\n",strerror(errno));
    	return -1;
    }

    // init socket params
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY = any local machine address
    serv_addr.sin_port = htons(port); 

    // bind the socket to parameters
    is_valid = bind(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (is_valid != 0){
       printf("\n Error : Bind Failed. %s \n", strerror(errno));
       close(socket_fd);
       return -1; 
    }
    
	// make socket listen for clients
    is_valid = listen(socket_fd, MAX_USERS);
    if (is_valid != 0){
    	printf("\n Error : Listen Failed. %s \n", strerror(errno));
    	close(socket_fd);
        return -1; 
    }

    //printf("after socket creation\n");

    keep_running = 1;

    while (keep_running){	
    	
    	// build fd_set for run
    	fd_set read_fds;
    	FD_ZERO(&read_fds);
    	FD_SET(socket_fd, &read_fds); // adding server's socket to list
    	max_socket_fd_for_select = socket_fd;
    	// adding the socket_fd's of connected users
    	for (i = 0; i < real_num_of_users; i++){
    		if (listed_users[i].is_connected == 1){
    			FD_SET(listed_users[i].user_socket_fd, &read_fds);
    			if (listed_users[i].user_socket_fd > max_socket_fd_for_select){
    				max_socket_fd_for_select = listed_users[i].user_socket_fd;
    			}
    		}
    	}

   	    //printf("before select\n");

    	// check if there are any pending connections - wait indefinitely
    	is_valid = select(max_socket_fd_for_select + 1, &read_fds, NULL, NULL, NULL);
    	if (is_valid == -1){
    		printf("\n Error when choosing socket to serve. %s \n", strerror(errno));
    		close_all_connections(socket_fd, listed_users, real_num_of_users);
    		return -1;
    	}

    	//printf("after select\n");

    	// first check if there are new pending connections
    	if (FD_ISSET(socket_fd, &read_fds)){

    		/* new connection */
	        addrsize = sizeof(struct sockaddr_in);
	        //printf("before accept\n");
	        conn_fd = accept(socket_fd, (struct sockaddr*)&peer_addr, &addrsize);
	        //printf("after accept\n");
	        if (conn_fd < 0){
	           printf("\n Error : Accept Failed. %s \n", strerror(errno));	         
	           continue;
	        }
	        
	        // #################################################
	        // ######## User Password part 
	        // #################################################
	        // get from client the user and password, validate it and send number of files
			keep_trying = 1;
			while (keep_trying){
				user_idx = 0;
				//printf("before get and validate func\n");
				is_valid = get_and_validate_user_password_data(conn_fd, &user_idx, listed_users, real_num_of_users);
				//printf("returned from get and validate func with: %d\n", is_valid);
				if (is_valid < 0){
					// no printing since the print happened in the function
					break; // start the while loop again = start listening again
				}
				else if (is_valid == 0){ // not authorized, try again
					keep_trying = 1;
				}
				else{ //(is_valid > 0) // authorized - update is_connected and socket_fd
					keep_trying = 0;
					listed_users[user_idx].is_connected = 1;
					listed_users[user_idx].user_socket_fd = conn_fd;
					//printf("authorized\n");
				}
				//printf("main - identification stage - %d\n", keep_trying);
			}
			FD_CLR(socket_fd, &read_fds); // remove from set
    	}

    	// now, for every user in reads_fds run needed command
    	// #################################################
        // ############ Commands part
        // #################################################
    	for (i = 0; i < real_num_of_users; i++){
    		//printf("in for loop - i is: %d\n", i);
    		if (FD_ISSET(listed_users[i].user_socket_fd, &read_fds)){

    			//printf("in if of for loop - i is: %d\n", i);
    			int bin_len;
    			char arg1[MAX_FILENAME];
				arg1[0] = '\0';

				conn_fd = listed_users[i].user_socket_fd;
				strcpy(full_path, listed_users[i].user_dir);
				full_path_len = strlen(full_path);
				//printf("full path: %s, full path len %d\n", full_path, full_path_len);

				// get the current command from client and according to that checking how much arguments need to pass
        		is_valid = recv_data(conn_fd, command_code, COMMAND_MSG_LEN);
        		if (is_valid < 0){
        			// no need to print since printing happens in recv_data
        			if (is_valid == -2){
        				//peer closed the connection error, so close connection here
        				close_specific_connection(listed_users, i);
        			}
        			continue;
        		}
        		//printf("command_code: %s\n", command_code);
        		command_code[1] = '\0';
				//printf("the command that was received from user - %s, %zu\n", command_code, strlen(command_code));

        		if (strcmp(command_code, LIST_OF_FILES_COMMAND) == 0 || strcmp(command_code, QUIT_COMMAND) == 0 
        			|| strcmp(command_code, USERS_ONLINE_COMMAND) == 0 || strcmp(command_code, READ_MSG_COMMAND) == 0){
			    	num_of_args = 0;
			    }
			    else if (strcmp(command_code, DELETE_FILE_COMMAND) == 0 || strcmp(command_code, ADD_FILE_COMMAND) == 0 
					|| strcmp(command_code, GET_FILE_COMMAND) == 0 || strcmp(command_code, MSG_COMMAND) == 0){
			    	num_of_args = 1;
			    }
				else{
					printf("Wrong command code\n");
					continue;
				}

    			// getting the argument
    			if (num_of_args > 0){
	        		// then, according to the command, receiving the argument's length and then the arg itself
					if(strcmp(command_code, MSG_COMMAND) == 0){
						bin_len = CLIENT_INTERACTION_LEN;
					}
					else{
						bin_len = FILENAME_MSG_LEN;	
					}
					char bin_message_len[bin_len];
		        	is_valid = recv_data(conn_fd, bin_message_len, bin_len);
		        	if (is_valid < 0){
		        		// no need to print since printing in recv_data
		        		if (is_valid == -2){
        					//peer closed the connection error, so close connection here
        					close_specific_connection(listed_users, i);
        				}
		        		continue;
		        	}
		        	bin_message_len[bin_len] = '\0';
					//printf("argument len in binary %s\n", bin_message_len);
		        		
					long_arg1_len = strtol(bin_message_len, &ptr_for_strtol, 2);
					//printf("argument len as long (after strtol) %ld\n", long_arg1_len);
					// check conversion went good
					if (long_arg1_len == LONG_MAX || long_arg1_len == LONG_MIN){
						printf("Error in converting the arg, %s\n",strerror(errno));
						close_all_connections(socket_fd, listed_users,real_num_of_users);
						return -1;
					}
									
					arg1_len = (int)long_arg1_len;
					//printf("argument len after cast from long to int %d\n", arg1_len);					
		        	is_valid = recv_data(conn_fd, arg1, arg1_len);
		        	//printf("is_valid %d\n", is_valid);
		        	if (is_valid < 0){
		        		// no need to print since printing in recv_data
		        		if (is_valid == -2){
        					//peer closed the connection error, so close connection here
        					close_specific_connection(listed_users, i);
        				}
		        		continue;
		        	}
		        	arg1[arg1_len]='\0';
					//printf("the argument that we got from client %s\n", arg1);
	        	}

	        	// now we have the command and the arguments

	        	// ########################################################## //
				// running the command
				// ########################################################## //
				command_result[0]='\0';

	        	// Quit Command
	        	if (strcmp(command_code, QUIT_COMMAND) == 0){
	        		close(conn_fd);
	        		listed_users[i].user_socket_fd = -1;
	        		listed_users[i].is_connected = 0;
	        	}

				// List of Files Command
	        	if (strcmp(command_code, LIST_OF_FILES_COMMAND) == 0){
					char list_len_str[LIST_OF_FILES_MSG_LEN];
					DIR *dirp;
					struct dirent *entry;
					
					list_len_str[0]='\0';
					dirp = opendir(full_path);
					if (dirp){
						char list_string[MAX_FILES_PER_USER*MAX_FILENAME];
						list_string[0]='\0';
						while ((entry = readdir(dirp)) != NULL){
							if (entry->d_type == DT_REG){
								// removing off-line file from list
								if (strcmp(entry->d_name, MESSAGE_FILE_NAME) != 0){
									strcat(list_string, entry->d_name);
									strcat(list_string, "\n");
								}
							}
						}
						closedir(dirp);
						list_len = strlen(list_string);
						padding(list_len, LIST_OF_FILES_MSG_LEN, list_len_str);
						is_valid = send_data(conn_fd, list_len_str, LIST_OF_FILES_MSG_LEN);
						if (is_valid < 0){
							// no need to print since printing in recv_data
							continue;
						}
						is_valid = send_data(conn_fd, list_string, strlen(list_string));
						if (is_valid < 0){
							// no need to print since printing in recv_data
							continue;
						}
					}
					else{
						printf("unknown dir\n");
						close_all_connections(socket_fd, listed_users, real_num_of_users);
						return -1;
					}
				}

				// Delete File Command
	        	if (strcmp(command_code, DELETE_FILE_COMMAND) == 0){
					// create full path for new file. it is argument number 1 in original command
					char full_file_path[full_path_len + arg1_len + 2];

					strcpy(full_file_path, full_path);
					strcat(full_file_path, arg1);		
					full_file_path[full_path_len + arg1_len + 1] = '\0';
	        		
					// based on https://linux.die.net/man/2/unlink
					is_valid = unlink(full_file_path);
	        		if (is_valid == -1){
	        			if (errno == ENOENT){
	        				strcat(command_result, "0"); // file does not exist
	        			}
	        			else{
	        				printf("Error when deleting file , %s\n",strerror(errno));
    						close_all_connections(socket_fd, listed_users, real_num_of_users);
	        				return -1;
	        			}
	        		}
	        		else{
	        			strcat(command_result, "1"); // success
					}
					if(strcmp(command_result, "1") == 0){
						// update the users struct that there is one file less - now we have the proper index of user
						listed_users[i].num_of_files--;
					}
	        		is_valid = send_data(conn_fd, command_result, DELETE_FILE_MSG_LEN);
	        		if (is_valid < 0){
	        			// no need to print since printing in recv_data
	        			continue;
	        		}
	        	}

	        	// Add File Command
	        	if (strcmp(command_code, ADD_FILE_COMMAND) == 0){
					// create full path for new file. it is argument number 2 in original command
	        		char full_file_path[full_path_len + arg1_len + 2];

	        		strcpy(full_file_path, full_path);
					strcat(full_file_path, arg1);		
					full_file_path[full_path_len + arg1_len + 1] = '\0';

					// check if dest file exists in to maintain proper num_of_files;
					int is_new_file = 1;
					is_valid = open(full_file_path, O_RDONLY);
					if (is_valid > 0){
						is_new_file = 0;
					}
					
	        		is_valid = recieve_file(conn_fd, full_file_path);
	        		//printf("is_valid - %d\n", is_valid);
					if (is_valid == 1){
	        			// no need to print since all the prints happen in recieve_file
	        			close_all_connections(socket_fd, listed_users, real_num_of_users);
	        			return -1;
	        		}
	        		if (is_valid == 2){
	        			// no need to print since all the prints happen in recieve_file
	        			continue;
	        		}
					// update the users struct that there is one file more - we have the proper user index now
					if(is_valid == 0 && is_new_file == 1){
						listed_users[i].num_of_files++;
					}
	        		sprintf(command_result, "%d", is_valid);
	        		is_valid = send_data(conn_fd, command_result, ADD_FILE_MSG_LEN);
	        		if (is_valid < 0){
	        			// no need to print since printing in send_data
	        			continue;
	        		}
	        	}

	        	// Get File Command
	        	if (strcmp(command_code, GET_FILE_COMMAND) == 0){

					char full_file_path[full_path_len + arg1_len + 2];

	        		strcpy(full_file_path, full_path);
					strcat(full_file_path, arg1);		
					full_file_path[full_path_len + arg1_len + 1] = '\0';
					//printf("get-file - full file path: %s\n", full_file_path);

					is_valid = open(full_file_path, O_RDONLY);
					if(is_valid == -1 && (errno == EACCES || errno == ENOENT)){ // if the path doesn't lead anywhere
						strcat(command_result, "0");
						is_valid = send_data(conn_fd, command_result, GET_FILE_MSG_LEN);
						if (is_valid < 0){
	        				// no need to print since printing in recv_data
	        				continue;
	        			}
					}
					else{
						close(is_valid);
						strcat(command_result, "1");
						is_valid = send_data(conn_fd, command_result, GET_FILE_MSG_LEN);
						if (is_valid < 0){
	        				// no need to print since printing in recv_data
	        				continue;
	        			}
        				//printf("get-file - before send file\n");
						is_valid = send_file(conn_fd, full_file_path);
						//printf("get-file - after send file\n");
						if(is_valid == 1){
							printf("There was a file operation error\n");
						    close_all_connections(socket_fd, listed_users, real_num_of_users);
						    return -1;

						}
						else if(is_valid == 2){
							printf("There was a network error\n");
							continue;
						}
					}
	        	}

	        	// Users On-line Command
	        	if (strcmp(command_code, USERS_ONLINE_COMMAND) == 0){
	        		char list_len_str[USERS_ONLINE_MSG_LEN];
	        		list_len_str[0]='\0';
	        		char list_string[MAX_USERS*USERNAME_MAX_LEN];
	        		list_string[0]='\0';

	        		strcat(list_string, "on-line users: ");

	        		for (j=0; j < real_num_of_users; j++){
	        			if (listed_users[j].is_connected == 1){
	        				strcat(list_string, listed_users[j].username);
							strcat(list_string, ",");
	        			}
	        		}
	        		list_len = strlen(list_string);
	        		list_string[list_len - 1] = '\n'; // change last comma to newline

	        		padding(list_len, USERS_ONLINE_MSG_LEN, list_len_str);
					is_valid = send_data(conn_fd, list_len_str, USERS_ONLINE_MSG_LEN);
					if (is_valid < 0){
						// no need to print since printing in recv_data
						continue;
					}
					is_valid = send_data(conn_fd, list_string, strlen(list_string));
					if (is_valid < 0){
						// no need to print since printing in recv_data
						continue;
					}
	        	}

				// Msg Command
				if (strcmp(command_code, MSG_COMMAND) == 0){
					int client_index, fd, curr_write, msg_to_send_len, chars_writen, flag = 0;
					char *rec_username, *msg;
					char msg_formated[USERNAME_MAX_LEN + MAX_MESSAGE_SIZE + 2]; // 2 is for ": " between username and message
					char msg_len_in_binary[CLIENT_INTERACTION_LEN]; 
					char rec_full_file_path[full_path_len + strlen(MESSAGE_FILE_NAME) + 1]; // 1 is for "/" between path and file name

					msg_formated[0] = '\0'; rec_full_file_path[0] = '\0'; msg_len_in_binary[0] = '\0'; 

					// extract recipient username and the msg to be sent from argument passed by current client
					rec_username = strtok(arg1, "_");
					msg = strtok(NULL, "\n");
					//printf("msg1 - rec_username: %s, msg: %s\n", rec_username, msg);

					// check if recipient client exists
					client_index = is_a_client(rec_username, listed_users, real_num_of_users);	
					//printf("msg2 - is a client: %d\n", client_index);
					if(client_index < 0){ // // recipient client doesn't exist
						strcpy(command_result, "0");
						is_valid = send_data(conn_fd, command_result, MSG_MSG_LEN);
						//is_valid = send_data(conn_fd, msg_command_result, MSG_MSG_LEN);
	        			if (is_valid < 0){
	        				// no need to print since printing in send_data
	        				continue;
	        			}
	        			continue;
					}

					// recipient client is on-line - send him the message
					if (listed_users[client_index].is_connected){
						strcat(msg_formated, "New message from ");
						strcat(msg_formated, listed_users[i].username);
						strcat(msg_formated, ": ");
						strcat(msg_formated, msg);
						strcat(msg_formated, "\n");
						//printf("msg3 - msg_formated: %s\n", msg_formated);

						is_valid = send_data(listed_users[client_index].user_socket_fd, CLIENT_INTERACTION_NOTIFICATION, COMMAND_MSG_LEN);
	        			//printf("msg4, is_valid: %d\n", is_valid);
	        			if (is_valid < 0){
	        				// no need to print since printing in send_data
							flag = 1;
	        			}
	        			if(!flag){			
							padding(strlen(msg_formated), CLIENT_INTERACTION_LEN, msg_len_in_binary);
							is_valid = send_data(listed_users[client_index].user_socket_fd, msg_len_in_binary, CLIENT_INTERACTION_LEN); // send client number of files
							//printf("msg5, is_valid: %d\n", is_valid);
							if (is_valid < 0){
	        					// no need to print since printing in send_data
								flag = 1;
	        				}
	        			}
	        			if(!flag){
							is_valid = send_data(listed_users[client_index].user_socket_fd, msg_formated, strlen(msg_formated));
		        			//printf("msg6, is_valid: %d\n", is_valid);
		        			if (is_valid < 0){
		        				// no need to print since printing in send_data
								flag = 1;
		        			}
		        		}
		        		if(!flag){
							is_valid = recv_data(listed_users[client_index].user_socket_fd, command_result, COMMAND_MSG_LEN);
							//printf("msg7, is_valid: %d\n", is_valid);
							if(is_valid < 0){
								// no need to print since printing in send_data
								if (is_valid == -2){
		        					//peer closed the connection error, so close connection here
		        					close_specific_connection(listed_users, i);
		        				}
								flag = 1;
							}
							command_result[COMMAND_MSG_LEN] = '\0';
							if(strcmp(command_result, CLIENT_INTERACTION_NOTIFICATION) != 0){
								//printf("msg8, command_result: %s\n", command_result);
								flag = 1;	
							}
							strcpy(command_result, "1");
						}
					}

					// if recipient client is off-line - write the message to his msg_file
					if(!listed_users[client_index].is_connected || flag == 1){
						strcat(rec_full_file_path, listed_users[client_index].user_dir);
						strcat(rec_full_file_path, "/");
						strcat(rec_full_file_path, MESSAGE_FILE_NAME);
						//printf("msg18 - rec_full_file_path: %s\n", rec_full_file_path);

						fd = open(rec_full_file_path, O_RDWR | O_APPEND);
						if (fd < 0){
							strcpy(command_result, "3");
							//printf("msg19 - command_result: %s\n", command_result);
							send_data(conn_fd, command_result, MSG_MSG_LEN);
							//printf("msg19 - msg_command_result: %s\n", msg_command_result);
	        				// no need to check if send was successful, because i'm crashing the server anyway
        				    close_all_connections(socket_fd, listed_users, real_num_of_users);
	        				return -1;
	        			}
						else{
							strcat(msg_formated, "Message received from ");
							strcat(msg_formated, listed_users[i].username);
							strcat(msg_formated, ": ");
							strcat(msg_formated, msg);
							strcat(msg_formated, "\n");
							msg_to_send_len = strlen(msg_formated);
							chars_writen = 0;
							//printf("msg20 - msg_formated: %s, msg_to_send_len: %d\n", msg_formated, msg_to_send_len);
							while(chars_writen < msg_to_send_len){
								curr_write = write(fd, msg_formated, msg_to_send_len - chars_writen);
								if(curr_write < 0){
									printf("error writing to file\n");
		        				    close_all_connections(socket_fd, listed_users, real_num_of_users);
									return -1;
								}
								chars_writen += curr_write;
							}
							strcpy(command_result, "2"); 
						}
					}

					// tell client the result...
					//printf("command_result: %s\n", command_result);
					//printf("msg_command_result: %s\n", msg_command_result);
					is_valid = send_data(conn_fd, command_result, MSG_MSG_LEN);
	        			if (is_valid < 0){
	        			// no need to print since printing in send_data
						continue;
	        		}
				}

				// Read Msgs Command
				if (strcmp(command_code, READ_MSG_COMMAND) == 0){					
					int file_fd, in_msg = 1, msg_loc =0;
					char data_read[1];
					char curr_msg[USERNAME_MAX_LEN + MAX_MESSAGE_SIZE + 3];
					char full_file_path[full_path_len + strlen(MESSAGE_FILE_NAME) + 2];
					char padded_msg[OFFLINE_MESSAGE_LEN];
					
					full_file_path[0] = '\0'; data_read[0] = '\0'; curr_msg[0]= '\0';
					//printf("read msgs - full_path: %s\n", full_path);
	        		strcpy(full_file_path, full_path);
					strcat(full_file_path, MESSAGE_FILE_NAME);		
					full_file_path[full_path_len + strlen(MESSAGE_FILE_NAME) + 2] = '\0';
					//printf("read msgs - full_file_path: %s\n", full_file_path);

					file_fd = open(full_file_path, O_RDONLY);
					if(file_fd < 0){
						return -1;
					}

					while(read(file_fd, data_read, 1) > 0){
		
						//printf("read msgs - reading file\n");
						if(strncmp(data_read, "\n",1) == 0){
							// finished reading a message. send to the client
							curr_msg[msg_loc] = '\0';							
							padding(strlen(curr_msg), OFFLINE_MESSAGE_LEN, padded_msg);
							//printf("read msgs - padded_msg to send: %s, strlen(padded_msg): %d\n", padded_msg, strlen(padded_msg));
							is_valid = send_data(conn_fd, padded_msg, OFFLINE_MESSAGE_LEN);
	    					//printf("read msgs - is_valid1: %d\n", is_valid);
	    					if(is_valid < 0){
	    						// no need to print since print happened in send_data
	    						break;	
	    					}
	    					//printf("read msgs - curr_msg to send: %s\n", curr_msg);
							is_valid = send_data(conn_fd, curr_msg, strlen(curr_msg));
	    					//printf("read msgs - is_valid2: %d\n", is_valid);
	    					if(is_valid < 0){
	    						// no need to print since print happened in send_data
	    						break;	
	    					}

							in_msg = 1; 
							msg_loc = 0;
							padded_msg[0] = '\0'; curr_msg[0]= '\0';
							continue;
						}

						if (in_msg){
							// reading a message
							strncpy(curr_msg + msg_loc,data_read, 1);
							msg_loc += 1;
							curr_msg[msg_loc]= '\0';
						}

						data_read[0] = '\0';
					}
					close(file_fd);

					padding(strlen(END_OF_OFLINE_MESSAGES), OFFLINE_MESSAGE_LEN, padded_msg);
					is_valid = send_data(conn_fd, padded_msg, OFFLINE_MESSAGE_LEN);
	    			if(is_valid < 0){
	    				// no need to print since print happened in send_data
	    				continue;	
	    			}
					is_valid = send_data(conn_fd, END_OF_OFLINE_MESSAGES, strlen(END_OF_OFLINE_MESSAGES));
	    			if(is_valid < 0){
	    				// no need to print since print happened in send_data
	    				continue;	
	    			}

					// now we empty the file
					is_valid = open(full_file_path, O_RDWR | O_TRUNC);
					if(is_valid < 0){
						printf("There was a file operation error\n");
       				    close_all_connections(socket_fd, listed_users, real_num_of_users);
						return -1;
					}
				}

    		}
    	}	
    }

    // out of mega loop
    close_all_connections(socket_fd, listed_users, real_num_of_users);
    if (keep_running == 1){
    	// left the loop because of an error so return -1
    	return -1;
    }
	
    return 0;
}
