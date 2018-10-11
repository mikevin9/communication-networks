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
#include <fcntl.h>

#include "utils.h"

// this is a helper func' for sendinf data.
// this method recives the length of the message we want to send and transforms it to a binary represantation of fixed size acording to the command
void padding(int messege_len, int final_len, char *padded){
	
	int i;
	char temp[final_len];
	temp[0] = '\0';
	for(i=0; i<final_len; i++){
	    sprintf(temp+i, "%d", (messege_len%2));
	    messege_len = messege_len/2;
	}
	// reversing the order of bits to the regular one
	for(i=0; i<final_len; i++){
		padded[i] = temp[final_len-i-1];
	}
	padded[final_len]= '\0';
}

// this method in charge of sending the data in buf between client and server
// returns #of byts sent ; -1 on network error
int send_data(int socket_fd, char *buf, int total_len){

	int curr_sent, bytes_sent;
	//send the data to the server
	bytes_sent = send(socket_fd, buf, total_len, 0); // 0 for no flags as instructed
	//check all the data was sent
	if (bytes_sent < 0){
		printf("problem sending data. %s\n", strerror(errno));
		return -1;
	}

	// its possible that not all data was sent to the server in one time so keep sending
	while (bytes_sent < total_len){
		curr_sent = send(socket_fd, buf + bytes_sent, total_len - bytes_sent, 0); // 0 for no flags as instructed
		if (curr_sent < 0){
			printf("problem sending data. %s\n", strerror(errno));
			return -1;
		}
		bytes_sent += curr_sent;
	}
	return bytes_sent; // return total number of send bytes
}

// this method recieves data in buf from between client and server 
// returns number of bytes recieved or -1 for error
// returns -2 when the other side closes the socket so the server will know to close the connection
int recv_data(int socket_fd, void *buf, int total_len){

	int bytes_read, curr_read;
	bytes_read = recv(socket_fd, (char *)buf, total_len, 0);
	if (bytes_read < 0){
		printf("Error in receiving data1. %s\n", strerror(errno));
		return -1;
	}

	if (bytes_read == 0){
		printf("Peer closed the socket\n");
		return -2;
	}

	curr_read = bytes_read; // dummy assingmet to enter while loop for the first time
	// its possible that not all the data was read at once, so keep reading it
	while (bytes_read < total_len && curr_read != 0){
		curr_read = recv(socket_fd, (char *)buf + bytes_read, total_len - bytes_read, 0);
		if (curr_read < 0){
			printf("Error in receiving data2. %s\n", strerror(errno));
			return -1;
		}

		if (curr_read == 0){
			printf("Peer closed the socket\n");
			return -2;
		}
		
		bytes_read += curr_read;
	}
	return bytes_read; // return total number of read bytes since it is OK
}

// this method gets as input socket fd and full path to a file. it writes the content transfered from the socket to the file specified
// returns 0 on success; 1 on error regarding file operations; 2 on network errors
int recieve_file(int socket_fd, char *full_path){
	
	long int long_file_size;
	int bytes_read, file_fd, total_read, file_size, is_valid, bytes_to_read, left_to_read, chars_writen, curr_write;
	char buf[FILE_BULK_SIZE], file_size_as_string[4], *ptr_for_strtol;
	
	// open the file
	file_fd = open(full_path, O_RDWR | O_CREAT | O_TRUNC,DEFAULT_MODE);
	if (file_fd < 0){
		printf("Error opening file for writing: %s\n", strerror(errno));
        return 1;
    }

    // get the incoming file's size
    is_valid = recv_data(socket_fd, file_size_as_string, FILE_SIZE_MSG_LEN);
    if (is_valid < 0){
    	// no need to print since print happend in send_data
    	close(file_fd);
    	return 2;	
    }
    file_size_as_string[FILE_SIZE_MSG_LEN] = '\0';
    long_file_size =  strtol(file_size_as_string, &ptr_for_strtol, 2);
	if(long_file_size == LONG_MAX || long_file_size == LONG_MIN){
		printf("Error in converting the file size, %s\n",strerror(errno));
		return -1;
	}
	file_size = (int)long_file_size;

	// reading the file - reading according to min(FILE_BULK_SIZE, file_size)
	// working in bulks in size FILE_BULK_SIZE - read the data from the socket and write to file
	
	total_read = 0;
	left_to_read = file_size;
	bytes_read = 1; // dummy assignment to enter while loop
	while (bytes_read > 0 && total_read < file_size){

		if (FILE_BULK_SIZE > left_to_read){
		bytes_to_read = left_to_read;
		}
		else{
			bytes_to_read = FILE_BULK_SIZE;
		}
		bytes_read = recv_data(socket_fd, buf ,bytes_to_read);
		if (bytes_read < 0){
			printf("Error while reading file. %s\n",strerror(errno));
	    	close(file_fd);
	    	return 2;
		}

		total_read += bytes_read; 
		left_to_read -= bytes_read;
		
		chars_writen = 0;
		while(chars_writen < bytes_read){
			curr_write = write(file_fd, buf, bytes_read - chars_writen);
			if(curr_write < 0){
				printf("Error while writing recieved data. %s\n",strerror(errno));
				close(file_fd);
				return 1;
			}
			chars_writen += curr_write;
		}
	}
	// finished everything successfully
	close(file_fd);
	return 0;
}

// this method gets as input socket fd and full path to a file and sends file's content to using the socket
// returns 0 on success; 1 on error regarding file operations; 2 on network errors
int send_file(int socket_fd, char *full_path){

	int bytes_read, bytes_sent, file_fd, total_sent, file_size, is_valid;
	char input_buf[FILE_BULK_SIZE], file_size_to_send_as_string[FILE_SIZE_MSG_LEN];
	struct stat file_stat;
	// open the file
	file_fd = open(full_path, O_RDONLY, DEFAULT_MODE);
	if (file_fd < 0){
		printf("Error openning the file. %s\n", strerror(errno));
		return 1;
	}

	is_valid = fstat(file_fd, &file_stat);
	if (is_valid < 0){
    	printf("Error while calculating file size. %s\n",strerror(errno));
    	close(file_fd);
    	return 1;
    }
	file_size = file_stat.st_size;

    //send file size to other side
    file_size_to_send_as_string[0] = '\0';
    padding(file_size, FILE_SIZE_MSG_LEN, file_size_to_send_as_string);
    is_valid = send_data(socket_fd, file_size_to_send_as_string, FILE_SIZE_MSG_LEN);
    if (is_valid < 0){
    	// no need to print since print happend in send_data
    	close(file_fd);
    	return 2;	
    }

    // working in bulks in size FILE_BULK_SIZE
	bytes_read = read(file_fd, input_buf, FILE_BULK_SIZE);
    if (bytes_read < 0){
    	printf("Error while reading file. %s\n",strerror(errno));
    	close(file_fd);
    	return 1;
    }

    total_sent = 0;
    while (bytes_read > 0 && total_sent < file_size){

    	//send the data
    	bytes_sent = send_data(socket_fd, input_buf, bytes_read);

    	//check all the data was sent
    	if (bytes_sent < 0 || bytes_sent != bytes_read){
    		// no need to print since send_data prints
    		close(file_fd);
    		return 2;
    	}

    	total_sent += bytes_sent;

    	// reading next chunk of the input file
    	bytes_read = read(file_fd, input_buf, FILE_BULK_SIZE);
    	if (bytes_read < 0){
    		printf("Error while reading file. %s\n",strerror(errno));
    		close(file_fd);
    		return 1;
    	}
    }
    // finished sending the file good
    close(file_fd);
	//printf("send_file command done\n");
	return 0;
}
