#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
int main(int argc, char* argv[]){
char password[20],read_name[20];
int fd;
fd= open("/dev/USB_hacked_data", O_RDWR);
if(fd<0){
	printf("unable to open file\n");
}
strcpy(password,"haiihari");
write(fd,password,sizeof(password));

read(fd,read_name,sizeof(read_name));

return 0;
}