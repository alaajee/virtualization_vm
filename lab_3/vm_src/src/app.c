#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* TODO */
void SAVE()
{
    asm volatile (
        "mov $999, %%rax \n"
        "syscall             \n"
        :
        :
        : "rax"
    );
}

char *buff_1 = "Hello World !!!\n";
char *buff_2 = "Bye Bye !!!\n";

#define FILENAME "./ay_caramba.txt"

int main(void)
{
    int fd = open(FILENAME, O_RDWR | O_CREAT, 0777);
    write(fd, buff_1, strlen(buff_1));
    SAVE();
    write(fd, buff_2, strlen(buff_2));
    close(fd);
    return 0;
}
