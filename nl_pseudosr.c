#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "fcntl.h"


#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

int main(int argc, char *argv[]) {

    //get kernel pid from parameter
    if (argc != 2) {
        printf("Usage: %s <kernel_pid>\n", argv[0]);
        return -1;
    }
    int kernel_pid = atoi(argv[1]);

    // Open a file for output
    int log_fd = open("/home/osboxes/RootAsLSM/nl_pseudosr.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd < 0) {
        perror("open");
        return -1;
    }

    // Redirect stdout and stderr to the file
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
    close(log_fd);

    printf("Script pseudo_sr started\n");
    printf("PID: %d\n", getpid());
    printf("Kernel PID: %d\n", kernel_pid);
    
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd;

    // Create a Netlink socket
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    // Bind the socket to the source address
    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        close(sock_fd);
        return -2;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   // Kernel
    dest_addr.nl_groups = 0;    /* unicast */

    // Allocate memory for the Netlink message
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh) {
        perror("malloc");
        close(sock_fd);
        return -3;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    // Fill in the Netlink message header
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), "Hello this is a msg from userspace");

    // Set up the I/O vector and message header for sending the Netlink message
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Sending message to kernel\n");
    // Send the Netlink message
    int ret;
    if ( (ret=sendmsg(sock_fd, &msg, 0)) < 0) {
        printf("send ret: %d\n", ret);
        perror("sendmsg");
        free(nlh);
        close(sock_fd);
        return -4;
    }

    printf("Netlink message sent\n");

    free(nlh);
    close(sock_fd);

    return 0;
}