#include <linux/capability.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <linux/user_namespace.h>
#include <linux/binfmts.h>
#include <linux/mnt_idmapping.h>
#include <uapi/linux/lsm.h>

#include <linux/security.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/un.h>
#include <linux/fs.h> // Pour kern_path_locked et vfs_unlink
#include <linux/namei.h> // Pour path_put
#include <linux/mount.h> // Pour init_user_ns
#include <linux/timekeeping.h> // Pour ktime_get_real_ts64

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/time.h>

// Add manually the definition of SO_RCVTIMEO if necessary
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO 20
#endif

#define TAILLE MAX_ARG_STRLEN

#define BUFFER_SIZE 1024

// NETLINK socket declares
#define MY_NETLINK 31
struct sock *nl_sk = NULL;

//AF_UNIX socket declares
#define SOCKET_PATH_TEMPLATE "/tmp/capdel_socket_%u"
struct socket *sock = NULL;
static char socket_path[BUFFER_SIZE];

static void nl_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlhead;

	trace_printk(KERN_INFO "	Entering: %s\n", __FUNCTION__);

	nlhead = (struct nlmsghdr*)skb->data;

	trace_printk(KERN_INFO "	MyNetlink has received: %s\n",(char*)nlmsg_data(nlhead));
}

static void ux_recv_msg(struct linux_binprm *bprm)
{
	char buffer[BUFFER_SIZE];
    struct msghdr msg;
    struct kvec iov;
	int ret;

	// Time
	/*
	struct __kernel_sock_timeval timeout;
	timeout.tv_sec = 5; // 5 seconds timeout
    timeout.tv_usec = 0;
	*/

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = BUFFER_SIZE - 1;

	// Set the receive timeout option
	/*
	    ret = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, KERNEL_SOCKPTR((char *)&timeout), sizeof(timeout));
    if (ret < 0) {
        trace_printk(KERN_INFO "    Error setting socket timeout: %d\n", ret);
        return ;
    }
	*/

	//Wait to receive message
    ret = kernel_recvmsg(sock, &msg, &iov, 1, BUFFER_SIZE - 1, MSG_WAITALL); // MSG_DONTWAIT enables nonblocking operation
	if (ret < 0) {
		trace_printk(KERN_INFO "	Error receiving data: %d\n", ret);
	} else {
		buffer[ret] = '\0';
		trace_printk(KERN_INFO "	Received data: %s\n", buffer);
	}
}

static int ux_sock_create(struct linux_binprm *bprm)
{
	int ret;
	
	snprintf(socket_path, BUFFER_SIZE, SOCKET_PATH_TEMPLATE, current->pid);
	
	struct sockaddr_un server_addr;

	// socket creation
	ret = sock_create_kern(&init_net, AF_UNIX, SOCK_DGRAM, 0, &sock);
	if (ret < 0) {
        trace_printk(KERN_INFO "	Error creating socket\n");
        return 0;
    }

	memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);
	
	// socket binding
    ret = kernel_bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        trace_printk(KERN_INFO "	Error binding socket\n");
        sock_release(sock);
        return 0;
    }
	
	return 1;

}

static int nl_sock_create(struct linux_binprm *bprm)
{
	struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, MY_NETLINK, &cfg);
	
    if(!nl_sk)
    {
        trace_printk(KERN_ALERT "	Error creating socket.\n");
        return 0;
    }

	return 1;
}

// Get arguments using bprm->p inspired by remove_arg_zero
static char** get_arguments(struct linux_binprm *bprm)
{
	if (!bprm->argc)
			return NULL;
	
	// Check if pages are initialized

	if (bprm->p == 0) {
		trace_printk(KERN_INFO "	No pages\n");
		return NULL;
	}
	
	unsigned long offset;
	char *kaddr;
	struct page *page;

	struct mm_struct *mm = bprm->mm;
	unsigned long pos = bprm->p;
	int argc = bprm->argc;

	// Create the variable to copy the command line
	
	char **argv = kmalloc(argc*sizeof(char*), GFP_KERNEL);
	if (!argv) {
		trace_printk(KERN_INFO "	No memory (argv)\n");
		return NULL;
	}
	for (int i = 0; i < argc; i++) {
		argv[i] = kmalloc(TAILLE, GFP_KERNEL);
		if (!argv[i]) {
			trace_printk(KERN_INFO "	No memory (argv[%d]\n", i);
			for (int j = 0; j < i; j++)
				kfree(argv[j]);
			kfree(argv);
			return NULL;
		}
	}

	// Get the arguments
	do {
		do {
			// Get the page
			offset = pos & ~PAGE_MASK;
			mmap_read_lock(mm);
			int ret = get_user_pages_remote(mm, pos, 1, 0, &page, NULL);
			mmap_read_unlock(mm);
			if (ret < 1) {	
				goto bcl;
			}

			// Get the content of the page
			kaddr = kmap_local_page(page);
			if (!kaddr) {
				goto bcl;
			}

			// Add the content of the page to argv
			if (kaddr[offset]) 
    			strncat(argv[bprm->argc - argc], &kaddr[offset], TAILLE - strlen(argv[bprm->argc - argc]) - 1);

			// Find the end of the content
			for (; offset < PAGE_SIZE && kaddr[offset]; offset++, pos++);
			pos++;

			// Unmap the page
			kunmap(page);

		} while (offset == PAGE_SIZE);
bcl:
	} while (argc-- > 1);

	return argv;
}

static int print_argv(struct linux_binprm *bprm, char **argv)
{
	// Print the command line
	char *command_line = kmalloc(TAILLE, GFP_KERNEL);
	if (!command_line) {
		trace_printk(KERN_INFO "	No memory (command_line)\n");
		return 0;
	}

	for (int i = 0; i < bprm->argc; i++) {
		strncat(command_line, argv[i], TAILLE - strlen(command_line) - 1);
		strncat(command_line, " ", TAILLE - strlen(command_line) - 1);
	}

	trace_printk(KERN_INFO "	Command line: %s\n", command_line);

	return 0;
}

static int free_argv(struct linux_binprm *bprm, char **argv)
{
	// Free the commande line arguments
	for (int i = 0; i < bprm->argc; i++)
		kfree(argv[i]);
	kfree(argv);

	return 0;
}

static int to_ignore(struct linux_binprm *bprm)
{
	// get uid
	int uid = current_uid().val;

	// Ignore root commands
	if (uid == 0)
		return 1;
	
	// Ignore some commands
	if (strnstr(bprm->filename, "python3", strlen(bprm->filename)))
		return 1;

	//Ignore all except ls
	if (!strnstr(bprm->filename, "/ls", strlen(bprm->filename)))
		return 1;

	return 0;
}

static int sr_exec(struct linux_binprm *bprm)
{
	struct subprocess_info *sub_info;
	
	// get pid
	char* pid = kmalloc(10, GFP_KERNEL);
	sprintf(pid, "%d", current->pid);

    // Execute the 'sr' command using NETLINK socket
	// char *argv_sr[] = { "/home/osboxes/RootAsLSM/pseudo_sr", pid, NULL };

	// Execute the 'sr' command using AF_UNIX socket
    char *argv_sr[] = { "/usr/bin/python3", "/home/osboxes/RootAsLSM/ux_pseudosr.py", socket_path, NULL };

    char *envp_sr[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

	sub_info = call_usermodehelper_setup(argv_sr[0], argv_sr, envp_sr, GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info == NULL) {
        trace_printk(KERN_INFO "	Failed to setup usermodehelper\n");
		netlink_kernel_release(nl_sk);
        return 0;
    }

	// UMH_NO_WAIT to don't wait at all 
	// UMH_WAIT_EXEC to wait for the exec, but not the process
 	// UMH_WAIT_PROC to wait for the process to complete
    int ret = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    if (ret < 0) {
        trace_printk(KERN_INFO "	Failed to execute sr command\n");
		trace_printk(KERN_INFO "	exiting myNetLink module\n");
		netlink_kernel_release(nl_sk);
        return 0;
    }

	return 1;
}

static void remove_sock_file(struct linux_binprm *bprm)
{
    struct path path;

    int ret = kern_path(socket_path, LOOKUP_FOLLOW, &path);
    if (ret == 0) {
        struct dentry *dentry = path.dentry;
        struct inode *dir = dentry->d_parent->d_inode;
        struct mnt_idmap *idmap = mnt_idmap(path.mnt);

		// Check if exists
		if (!dir || !idmap) {
        pr_err("dir or idmap is NULL\n");
        path_put(&path);
        return;
    	}

        // Remove socket file
        inode_lock(dir);
        ret = vfs_unlink(idmap, dir, dentry, NULL);
        inode_unlock(dir);

        path_put(&path);
    }
}

/*
 * Calculate the new process capability sets from the capability sets attached
 * to a file.
 */
int rm_cap_bprm_creds_from_file(struct linux_binprm *bprm, const struct file *file)
{
	struct cred *new = bprm->cred;
	new->cap_bset.val = cap_lower(new->cap_bset, CAP_NET_BROADCAST);

	// Ignore some commands
	if (to_ignore(bprm))
		return 0;

	char **argv = get_arguments(bprm);
	if (!argv) {
		trace_printk(KERN_INFO "	No arguments\n");
		return 0;
	}

	print_argv(bprm, argv);
	free_argv(bprm, argv);

	if (ux_sock_create(bprm) == 0)
		return 0;

	if (sr_exec(bprm) == 0) {
		sock_release(sock);
		remove_sock_file(bprm);
		return 0;
	}

	ux_recv_msg(bprm);

	//Release the socket
	//netlink_kernel_release(nl_sk);
	sock_release(sock);

	//Remove the socket file (For AF_UNIX socket)
	remove_sock_file(bprm);

	return 0;
}

#ifdef CONFIG_SECURITY

static const struct lsm_id capability_lsmid = {
	.name = "capdel",
	.id = LSM_ID_CAPDEL,
};

static struct security_hook_list capability_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(bprm_creds_from_file, rm_cap_bprm_creds_from_file),
};

static int __init capability_init(void)
{
	security_add_hooks(capability_hooks, ARRAY_SIZE(capability_hooks),
			   &capability_lsmid);
	return 0;
}

DEFINE_LSM(capdel) = {
	.name = "capdel",
	.order = LSM_ORDER_LAST,
	.init = capability_init,
};

#endif /* CONFIG_SECURITY */
