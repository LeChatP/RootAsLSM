// SPDX-License-Identifier: GPL-2.0-or-later 
/* Common capabilities, needed by capability.o.
 */

#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/ptrace.h>
#include <linux/xattr.h>
#include <linux/hugetlb.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <linux/securebits.h>
#include <linux/user_namespace.h>
#include <linux/binfmts.h>
#include <linux/personality.h>
#include <linux/mnt_idmapping.h>
#include <uapi/linux/lsm.h>

#include <linux/security.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/kmod.h>
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
//#include <sys/socket.h> //timeout
//#include <linux/timer.h> // Pour la structure timeval
/*#include <uapi/asm/socket.h>
#include <uapi/asm-generic/socket.h> // Pour les options de socket
#include <linux/timer.h>
#include <linux/sockios.h>*/
// Ajouter manuellement la définition de SO_RCVTIMEO si nécessaire
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO 20
#endif

#define MY_NETLINK 31
struct sock *nl_sk = NULL;

//include the file exec.c
//#include "/home/osboxes/RootAsLSM/kernelbuild/linux-6.8.7/fs/exec.c"


#define TAILLE MAX_ARG_STRLEN
#define SOCKET_PATH_TEMPLATE "/tmp/capdel_socket_%u"
#define BUFFER_SIZE 1024
//static DEFINE_MUTEX(my_mutex);


//#define PF_PARENT_PROCESS 0x10000000 // Définir un bit personnalisé dans les flags

struct socket *sock = NULL;
static char socket_path[BUFFER_SIZE];
/*
static int sr_recv_msg(void *data)
{
	
	int ret;

	// Recevoir des messages
	char buffer[BUFFER_SIZE];
    struct msghdr msg;
    struct kvec iov;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = BUFFER_SIZE - 1;

	if (!sock) {
		trace_printk(KERN_INFO "	sock is NULL\n");
		return 0;
	}

	//No wait to receive message
    ret = kernel_recvmsg(sock, &msg, &iov, 1, BUFFER_SIZE - 1, MSG_WAITALL);
	if (ret < 0) {
		trace_printk(KERN_INFO "	Error receiving data: %d\n", ret);
		return 1;
	} else {
		buffer[ret] = '\0';
		trace_printk(KERN_INFO "	Received data: %s\n", buffer);
		return 1;
	}

    return 1;
}
*/
/*
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlhead;
//    struct sk_buff *skb_out;
//    int pid, res, msg_size;


    //printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    //msg_size = strlen(msg);

    nlhead = (struct nlmsghdr*)skb->data;    //nlhead message comes from skb's data... (sk_buff: unsigned char *data)

    trace_printk(KERN_INFO "	MyNetlink has received: %s\n",(char*)nlmsg_data(nlhead));
}*/
/*
static int myNetlink_handle_msg(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack * nla)
{
    char *msg = (char *)nlmsg_data(nlh);
    trace_printk(KERN_INFO "MyNetlink has received: %s\n", msg);
    return 0;
}*/

static void nl_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlhead;

	trace_printk(KERN_INFO "	Entering: %s\n", __FUNCTION__);

	nlhead = (struct nlmsghdr*)skb->data;    //nlhead message comes from skb's data... (sk_buff: unsigned char *data)

	trace_printk(KERN_INFO "	MyNetlink has received: %s\n",(char*)nlmsg_data(nlhead));

    //netlink_rcv_skb(skb, &myNetlink_handle_msg);
}

static void sr_recv_msg(struct linux_binprm *bprm)
{
	// Recevoir des messages
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
	//No wait to receive message
    ret = kernel_recvmsg(sock, &msg, &iov, 1, BUFFER_SIZE - 1, MSG_WAITALL);
	if (ret < 0) {
		trace_printk(KERN_INFO "	Error receiving data: %d\n", ret);
	} else {
		buffer[ret] = '\0';
		trace_printk(KERN_INFO "	Received data: %s\n", buffer);
	}
}

static int sr_sock_create(struct linux_binprm *bprm)
{
	int ret;
	

	/*struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    snprintf(socket_path, BUFFER_SIZE, SOCKET_PATH_TEMPLATE, (unsigned long long)ts.tv_nsec);*/
	snprintf(socket_path, BUFFER_SIZE, SOCKET_PATH_TEMPLATE, current->pid);
	
	// Supprimer le fichier de socket s'il existe déjà
    struct path pathA;

	//mutex_lock(&my_mutex); // Protéger les sections critiques avec un mutex

    ret = kern_path(socket_path, LOOKUP_FOLLOW, &pathA);
    if (ret == 0) {
		trace_printk(KERN_INFO "	Chemin existant\n");
	}
	
	struct sockaddr_un server_addr;

	//Creation du socket
	ret = sock_create_kern(&init_net, AF_UNIX, SOCK_DGRAM, 0, &sock);
	if (ret < 0) {
        trace_printk(KERN_INFO "	Error creating socket\n");
        return 0;
    }

	memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

	
	// Liaison de la socket
    ret = kernel_bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        trace_printk(KERN_INFO "	Error binding socket\n");
		//123current->flags &= ~PF_PARENT_PROCESS;
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

       /*netlink_kernel_create() returns a pointer, should be checked with == NULL */
    nl_sk = netlink_kernel_create(&init_net, MY_NETLINK, &cfg);
    //trace_printk("Entering: %s, protocol family = %d \n",__FUNCTION__, MY_NETLINK);
    if(!nl_sk)
    {
        trace_printk(KERN_ALERT "	Error creating socket.\n");
        return 0;
    }
	//trace_printk(KERN_ALERT "	MyNetLink Init OK!\n");
	return 1;
}

static int print_arguments(struct linux_binprm *bprm)
{
	if (!bprm->argc)
			return 1;
	
	// Check if pages are initialized

	if (bprm->p == 0) {
		trace_printk(KERN_INFO "	No pages\n");
		return 2;
	}

	// Print the first argument using bprm->p inspired by remove_arg_zero
	
	unsigned long offset;
	char *kaddr;
	struct page *page;

	struct mm_struct *mm = bprm->mm;
	unsigned long pos = bprm->p;
	int argc = bprm->argc;

	// Create the variable to copy the command line
	// char *command_line = kmalloc(TAILLE, GFP_KERNEL);
	char **argv = kmalloc(argc*sizeof(char*), GFP_KERNEL);
	if (!argv) {
		trace_printk(KERN_INFO "	No memory (argv)\n");
		return 3;
	}
	for (int i = 0; i < argc; i++) {
		argv[i] = kmalloc(TAILLE, GFP_KERNEL);
		if (!argv[i]) {
			trace_printk(KERN_INFO "	No memory (argv[%d]\n", i);
			for (int j = 0; j < i; j++)
				kfree(argv[j]);
			kfree(argv);
			return 4;
		}
	}
	
	// command_line[0] = '\0';

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

			// Add the content of the page to the command line
			if (kaddr[offset]) {
				//trace_printk(KERN_INFO "	Argc: %d	Arg: %s\n", bprm->argc, &kaddr[offset]);
    			strncat(argv[bprm->argc - argc], &kaddr[offset], TAILLE - strlen(argv[bprm->argc - argc]) - 1);
				//strncat(command_line, " ", TAILLE - strlen(command_line) - 1);
			}

			// Find the end of the content
			for (; offset < PAGE_SIZE && kaddr[offset]; offset++, pos++);
			pos++;

			// Unmap the page
			kunmap(page);

		} while (offset == PAGE_SIZE);
bcl:
	} while (argc-- > 1);
	
	// Print the number of arguments and the command line
	//trace_printk(KERN_INFO "	Argc: %d\n", bprm->argc);
	// trace_printk(KERN_INFO "	Command line: %s\n", command_line);
/*	for (int i = 0; i < bprm->argc; i++)
		trace_printk(KERN_INFO "	Arg %d : %s\n", i, argv[i]);
*/
	// Free the commande line arguments
	for (int i = 0; i < bprm->argc; i++)
		kfree(argv[i]);
	kfree(argv);

	return 0;
}

struct usermode_helper_data {
    int ret_val;
};

static int setup_usermodehelper(struct subprocess_info *info, struct cred *new)
{
    struct usermode_helper_data *data = info->data;
    data->ret_val = 0;
    return 0;
}

static void cleanup_usermodehelper(struct subprocess_info *info)
{
    struct usermode_helper_data *data = info->data;
    data->ret_val = info->retval;
}

static int to_ignore(struct linux_binprm *bprm)
{
    //check if pid is > 10
	/*if (current->pid <= 10)
		return 1;*/

	// get uid
	int uid = current_uid().val;

	if (uid == 0)
		return 1;
	
	//if (/*strnstr(bprm->filename, "python3", strlen(bprm->filename)))// || */!strnstr(bprm->filename, "/ls", strlen(bprm->filename)))
	//	{//trace_printk(KERN_INFO "	Ignored (flags)\n");
	//	return 1;}
	/*
	if (strnstr(bprm->filename, "modprobe", strlen(bprm->filename)))// || !strnstr(bprm->filename, "printenv", strlen(bprm->filename)))
		{trace_printk(KERN_INFO "	Ignored (flags)\n");
		return 1;}

	if (strnstr(bprm->filename, "init", strlen(bprm->filename)))// || !strnstr(bprm->filename, "printenv", strlen(bprm->filename)))
		{trace_printk(KERN_INFO "	Ignored (flags)\n");
		return 1;}
	
	if (strnstr(bprm->filename, "mount", strlen(bprm->filename)))// || !strnstr(bprm->filename, "printenv", strlen(bprm->filename)))
		{trace_printk(KERN_INFO "	Ignored (flags)\n");
		return 1;}
	
	if (strnstr(bprm->filename, "journal", strlen(bprm->filename)))// || !strnstr(bprm->filename, "printenv", strlen(bprm->filename)))
		{trace_printk(KERN_INFO "	Ignored (flags)\n");
		return 1;}

	if (strnstr(bprm->filename, "/ln", strlen(bprm->filename)))// || !strnstr(bprm->filename, "printenv", strlen(bprm->filename)))
		{trace_printk(KERN_INFO "	Ignored (flags)\n");
		return 1;}

	if (strnstr(bprm->filename, "pseudo_sr", strlen(bprm->filename)))// || !strnstr(bprm->filename, "printenv", strlen(bprm->filename)))
		{trace_printk(KERN_INFO "	Ignored (flags)\n");
		return 1;}
	*/
	//mount
	
	return 0;
}

static int sr_exec(struct linux_binprm *bprm)
{
	struct subprocess_info *sub_info;
	struct usermode_helper_data data;

	//Execute the 'sr' command
    char *argv_sr[] = { "/usr/bin/python3", "/home/osboxes/RootAsLSM/pseudo_sr.py", socket_path, NULL };
	
	// get pid
	char* pid = kmalloc(10, GFP_KERNEL);
	sprintf(pid, "%d", current->pid);

    //char *argv_sr[] = { "/home/osboxes/RootAsLSM/pseudo_sr", pid, NULL };
    char *envp_sr[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

/*	sub_info = call_usermodehelper_setup(argv_sr[0], argv_sr, envp_sr, GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info == NULL) {
        trace_printk(KERN_INFO "	Failed to setup usermodehelper\n");
		//123current->flags &= ~PF_PARENT_PROCESS;
		netlink_kernel_release(nl_sk);
        goto out;
    }*/

	sub_info = call_usermodehelper_setup(argv_sr[0], argv_sr, envp_sr, GFP_KERNEL, setup_usermodehelper, cleanup_usermodehelper, &data);
    if (sub_info == NULL) {
        trace_printk(KERN_INFO "	Failed to setup usermodehelper\n");
		trace_printk(KERN_INFO "	exiting myNetLink module\n");
        netlink_kernel_release(nl_sk);
        return 0;
    }

    int ret = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    if (ret < 0) {
        trace_printk(KERN_INFO "	Failed to execute sr command\n");
		//123current->flags &= ~PF_PARENT_PROCESS;
		trace_printk(KERN_INFO "	exiting myNetLink module\n");
		netlink_kernel_release(nl_sk);
        return 0;
    }

	// Récupérer la valeur de retour
    trace_printk(KERN_INFO "	Script return value: %d\n", data.ret_val);
	return 1;
}

static void remove_path(struct linux_binprm *bprm)
{
	// Supprimer le fichier de socket s'il existe déjà
    struct path path;

	//mutex_lock(&my_mutex); // Protéger les sections critiques avec un mutex

    int ret = kern_path(socket_path, LOOKUP_FOLLOW, &path);
    if (ret == 0) {
		//trace_printk(KERN_INFO "	Chemin existant\n");
        struct dentry *dentry = path.dentry;
        struct inode *dir = dentry->d_parent->d_inode;
        struct mnt_idmap *idmap = mnt_idmap(path.mnt);

		if (!dir || !idmap) {
        pr_err("dir or idmap is NULL\n");
        path_put(&path);
		//mutex_unlock(&my_mutex);
        return;
    	}

        // Supprimer le fichier de socket s'il existe déjà
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

	/******************SOCKET*********************/

	if (sr_sock_create(bprm) == 0)
		return 0;

	/******************EXEC***********************/

	if (sr_exec(bprm) == 0)
		return 0;

/*	//thread launch
	static struct task_struct *task;

	task = kthread_run(sr_recv_msg , NULL, "sr_recv_msg");
    if (IS_ERR(task)) {
        trace_printk(KERN_INFO "	Failed to create kernel thread\n");
		//123current->flags &= ~PF_PARENT_PROCESS;
		sock_release(sock);
		goto del_sock;
        //return PTR_ERR(task);
    }
*/

	/*******************SOCKET*******************/

	sr_recv_msg(bprm);

	//Release the socket
	//netlink_kernel_release(nl_sk);
	sock_release(sock);

	//Remove the socket file
	remove_path(bprm);
	
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
