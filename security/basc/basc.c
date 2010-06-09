/* Author information here 
 *
 *  
 */ 


#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/list.h>


#ifdef CONFIG_SECURITY_BASC 


static int basc_sysctl(ctl_table *table, int op)
{
	return 0;
}

static int basc_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int basc_quota_on(struct dentry *dentry)
{
	return 0;
}


static void basc_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static void basc_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int basc_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void basc_sb_free_security(struct super_block *sb)
{
}

static int basc_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int basc_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static int basc_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int basc_sb_statfs(struct dentry *dentry)
{
	return 0;
}


static void basc_sb_clone_mnt_opts(const struct super_block *oldsb,
				  struct super_block *newsb)
{
}


static int basc_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static void basc_inode_free_security(struct inode *inode)
{
}

static int basc_inode_init_security(struct inode *inode, struct inode *dir,
				   char **name, void **value, size_t *len)
{
	return -EOPNOTSUPP;
}

static int basc_inode_create(struct inode *inode, struct dentry *dentry,
			    int mask)
{
	return 0;
}

static int basc_inode_link(struct dentry *old_dentry, struct inode *inode,
			  struct dentry *new_dentry)
{
	return 0;
}

static int basc_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int basc_inode_symlink(struct inode *inode, struct dentry *dentry,
			     const char *name)
{
	return 0;
}

static int basc_inode_mkdir(struct inode *inode, struct dentry *dentry,
			   int mask)
{
	return 0;
}

static int basc_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int basc_inode_mknod(struct inode *inode, struct dentry *dentry,
			   int mode, dev_t dev)
{
	return 0;
}

static int basc_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return 0;
}

static int basc_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int basc_inode_follow_link(struct dentry *dentry,
				 struct nameidata *nameidata)
{
	return 0;
}

static int basc_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static int basc_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int basc_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void basc_inode_post_setxattr(struct dentry *dentry, const char *name,
				    const void *value, size_t size, int flags)
{
}

static int basc_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int basc_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int basc_inode_getsecurity(const struct inode *inode, const char *name,
				 void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static int basc_inode_setsecurity(struct inode *inode, const char *name,
				 const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static int basc_inode_listsecurity(struct inode *inode, char *buffer,
				  size_t buffer_size)
{
	return 0;
}

static void basc_inode_getsecid(const struct inode *inode, u32 *secid)
{
	*secid = 0;
}

#ifdef CONFIG_SECURITY_PATH
static int basc_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			  unsigned int dev)
{
	return 0;
}

static int basc_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	return 0;
}

static int basc_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int basc_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int basc_path_symlink(struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	return 0;
}

static int basc_path_link(struct dentry *old_dentry, struct path *new_dir,
			 struct dentry *new_dentry)
{
	return 0;
}

static int basc_path_rename(struct path *old_path, struct dentry *old_dentry,
			   struct path *new_path, struct dentry *new_dentry)
{
	return 0;
}

static int basc_path_truncate(struct path *path, loff_t length,
			     unsigned int time_attrs)
{
	return 0;
}

static int basc_path_chmod(struct dentry *dentry, struct vfsmount *mnt,
			  mode_t mode)
{
	return 0;
}

static int basc_path_chown(struct path *path, uid_t uid, gid_t gid)
{
	return 0;
}

static int basc_path_chroot(struct path *root)
{
	return 0;
}
#endif

static int basc_file_permission(struct file *file, int mask)
{
	/* printk("basc: file_permission called\n"); */
	return 0;
}

static int basc_file_alloc_security(struct file *file)
{
	return 0;
}

static void basc_file_free_security(struct file *file)
{
}

static int basc_file_ioctl(struct file *file, unsigned int command,
			  unsigned long arg)
{
	return 0;
}

static int basc_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			     unsigned long prot)
{
	return 0;
}

static int basc_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int basc_file_fcntl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	return 0;
}

static int basc_file_set_fowner(struct file *file)
{
	return 0;
}

static int basc_file_send_sigiotask(struct task_struct *tsk,
				   struct fown_struct *fown, int sig)
{
	return 0;
}

static int basc_file_receive(struct file *file)
{
	return 0;
}

static int basc_dentry_open(struct file *file, const struct cred *cred)
{
	return 0;
}

static int basc_task_create(unsigned long clone_flags)
{
	return 0;
}

static int basc_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static void basc_cred_free(struct cred *cred)
{
}

static int basc_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	return 0;
}


static void basc_cred_transfer(struct cred *new, const struct cred *old)
{
}

static int basc_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int basc_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int basc_kernel_module_request(char *kmod_name)
{
	return 0;
}

static int basc_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int basc_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int basc_task_getsid(struct task_struct *p)
{
	return 0;
}

static void basc_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int basc_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int basc_task_setrlimit(unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int basc_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int basc_task_movememory(struct task_struct *p)
{
	return 0;
}

static int basc_task_wait(struct task_struct *p)
{
	return 0;
}

static int basc_task_kill(struct task_struct *p, struct siginfo *info,
			 int sig, u32 secid)
{
	return 0;
}

static void basc_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

static int basc_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

static void basc_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static int basc_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static void basc_msg_msg_free_security(struct msg_msg *msg)
{
}

static int basc_msg_queue_alloc_security(struct msg_queue *msq)
{
	return 0;
}

static void basc_msg_queue_free_security(struct msg_queue *msq)
{
}

static int basc_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return 0;
}

static int basc_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static int basc_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
				int msgflg)
{
	return 0;
}

static int basc_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				struct task_struct *target, long type, int mode)
{
	return 0;
}

static int basc_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void basc_shm_free_security(struct shmid_kernel *shp)
{
}

static int basc_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int basc_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int basc_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,
			 int shmflg)
{
	return 0;
}

static int basc_sem_alloc_security(struct sem_array *sma)
{
	return 0;
}

static void basc_sem_free_security(struct sem_array *sma)
{
}

static int basc_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int basc_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int basc_sem_semop(struct sem_array *sma, struct sembuf *sops,
			 unsigned nsops, int alter)
{
	return 0;
}

#ifdef CONFIG_SECURITY_NETWORK
static int basc_socket_create(int family, int type, int protocol, int kern)
{
	/* printk("basc: socket_create called\n"); */
	return 0;
}

static int basc_socket_post_create(struct socket *sock, int family, int type,
				  int protocol, int kern)
{
	return 0;
}

static int basc_socket_bind(struct socket *sock, struct sockaddr *address,
			   int addrlen)
{
	return 0;
}

static int basc_socket_connect(struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	/* printk("basc: socket_connect called\n");*/
	return 0;
}

static int basc_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int basc_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int basc_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return 0;
}

static int basc_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			      int size, int flags)
{
	return 0;
}

static int basc_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int basc_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int basc_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int basc_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int basc_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int basc_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int basc_socket_getpeersec_stream(struct socket *sock,
					char __user *optval,
					int __user *optlen, unsigned len)
{
	return 0;
}

static int basc_socket_getpeersec_dgram(struct socket *sock,
				       struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int basc_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void basc_sk_free_security(struct sock *sk)
{
}

static void basc_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void basc_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void basc_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int basc_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				 struct request_sock *req)
{
	return 0;
}

static void basc_inet_csk_clone(struct sock *newsk,
			       const struct request_sock *req)
{
}

static void basc_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}



static void basc_req_classify_flow(const struct request_sock *req,
				  struct flowi *fl)
{
}

static int basc_tun_dev_create(void)
{
	return 0;
}

static void basc_tun_dev_post_create(struct sock *sk)
{
}

static int basc_tun_dev_attach(struct sock *sk)
{
	return 0;
}
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static int basc_xfrm_policy_alloc_security(struct xfrm_sec_ctx **ctxp,
					  struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

static int basc_xfrm_policy_clone_security(struct xfrm_sec_ctx *old_ctx,
					  struct xfrm_sec_ctx **new_ctxp)
{
	return 0;
}

static void basc_xfrm_policy_free_security(struct xfrm_sec_ctx *ctx)
{
}

static int basc_xfrm_policy_delete_security(struct xfrm_sec_ctx *ctx)
{
	return 0;
}

static int basc_xfrm_state_alloc_security(struct xfrm_state *x,
					 struct xfrm_user_sec_ctx *sec_ctx,
					 u32 secid)
{
	return 0;
}

static void basc_xfrm_state_free_security(struct xfrm_state *x)
{
}

static int basc_xfrm_state_delete_security(struct xfrm_state *x)
{
	return 0;
}

static int basc_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 sk_sid, u8 dir)
{
	return 0;
}

static int basc_xfrm_state_pol_flow_match(struct xfrm_state *x,
					 struct xfrm_policy *xp,
					 struct flowi *fl)
{
	return 1;
}

static int basc_xfrm_decode_session(struct sk_buff *skb, u32 *fl, int ckall)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */
static void basc_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int basc_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static int basc_setprocattr(struct task_struct *p, char *name, void *value,
			   size_t size)
{
	return -EINVAL;
}

static int basc_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static int basc_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return -EOPNOTSUPP;
}

static void basc_release_secctx(char *secdata, u32 seclen)
{
}

static int basc_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

static int basc_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

static int basc_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}
#ifdef CONFIG_KEYS
static int basc_key_alloc(struct key *key, const struct cred *cred,
			 unsigned long flags)
{
	return 0;
}

static void basc_key_free(struct key *key)
{
}

static int basc_key_permission(key_ref_t key_ref, const struct cred *cred,
			      key_perm_t perm)
{
	return 0;
}

static int basc_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
static int basc_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
	return 0;
}

static int basc_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static int basc_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

static void basc_audit_rule_free(void *lsmrule)
{
}
#endif /* CONFIG_AUDIT */


static int basc_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
	return 0;
}

static int basc_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int basc_capget(struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int basc_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return 0;	
}


static int basc_capable(struct task_struct *tsk, const struct cred *cred,
			   int cap, int audit)
{
	return 0;
}

static int basc_syslog(int type)
{
	return 0;
}

static int basc_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

static int basc_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int basc_netlink_recv(struct sk_buff *skb, int capability)
{
	return 0;	
}

static int basc_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

static int basc_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
}
	
static int basc_mount(char *dev_name,
			 struct path *path,
			 char *type,
			 unsigned long flags,
			 void *data)
{
	return 0;
} 

static int basc_umount(struct vfsmount *mnt, int flags)
{
	return 0;
} 


static int basc_set_mnt_opts(struct super_block *sb,
				struct security_mnt_opts *opts)
{
	return 0;
} 




static int basc_parse_opts_str(char *options,
				  struct security_mnt_opts *opts)
{
	return 0;
} 




static int basc_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	return 0;
} 


static int basc_inode_removexattr(struct dentry *dentry, const char *name)
{
	return 0;
} 





static int basc_file_mmap(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags,
			     unsigned long addr, unsigned long addr_only)
{
	/* printk("basc: file_mmap called\n"); */
	return 0;
} 






static int basc_task_setnice(struct task_struct *p, int nice)
{
	return 0;
} 





static int basc_task_setioprio(struct task_struct *p, int ioprio)
{
	return 0;
} 



static int basc_task_setscheduler(struct task_struct *p, int policy, struct sched_param *lp)
{
	return 0;
} 


static int basc_socket_unix_stream_connect(struct socket *sock,
					      struct socket *other,
					      struct sock *newsk)
{
	return 0;
} 


static int basc_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	return 0;
} 




static struct security_operations basc_ops = {
	.name =				"basc",

	.ptrace_access_check =		basc_ptrace_access_check,
	.ptrace_traceme =		basc_ptrace_traceme,
	.capget =			basc_capget,
	.capset =			basc_capset,
	.sysctl =			basc_sysctl,
	.capable =			basc_capable,
	.quotactl =			basc_quotactl,
	.quota_on =			basc_quota_on,
	.syslog =			basc_syslog,
	.vm_enough_memory =		basc_vm_enough_memory,

	.netlink_send =			basc_netlink_send,
	.netlink_recv =			basc_netlink_recv,

	.bprm_set_creds =		basc_bprm_set_creds,
	.bprm_committing_creds =	basc_bprm_committing_creds,
	.bprm_committed_creds =		basc_bprm_committed_creds,
	.bprm_secureexec =		basc_bprm_secureexec,

	.sb_alloc_security =		basc_sb_alloc_security,
	.sb_free_security =		basc_sb_free_security,
	.sb_copy_data =			basc_sb_copy_data,
	.sb_kern_mount =		basc_sb_kern_mount,
	.sb_show_options =		basc_sb_show_options,
	.sb_statfs =			basc_sb_statfs,
	.sb_mount =			basc_mount,
	.sb_umount =			basc_umount,
	.sb_set_mnt_opts =		basc_set_mnt_opts,
	.sb_clone_mnt_opts =		basc_sb_clone_mnt_opts,
	.sb_parse_opts_str = 		basc_parse_opts_str,


	.inode_alloc_security =		basc_inode_alloc_security,
	.inode_free_security =		basc_inode_free_security,
	.inode_init_security =		basc_inode_init_security,
	.inode_create =			basc_inode_create,
	.inode_link =			basc_inode_link,
	.inode_unlink =			basc_inode_unlink,
	.inode_symlink =		basc_inode_symlink,
	.inode_mkdir =			basc_inode_mkdir,
	.inode_rmdir =			basc_inode_rmdir,
	.inode_mknod =			basc_inode_mknod,
	.inode_rename =			basc_inode_rename,
	.inode_readlink =		basc_inode_readlink,
	.inode_follow_link =		basc_inode_follow_link,
	.inode_permission =		basc_inode_permission,
	.inode_setattr =		basc_inode_setattr,
	.inode_getattr =		basc_inode_getattr,
	.inode_setxattr =		basc_inode_setxattr,
	.inode_post_setxattr =		basc_inode_post_setxattr,
	.inode_getxattr =		basc_inode_getxattr,
	.inode_listxattr =		basc_inode_listxattr,
	.inode_removexattr =		basc_inode_removexattr,
	.inode_getsecurity =		basc_inode_getsecurity,
	.inode_setsecurity =		basc_inode_setsecurity,
	.inode_listsecurity =		basc_inode_listsecurity,
	.inode_getsecid =		basc_inode_getsecid,

	.file_permission =		basc_file_permission,
	.file_alloc_security =		basc_file_alloc_security,
	.file_free_security =		basc_file_free_security,
	.file_ioctl =			basc_file_ioctl,
	.file_mmap =			basc_file_mmap,
	.file_mprotect =		basc_file_mprotect,
	.file_lock =			basc_file_lock,
	.file_fcntl =			basc_file_fcntl,
	.file_set_fowner =		basc_file_set_fowner,
	.file_send_sigiotask =		basc_file_send_sigiotask,
	.file_receive =			basc_file_receive,

	.dentry_open =			basc_dentry_open,

	.task_create =			basc_task_create,
	.cred_alloc_blank =		basc_cred_alloc_blank,
	.cred_free =			basc_cred_free,
	.cred_prepare =			basc_cred_prepare,
	.cred_transfer =		basc_cred_transfer,
	.kernel_act_as =		basc_kernel_act_as,
	.kernel_create_files_as =	basc_kernel_create_files_as,
	.kernel_module_request =	basc_kernel_module_request,
	.task_setpgid =			basc_task_setpgid,
	.task_getpgid =			basc_task_getpgid,
	.task_getsid =			basc_task_getsid,
	.task_getsecid =		basc_task_getsecid,
	.task_setnice =			basc_task_setnice,
	.task_setioprio =		basc_task_setioprio,
	.task_getioprio =		basc_task_getioprio,
	.task_setrlimit =		basc_task_setrlimit,
	.task_setscheduler =		basc_task_setscheduler,
	.task_getscheduler =		basc_task_getscheduler,
	.task_movememory =		basc_task_movememory,
	.task_kill =			basc_task_kill,
	.task_wait =			basc_task_wait,
	.task_to_inode =		basc_task_to_inode,

	.ipc_permission =		basc_ipc_permission,
	.ipc_getsecid =			basc_ipc_getsecid,

	.msg_msg_alloc_security =	basc_msg_msg_alloc_security,
	.msg_msg_free_security =	basc_msg_msg_free_security,

	.msg_queue_alloc_security =	basc_msg_queue_alloc_security,
	.msg_queue_free_security =	basc_msg_queue_free_security,
	.msg_queue_associate =		basc_msg_queue_associate,
	.msg_queue_msgctl =		basc_msg_queue_msgctl,
	.msg_queue_msgsnd =		basc_msg_queue_msgsnd,
	.msg_queue_msgrcv =		basc_msg_queue_msgrcv,

	.shm_alloc_security =		basc_shm_alloc_security,
	.shm_free_security =		basc_shm_free_security,
	.shm_associate =		basc_shm_associate,
	.shm_shmctl =			basc_shm_shmctl,
	.shm_shmat =			basc_shm_shmat,

	.sem_alloc_security =		basc_sem_alloc_security,
	.sem_free_security =		basc_sem_free_security,
	.sem_associate =		basc_sem_associate,
	.sem_semctl =			basc_sem_semctl,
	.sem_semop =			basc_sem_semop,

	.d_instantiate =		basc_d_instantiate,

	.getprocattr =			basc_getprocattr,
	.setprocattr =			basc_setprocattr,

	.secid_to_secctx =		basc_secid_to_secctx,
	.secctx_to_secid =		basc_secctx_to_secid,
	.release_secctx =		basc_release_secctx,
	.inode_notifysecctx =		basc_inode_notifysecctx,
	.inode_setsecctx =		basc_inode_setsecctx,
	.inode_getsecctx =		basc_inode_getsecctx,

	.unix_stream_connect =		basc_socket_unix_stream_connect,
	.unix_may_send =		basc_socket_unix_may_send,

	.socket_create =		basc_socket_create,
	.socket_post_create =		basc_socket_post_create,
	.socket_bind =			basc_socket_bind,
	.socket_connect =		basc_socket_connect,
	.socket_listen =		basc_socket_listen,
	.socket_accept =		basc_socket_accept,
	.socket_sendmsg =		basc_socket_sendmsg,
	.socket_recvmsg =		basc_socket_recvmsg,
	.socket_getsockname =		basc_socket_getsockname,
	.socket_getpeername =		basc_socket_getpeername,
	.socket_getsockopt =		basc_socket_getsockopt,
	.socket_setsockopt =		basc_socket_setsockopt,
	.socket_shutdown =		basc_socket_shutdown,
	.socket_sock_rcv_skb =		basc_socket_sock_rcv_skb,
	.socket_getpeersec_stream =	basc_socket_getpeersec_stream,
	.socket_getpeersec_dgram =	basc_socket_getpeersec_dgram,
	.sk_alloc_security =		basc_sk_alloc_security,
	.sk_free_security =		basc_sk_free_security,
	.sk_clone_security =		basc_sk_clone_security,
	.sk_getsecid =			basc_sk_getsecid,
	.sock_graft =			basc_sock_graft,
	.inet_conn_request =		basc_inet_conn_request,
	.inet_csk_clone =		basc_inet_csk_clone,
	.inet_conn_established =	basc_inet_conn_established,
	.req_classify_flow =		basc_req_classify_flow,
	.tun_dev_create =		basc_tun_dev_create,
	.tun_dev_post_create = 		basc_tun_dev_post_create,
	.tun_dev_attach =		basc_tun_dev_attach,

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	.xfrm_policy_alloc_security =	basc_xfrm_policy_alloc,
	.xfrm_policy_clone_security =	basc_xfrm_policy_clone,
	.xfrm_policy_free_security =	basc_xfrm_policy_free,
	.xfrm_policy_delete_security =	basc_xfrm_policy_delete,
	.xfrm_state_alloc_security =	basc_xfrm_state_alloc,
	.xfrm_state_free_security =	basc_xfrm_state_free,
	.xfrm_state_delete_security =	basc_xfrm_state_delete,
	.xfrm_policy_lookup =		basc_xfrm_policy_lookup,
	.xfrm_state_pol_flow_match =	basc_xfrm_state_pol_flow_match,
	.xfrm_decode_session =		basc_xfrm_decode_session,
#endif

#ifdef CONFIG_KEYS
	.key_alloc =			basc_key_alloc,
	.key_free =			basc_key_free,
	.key_permission =		basc_key_permission,
	.key_getsecurity =		basc_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
	.audit_rule_init =		basc_audit_rule_init,
	.audit_rule_known =		basc_audit_rule_known,
	.audit_rule_match =		basc_audit_rule_match,
	.audit_rule_free =		basc_audit_rule_free,
#endif
};

static struct dentry *basc_dir;
static struct dentry *basc_output_file;



#define NUM_CRITICAL_CALLS 5 
#define MAX_EXEC_IDENT_LEN 10 


struct hg_inst {
	char exec_ident[MAX_EXEC_IDENT_LEN + 1];  
	/* executable identifier this hypergram is associated with */ 
	
	long double call_val[NUM_CRITICAL_CALLS]; 
	struct list_head list; 
	/* might also need a hashlist for storing the latest value of the hypergram */ 
};

struct list_head basc_measurements; /* list of all basc measurements */ 



static void *basc_measurements_start (struct seq_file *m, loff_t *pos)
{
	printk("basc: inside measurements_start\n"); 
	loff_t l = *pos; 
	struct hg_inst *inst; 


	
	/* worry about rcu, mutex and locks later */ 
	list_for_each_entry(inst, &basc_measurements, list) {
		printk("basc: inside measurements_start list_for_each_entry\n");
		if (!l--)  /* count 'l' number of positions to return the 'lth' hg_inst */ 
			return inst; 
	} 
	return NULL;  /* if past the last inst, return NULL */
}

static void *basc_measurements_next (struct seq_file *m, void *v, loff_t *pos) 
{
	printk("basc: inside measurements_next\n");
	struct hg_inst *inst = v; /* cast the void pointer to the next hg_inst */ 
	
	/* get the next in list */ 
	inst = list_entry (inst->list.next, struct hg_inst, list); 
	/* increment the pos for later calls */ 
	(*pos)++; 
		
	printk("basc: inside measurements_next . sending next node.\n");
	/* since linux has circular doubly-linked list, make sure we don't loop */ 
	return (&inst->list == &basc_measurements) ? NULL : inst; 
}

static void basc_measurements_stop (struct seq_file *m, void *v)
{	/* don't need to do anything */ 
	printk("basc: inside measurements_stop\n");
}



static int basc_measurements_show (struct seq_file *m, void *v) 
{
	int i = 0;
	printk("basc: inside measurements_show\n");
	/* get the hg_inst to show */ 
	struct hg_inst *inst = v; 
	
	printk("basc: inside measurements_show. printing ident\n");
	/* print out the executable associated with the hypergram */ 
	seq_printf(m, "%s ", inst->exec_ident); 

	printk("basc: inside measurements_show. printing vals\n");
	/* loop over and print out the hypergram call_val */
	for (i = 0; i < NUM_CRITICAL_CALLS; i++){
		seq_printf(m, "%Lf, ", inst->call_val[i]); 
	}
	seq_printf(m, "\n");
	return 0;
}


/* 
static int add_hypergram_inst(char *exec_ident, long double *cv){
{	
	int i = 0; / * for loops for call_val * / 

	/ * got the exec_identifier and instance call_vals * /  

	struct hg_inst *inst; 
	inst = kmalloc(sizeof(*inst), GFP_KERNEL); 

	if (inst == NULL){
		pr_err("Out of memory error while recording hypergram.\n");
		return -ENOMEM; 
	}

	/ * assign values to the new instance record * / 
	strncpy(inst->exec_ident, exec_ident, MAX_EXEC_IDENT_LEN);
 	for (i = 0; i < NUM_CRITICAL_CALLS; i++){ 
		inst->call_val[i] = cv[i]; 
	} 

	/ * add the new instance to the list * / 
	INIT_LIST_HEAD(&inst->list); 
	list_add_tail(&inst->list, &basc_measurements); 

	/ * also PCR_EXTEND here * / 

	return 0; 
}
*/

static struct seq_operations basc_measurements_ops = {
	.start = basc_measurements_start,
	.next  = basc_measurements_next,
	.stop  = basc_measurements_stop,
	.show  = basc_measurements_show
};

static int ct_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &basc_measurements_ops);
};


static const struct file_operations basc_measurements_file_ops = {
	.open = ct_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static __init basc_init(void){
	/* register the hooks */	
	
	if (register_security(&basc_ops))
		panic("basc: Unable to register basc with kernel.\n");
	else 
		printk("basc: registered with the kernel\n");

	/* create and set the fs */ 

	basc_dir = securityfs_create_dir("basc", NULL);
	if (IS_ERR(basc_dir)){
		printk("basc: couldn't create securityfs basc directory\n");
		return -1;
	}

	/* create the basc_output_file */
	basc_output_file =
	    securityfs_create_file("basc_output_file",
				   S_IRUSR | S_IRGRP, basc_dir, NULL,
				   &basc_measurements_file_ops);
	if (IS_ERR(basc_output_file)){
		printk("basc: couldn't create basc_output_file\n");
		return 0;
	}
	printk("basc: basc_output_file created.\n");



	/* list of all measurements has to be made list head */
	INIT_LIST_HEAD(&basc_measurements);	    


	/* create two sample hypergrams */ 
	struct hg_inst *inst; 
	inst = kmalloc(sizeof(*inst), GFP_KERNEL); 

	if (inst == NULL){
		pr_err("Out of memory error while recording hypergram.\n");
		return -ENOMEM; 
	}

	/* add the new instance to the list */ 
	INIT_LIST_HEAD(&(inst->list)); 
	list_add_tail(&(inst->list), &basc_measurements); 

	/* probably should memset these first ... nope. Not necessary.*/
	strcpy(inst->exec_ident, "test 1"); 
	inst->call_val[0] = 1;
	inst->call_val[1] = 2;
	inst->call_val[2] = 3;
	inst->call_val[3] = 4;
	inst->call_val[4] = 5;


	/* end of sample hypergrams */ 

	return 0;
}

static void __exit basc_exit (void)
{	
	return;
}



module_init (basc_init);
module_exit (basc_exit);

MODULE_DESCRIPTION("BASC");
MODULE_LICENSE("GPL");
#endif /* CONFIG_SECURITY_BASC */

