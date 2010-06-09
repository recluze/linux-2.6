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


#ifdef CONFIG_SECURITY_scbm 


static int scbm_sysctl(ctl_table *table, int op)
{
	return 0;
}

static int scbm_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int scbm_quota_on(struct dentry *dentry)
{
	return 0;
}


static void scbm_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static void scbm_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int scbm_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void scbm_sb_free_security(struct super_block *sb)
{
}

static int scbm_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int scbm_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static int scbm_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int scbm_sb_statfs(struct dentry *dentry)
{
	return 0;
}


static void scbm_sb_clone_mnt_opts(const struct super_block *oldsb,
				  struct super_block *newsb)
{
}


static int scbm_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static void scbm_inode_free_security(struct inode *inode)
{
}

static int scbm_inode_init_security(struct inode *inode, struct inode *dir,
				   char **name, void **value, size_t *len)
{
	return -EOPNOTSUPP;
}

static int scbm_inode_create(struct inode *inode, struct dentry *dentry,
			    int mask)
{
	return 0;
}

static int scbm_inode_link(struct dentry *old_dentry, struct inode *inode,
			  struct dentry *new_dentry)
{
	return 0;
}

static int scbm_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int scbm_inode_symlink(struct inode *inode, struct dentry *dentry,
			     const char *name)
{
	return 0;
}

static int scbm_inode_mkdir(struct inode *inode, struct dentry *dentry,
			   int mask)
{
	return 0;
}

static int scbm_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int scbm_inode_mknod(struct inode *inode, struct dentry *dentry,
			   int mode, dev_t dev)
{
	return 0;
}

static int scbm_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return 0;
}

static int scbm_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int scbm_inode_follow_link(struct dentry *dentry,
				 struct nameidata *nameidata)
{
	return 0;
}

static int scbm_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static int scbm_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int scbm_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void scbm_inode_post_setxattr(struct dentry *dentry, const char *name,
				    const void *value, size_t size, int flags)
{
}

static int scbm_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int scbm_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int scbm_inode_getsecurity(const struct inode *inode, const char *name,
				 void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static int scbm_inode_setsecurity(struct inode *inode, const char *name,
				 const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static int scbm_inode_listsecurity(struct inode *inode, char *buffer,
				  size_t buffer_size)
{
	return 0;
}

static void scbm_inode_getsecid(const struct inode *inode, u32 *secid)
{
	*secid = 0;
}

#ifdef CONFIG_SECURITY_PATH
static int scbm_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			  unsigned int dev)
{
	return 0;
}

static int scbm_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	return 0;
}

static int scbm_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int scbm_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int scbm_path_symlink(struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	return 0;
}

static int scbm_path_link(struct dentry *old_dentry, struct path *new_dir,
			 struct dentry *new_dentry)
{
	return 0;
}

static int scbm_path_rename(struct path *old_path, struct dentry *old_dentry,
			   struct path *new_path, struct dentry *new_dentry)
{
	return 0;
}

static int scbm_path_truncate(struct path *path, loff_t length,
			     unsigned int time_attrs)
{
	return 0;
}

static int scbm_path_chmod(struct dentry *dentry, struct vfsmount *mnt,
			  mode_t mode)
{
	return 0;
}

static int scbm_path_chown(struct path *path, uid_t uid, gid_t gid)
{
	return 0;
}

static int scbm_path_chroot(struct path *root)
{
	return 0;
}
#endif

static int scbm_file_permission(struct file *file, int mask)
{
	/* printk("scbm: file_permission called\n"); */
	return 0;
}

static int scbm_file_alloc_security(struct file *file)
{
	return 0;
}

static void scbm_file_free_security(struct file *file)
{
}

static int scbm_file_ioctl(struct file *file, unsigned int command,
			  unsigned long arg)
{
	return 0;
}

static int scbm_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			     unsigned long prot)
{
	return 0;
}

static int scbm_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int scbm_file_fcntl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	return 0;
}

static int scbm_file_set_fowner(struct file *file)
{
	return 0;
}

static int scbm_file_send_sigiotask(struct task_struct *tsk,
				   struct fown_struct *fown, int sig)
{
	return 0;
}

static int scbm_file_receive(struct file *file)
{
	return 0;
}

static int scbm_dentry_open(struct file *file, const struct cred *cred)
{
	return 0;
}

static int scbm_task_create(unsigned long clone_flags)
{
	return 0;
}

static int scbm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static void scbm_cred_free(struct cred *cred)
{
}

static int scbm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	return 0;
}


static void scbm_cred_transfer(struct cred *new, const struct cred *old)
{
}

static int scbm_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int scbm_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int scbm_kernel_module_request(char *kmod_name)
{
	return 0;
}

static int scbm_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int scbm_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int scbm_task_getsid(struct task_struct *p)
{
	return 0;
}

static void scbm_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int scbm_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int scbm_task_setrlimit(unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int scbm_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int scbm_task_movememory(struct task_struct *p)
{
	return 0;
}

static int scbm_task_wait(struct task_struct *p)
{
	return 0;
}

static int scbm_task_kill(struct task_struct *p, struct siginfo *info,
			 int sig, u32 secid)
{
	return 0;
}

static void scbm_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

static int scbm_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

static void scbm_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static int scbm_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static void scbm_msg_msg_free_security(struct msg_msg *msg)
{
}

static int scbm_msg_queue_alloc_security(struct msg_queue *msq)
{
	return 0;
}

static void scbm_msg_queue_free_security(struct msg_queue *msq)
{
}

static int scbm_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return 0;
}

static int scbm_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static int scbm_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
				int msgflg)
{
	return 0;
}

static int scbm_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				struct task_struct *target, long type, int mode)
{
	return 0;
}

static int scbm_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void scbm_shm_free_security(struct shmid_kernel *shp)
{
}

static int scbm_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int scbm_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int scbm_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,
			 int shmflg)
{
	return 0;
}

static int scbm_sem_alloc_security(struct sem_array *sma)
{
	return 0;
}

static void scbm_sem_free_security(struct sem_array *sma)
{
}

static int scbm_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int scbm_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int scbm_sem_semop(struct sem_array *sma, struct sembuf *sops,
			 unsigned nsops, int alter)
{
	return 0;
}

#ifdef CONFIG_SECURITY_NETWORK
static int scbm_socket_create(int family, int type, int protocol, int kern)
{
	/* printk("scbm: socket_create called\n"); */
	return 0;
}

static int scbm_socket_post_create(struct socket *sock, int family, int type,
				  int protocol, int kern)
{
	return 0;
}

static int scbm_socket_bind(struct socket *sock, struct sockaddr *address,
			   int addrlen)
{
	return 0;
}

static int scbm_socket_connect(struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	/* printk("scbm: socket_connect called\n");*/
	return 0;
}

static int scbm_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int scbm_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int scbm_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return 0;
}

static int scbm_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			      int size, int flags)
{
	return 0;
}

static int scbm_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int scbm_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int scbm_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int scbm_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int scbm_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int scbm_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int scbm_socket_getpeersec_stream(struct socket *sock,
					char __user *optval,
					int __user *optlen, unsigned len)
{
	return 0;
}

static int scbm_socket_getpeersec_dgram(struct socket *sock,
				       struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int scbm_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void scbm_sk_free_security(struct sock *sk)
{
}

static void scbm_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void scbm_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void scbm_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int scbm_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				 struct request_sock *req)
{
	return 0;
}

static void scbm_inet_csk_clone(struct sock *newsk,
			       const struct request_sock *req)
{
}

static void scbm_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}



static void scbm_req_classify_flow(const struct request_sock *req,
				  struct flowi *fl)
{
}

static int scbm_tun_dev_create(void)
{
	return 0;
}

static void scbm_tun_dev_post_create(struct sock *sk)
{
}

static int scbm_tun_dev_attach(struct sock *sk)
{
	return 0;
}
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static int scbm_xfrm_policy_alloc_security(struct xfrm_sec_ctx **ctxp,
					  struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

static int scbm_xfrm_policy_clone_security(struct xfrm_sec_ctx *old_ctx,
					  struct xfrm_sec_ctx **new_ctxp)
{
	return 0;
}

static void scbm_xfrm_policy_free_security(struct xfrm_sec_ctx *ctx)
{
}

static int scbm_xfrm_policy_delete_security(struct xfrm_sec_ctx *ctx)
{
	return 0;
}

static int scbm_xfrm_state_alloc_security(struct xfrm_state *x,
					 struct xfrm_user_sec_ctx *sec_ctx,
					 u32 secid)
{
	return 0;
}

static void scbm_xfrm_state_free_security(struct xfrm_state *x)
{
}

static int scbm_xfrm_state_delete_security(struct xfrm_state *x)
{
	return 0;
}

static int scbm_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 sk_sid, u8 dir)
{
	return 0;
}

static int scbm_xfrm_state_pol_flow_match(struct xfrm_state *x,
					 struct xfrm_policy *xp,
					 struct flowi *fl)
{
	return 1;
}

static int scbm_xfrm_decode_session(struct sk_buff *skb, u32 *fl, int ckall)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */
static void scbm_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int scbm_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static int scbm_setprocattr(struct task_struct *p, char *name, void *value,
			   size_t size)
{
	return -EINVAL;
}

static int scbm_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static int scbm_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return -EOPNOTSUPP;
}

static void scbm_release_secctx(char *secdata, u32 seclen)
{
}

static int scbm_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

static int scbm_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

static int scbm_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}
#ifdef CONFIG_KEYS
static int scbm_key_alloc(struct key *key, const struct cred *cred,
			 unsigned long flags)
{
	return 0;
}

static void scbm_key_free(struct key *key)
{
}

static int scbm_key_permission(key_ref_t key_ref, const struct cred *cred,
			      key_perm_t perm)
{
	return 0;
}

static int scbm_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
static int scbm_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
	return 0;
}

static int scbm_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static int scbm_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

static void scbm_audit_rule_free(void *lsmrule)
{
}
#endif /* CONFIG_AUDIT */


static int scbm_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
	return 0;
}

static int scbm_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int scbm_capget(struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int scbm_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return 0;	
}


static int scbm_capable(struct task_struct *tsk, const struct cred *cred,
			   int cap, int audit)
{
	return 0;
}

static int scbm_syslog(int type)
{
	return 0;
}

static int scbm_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

static int scbm_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int scbm_netlink_recv(struct sk_buff *skb, int capability)
{
	return 0;	
}

static int scbm_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

static int scbm_bprm_secureexec(struct linux_binprm *bprm)
{
	return 0;
}
	
static int scbm_mount(char *dev_name,
			 struct path *path,
			 char *type,
			 unsigned long flags,
			 void *data)
{
	return 0;
} 

static int scbm_umount(struct vfsmount *mnt, int flags)
{
	return 0;
} 


static int scbm_set_mnt_opts(struct super_block *sb,
				struct security_mnt_opts *opts)
{
	return 0;
} 




static int scbm_parse_opts_str(char *options,
				  struct security_mnt_opts *opts)
{
	return 0;
} 




static int scbm_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	return 0;
} 


static int scbm_inode_removexattr(struct dentry *dentry, const char *name)
{
	return 0;
} 





static int scbm_file_mmap(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags,
			     unsigned long addr, unsigned long addr_only)
{
	/* printk("scbm: file_mmap called\n"); */
	return 0;
} 






static int scbm_task_setnice(struct task_struct *p, int nice)
{
	return 0;
} 





static int scbm_task_setioprio(struct task_struct *p, int ioprio)
{
	return 0;
} 



static int scbm_task_setscheduler(struct task_struct *p, int policy, struct sched_param *lp)
{
	return 0;
} 


static int scbm_socket_unix_stream_connect(struct socket *sock,
					      struct socket *other,
					      struct sock *newsk)
{
	return 0;
} 


static int scbm_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	return 0;
} 




static struct security_operations scbm_ops = {
	.name =				"scbm",

	.ptrace_access_check =		scbm_ptrace_access_check,
	.ptrace_traceme =		scbm_ptrace_traceme,
	.capget =			scbm_capget,
	.capset =			scbm_capset,
	.sysctl =			scbm_sysctl,
	.capable =			scbm_capable,
	.quotactl =			scbm_quotactl,
	.quota_on =			scbm_quota_on,
	.syslog =			scbm_syslog,
	.vm_enough_memory =		scbm_vm_enough_memory,

	.netlink_send =			scbm_netlink_send,
	.netlink_recv =			scbm_netlink_recv,

	.bprm_set_creds =		scbm_bprm_set_creds,
	.bprm_committing_creds =	scbm_bprm_committing_creds,
	.bprm_committed_creds =		scbm_bprm_committed_creds,
	.bprm_secureexec =		scbm_bprm_secureexec,

	.sb_alloc_security =		scbm_sb_alloc_security,
	.sb_free_security =		scbm_sb_free_security,
	.sb_copy_data =			scbm_sb_copy_data,
	.sb_kern_mount =		scbm_sb_kern_mount,
	.sb_show_options =		scbm_sb_show_options,
	.sb_statfs =			scbm_sb_statfs,
	.sb_mount =			scbm_mount,
	.sb_umount =			scbm_umount,
	.sb_set_mnt_opts =		scbm_set_mnt_opts,
	.sb_clone_mnt_opts =		scbm_sb_clone_mnt_opts,
	.sb_parse_opts_str = 		scbm_parse_opts_str,


	.inode_alloc_security =		scbm_inode_alloc_security,
	.inode_free_security =		scbm_inode_free_security,
	.inode_init_security =		scbm_inode_init_security,
	.inode_create =			scbm_inode_create,
	.inode_link =			scbm_inode_link,
	.inode_unlink =			scbm_inode_unlink,
	.inode_symlink =		scbm_inode_symlink,
	.inode_mkdir =			scbm_inode_mkdir,
	.inode_rmdir =			scbm_inode_rmdir,
	.inode_mknod =			scbm_inode_mknod,
	.inode_rename =			scbm_inode_rename,
	.inode_readlink =		scbm_inode_readlink,
	.inode_follow_link =		scbm_inode_follow_link,
	.inode_permission =		scbm_inode_permission,
	.inode_setattr =		scbm_inode_setattr,
	.inode_getattr =		scbm_inode_getattr,
	.inode_setxattr =		scbm_inode_setxattr,
	.inode_post_setxattr =		scbm_inode_post_setxattr,
	.inode_getxattr =		scbm_inode_getxattr,
	.inode_listxattr =		scbm_inode_listxattr,
	.inode_removexattr =		scbm_inode_removexattr,
	.inode_getsecurity =		scbm_inode_getsecurity,
	.inode_setsecurity =		scbm_inode_setsecurity,
	.inode_listsecurity =		scbm_inode_listsecurity,
	.inode_getsecid =		scbm_inode_getsecid,

	.file_permission =		scbm_file_permission,
	.file_alloc_security =		scbm_file_alloc_security,
	.file_free_security =		scbm_file_free_security,
	.file_ioctl =			scbm_file_ioctl,
	.file_mmap =			scbm_file_mmap,
	.file_mprotect =		scbm_file_mprotect,
	.file_lock =			scbm_file_lock,
	.file_fcntl =			scbm_file_fcntl,
	.file_set_fowner =		scbm_file_set_fowner,
	.file_send_sigiotask =		scbm_file_send_sigiotask,
	.file_receive =			scbm_file_receive,

	.dentry_open =			scbm_dentry_open,

	.task_create =			scbm_task_create,
	.cred_alloc_blank =		scbm_cred_alloc_blank,
	.cred_free =			scbm_cred_free,
	.cred_prepare =			scbm_cred_prepare,
	.cred_transfer =		scbm_cred_transfer,
	.kernel_act_as =		scbm_kernel_act_as,
	.kernel_create_files_as =	scbm_kernel_create_files_as,
	.kernel_module_request =	scbm_kernel_module_request,
	.task_setpgid =			scbm_task_setpgid,
	.task_getpgid =			scbm_task_getpgid,
	.task_getsid =			scbm_task_getsid,
	.task_getsecid =		scbm_task_getsecid,
	.task_setnice =			scbm_task_setnice,
	.task_setioprio =		scbm_task_setioprio,
	.task_getioprio =		scbm_task_getioprio,
	.task_setrlimit =		scbm_task_setrlimit,
	.task_setscheduler =		scbm_task_setscheduler,
	.task_getscheduler =		scbm_task_getscheduler,
	.task_movememory =		scbm_task_movememory,
	.task_kill =			scbm_task_kill,
	.task_wait =			scbm_task_wait,
	.task_to_inode =		scbm_task_to_inode,

	.ipc_permission =		scbm_ipc_permission,
	.ipc_getsecid =			scbm_ipc_getsecid,

	.msg_msg_alloc_security =	scbm_msg_msg_alloc_security,
	.msg_msg_free_security =	scbm_msg_msg_free_security,

	.msg_queue_alloc_security =	scbm_msg_queue_alloc_security,
	.msg_queue_free_security =	scbm_msg_queue_free_security,
	.msg_queue_associate =		scbm_msg_queue_associate,
	.msg_queue_msgctl =		scbm_msg_queue_msgctl,
	.msg_queue_msgsnd =		scbm_msg_queue_msgsnd,
	.msg_queue_msgrcv =		scbm_msg_queue_msgrcv,

	.shm_alloc_security =		scbm_shm_alloc_security,
	.shm_free_security =		scbm_shm_free_security,
	.shm_associate =		scbm_shm_associate,
	.shm_shmctl =			scbm_shm_shmctl,
	.shm_shmat =			scbm_shm_shmat,

	.sem_alloc_security =		scbm_sem_alloc_security,
	.sem_free_security =		scbm_sem_free_security,
	.sem_associate =		scbm_sem_associate,
	.sem_semctl =			scbm_sem_semctl,
	.sem_semop =			scbm_sem_semop,

	.d_instantiate =		scbm_d_instantiate,

	.getprocattr =			scbm_getprocattr,
	.setprocattr =			scbm_setprocattr,

	.secid_to_secctx =		scbm_secid_to_secctx,
	.secctx_to_secid =		scbm_secctx_to_secid,
	.release_secctx =		scbm_release_secctx,
	.inode_notifysecctx =		scbm_inode_notifysecctx,
	.inode_setsecctx =		scbm_inode_setsecctx,
	.inode_getsecctx =		scbm_inode_getsecctx,

	.unix_stream_connect =		scbm_socket_unix_stream_connect,
	.unix_may_send =		scbm_socket_unix_may_send,

	.socket_create =		scbm_socket_create,
	.socket_post_create =		scbm_socket_post_create,
	.socket_bind =			scbm_socket_bind,
	.socket_connect =		scbm_socket_connect,
	.socket_listen =		scbm_socket_listen,
	.socket_accept =		scbm_socket_accept,
	.socket_sendmsg =		scbm_socket_sendmsg,
	.socket_recvmsg =		scbm_socket_recvmsg,
	.socket_getsockname =		scbm_socket_getsockname,
	.socket_getpeername =		scbm_socket_getpeername,
	.socket_getsockopt =		scbm_socket_getsockopt,
	.socket_setsockopt =		scbm_socket_setsockopt,
	.socket_shutdown =		scbm_socket_shutdown,
	.socket_sock_rcv_skb =		scbm_socket_sock_rcv_skb,
	.socket_getpeersec_stream =	scbm_socket_getpeersec_stream,
	.socket_getpeersec_dgram =	scbm_socket_getpeersec_dgram,
	.sk_alloc_security =		scbm_sk_alloc_security,
	.sk_free_security =		scbm_sk_free_security,
	.sk_clone_security =		scbm_sk_clone_security,
	.sk_getsecid =			scbm_sk_getsecid,
	.sock_graft =			scbm_sock_graft,
	.inet_conn_request =		scbm_inet_conn_request,
	.inet_csk_clone =		scbm_inet_csk_clone,
	.inet_conn_established =	scbm_inet_conn_established,
	.req_classify_flow =		scbm_req_classify_flow,
	.tun_dev_create =		scbm_tun_dev_create,
	.tun_dev_post_create = 		scbm_tun_dev_post_create,
	.tun_dev_attach =		scbm_tun_dev_attach,

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	.xfrm_policy_alloc_security =	scbm_xfrm_policy_alloc,
	.xfrm_policy_clone_security =	scbm_xfrm_policy_clone,
	.xfrm_policy_free_security =	scbm_xfrm_policy_free,
	.xfrm_policy_delete_security =	scbm_xfrm_policy_delete,
	.xfrm_state_alloc_security =	scbm_xfrm_state_alloc,
	.xfrm_state_free_security =	scbm_xfrm_state_free,
	.xfrm_state_delete_security =	scbm_xfrm_state_delete,
	.xfrm_policy_lookup =		scbm_xfrm_policy_lookup,
	.xfrm_state_pol_flow_match =	scbm_xfrm_state_pol_flow_match,
	.xfrm_decode_session =		scbm_xfrm_decode_session,
#endif

#ifdef CONFIG_KEYS
	.key_alloc =			scbm_key_alloc,
	.key_free =			scbm_key_free,
	.key_permission =		scbm_key_permission,
	.key_getsecurity =		scbm_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
	.audit_rule_init =		scbm_audit_rule_init,
	.audit_rule_known =		scbm_audit_rule_known,
	.audit_rule_match =		scbm_audit_rule_match,
	.audit_rule_free =		scbm_audit_rule_free,
#endif
};

static struct dentry *scbm_dir;
static struct dentry *scbm_output_file;



#define NUM_CRITICAL_CALLS 5 
#define MAX_EXEC_IDENT_LEN 10 


struct hg_inst {
	char exec_ident[MAX_EXEC_IDENT_LEN + 1];  
	/* executable identifier this hypergram is associated with */ 
	
	long double call_val[NUM_CRITICAL_CALLS]; 
	struct list_head list; 
	/* might also need a hashlist for storing the latest value of the hypergram */ 
};

struct list_head scbm_measurements; /* list of all scbm measurements */ 



static void *scbm_measurements_start (struct seq_file *m, loff_t *pos)
{
	printk("scbm: inside measurements_start\n"); 
	loff_t l = *pos; 
	struct hg_inst *inst; 


	
	/* worry about rcu, mutex and locks later */ 
	list_for_each_entry(inst, &scbm_measurements, list) {
		printk("scbm: inside measurements_start list_for_each_entry\n");
		if (!l--)  /* count 'l' number of positions to return the 'lth' hg_inst */ 
			return inst; 
	} 
	return NULL;  /* if past the last inst, return NULL */
}

static void *scbm_measurements_next (struct seq_file *m, void *v, loff_t *pos) 
{
	printk("scbm: inside measurements_next\n");
	struct hg_inst *inst = v; /* cast the void pointer to the next hg_inst */ 
	
	/* get the next in list */ 
	inst = list_entry (inst->list.next, struct hg_inst, list); 
	/* increment the pos for later calls */ 
	(*pos)++; 
		
	printk("scbm: inside measurements_next . sending next node.\n");
	/* since linux has circular doubly-linked list, make sure we don't loop */ 
	return (&inst->list == &scbm_measurements) ? NULL : inst; 
}

static void scbm_measurements_stop (struct seq_file *m, void *v)
{	/* don't need to do anything */ 
	printk("scbm: inside measurements_stop\n");
}



static int scbm_measurements_show (struct seq_file *m, void *v) 
{
	int i = 0;
	printk("scbm: inside measurements_show\n");
	/* get the hg_inst to show */ 
	struct hg_inst *inst = v; 
	
	printk("scbm: inside measurements_show. printing ident\n");
	/* print out the executable associated with the hypergram */ 
	seq_printf(m, "%s ", inst->exec_ident); 

	printk("scbm: inside measurements_show. printing vals\n");
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
	list_add_tail(&inst->list, &scbm_measurements); 

	/ * also PCR_EXTEND here * / 

	return 0; 
}
*/

static struct seq_operations scbm_measurements_ops = {
	.start = scbm_measurements_start,
	.next  = scbm_measurements_next,
	.stop  = scbm_measurements_stop,
	.show  = scbm_measurements_show
};

static int ct_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scbm_measurements_ops);
};


static const struct file_operations scbm_measurements_file_ops = {
	.open = ct_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static __init scbm_init(void){
	/* register the hooks */	
	
	if (register_security(&scbm_ops))
		panic("scbm: Unable to register scbm with kernel.\n");
	else 
		printk("scbm: registered with the kernel\n");

	/* create and set the fs */ 

	scbm_dir = securityfs_create_dir("scbm", NULL);
	if (IS_ERR(scbm_dir)){
		printk("scbm: couldn't create securityfs scbm directory\n");
		return -1;
	}

	/* create the scbm_output_file */
	scbm_output_file =
	    securityfs_create_file("scbm_output_file",
				   S_IRUSR | S_IRGRP, scbm_dir, NULL,
				   &scbm_measurements_file_ops);
	if (IS_ERR(scbm_output_file)){
		printk("scbm: couldn't create scbm_output_file\n");
		return 0;
	}
	printk("scbm: scbm_output_file created.\n");



	/* list of all measurements has to be made list head */
	INIT_LIST_HEAD(&scbm_measurements);	    


	/* create two sample hypergrams */ 
	struct hg_inst *inst; 
	inst = kmalloc(sizeof(*inst), GFP_KERNEL); 

	if (inst == NULL){
		pr_err("Out of memory error while recording hypergram.\n");
		return -ENOMEM; 
	}

	/* add the new instance to the list */ 
	INIT_LIST_HEAD(&(inst->list)); 
	list_add_tail(&(inst->list), &scbm_measurements); 

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

static void __exit scbm_exit (void)
{	
	return;
}



module_init (scbm_init);
module_exit (scbm_exit);

MODULE_DESCRIPTION("scbm");
MODULE_LICENSE("GPL");
#endif /* CONFIG_SECURITY_scbm */

