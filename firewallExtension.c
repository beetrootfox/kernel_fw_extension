#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/dcache.h>

MODULE_AUTHOR ("1230806");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

#define SUCCESS 0
#define PROC_ENTRY_FILENAME "firewallExtension"
#define BUF_LEN 2048
#define NAME_BF 80

DECLARE_RWSEM(rwsema);
DEFINE_MUTEX(oclock);

char message[BUF_LEN];
static int Proc_Open = 0;

static struct proc_dir_entry *Proc_File;

struct rule_list{
	long port;
	char* program;
	struct list_head list;
};

struct rule_list myhead;
struct rule_list *tmp;
struct list_head *p, *sp;
char rule_segment[BUF_LEN];

void read_rules(void){
	down_read(&rwsema);
	list_for_each_safe(p, sp, &(myhead.list)){
		tmp = list_entry(p, struct rule_list, list);
		printk(KERN_INFO "Firewall rule: %d %s", tmp->port, tmp->program);
	}
	up_read(&rwsema);
}

ssize_t kernelWrite (struct file *file, const char __user *buffer, size_t count, loff_t *offset){
	char command;

	if(get_user (command, buffer)){
		return -EFAULT;
	}
	int i = 0;
	switch(command){
		case 'L':
		{
			read_rules();
			i = count;
		}
		break;
		case 'W':
		{
			i += 2;
			int k;
			struct rule_list otherhead;
			INIT_LIST_HEAD(&(otherhead.list));
			while(i < count){
				k = 0;
				while(i < count && k < BUF_LEN){
					get_user(rule_segment[k], buffer + i);
					i++;
					k++;
					if(rule_segment[k-1] == ' '){
						goto port_capture;
					}
				}
			port_capture:
				tmp = (struct rule_list*) kmalloc(sizeof(struct rule_list), GFP_KERNEL);
				if(!tmp){
					printk(KERN_ALERT "Error: Could not add a rule to the ruleset");
					return -ENOMEM;
				}
				rule_segment[k-1] = '\0';
				kstrtol(rule_segment, 10, &(tmp->port));
				k = 0;
				while(i < count && k < BUF_LEN){
					get_user(rule_segment[k], buffer + i);
					i++;
					k++;
					if(rule_segment[k-1] == '\n' || rule_segment[k-1] == '\0'){
						goto program_capture;
					}
				}
			program_capture:
				rule_segment[k-1] = '\0';
				tmp->program = (char*) kmalloc(sizeof(char) * k, GFP_KERNEL);
				if(!tmp){
					printk(KERN_ALERT "Error: Could not add a rule to the ruleset");
					return -ENOMEM;
				}
				memcpy(tmp->program, rule_segment, k);
				list_add(&(tmp->list), &(otherhead.list));
			}
			down_write(&rwsema);
			list_for_each_safe(p, sp, &(myhead.list)){
				tmp = list_entry(p, struct rule_list, list);
				list_del(p);
				kfree(tmp->program);
				kfree(tmp);
			}
			list_for_each_safe(p, sp, &(otherhead.list)){
				tmp = list_entry(p, struct rule_list, list);
		//		printk(KERN_INFO "Adding: port: %d, prog: %s\n", tmp->port, tmp->program);
				list_add(&(tmp->list), &(myhead.list));
			}
			up_write(&rwsema);
		}
		break;
		default:
		printk(KERN_INFO "firewallExtension kernelWrite: illegal command");
	}
	return i;
}

int procfs_open(struct inode *inode, struct file *file){
	mutex_lock(&oclock);
	if(Proc_Open){
		mutex_unlock(&oclock);
		return -EAGAIN;
	}
	Proc_Open++;
	mutex_unlock(&oclock);
	try_module_get(THIS_MODULE);
	return SUCCESS;
}

int procfs_close(struct inode *inode, struct file *file){
	mutex_lock(&oclock);
	Proc_Open--;
	mutex_unlock(&oclock);
	module_put(THIS_MODULE);
	return SUCCESS;
}

struct nf_hook_ops *reg;

unsigned int FirewallExtensionHook (const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *)) {

	struct tcphdr *tcp;
	struct tcphdr _tcph;
	struct sock *sk;

	sk = skb->sk;
	if(!sk){
		printk(KERN_INFO "Firewall: netfilter called with empty socket\n");
		return NF_ACCEPT;
	}

	if(sk->sk_protocol != IPPROTO_TCP){
		printk(KERN_INFO "Firewall: netfilter called with non-TCP-packet.\n");
		return NF_ACCEPT;
	}

	tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
	if(!tcp){
		printk(KERN_INFO "Could not get tcp-header!\n");
		return NF_ACCEPT;
	}
	if(tcp->syn){
		if(in_irq() || in_softirq()){
			printk(KERN_INFO "Not in user context\n");
			return NF_ACCEPT;
		}

		        struct path path;
        		pid_t mod_pid;
        		struct dentry *procDentry;
			struct dentry *parent;

        		char cmdlineFile[NAME_BF];
        		int res;

        		mod_pid = current->pid;
        		snprintf(cmdlineFile, NAME_BF, "/proc/%d/exe", mod_pid);
        		res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
        		if(res){
                		printk(KERN_INFO "Could not get dentry for %s!\n", cmdlineFile);
                		return -EFAULT;
        		}

       			procDentry = path.dentry;
			parent = procDentry->d_parent;
			char fullname[2*NAME_BF];
			snprintf(fullname, 2*NAME_BF, "%s/%s", parent->d_name.name, procDentry->d_name.name);

			down_read(&rwsema);
			int FLAG = 0;
			list_for_each(p, &(myhead.list)){
				tmp = list_entry(p, struct rule_list, list);
				if(ntohs (tcp->dest) == tmp->port)
					FLAG = 1;
			}

			if(!FLAG){
				return NF_ACCEPT;
			}

			char *p1;
			char *p2;
			char *p3;
			list_for_each(p, &(myhead.list)){
                                tmp = list_entry(p, struct rule_list, list);
				p1 = tmp->program;
				p2 = p1;
				p3 = p1;
				int i = 0;
				while(*p1 != '\0'){
					if(*p1 == '/'){
						p1++;
						p3 = p2;
						p2 = p1;
					}
					p1++;
				}
                              	if(strcmp(p3, fullname) == 0 &&
					ntohs (tcp->dest) == tmp->port){
					printk(KERN_INFO "Rule exists, accept connection\n");
					return NF_ACCEPT;
				}

                        }
			up_read(&rwsema);
			printk(KERN_INFO "Rule does not exist, terminate connection\n");
			tcp_done(sk);
			return NF_DROP;

	}

	return NF_ACCEPT;
}

EXPORT_SYMBOL (FirewallExtensionHook);

const struct file_operations File_Ops = {
	.owner = THIS_MODULE,
	.write = kernelWrite,
	.open = procfs_open,
	.release = procfs_close
};

static struct nf_hook_ops firewallExtension_ops = {
	.hook = FirewallExtensionHook,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_OUT
};

int init_module(void)
{
	printk(KERN_INFO "Initializing kernel module:\n");

	Proc_File = proc_create_data (PROC_ENTRY_FILENAME, 0, NULL, &File_Ops, NULL);

	if(Proc_File == NULL){
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
			PROC_ENTRY_FILENAME);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&(myhead.list));

	int errno;

	errno = nf_register_hook (&firewallExtension_ops);
	if(errno){
		printk (KERN_INFO "Firewall extension could not be registered\n");
	}else{
		printk(KERN_INFO "Firewall extension module loaded\n");
	}
	printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);
  	// A non 0 return means init_module failed; module can't be loaded.
	return errno;
}


void cleanup_module(void)
{
	 list_for_each_safe(p, sp, &(myhead.list)){
        	 tmp = list_entry(p, struct rule_list, list);
                 list_del(p);
                 kfree(tmp->program);
                 kfree(tmp);
         }
	remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	nf_unregister_hook (&firewallExtension_ops);
	printk(KERN_INFO "Firewall extensions module unloaded\n");
}

