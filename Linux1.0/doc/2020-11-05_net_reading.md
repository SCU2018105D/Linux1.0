---
layout:     post
title:      linux 网络编程源码解析
subtitle:   Linux 网络编程源码解析(一)
date:       2019-12-27
author:     王鹏程
header-img: img/post-bg-ios10.jpg
catalog: true
tags:
    - C/C++
    - Linux kernel
    - 并行编程，源码编程
---

# Linux 网络编程源码解析(一)

_参考链接:_
- [linux内核网络协议栈架构分析，全流程分析-干货](https://blog.csdn.net/zxorange321/article/details/75676063)
- []()


## 0. 说明
本文档制作基于Linux-2.6.32，

## 1. TCP协议

### 1.1 分层
TCP协议中的分层信息如下:

![](https://img-blog.csdn.net/20170328143202890?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcXdhc3p4NTIz/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

### 1.2 TCP/IP中的分层

SNMP也是使用了UDP协议，TCP和UDP的每组数据都通过端系统和每个中间路由器中的IP层在互联网中进行传输。

ICMP是IP协议的附属协议。I P层用它来与其他主机或路由器交换错误报文和其他重要信息。

IGMP是Internet组管理协议。它用来把一个UDP数据报多播到多个主机。我们在第1 2章中描述广播（把一个UDP数据报发送到某个指定网络上的所有主机）和多播的一般特性，然后在第1 3章中对IGMP协议本身进行描述。

ARP（地址解析协议）和RARP（逆地址解析协议）是某些网络接口（如以太网和令牌环网）使用的特殊协议，用来转换I P层和网络接口层使用的地址。我们分别在第4章和第5章对这两种协议进行分析和介绍。

### 1.3 封装

当应用程序使用TCP传输数据时，数据被送入协议中，然后逐个通过每一层直到被当做一串比特流送入网络。其中每层对接受到的数据都要增加一些首部信息

### 1.4 分用

当目的主机收到一个以太网数据帧时，数据就开始从协议栈中由底向上升，同时去掉各层协议加上的报文首部。每层协议盒都要去检查报文首部中的协议标识，以确定接收数据的上层协议。这个过程称作分用。

## 3 数据包格式

以太网头部数据

```c
struct ethhdr {
    /* 目的地址 */ 
    unsigned char h_dest[ETH_ALEN];
    /* 源地址 */
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto; /* 帧的类型 */
}__attribute__((packed));

/* 环路网帧 */
#define ETH_P_LOOP   0x0060    /* Ethernet Loopback packet */
/*  */
#define ETH_P_PUP 0x0200     /* Xerox PUP packet      */

#define ETH_P_PUPAT  0x0201    /* Xerox PUP Addr Trans packet  */

#define ETH_P_IP  0x0800     /* Internet Protocol packet */

#define ETH_P_X25 0x0805     /* CCITT X.25        */

#define ETH_P_ARP 0x0806     /* Address Resolution packet    */

#define    ETH_P_BPQ  0x08FF    /* G8BPQ AX.25Ethernet Packet  [ NOT AN OFFICIALLYREGISTERED ID ] */

#define ETH_P_IEEEPUP    0x0a00    /* Xerox IEEE802.3 PUP packet */

#define ETH_P_IEEEPUPAT  0x0a01    /* Xerox IEEE802.3 PUP Addr Trans packet */

#define ETH_P_DEC       0x6000         /* DEC Assigned proto           */

#define ETH_P_DNA_DL    0x6001         /* DEC DNA Dump/Load            */

#define ETH_P_DNA_RC    0x6002         /* DEC DNA Remote Console       */

#define ETH_P_DNA_RT    0x6003         /* DEC DNA Routing              */

#define ETH_P_LAT       0x6004         /* DEC LAT                      */

#define ETH_P_DIAG      0x6005         /* DEC Diagnostics              */

#define ETH_P_CUST      0x6006         /* DEC Customer use             */

#define ETH_P_SCA       0x6007         /* DEC Systems Comms Arch       */
/* 交换以太网桥 */
#define ETH_P_TEB 0x6558     /* Trans Ether Bridging     */
/*  */
#define ETH_P_RARP      0x8035      /* Reverse Addr Res packet  */

#define ETH_P_ATALK  0x809B    /* Appletalk DDP     */
/* 以太网帧包 */
#define ETH_P_AARP   0x80F3    /* Appletalk AARP    */

#define ETH_P_8021Q  0x8100         /* 802.1Q VLAN Extended Header  */

#define ETH_P_IPX 0x8137     /* IPX over DIX          */

#define ETH_P_IPV6   0x86DD    /* IPv6 over bluebook       */

#define ETH_P_PAUSE  0x8808    /* IEEE Pause frames. See 802.3 31B */

#define ETH_P_SLOW   0x8809    /* Slow Protocol. See 802.3ad 43B */

#define ETH_P_WCCP   0x883E    /* Web-cache coordination protocol

                   * defined in draft-wilson-wrec-wccp-v2-00.txt*/

#define ETH_P_PPP_DISC   0x8863    /* PPPoE discovery messages     */

#define ETH_P_PPP_SES    0x8864    /* PPPoE session messages   */

#define ETH_P_MPLS_UC    0x8847    /* MPLS Unicast traffic     */

#define ETH_P_MPLS_MC    0x8848    /* MPLS Multicast traffic   */

#define ETH_P_ATMMPOA    0x884c    /* MultiProtocol Over ATM   */

#define ETH_P_ATMFATE    0x8884    /* Frame-based ATM Transport

                   * over Ethernet

                   */

#define ETH_P_PAE 0x888E     /* Port Access Entity (IEEE 802.1X) */

#define ETH_P_AOE 0x88A2     /* ATA over Ethernet     */

#define ETH_P_TIPC   0x88CA    /* TIPC           */

#define ETH_P_1588   0x88F7    /* IEEE 1588 Timesync */

#define ETH_P_FCOE   0x8906    /* Fibre Channel over Ethernet  */

#define ETH_P_TDLS   0x890D    /* TDLS */

#define ETH_P_FIP 0x8914     /* FCoE Initialization Protocol */

#define ETH_P_EDSA   0xDADA    /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID] */

#define ETH_P_AF_IUCV   0xFBFB     /* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]*/
```

### 3.2 iphdr

描述ip头部

```c
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD) /* 小端 */

    __u8 ihl:4,

    version:4;

#elif defined (__BIG_ENDIAN_BITFIELD) /* 大端 */

    __u8 version:4, /* 版本号 */
    ihl:4; /* 首部长度 */

#else

#error "Please fix<asm/byteorder.h>"

#endif
    /* 基本操作 */
    __u8   tos;             /* 首部长度 */
    __be16 tot_len;         /* 总长度 */
    __be16 id;              /* 编号 */
    __be16 frag_off;        /* 片偏移 */
    __u8   ttl;             /* 生存时间 */
    __u8   protocol;        /* 协议 */
    __sum16    check;       /* 首部校验和 */
    __be32 saddr;           /* 源地址 */
    __be32 daddr;           /* 目的地址 */
    /*The options start here. */

};
```

![IP头部示例](https://img-blog.csdn.net/20161121094548351?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

### 4.1 内核协议栈分层结构

Physical device hardware : 指的实实在在的物理设备。    对应physical layer

Device agnostic interface : 设备无关层。                                对应Link layer

Network protocols            :  网络层。                                        对应Ip layer 和 transportlayer

Protocol agnostic interface: 协议无关层                                  适配系统调用层，屏蔽了协议的细节

System callinterface:系统调用层     提供给应用层的系统调用，屏蔽了socket操作的细节

BSD socket：  BSD Socket层           提供统一socket操作的接口， socket结构关系紧密

Inet socket:      inet socket 层          调用ip层协议的统一接口，sock结构关系紧密

### 4.2 msgdhr
描述了从应用层传递下来的消息格式，包含有用户空间地址，消息标记等重要信息。

```c
struct msghdr {
    /* 消息名称 */ 
    void   *msg_name; /* Socket name           */
    /* 消息长度 */
    int    msg_namelen; /* Length of name    */
    /* 数据块指针；主要是用户地址空间的起始地址 */
    struct iovec*    msg_iov;  /* Data blocks           */
    /* 数据块大小 */
    __kernel_size_t   msg_iovlen;  /* Number of blocks      */
    /* 消息控制指针 */
    void   *   msg_control; /* Per protocolmagic (eg BSD file descriptor passing) */
    /* 控制头部长度 */
    __kernel_size_t   msg_controllen;  /* Length of cmsglist */

    unsigned   msg_flags;

};
```

### 4.3 iovec

描述了用户地址空间的起始位置

```c
struct iovec {
    void __user*iov_base;  /* BSD uses caddr_t(1003.1g requires void *) */
    __kernel_size_t iov_len;/* Must be size_t(1003.1g) */
};
```

### 4.4 file

文件描述符

```c
struct file {

    /*

     * fu_list becomes invalid after file_free iscalled and queued via

     * fu_rcuhead for RCU freeing

     */

    union {

       struct list_head  fu_list;

       struct rcu_head   fu_rcuhead;

    } f_u;

    struct path       f_path;

#define f_dentry  f_path.dentry

#define f_vfsmnt  f_path.mnt

    const struct file_operations   *f_op;

    spinlock_t    f_lock; /* f_ep_links,f_flags, no IRQ */

    atomic_long_t     f_count;

    unsigned int      f_flags;

    fmode_t           f_mode;

    loff_t        f_pos;

    struct fown_struct   f_owner;

    const struct cred *f_cred;

    struct file_ra_state f_ra;

 

    u64        f_version;

#ifdef CONFIG_SECURITY

    void          *f_security;

#endif

    /* needed for tty driver, and maybeothers */

   void        *private_data;

 

#ifdef CONFIG_EPOLL

    /* Used by fs/eventpoll.c to link allthe hooks to this file */

    struct list_head  f_ep_links;

#endif /*#ifdef CONFIG_EPOLL */

    struct address_space*f_mapping;

#ifdef CONFIG_DEBUG_WRITECOUNT

    unsigned long f_mnt_write_state;

#endif

};
```

### 4.5 file_operations

文件操作相关结构体，包括read()，write(),open()，ioctl()等

```c
structfile_operations {

    struct module *owner;

    loff_t (*llseek)(struct file*, loff_t,int);

    ssize_t (*read) (struct file*,char __user*,size_t, loff_t*);

    ssize_t (*write) (struct file*,constchar __user*,size_t, loff_t*);

    ssize_t (*aio_read)(struct kiocb*, const struct iovec *,unsignedlong, loff_t);

    ssize_t (*aio_write)(struct kiocb*, const struct iovec *,unsignedlong, loff_t);

    int (*readdir)(struct file*,void*, filldir_t);

    unsigned int (*poll)(struct file*,struct poll_table_struct *);

    int (*ioctl) (struct inode*,struct file*,unsignedint,unsignedlong);

    long (*unlocked_ioctl)(struct file*, unsigned int,unsignedlong);

    long (*compat_ioctl)(struct file*, unsigned int,unsignedlong);

    int (*mmap)(struct file*,struct vm_area_struct *);

    int (*open) (struct inode*,struct file*);

    int (*flush)(struct file*, fl_owner_t id);

    int (*release)(struct inode*,struct file *);

    int (*fsync)(struct file*,struct dentry *,int datasync);

    int (*aio_fsync)(struct kiocb*, int datasync);

    int (*fasync)(int,struct file *,int);

    int (*lock)(struct file*,int,struct file_lock *);

    ssize_t (*sendpage)(struct file*, struct page *, int, size_t, loff_t *,int);

    unsigned long (*get_unmapped_area)(struct file*,unsignedlong,unsignedlong,unsignedlong,unsignedlong);

    int (*check_flags)(int);

    int (*flock)(struct file*,int,struct file_lock *);

    ssize_t (*splice_write)(struct pipe_inode_info*,struct file *, loff_t*,size_t,unsignedint);

    ssize_t (*splice_read)(struct file*, loff_t *,struct pipe_inode_info*,size_t,unsignedint);

    int (*setlease)(struct file*,long,struct file_lock **);

};
```

### 4.6 socket 

向应用层提供的BSD socket 操作结构体，协议无关，主要用作，应用层提供统一的socket操作。

```c
/**

 * struct socket - general BSD socket

 * @state: socket state (%SS_CONNECTED, etc)

 * @type: socket type (%SOCK_STREAM, etc)

 * @flags: socket flags (%SOCK_ASYNC_NOSPACE, etc)

 *  @ops:protocol specific socket operations

 * @fasync_list: Asynchronous wake up list

 * @file: File back pointer for gc

 *  @sk:internal networking protocol agnostic socket representation

 * @wait: wait queue for several uses

 */

struct socket {

   socket_state    state;

 

    kmemcheck_bitfield_begin(type);

    short         type;

    kmemcheck_bitfield_end(type);

 

    unsigned long     flags;

    /*

     * Please keep fasync_list & wait fields inthe same cache line

     */

    struct fasync_struct*fasync_list;

    wait_queue_head_t wait;

 

    struct file    *file;

   struct sock    *sk;

   const struct proto_ops   *ops;

};

 
/* 错误类枚举 */
typedef enum {

    SS_FREE = 0,         /* not allocated     */

    SS_UNCONNECTED,         /* unconnected to any socket    */

    SS_CONNECTING,          /* in process of connecting */

    SS_CONNECTED,       /* connected to socket      */

    SS_DISCONNECTING     /* in process of disconnecting  */

} socket_state;
```

### 4.7 sock

网络层sock（可理解为C++基类），定义与协议无关操作,是网络层的统一的结构，传输层在此基础上实现了inet_sock（可理解为C++派生类）。

```c
/**

  * structsock - network layer representation of sockets

  * @__sk_common:shared layout with inet_timewait_sock

  * @sk_shutdown:mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN

  * @sk_userlocks:%SO_SNDBUF and %SO_RCVBUF settings

  * @sk_lock:  synchronizer

  * @sk_rcvbuf:size of receive buffer in bytes

  * @sk_sleep:sock wait queue

  * @sk_dst_cache:destination cache

  * @sk_dst_lock:destination cache lock

  * @sk_policy:flow policy

  * @sk_rmem_alloc:receive queue bytes committed

  * @sk_receive_queue:incoming packets

  * @sk_wmem_alloc:transmit queue bytes committed

  * @sk_write_queue:Packet sending queue

  * @sk_async_wait_queue:DMA copied packets

  * @sk_omem_alloc:"o" is "option" or "other"

  * @sk_wmem_queued:persistent queue size

  * @sk_forward_alloc:space allocated forward

  * @sk_allocation:allocation mode

  * @sk_sndbuf:size of send buffer in bytes

  * @sk_flags:%SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE,

  *        %SO_OOBINLINE settings, %SO_TIMESTAMPINGsettings

  * @sk_no_check:%SO_NO_CHECK setting, wether or not checkup packets

  * @sk_route_caps:route capabilities (e.g. %NETIF_F_TSO)

  * @sk_gso_type:GSO type (e.g. %SKB_GSO_TCPV4)

  * @sk_gso_max_size:Maximum GSO segment size to build

  * @sk_lingertime:%SO_LINGER l_linger setting

  * @sk_backlog:always used with the per-socket spinlock held

  * @sk_callback_lock:used with the callbacks in the end of this struct

  * @sk_error_queue:rarely used

  * @sk_prot_creator:sk_prot of original sock creator (see ipv6_setsockopt,

  *          IPV6_ADDRFORM for instance)

  * @sk_err:last error

  * @sk_err_soft:errors that don't cause failure but are the cause of a

  *           persistent failure not just 'timed out'

  * @sk_drops:raw/udp drops counter

  * @sk_ack_backlog:current listen backlog

  * @sk_max_ack_backlog:listen backlog set in listen()

  * @sk_priority:%SO_PRIORITY setting

  * @sk_type:socket type (%SOCK_STREAM, etc)

  * @sk_protocol:which protocol this socket belongs in this network family

  * @sk_peercred:%SO_PEERCRED setting

  * @sk_rcvlowat:%SO_RCVLOWAT setting

  * @sk_rcvtimeo:%SO_RCVTIMEO setting

  * @sk_sndtimeo:%SO_SNDTIMEO setting

  * @sk_filter:socket filtering instructions

  * @sk_protinfo:private area, net family specific, when not using slab

  * @sk_timer:sock cleanup timer

  * @sk_stamp:time stamp of last packet received

  * @sk_socket:Identd and reporting IO signals

  * @sk_user_data:RPC layer private data

  * @sk_sndmsg_page:cached page for sendmsg

  * @sk_sndmsg_off:cached offset for sendmsg

  * @sk_send_head:front of stuff to transmit

  * @sk_security:used by security modules

  * @sk_mark:generic packet mark

  * @sk_write_pending:a write to stream socket waits to start

  * @sk_state_change:callback to indicate change in the state of the sock

  * @sk_data_ready:callback to indicate there is data to be processed

  * @sk_write_space:callback to indicate there is bf sending space available

  * @sk_error_report:callback to indicate errors (e.g. %MSG_ERRQUEUE)

  * @sk_backlog_rcv:callback to process the backlog

  * @sk_destruct:called at sock freeing time, i.e. when all refcnt == 0

 */
/* 套接字基础定义 */
struct sock {

    /*

     * Now struct inet_timewait_sock also usessock_common, so please just

     * don't add nothing before this first member(__sk_common) --acme

     */

    struct sock_common   __sk_common;

#define sk_node          __sk_common.skc_node

#define sk_nulls_node       __sk_common.skc_nulls_node

#define sk_refcnt    __sk_common.skc_refcnt

 

#define sk_copy_start       __sk_common.skc_hash

#define sk_hash          __sk_common.skc_hash

#define sk_family    __sk_common.skc_family

#define sk_state     __sk_common.skc_state

#define sk_reuse     __sk_common.skc_reuse

#define sk_bound_dev_if     __sk_common.skc_bound_dev_if

#define sk_bind_node     __sk_common.skc_bind_node

#definesk_prot          __sk_common.skc_prot

#define sk_net           __sk_common.skc_net

    kmemcheck_bitfield_begin(flags);

    unsigned int      sk_shutdown  : 2,

              sk_no_check  :2,

              sk_userlocks :4,

              sk_protocol  :8,

              sk_type      :16;

    kmemcheck_bitfield_end(flags);

    int        sk_rcvbuf;

    socket_lock_t     sk_lock;

    /*

     * The backlog queue is special, it is alwaysused with

     * the per-socket spinlock held and requireslow latency

     * access. Therefore we special case it'simplementation.

     */

    struct {

       struct sk_buff *head;

       struct sk_buff *tail;

    } sk_backlog;

    wait_queue_head_t *sk_sleep;

    struct dst_entry  *sk_dst_cache;

#ifdef CONFIG_XFRM

    struct xfrm_policy  *sk_policy[2];

#endif

    rwlock_t      sk_dst_lock;

    atomic_t       sk_rmem_alloc;

    atomic_t      sk_wmem_alloc;

    atomic_t      sk_omem_alloc;

    int        sk_sndbuf;

    struct sk_buff_head  sk_receive_queue;

    struct sk_buff_head  sk_write_queue;

#ifdef CONFIG_NET_DMA

    struct sk_buff_head  sk_async_wait_queue;

#endif

    int        sk_wmem_queued;

    int        sk_forward_alloc;

    gfp_t         sk_allocation;

    int        sk_route_caps;

    int        sk_gso_type;

    unsigned int      sk_gso_max_size;

    int        sk_rcvlowat;

    unsigned long     sk_flags;

    unsigned long        sk_lingertime;

    struct sk_buff_head  sk_error_queue;

    struct proto      *sk_prot_creator;

    rwlock_t      sk_callback_lock;

    int        sk_err,

              sk_err_soft;

    atomic_t      sk_drops;

    unsigned short       sk_ack_backlog;

    unsigned short       sk_max_ack_backlog;

    __u32         sk_priority;

    struct ucred      sk_peercred;

    long          sk_rcvtimeo;

    long          sk_sndtimeo;

    struct sk_filter     *sk_filter;

    void          *sk_protinfo;

    struct timer_list sk_timer;

    ktime_t           sk_stamp;

    struct socket     *sk_socket;

    void          *sk_user_data;

    struct page       *sk_sndmsg_page;

    struct sk_buff      *sk_send_head;

    __u32         sk_sndmsg_off;

    int        sk_write_pending;

#ifdef CONFIG_SECURITY

    void          *sk_security;

#endif

    __u32         sk_mark;

    u32        sk_classid;

    void          (*sk_state_change)(struct sock*sk);

    void          (*sk_data_ready)(struct sock*sk,int bytes);

    void          (*sk_write_space)(struct sock*sk);

    void          (*sk_error_report)(struct sock*sk);
    int        (*sk_backlog_rcv)(struct sock*sk,

                       struct sk_buff*skb); 
    void                   (*sk_destruct)(struct sock*sk);

};


```

### 4.8 sock_common

最小网络层表示结构体

```c
struct sock_common {

    /*

     * first fields are not copied in sock_copy()

     */

    union {

       struct hlist_node skc_node;

       struct hlist_nulls_node skc_nulls_node;

    };

    atomic_t      skc_refcnt;

    unsigned int      skc_hash;

    unsigned short       skc_family;

    volatile unsigned char   skc_state;

    unsigned char     skc_reuse;

    int        skc_bound_dev_if;

    struct hlist_node skc_bind_node;

    struct proto     *skc_prot;

#ifdef CONFIG_NET_NS
    struct net    *skc_net;
#endif

};
```

### 4.9 inet_sock

Inet_sock表示层结构体，在sock上做的扩展，用于在网络层之上表示inet协议族的的传输层公共结构体。

```
/* 以太网sock结构体 */
struct inet_sock {

    /* sk and pinet6 has to be the firsttwo members of inet_sock */

    struct sock       sk;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)

    struct ipv6_pinfo *pinet6;

#endif

    /* Socket demultiplex comparisons onincoming packets. */

    __be32        daddr;

    __be32        rcv_saddr;

    __be16        dport;

    __u16         num;

    __be32        saddr;
    __s16         uc_ttl;
    __u16         cmsg_flags;
    struct ip_options *opt;
    __be16        sport;

    __u16         id;

    __u8          tos;

    __u8          mc_ttl;

    __u8          pmtudisc;

    __u8          recverr:1,

              is_icsk:1,

              freebind:1,

              hdrincl:1,

              mc_loop:1,

              transparent:1,

              mc_all:1;

    int        mc_index;

    __be32        mc_addr;

    struct ip_mc_socklist   *mc_list;
    struct {

       unsigned int      flags;

       unsigned int      fragsize;

       struct ip_options*opt;

       struct dst_entry *dst;

       int        length;/* Total length ofall frames */

       __be32        addr;

       struct flowi      fl;

    } cork;

};

```

### 4.10 udp_sock

传输层UDP协议专用sock结构，在传输层inet_sock上扩展

```c
structudp_sock {

    /* inet_sock has to be the firstmember */

    struct inet_sock inet;

    int    pending; /* Any pending frames ? */

    unsigned int  corkflag; /* Cork is required*/

    __u16      encap_type; /* Is this anEncapsulation socket? */

    /*

     * Following member retains the information tocreate a UDP header

     * when the socket is uncorked.

     */

    __u16      len;     /* total length ofpending frames */

    /*

     * Fields specific to UDP-Lite.

     */

    __u16      pcslen;

    __u16      pcrlen;

/* indicator bits used by pcflag: */

#define UDPLITE_BIT      0x1        /* set by udpliteproto init function */

#define UDPLITE_SEND_CC  0x2       /* set via udplitesetsockopt         */

#define UDPLITE_RECV_CC  0x4   /* set via udplite setsocktopt        */

    __u8       pcflag;       /* marks socket asUDP-Lite if > 0    */

    __u8       unused[3];

    /*

     * For encapsulation sockets.

     */

    int (*encap_rcv)(struct sock*sk,struct sk_buff *skb);

};
```

### 4.11 proto_ops

socket 层到inet_sock层主要接口，用户socket 结构操作

```c
struct proto {
	void          (*close)(struct sock*sk,
	                  long timeout);
	int        (*connect)(struct sock*sk,
	                      struct sockaddr*uaddr,
	                  int addr_len);
	int        (*disconnect)(struct sock*sk,int flags);
	struct sock *     (*accept)(struct sock*sk,int flags,int*err);
	int        (*ioctl)(struct sock*sk,int cmd,
	                   unsignedlong arg);
	int        (*init)(struct sock*sk);
	void          (*destroy)(struct sock*sk);
	void          (*shutdown)(struct sock*sk,int how);
	int        (*setsockopt)(struct sock*sk,int level,
	                  int optname,char __user*optval,
	                  unsignedint optlen);
	int        (*getsockopt)(struct sock*sk,int level,
	                  int optname,char __user*optval,
	                  int __user*option);
	#ifdef CONFIG_COMPAT
	    int        (*compat_setsockopt)(struct sock*sk,
	                  int level,
	                  int optname,char __user*optval,
	                  unsignedint optlen);
	int        (*compat_getsockopt)(struct sock*sk,
	                  int level,
	                  int optname,char __user*optval,
	                  int __user*option);
	#endif
	    int        (*sendmsg)(struct kiocb*iocb,struct sock *sk,
	                     struct msghdr*msg, size_t len);
	int        (*recvmsg)(struct kiocb*iocb,struct sock *sk,
	                     struct msghdr*msg,
	                  size_t len,int noblock,int flags,
	                  int *addr_len);
	int        (*sendpage)(struct sock*sk,struct page *page,
	                  int offset, size_t size,int flags);
	int        (*bind)(struct sock*sk,
	                  struct sockaddr*uaddr,int addr_len);
	int        (*backlog_rcv)(struct sock*sk,
	                     struct sk_buff*skb);
	/* Keeping track of sk's, lookingthem up, and port selection methods. */
	void          (*hash)(struct sock*sk);
	void          (*unhash)(struct sock*sk);
	int        (*get_port)(struct sock*sk,unsignedshort snum);
	/* Keeping track of sockets in use */
	#ifdef CONFIG_PROC_FS
	    unsigned int      inuse_idx;
	#endif
	/* Memory pressure */
	void          (*enter_memory_pressure)(struct sock*sk);
	atomic_t      *memory_allocated;
	/* Current allocated memory. */
	struct percpu_counter   *sockets_allocated;
	/* Current number ofsockets. */
	/*
     * Pressure flag: try to collapse.
     * Technical note: it is used by multiplecontexts non atomically.
     * All the __sk_mem_schedule() is of thisnature: accounting
     * is strict, actions are advisory and havesome latency.
     */
	int        *memory_pressure;
	int        *sysctl_mem;
	int        *sysctl_wmem;
	int        *sysctl_rmem;
	int        max_header;
	struct kmem_cache *slab;
	unsigned int      obj_size;
	int        slab_flags;
	struct percpu_counter   *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops*twsk_prot;
	union {
		struct inet_hashinfo*hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
	}
	h;
	struct module     *owner;
	char          name[32];
	struct list_head  node;
	#ifdef SOCK_REFCNT_DEBUG
	    atomic_t      socks;
	#endif
};
```

### 4.13 net_proto_family

用于标识和注册协议族，常见的协议有ipv4,ipv6
协议族；用于完成某些特定功能的协议集合

```c
struct net_proto_family {
    // 协议族定义
    int    family;
    // 创建协议族
    int    (*create)(struct net*net,struct socket *sock,
                int protocol,int kern);
    // 所有人
    struct module *owner;
};
```

### 4.14 softnet_data

内核为每个CPU都分配一个这样的softnet_data数据空间；每个CPU都有一个这样的队列，用于接收数据包。

```c
/*

 * Incoming packets are placed onper-cpu queues so that

 * no locking is needed.

 */

struct softnet_data {
    /* 输出队列 */
    struct Qdisc      *output_queue;
    /* poll队列 */
    struct list_head  poll_list;
    /* socket 缓冲buffer */
    struct sk_buff      *completion_queue;

    /* Elements below can be accessedbetween CPUs for RPS */
    /* cpu回调函数 */
    struct call_single_data  csd ____cacheline_aligned_in_smp;
    /* 输入队列头部 */
    unsigned int            input_queue_head;
    /* socket缓冲区头部 */
    struct sk_buff_head  input_pkt_queue;
    /* napi数据结构体 */
    struct napi_struct   backlog;
};

```
![NAPI机制](https://www.jianshu.com/p/7d4e36c0abe8)
```c
/*
 * Structure for NAPI scheduling similar to tasklet but with weighting
 */
struct napi_struct {
    /* The poll_list must only be managed by the entity which
     * changes the state of the NAPI_STATE_SCHED bit.  This means
     * whoever atomically sets that bit can add this napi_struct
     * to the per-CPU poll_list, and whoever clears that bit
     * can remove from the list right before clearing the bit.
     */
    struct list_head    poll_list;

    unsigned long       state;//设备状态
    int         weight; //每次轮询最大处理数据包数量
    unsigned int        gro_count;
    int         (*poll)(struct napi_struct *, int);//轮询设备的回调函数
#ifdef CONFIG_NETPOLL
    int         poll_owner;
#endif
    struct net_device   *dev;
    struct sk_buff      *gro_list;
    struct sk_buff      *skb;
    struct hrtimer      timer;
    struct list_head    dev_list;
    struct hlist_node   napi_hash_node;
    unsigned int        napi_id;
};
```

### 4.15 sk_buff

描述一个帧结构的属性，持有socket，到达时间，到达设备，各层头部大小，下一站路由入口，帧长度，校验和，等等。([Linux内核：sk_buff解析](https://www.cnblogs.com/tzh36/p/5424564.html))

Packet data：通过网卡收发的报文，包括链路层、网络层、传输层的协议头和携带的应用数据，包括head room,data,tail room三部分。

skb_shared_info 作为packet data的补充，用于存储ip分片，其中sk_buff *frag_list是一系列子skbuff链表，而frag[]是由一组单独的page组成的数据缓冲区。

Data buffer：用于存储packet data的缓冲区，分为以上两部分。

Sk_buff：缓冲区控制结构sk_buff。

整个sk_buff结构图如图1。

![sk_buff组成](https://images2015.cnblogs.com/blog/941007/201604/941007-20160423142020366-1506677960.gif)

```c
/* struct sk_buff - socket buffer */
struct sk_buff {
	/* These two members must be first. */
	struct sk_buff         *next;
	struct sk_buff         *prev;
	struct sock             *sk;
	struct skb_timeval  tstamp;
	/* Time we arrived，记录接收或发送报文的时间戳 */
	struct net_device    *dev;
	/* 通过该设备接收或发送，记录网络接口的信息和完成操作 */
    struct net_device    *input_dev; /* 接收数据的网络设备 */
    struct net_device    *curlayer_input_dev;
    struct net_device    *l2tp_input_dev;
    union {
        struct tcphdr   *th;
        struct udphdr  *uh;
        struct icmphdr*icmph;
        struct igmphdr       *igmph;
        struct iphdr     *ipiph;
        struct ipv6hdr*ipv6h;
        unsigned char  *raw;
    } h; //传输层报头
    union {
        struct iphdr        *iph;
        struct ipv6hdr      *ipv6h;
        struct arphdr       *arph;
        unsigned char       *raw;
    } nh; //网络层报头
    union {
        unsigned char       *raw;
    } mac; //链路层报头
    unsigned int           len, //len缓冲区中数据部分的长度。
    data_len, //data_len只计算分片中数据的长度
    mac_len, //mac头的长度
    csum; //校验和
    __u32            priority;
    __u8              local_df:1,
    cloned:1, //表示该结构是另一个sk_buff克隆的
    ip_summed:2,
    nohdr:1,
    nfctinfo:3;
    __u8              pkt_type:3,
    fclone:2,
    ipvs_property:1;
    __be16                  protocol;
    __u32 flag; /*packet flags*/
	.
	.
	.
	/* These elements must be at the end, see alloc_skb() for details.  */
	unsigned int           truesize;
	//这是缓冲区的总长度，包括sk_buff结构和数据部分
	atomic_t         users;
	unsigned char         *head, //指向缓冲区的头部
	*data,// 指向实际数据的头部
	*tail, //指向实际数据的尾部
	*end;
	//指向缓冲区的尾部
};
```

### 4.16 sk_buff_head

数据包队列

```c
struct sk_buff_head {

    /* These two members must be first.*/
    struct sk_buff    *next;
    struct sk_buff    *prev;
    /* 队列长度 */
    __u32      qlen;
    /* 自旋锁 */
    spinlock_t lock;
};
```
### 4.17 net_device 

描述网络设备的所有属性，数据等信息；[网络设备之net_device结构与操作](https://www.cnblogs.com/wanpengcoder/p/7526116.html)

```c
struct net_device {
    /* 设备名称，如eth0 */
    char            name[IFNAMSIZ];
    /* 名称hash */
    struct hlist_node    name_hlist;
    char             *ifalias;
    /*
     *    I/O specific fields
     *    FIXME: Merge these and struct ifmap into one
     */
    /*
        描述设备所用的共享内存，用于设备与内核沟通
        其初始化和访问只会在设备驱动程序内进行
    */
    unsigned long        mem_end;
    unsigned long        mem_start;

    /* 设备自有内存映射到I/O内存的起始地址 */
    unsigned long        base_addr;

    /*
        设备与内核对话的中断编号，此值可由多个设备共享
        驱动程序使用request_irq函数分配此变量，使用free_irq予以释放
    */
    int            irq;

    /* 侦测网络状态的改变次数 */
    atomic_t        carrier_changes;

    /*
     *    Some hardware also needs these fields (state,dev_list,
     *    napi_list,unreg_list,close_list) but they are not
     *    part of the usual set specified in Space.c.
     */

    /*
     *  网络队列子系统使用的一组标识
     *  由__LINK_STATE_xxx标识
     */
    unsigned long        state;

    struct list_head    dev_list;
    struct list_head    napi_list;
    struct list_head    unreg_list;
    struct list_head    close_list;

    /* 当前设备所有协议的链表 */
    struct list_head    ptype_all;
    /* 当前设备特定协议的链表 */
    struct list_head    ptype_specific;

    struct {
        struct list_head upper;
        struct list_head lower;
    } adj_list;

    /*
        用于存在其他一些设备功能
        可报告适配卡的功能，以便与CPU通信
        使用NETIF_F_XXX标识功能特性
    */
    netdev_features_t    features;
    netdev_features_t    hw_features;
    netdev_features_t    wanted_features;
    netdev_features_t    vlan_features;
    netdev_features_t    hw_enc_features;
    netdev_features_t    mpls_features;
    netdev_features_t    gso_partial_features;

    /* 网络设备索引号 */
    int            ifindex;

    /* 设备组，默认都属于0组 */
    int            group;

    struct net_device_stats    stats;

    atomic_long_t        rx_dropped;
    atomic_long_t        tx_dropped;
    atomic_long_t        rx_nohandler;

#ifdef CONFIG_WIRELESS_EXT
    const struct iw_handler_def *wireless_handlers;
    struct iw_public_data    *wireless_data;
#endif
    /* 设备操作接口 */
    const struct net_device_ops *netdev_ops;
    /* ethtool操作接口 */
    const struct ethtool_ops *ethtool_ops;
#ifdef CONFIG_NET_SWITCHDEV
    const struct switchdev_ops *switchdev_ops;
#endif
#ifdef CONFIG_NET_L3_MASTER_DEV
    const struct l3mdev_ops    *l3mdev_ops;
#endif
#if IS_ENABLED(CONFIG_IPV6)
    const struct ndisc_ops *ndisc_ops;
#endif

#ifdef CONFIG_XFRM
    const struct xfrmdev_ops *xfrmdev_ops;
#endif

    /* 头部一些操作，如链路层缓存，校验等 */
    const struct header_ops *header_ops;

    /* 标识接口特性，IFF_XXX，如IFF_UP */
    unsigned int        flags;

    /*
        用于存储用户空间不可见的标识
        由VLAN和Bridge虚拟设备使用
    */
    unsigned int        priv_flags;

    /* 几乎不使用，为了兼容保留 */
    unsigned short        gflags;

    /* 结构对齐填充 */
    unsigned short        padded;

    /* 与interface group mib中的IfOperStatus相关 */
    unsigned char        operstate;
    unsigned char        link_mode;

    /*
        接口使用的端口类型
    */
    unsigned char        if_port;

    /*
        设备使用的DMA通道
        并非所有设备都可以用DMA，有些总线不支持DMA
    */
    unsigned char        dma;

    /*
        最大传输单元，标识设备能处理帧的最大尺寸
        Ethernet-1500
    */
    unsigned int        mtu;
    /* 最小mtu，Ethernet-68 */
    unsigned int        min_mtu;
    /* 最大mut，Ethernet-65535 */
    unsigned int        max_mtu;

    /*     设备所属类型
        ARP模块中，用type判断接口的硬件地址类型
        以太网接口为ARPHRD_ETHER
    */
    unsigned short        type;
    /*
        设备头部长度
        Ethernet报头是ETH_HLEN=14字节
    */
    unsigned short        hard_header_len;
    unsigned char        min_header_len;

    /* 必须的头部空间 */
    unsigned short        needed_headroom;
    unsigned short        needed_tailroom;

    /* Interface address info. */
    /* 硬件地址，通常在初始化过程中从硬件读取 */
    unsigned char        perm_addr[MAX_ADDR_LEN];
    unsigned char        addr_assign_type;
    /* 硬件地址长度 */
    unsigned char        addr_len;
    unsigned short        neigh_priv_len;
    unsigned short          dev_id;
    unsigned short          dev_port;
    spinlock_t        addr_list_lock;
    /* 设备名赋值类型，如NET_NAME_UNKNOWN */
    unsigned char        name_assign_type;
    bool            uc_promisc;
    struct netdev_hw_addr_list    uc;
    struct netdev_hw_addr_list    mc;
    struct netdev_hw_addr_list    dev_addrs;

#ifdef CONFIG_SYSFS
    struct kset        *queues_kset;
#endif
    /* 混杂模式开启数量 */
    unsigned int        promiscuity;

    /* 非零值时，设备监听所有多播地址 */
    unsigned int        allmulti;


    /* Protocol-specific pointers */
/* 特定协议的指针 */
#if IS_ENABLED(CONFIG_VLAN_8021Q)
    struct vlan_info __rcu    *vlan_info;
#endif
#if IS_ENABLED(CONFIG_NET_DSA)
    struct dsa_switch_tree    *dsa_ptr;
#endif
#if IS_ENABLED(CONFIG_TIPC)
    struct tipc_bearer __rcu *tipc_ptr;
#endif
    void             *atalk_ptr;
    /* ip指向in_device结构 */
    struct in_device __rcu    *ip_ptr;
    struct dn_dev __rcu     *dn_ptr;
    struct inet6_dev __rcu    *ip6_ptr;
    void            *ax25_ptr;
    struct wireless_dev    *ieee80211_ptr;
    struct wpan_dev        *ieee802154_ptr;
#if IS_ENABLED(CONFIG_MPLS_ROUTING)
    struct mpls_dev __rcu    *mpls_ptr;
#endif

/*
 * Cache lines mostly used on receive path (including eth_type_trans())
 */
    /* Interface address info used in eth_type_trans() */
    unsigned char        *dev_addr;

#ifdef CONFIG_SYSFS
    /* 接收队列 */
    struct netdev_rx_queue    *_rx;

    /* 接收队列数 */
    unsigned int        num_rx_queues;
    unsigned int        real_num_rx_queues;
#endif

    struct bpf_prog __rcu    *xdp_prog;
    unsigned long        gro_flush_timeout;

    /* 如网桥等的收包回调 */
    rx_handler_func_t __rcu    *rx_handler;
    /* 回调参数 */
    void __rcu        *rx_handler_data;

#ifdef CONFIG_NET_CLS_ACT
    struct tcf_proto __rcu  *ingress_cl_list;
#endif
    struct netdev_queue __rcu *ingress_queue;
#ifdef CONFIG_NETFILTER_INGRESS
    /* netfilter入口 */
    struct nf_hook_entry __rcu *nf_hooks_ingress;
#endif

    /* 链路层广播地址 */
    unsigned char        broadcast[MAX_ADDR_LEN];
#ifdef CONFIG_RFS_ACCEL
    struct cpu_rmap        *rx_cpu_rmap;
#endif
    /* 接口索引hash */
    struct hlist_node    index_hlist;

/*
 * Cache lines mostly used on transmit path
 */
     /* 发送队列 */
    struct netdev_queue    *_tx ____cacheline_aligned_in_smp;
    /* 发送队列数 */
    unsigned int        num_tx_queues;
    unsigned int        real_num_tx_queues;
    /* 排队规则 */
    struct Qdisc        *qdisc;
#ifdef CONFIG_NET_SCHED
    DECLARE_HASHTABLE    (qdisc_hash, 4);
#endif
    /*
        可在设备发送队列中排队的最大数据包数
    */
    unsigned long        tx_queue_len;
    spinlock_t        tx_global_lock;

    /*     网络层确定传输超时，
        调用驱动程序tx_timeout接口的最短时间
    */
    int            watchdog_timeo;

#ifdef CONFIG_XPS
    struct xps_dev_maps __rcu *xps_maps;
#endif
#ifdef CONFIG_NET_CLS_ACT
    struct tcf_proto __rcu  *egress_cl_list;
#endif

    /* These may be needed for future network-power-down code. */
    /* watchdog定时器 */
    struct timer_list    watchdog_timer;

    /* 引用计数 */
    int __percpu        *pcpu_refcnt;

    /*     网络设备的注册和除名以两步进行，
        该字段用于处理第二步
    */
    struct list_head    todo_list;

    struct list_head    link_watch_list;

    /* 设备的注册状态 */
    enum { NETREG_UNINITIALIZED=0,
           NETREG_REGISTERED,    /* completed register_netdevice */
           NETREG_UNREGISTERING,    /* called unregister_netdevice */
           NETREG_UNREGISTERED,    /* completed unregister todo */
           NETREG_RELEASED,        /* called free_netdev */
           NETREG_DUMMY,        /* dummy device for NAPI poll */
    } reg_state:8;

    /* 设备要被释放标记 */
    bool dismantle;

    enum {
        RTNL_LINK_INITIALIZED,
        RTNL_LINK_INITIALIZING,
    } rtnl_link_state:16;

    bool needs_free_netdev;
    void (*priv_destructor)(struct net_device *dev);

#ifdef CONFIG_NETPOLL
    struct netpoll_info __rcu    *npinfo;
#endif

    possible_net_t            nd_net;

    /* mid-layer private */
    union {
        void                    *ml_priv;
        struct pcpu_lstats __percpu        *lstats;
        struct pcpu_sw_netstats __percpu    *tstats;
        struct pcpu_dstats __percpu        *dstats;
        struct pcpu_vstats __percpu        *vstats;
    };

#if IS_ENABLED(CONFIG_GARP)
    struct garp_port __rcu    *garp_port;
#endif
#if IS_ENABLED(CONFIG_MRP)
    struct mrp_port __rcu    *mrp_port;
#endif

    struct device        dev;
    const struct attribute_group *sysfs_groups[4];
    const struct attribute_group *sysfs_rx_queue_group;

    const struct rtnl_link_ops *rtnl_link_ops;

    /* for setting kernel sock attribute on TCP connection setup */
#define GSO_MAX_SIZE        65536
    unsigned int        gso_max_size;
#define GSO_MAX_SEGS        65535
    u16            gso_max_segs;

#ifdef CONFIG_DCB
    const struct dcbnl_rtnl_ops *dcbnl_ops;
#endif
    u8            num_tc;
    struct netdev_tc_txq    tc_to_txq[TC_MAX_QUEUE];
    u8            prio_tc_map[TC_BITMASK + 1];

#if IS_ENABLED(CONFIG_FCOE)
    unsigned int        fcoe_ddp_xid;
#endif
#if IS_ENABLED(CONFIG_CGROUP_NET_PRIO)
    struct netprio_map __rcu *priomap;
#endif
    struct phy_device    *phydev;
    struct lock_class_key    *qdisc_tx_busylock;
    struct lock_class_key    *qdisc_running_key;
    bool            proto_down;
};
```

