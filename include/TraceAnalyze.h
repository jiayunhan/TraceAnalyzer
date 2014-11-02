/*
 * TraceAnalyze.h
 *
 * Created by: Qi Alfred Chen, 1/07/2013
 *
 */
#ifndef _TRACEANALYZE_H
#define _TRACEANALYZE_H

#include "stl.h"
#include "pcap.h"
#include "basic.h"
#include "io.h"
#include "tcp_ip.h"
#include "context.h"
#include "DNSops.h"
#include "tcpflowstat.h"

class TraceAnalyze {
private:
    int pktcnt;
    int newInFile;
    vector<struct DNSQueryComb*> dnsquery;

public:

    vector<struct TCPFlowStat*> tcpflows;
    vector<struct DNSQueryComb*> ansdnsquery;
    TraceAnalyze();
    void setNewInFile(int nv);
    void bswapIP(ip* ip);
    void bswapTCP(tcphdr* tcphdr);
    void bswapUDP(udphdr* udphdr);
    void bswapIPv6(struct ip6_hdr* ip6);
    void bswapDNS(struct DNS_HEADER* dnshdr);
    void feedTracePacket(Context ctx, const struct pcap_pkthdr *header, const u_char *pkt_data);

};

#endif /* _TRACEANALYZE_H */
