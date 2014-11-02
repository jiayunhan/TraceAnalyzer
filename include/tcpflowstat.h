/*
 * tcpflow.h
 *
 * Created by: Qi Alfred Chen, 1/07/2013
 *
 */
#ifndef TCP_FLOW_H_INCLUDED
#define TCP_FLOW_H_INCLUDED


#include "basic.h"
#include "TraceAnalyze.h"
#include <arpa/inet.h>

#define TCPCONSTATE_CLOSED 0
#define TCPCONSTATE_SYN_SEND 1
#define TCPCONSTATE_SYN_RECEIVED 2
#define TCPCONSTATE_ESTABLISHED 3
#define TCPCONSTATE_FIN 4

#define SIMUL_SYNACK_NOT_RECEIVED 0
#define SIMUL_SYNACK_RECEIVED 1

#define PKTSENDER_CLT 0
#define PKTSENDER_SVR 1

#define FLOWINITBYCLT 0
#define FLOWINITBYSVR 1

class TCPFlowStat {
public:
    u_int cltip;
    u_int svrip;
    u_short cltport;
    u_short svrport;

    u_int tcpconnstate;
    double syntime, synacktime, acktime;
    double syntosynacktime, synacktoacktime;


    u_int cltseq,cltackseq,svrseq,svrackseq;
    u_int cltinitseq,svrinitseq;

    int simulsyn, simulsynackstate;
    int flowinitby;

    //metrics
    double tcpconnsetuptime;
    int cltretxbytes,svrretxbytes,cltretxnum,svrretxnum;

    TCPFlowStat();
    void swapcltsvr();
    void printStat();
    int isClient(u_int ipaddr);
    char * getStrAddr(u_int ip);
    static int isNewFlow(struct ip* ip, struct tcphdr* tcphdr);
    int getPacketDirection(u_int srcip, u_int dstip, u_short srcport, u_short dstport);
    void addPacket(struct ip* ip, struct tcphdr* tcphdr, double ts);
    int isMyPacket(struct ip* ip, struct tcphdr* tcphdr);

};

#endif // TCP_FLOW_H_INCLUDED
