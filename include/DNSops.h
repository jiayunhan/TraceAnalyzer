#ifndef DNSOPS_H_INCLUDED
#define DNSOPS_H_INCLUDED

#include "TraceAnalyze.h"

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Structure of a Query
struct QUERY
{
	unsigned char *name;
	struct QUESTION *ques;
};

#define MAXURLNUM 10
struct DNSQueryComb{
    double ts;
    unsigned short trxid;
    char* urls[MAXURLNUM];
    int urlsnum;

    DNSQueryComb(){
        ts=0;
        trxid=0;
        urlsnum=0;
    }
    int deleteurl(struct DNSQueryComb* known, struct DNSQueryComb* &ans){
        int deletesth=0;
        for (int i=0;i<known->urlsnum;i++){
          int j=0;
          for (;j<urlsnum && strcmp(known->urls[i],urls[j])!=0;j++);
          if (j<urlsnum){
            ans->urls[ans->urlsnum++]=urls[j];

            for (int k=j+1;k<urlsnum;k++)
              urls[k-1]=urls[k];
            urlsnum--;
            deletesth=1;
          }
        }
        return deletesth;
    }
};


void getQueryString(char* querystr, int querynum, struct DNSQueryComb* newq);

#endif // DNSOPS_H_INCLUDED
