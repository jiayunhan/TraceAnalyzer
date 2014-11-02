#ifndef _PACO_PACKET_ANALYZER_H
#define _PACO_PACKET_ANALYZER_H

#include "stl.h"
#include "pcap.h"
#include "basic.h"
#include "io.h"
#include "tcp_ip.h"
#include "context.h"
#include "TraceAnalyze.h"

class PacketAnalyzer {
private:
	vector<string> mTraceList;
	Context mTraceCtx;
    string mTraceListFileName;
	string getFolder(string s);
	void configTraceList();
public:
	TraceAnalyze mTraceAnalyze;
	PacketAnalyzer();

    void init();
	void checkSystem();
	void clearConfig();
	void setTraceListFileName(string fn);
	void addTrace(string tracename);
	Context getContext();
	string getTraceListFileName();
	void run();
	void dh(u_char *c, const struct pcap_pkthdr *header, const u_char *pkt_data);

};


#endif /* _PACO_PACKET_ANALYZER_H */
