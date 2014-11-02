
#include "packet_analyzer.h"

void dispatcher_handler(u_char *c, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  //  cout<<"in dispatcher_handler\n";
  PacketAnalyzer* analyzer = (PacketAnalyzer *) c;
  (analyzer->mTraceAnalyze).feedTracePacket(analyzer->getContext(), header, pkt_data);
}

PacketAnalyzer::PacketAnalyzer() {
}

void PacketAnalyzer::checkSystem() {
	int xx = -1;
#if BYTE_ORDER == LITTLE_ENDIAN
	xx = 0;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	xx = 1;
#endif
	switch (xx) {
		case 0:
			cout << "BYTE_ORDER LITTLE_ENDIAN" << endl;
			break;
		case 1:
			cout << "BYTE_ORDER BIG_ENDIAN" << endl;
			break;
		default:
			cout << "BYTE_ORDER NOT BIG NOT SMALL" << endl;
			break;
	}

	//test uint64
	cout << "Length of uint64 should be 8: " << sizeof(uint64) << endl;
}

void PacketAnalyzer::init(){
    checkSystem();
}

void PacketAnalyzer::configTraceList() {
	ifstream trace_list(mTraceListFileName.c_str());
	string s;
	while (getline(trace_list, s)) {
		mTraceList.push_back(s);
	}
}

void PacketAnalyzer::clearConfig(){
    mTraceListFileName="";
    mTraceList.clear();
}

void PacketAnalyzer::setTraceListFileName(string fn){
    mTraceListFileName=fn;
    configTraceList();
}

void PacketAnalyzer::addTrace(string tracename){
    mTraceList.push_back(tracename);
}

string PacketAnalyzer::getTraceListFileName(){
    return mTraceListFileName;
}

Context PacketAnalyzer::getContext(){
    return mTraceCtx;
}

string PacketAnalyzer::getFolder(string s) {
	int pos = s.rfind("/");
	return s.substr(0, pos+1);
}

void PacketAnalyzer::run() {
	// read packet
	char errbuf[PCAP_ERRBUF_SIZE];
	vector<string>::iterator it;
	pcap_t *trace_file;

	string curr_folder, tmp_folder, tmp_s;
	int trace_count = 0;
	for (it = mTraceList.begin(); it != mTraceList.end(); it++) {

	    mTraceAnalyze.setNewInFile(1);

		if (trace_count % 1000 == 0) {
			cout << trace_count << " files processed." << endl;
		}

		// open pcap file successfully?
		if ((trace_file = pcap_open_offline(it->c_str(), errbuf)) == NULL) {
			cout << " Unable to open the file: " << *it << endl;
			//continue;
		}



		// read application map
		/*tmp_folder = getFolder(*it);
		tmp_folder += "appname";
		if (tmp_folder.compare(curr_folder) != 0) {
			curr_folder = tmp_folder;
			cout << "Folder Name: " << curr_folder << endl;
			mTraceCtx.clearAppNameMap();

			ifstream appNameFile(tmp_folder.c_str());
			while (getline(appNameFile, tmp_s)) {
				mTraceCtx.addAppName(tmp_s);
			}
		}*/


		// pcap link layer header length

		if (pcap_datalink(trace_file) == DLT_LINUX_SLL) {
			mTraceCtx.setEtherLen(16);
		} else {
			mTraceCtx.setEtherLen(14);
		}

		cout << "Pcap trace Ethernet header length: " << mTraceCtx.getEtherLen() << endl;

		/* read and dispatch packets until EOF is reached */
		pcap_loop(trace_file, 0, dispatcher_handler, (u_char*)this);
		pcap_close(trace_file);
		trace_count++;
	}
}
