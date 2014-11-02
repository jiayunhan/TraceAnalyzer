#include "packet_analyzer.h"
using namespace std;
#define MAX_FILE_ID 1
#include <string>
#include <iostream>
#include <sstream>
PacketAnalyzer analyzer;
void addTracesFromFolderList(string fl){
	string s,num;
	string suffix = ".cap";
	for(int i=0; i<MAX_FILE_ID; i++){
		stringstream ss;
		ss <<(i+1);
		num = ss.str();
		s = fl+num+suffix;
		std::cout<<s<<endl;
		analyzer.addTrace(s);
	}
}


int main() {
//	string traceList("/home/alfred/Project/TMobile/Facebook/tracelist");
//ls -d $PWD/*
	addTracesFromFolderList("/data/eNodeB180/S.42.94.74.180.M.");



//	analyzer.setTraceListFileName(traceList);
	analyzer.init();
	analyzer.run();


	return 0;
}
