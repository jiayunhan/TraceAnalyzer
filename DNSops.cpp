
#include "DNSops.h"

void getQueryString(char* querystr, int querynum, struct DNSQueryComb* newq){
    char url[1000];
    int i=0;
    for (int qn=0;qn<querynum;qn++){
        int urlind=0;
        while (querystr[i]!=0){
            int sublen=querystr[i++];
            for (int j=0;j<sublen;j++){
               url[urlind++]=querystr[i++];
            }
            url[urlind++]='.';
        }
        url[urlind-1]='\0';
        i++;
    //    printf("%s\n",url);

        char* nu=(char*)malloc(strlen(url)+1);
        strcpy(nu,url);


        newq->urls[newq->urlsnum++]=nu;

        i=i+4;
    }


}


