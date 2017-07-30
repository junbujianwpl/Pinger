#include "Pinger.h"

unsigned int Pinger::m_uiCnt__=0;

Pinger::Pinger()
{
    WSADATA data;
    char tips[256]={0};
    sprintf(tips,"wsa init ret %d,errCode:%d.\n",WSAStartup(MAKEWORD(1,1),&data),WSAGetLastError());
    m_strTips_+=tips;
    m_uiId__=m_uiCnt__++;
}

Pinger::~Pinger()
{
    WSACleanup();
}

int Pinger::ping(char *dstIP, int packNum, int sndTime, int rcvTime)
{
    int nRet=0;
    m_strTips_+="ping tips.\n";
    char tips[256]={0};
    SOCKET sockRaw=INVALID_SOCKET;
    struct sockaddr_in  dest,from;
    unsigned short seq_no=0;

    int bread,datasize;
    int fromlen=sizeof(from);
    char icmp_data[1024]={0};
    char rcvbuf[1024]={0};
    unsigned int addr = inet_addr(dstIP);
    int timeout=sndTime;

    if(INADDR_NONE ==addr){
        m_strTips_+=strcat("invalid dstip,",dstIP);
        return EnInvalidIp;
    }

    sockRaw=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(INVALID_SOCKET == sockRaw){
        sprintf(tips,"create sock failed,errcode:%d\n",WSAGetLastError());
        m_strTips_+=tips;
        return EnSockErr;
    }

    //set send time-out val
    bread = setsockopt(sockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(timeout));
    sprintf(tips,"set send time-out %d,ret:%d,errCode:%d.",timeout,bread,WSAGetLastError());
    m_strTips_+=tips;

    //set recv time-out val
    timeout=rcvTime;
    bread = setsockopt(sockRaw,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
    sprintf(tips,"set recv time-out %d,ret:%d,errCode:%d.",timeout,bread,WSAGetLastError());
    m_strTips_+=tips;

    memset(&dest,0,sizeof(dest));
    dest.sin_addr.s_addr=addr;
    dest.sin_family= AF_INET;
    datasize=DEF_PACKET_SIZE+sizeof(IcmpHead);
    fillImcpData(icmp_data,datasize);

    for(;packNum>0;packNum--){
        ((IcmpHead*)icmp_data)->ulTimeStamp=GetTickCount();
        ((IcmpHead*)icmp_data)->usSeq=seq_no++;
        ((IcmpHead*)icmp_data)->ususIcmpChkSum=checkSum((WORD*)icmp_data,datasize);

        int bwrote = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,sizeof(dest));
        sprintf(tips,"send,ret:%d,sndErrCode:%d,",bwrote,WSAGetLastError());
        m_strTips_+=tips;

        bread = recvfrom(sockRaw,rcvbuf,sizeof(rcvbuf),0,(struct sockaddr*)&from,&fromlen);
        sprintf(tips,"recv,ret:%d,rcvErrCode:%d.\n",bwrote,WSAGetLastError());
        m_strTips_+=tips;

        if(bread>0){
            decodeIcmpHead(rcvbuf,bread,&from);
            nRet++;
        }
        Sleep(10);
    }

    if(INVALID_SOCKET != sockRaw){
        int clsRet= closesocket(sockRaw);
        sprintf(tips,"close sock:%u,ret:%d,errCode:%d\n",sockRaw,clsRet,WSAGetLastError());
        m_strTips_+=tips;
    }

    return nRet;
}

unsigned short Pinger::checkSum(WORD *buf, int wordCnt)
{
    WORD wChkSum=0;
    for(;wordCnt>0;wordCnt--){
        wChkSum+=*buf++;
    }
    wChkSum=(wChkSum>>16)+(wChkSum & 0xffff);
    wChkSum+=(wChkSum>>16);

    return (WORD)(~wChkSum);
}

int Pinger::decodeIcmpHead(char *rcvBuf, unsigned int bread, sockaddr_in *from)
{
    if(NULL == rcvBuf || NULL == from){
        m_strTips_+="decode imcp head encounter null ptr.\n";
        return EnNullPtr;
    }

    char tips[256]={0};
    IpHead *ipHead=(IpHead*)rcvBuf;
    IcmpHead *icmpHead=NULL;
    WORD  wIpHeadLen=ipHead->uiHeadLen*4;

    if(bread<(wIpHeadLen+ICMP_MIN)){
        sprintf(tips,"too few bytes from %s\n",inet_ntoa((from->sin_addr)));
        m_strTips_+=tips;
        return EnBadData;
    }

    icmpHead=(IcmpHead*)(rcvBuf+wIpHeadLen);

    if(icmpHead->ucType != ICMP_ECHOREPLY){
        sprintf(tips,"no echo tpye %d rcved.\n",int(icmpHead->ucType));
        m_strTips_+=tips;
    }

    if(icmpHead->usIcmpId != m_uiId__){
        sprintf(tips,"some one's pack. realId:%u,myId:%u.\n",icmpHead->usIcmpId,m_uiId__);
        m_strTips_+=tips;
    }

    sprintf(tips,"reply from %s, %u bytes, time:%u ms, seq:%d.\n",inet_ntoa(from->sin_addr),
            bread-wIpHeadLen,GetTickCount()-icmpHead->ulTimeStamp,icmpHead->usSeq);
    m_strTips_+=tips;

    return 0;
}

void Pinger::fillImcpData(char *icmpData, int byteCnt)
{
    if(NULL == icmpData){
        m_strTips_+="fill icmp data encounter null ptr.\n";
        return;
    }

    IcmpHead *icmpHead=(IcmpHead*)icmpData;
    char* dataPart=NULL;
    icmpHead->ucType=ICMP_ECHO;
    icmpHead->ucCode=0;
    icmpHead->ususIcmpChkSum=0;
    icmpHead->usIcmpId=m_uiId__;
    dataPart=icmpData+sizeof(icmpHead);
    memset(dataPart,0,byteCnt-sizeof(IcmpHead));

}
