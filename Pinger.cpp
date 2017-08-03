#include "Pinger.h"

unsigned int Pinger::m_uiCnt__=0;

Pinger::Pinger()
{
    WSADATA data;
    char tips[256]={0};
    snprintf(tips,sizeof(tips),"wsa init ret %d,errCode:%d.\n",WSAStartup(MAKEWORD(1,2),&data),WSAGetLastError());
    m_strTips_+=tips;
    m_uiId__=m_uiCnt__++;
}

Pinger::~Pinger()
{
    WSACleanup();
}

int Pinger::ping(const char *dstIP, const int& packNum, const int& sndTime, const int& rcvTime)
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
        m_strTips_+="invalid dstip,";
        m_strTips_+=dstIP;
        return EnInvalidIp;
    }

    sockRaw=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(INVALID_SOCKET == sockRaw){
        snprintf(tips,sizeof(tips),"create sock failed,errcode:%d\n",WSAGetLastError());
        m_strTips_+=tips;
        return EnSockErr;
    }

    //set send time-out val
    bread = setsockopt(sockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(timeout));
    snprintf(tips,sizeof(tips),"set send time-out %d,ret:%d,errCode:%d.",timeout,bread,WSAGetLastError());
    m_strTips_+=tips;

    //set recv time-out val
    timeout=rcvTime;
    bread = setsockopt(sockRaw,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
    snprintf(tips,sizeof(tips),"set recv time-out %d,ret:%d,errCode:%d.",timeout,bread,WSAGetLastError());
    m_strTips_+=tips;

    memset(&dest,0,sizeof(dest));
    dest.sin_addr.s_addr=addr;
    dest.sin_family= AF_INET;
    datasize=DEF_PACKET_SIZE+sizeof(IcmpHead);


    m_strTips_+="\n";
    for(int i=packNum;i>0;i--){
        fillIcmpData(icmp_data,datasize);
        ((IcmpHead*)icmp_data)->ulTimeStamp=GetTickCount();
        ((IcmpHead*)icmp_data)->usSeq=seq_no++;
        ((IcmpHead*)icmp_data)->ususIcmpChkSum=checkSum((WORD*)icmp_data,datasize);

        int bwrote = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,sizeof(dest));
        snprintf(tips,sizeof(tips),"send,ret:%d,sndErrCode:%d,",bwrote,WSAGetLastError());
        m_strTips_+=tips;

        bread = recvfrom(sockRaw,rcvbuf,sizeof(rcvbuf),0,(struct sockaddr*)&from,&fromlen);
        snprintf(tips,sizeof(tips),"recv,ret:%d,rcvErrCode:%d.",bread,WSAGetLastError());
        m_strTips_+=tips;

        if(bread>0){
            decodeIcmpHead(rcvbuf,bread,&from);
            nRet++;
        }
        Sleep(20);
        m_strTips_+="\n";
    }

    if(INVALID_SOCKET != sockRaw){
        int clsRet= closesocket(sockRaw);
        snprintf(tips,sizeof(tips),"close sock:%u,ret:%d,errCode:%d\n",sockRaw,clsRet,WSAGetLastError());
        m_strTips_+=tips;
    }

    return nRet;
}

unsigned short Pinger::checkSum(const WORD *buf, const int& wordCnt)
{
    WORD wChkSum=0;
    for(int i = wordCnt;i>0;i--){
        wChkSum+=*buf++;
    }
    wChkSum=(wChkSum>>16)+(wChkSum & 0xffff);
    wChkSum+=(wChkSum>>16);

    return (WORD)(~wChkSum);
}

int Pinger::decodeIcmpHead(char *rcvBuf, const unsigned int bread, const sockaddr_in *from)
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
        snprintf(tips,sizeof(tips),"too few bytes from %s\n",inet_ntoa((from->sin_addr)));
        m_strTips_+=tips;
        return EnBadData;
    }

    icmpHead=(IcmpHead*)(rcvBuf+wIpHeadLen);

    if(icmpHead->ucType != ICMP_ECHOREPLY){
        snprintf(tips,sizeof(tips),"no echo tpye %d rcved.\n",int(icmpHead->ucType));
        m_strTips_+=tips;
    }

    if(icmpHead->usIcmpId != m_uiId__){
        snprintf(tips,sizeof(tips),"some one's pack. realId:%u,myId:%u.\n",icmpHead->usIcmpId,m_uiId__);
        m_strTips_+=tips;
    }

    snprintf(tips,sizeof(tips),"reply from %s, %u bytes, time:%u ms, seq:%d, id:%u.\n",inet_ntoa(from->sin_addr),
            bread-wIpHeadLen,GetTickCount()-icmpHead->ulTimeStamp,icmpHead->usSeq,icmpHead->usIcmpId);
    m_strTips_+=tips;

    return 0;
}

void Pinger::fillIcmpData(char *icmpData, const int &byteCnt)
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
    dataPart=icmpData+sizeof(IcmpHead);
    memset(dataPart,0,byteCnt-sizeof(IcmpHead));

}
