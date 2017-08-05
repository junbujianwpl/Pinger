#ifndef PINGER_H
#define PINGER_H

#include <windows.h>
#include <winsock.h>
#include <string>

#pragma pack(push)
#pragma pack(1)

struct IpHead{
    unsigned int    uiHeadLen:4;            ///<头部长度
    unsigned int    uiVersion:4;            ///<版本
    unsigned char   ucTos;                  ///<服务类型,type of service
    unsigned short  usTotalLen;             ///<总长度
    unsigned short  usIpId;                 ///<标识
    unsigned short  usFlags;                ///<3位标志+13位片偏移
    unsigned char   ucTtl;                  ///<TTL,time to live
    unsigned char   ucProtocol;             ///<协议
    unsigned short  usCheckSum;             ///<首部总校验和
    unsigned int    uiSrcIP;                ///<源ip
    unsigned int    uiDstIP;                ///<目的ip
};

struct IcmpHead{
    unsigned char   ucType;                 ///<类型
    unsigned char   ucCode;                 ///<代码
    unsigned short  ususIcmpChkSum;         ///<校验和
    unsigned short  usIcmpId;               ///<id
    unsigned char   usSeq;                  ///<序号
    unsigned long   ulTimeStamp;            ///<时间戳
};

#pragma pack(pop)


#define DEF_PACKET_SIZE     32
#define ECHO_REQUEST        8
#define ECHO_REPLY          0
#define ICMP_ECHOREPLY      0
#define ICMP_MIN            sizeof(IcmpHead)
#define ICMP_ECHO           8

class Pinger
{
public:
    Pinger();
    virtual ~Pinger();

    /**
     * @brief ping          ping指定ip地址
     * @param dstIP         目的ip，不能包含空格等非法字符
     * @param packNum       一共ping几包
     * @param sndTime       发送超时时间，单位毫秒
     * @param rcvTime       接收超时时间，单位毫秒
     * @return              成功ping通的包数，大于0表示ping通
     */
    int ping(const char* dstIP, const int& packNum, const int &sndTime, const int &rcvTime);

    /**
     * @brief getTips       获取提示信息
     * @return              提示信息
     */
    std::string getTips() const {return m_strTips_;}

protected:

    /**
     * @brief checkSum      计算校验和
     * @param buf           待计算缓冲区
     * @param wordCnt       字个数
     * @return              校验和
     */
    unsigned short checkSum(const WORD *buf, const int &wordCnt);

    /**
     * @brief decodeIcmpHead        解析icmp头
     * @param rcvBuf                头部缓冲区
     * @param bread                 字节数
     * @param from                  来源ip地址
     * @return                      0表示正常，其他见错误码EnErrCode
     */
    int decodeIcmpHead(char *rcvBuf,const unsigned int bread,const sockaddr_in *from);

    /**
     * @brief fillImcpData          填充icmp数据
     * @param icmpData              缓冲区
     * @param byteCnt               缓冲区长度
     */
    void fillIcmpData(char *icmpData, const int& byteCnt);

    std::string  m_strTips_;                ///<提示信息

private:
    enum EnErrCode{
        EnOK,
        EnNullPtr=-100,
        EnBadData,
        EnInvalidIp,
        EnSockErr,
    };

    unsigned int m_uiId__;                  ///<当前对象id计数

    static unsigned int m_uiCnt__;          ///<总对象创建数计数

    SOCKET m_sock__;                         ///<套按字
};

#endif // PINGER_H
