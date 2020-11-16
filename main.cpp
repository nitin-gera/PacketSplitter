#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <errno.h>

using namespace std;

void ProcessPacket(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
//void PrintData (unsigned char* , int);

int sock_raw;
int data_size;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;


int to_esi_flag=0;
int udp_sock;
int inputPort,outputPort;
char *inputIp, *outputIp , *outputInterface, *inputInterface;



struct sockaddr_in their_addr,local_addr;
char to_esi_buffer[]="Hello India";

int main(int argc, char *argv[])
{

    inputPort = -1;
    outputPort = -1;
    inputIp = NULL;
    outputIp = NULL;
    outputInterface = NULL;
    inputInterface = NULL;
    
    //printf("\n argc %d",argc);

    if (argc != 7)
    {

         printf("\n All argc are not provided : I/P port , O/P port , O/P ip, I/P interface, O/P interface \n\n");
	 exit(1); 
    }
	
    int i = 1;
    inputPort = atoi(argv[i++]);
    outputPort = atoi(argv[i++]);
    inputIp = argv[i++];
    outputIp = argv[i++];
    inputInterface = argv[i++];
    outputInterface = argv[i++];
         
   
    printf("\n I/P port=(%d),O/P port=(%d),\n I/P ip=(%s),O/P ip=(%s),\n I/P interface=(%s),O/P interface=(%s)\n",inputPort,outputPort,inputIp,outputIp,inputInterface,outputInterface);    
   

    socklen_t saddr_size;
    
    struct sockaddr saddr;
    int z;
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    printf("Starting...\n");

    //Create a raw socket that shall sniff
    sock_raw = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));
    if(sock_raw < 0)
    {
        printf("socket() failed with error %d, ('%s')\n", errno, strerror(errno));
        return 1;
    }

//    z = setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, "ens4f1", strlen("ens4f1") + 1);	
    z = setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, inputInterface, strlen(inputInterface) + 1);
    printf("\nInput sockect Env: setsockopt = (%d) -- (-1:Failure 0:Successful)\n",z);


    if ((udp_sock=socket(AF_INET, SOCK_DGRAM, 0))==-1)
    {
        printf(" error in opening sending socket to esi/tdm\n");
        exit(0);
    }

    //z=setsockopt(udp_sock, SOL_SOCKET, SO_BINDTODEVICE, "eno1", strlen("eno1") + 1);
    z=setsockopt(udp_sock, SOL_SOCKET, SO_BINDTODEVICE, outputInterface, strlen(outputInterface) + 1);
    printf("\nOutput sockect Env: setsockopt =(%d) -- (-1:Failure 0:Successful) \n",z);

    memset((char *) &local_addr, 0, sizeof(local_addr));
    memset((char *) &their_addr, 0, sizeof(their_addr));

    local_addr.sin_family = AF_INET;
    //local_addr.sin_port = htons(21284);// source port no. is irrelevant here
    local_addr.sin_port = htons(inputPort);

    local_addr.sin_addr.s_addr = INADDR_ANY;
    if ( local_addr.sin_addr.s_addr == INADDR_NONE )
    {
        printf("Bad address LOCKON\n");
        exit(1);
    }

    if(bind(udp_sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1)
    {
            printf("\n Error in binding socket for Input\n");
    }

    their_addr.sin_family = AF_INET; // host byte order
    //their_addr.sin_port = htons(21286); // short, network byte order
    their_addr.sin_port = htons(outputPort); // short, network byte order

    //their_addr.sin_addr.s_addr = inet_addr("230.1.1.15");
    their_addr.sin_addr.s_addr = inet_addr(outputIp);

    while(1)
    {
         saddr_size = sizeof(saddr);

        //Receive a packet

        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("\n Recvfrom error , failed to get packets\n");
            return 1;
        }
        else
        {
            //printf("\ndatasize (%d)\n",data_size);
        }
    
        ProcessPacket(buffer , data_size);
    }

    printf("Finished");
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
            break;

        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;
        case 41:
            abort();
        default:
            ++others;
            break;
    }
    printf("TCP:(%d)  UDP:(%d)  ICMP:(%d)  IGMP:(%d)  Others:(%d)  Total:(%d) Datasize:(%d) \r",tcp,udp,icmp,igmp,others,total,data_size);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    //struct ethhdr *ethdr = (struct ethhdr *)Buffer;
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    Size -= sizeof(struct ethhdr);


    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
}


void print_udp_packet(unsigned char *Buffer , int Size)
{
    int numbytes;
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    Size -= sizeof(struct ethhdr);
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + sizeof(struct ethhdr) + iphdrlen);

//    fprintf(logfile,"\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    if( (ntohs(udph->dest)==inputPort) && (!strcmp(inet_ntoa(dest.sin_addr),inputIp)))
//    if( (ntohs(udph->dest)==21288) && (!strcmp(inet_ntoa(dest.sin_addr),"192.1.1.20")))
    {
        to_esi_flag=1;

        printf("\n Reached Here");
        if ((numbytes=sendto(udp_sock,(Buffer + sizeof(struct ethhdr) + iphdrlen + sizeof udph ) ,( Size - sizeof udph - iph->ihl * 4 ), 0,(struct sockaddr *)&their_addr, sizeof(struct sockaddr))) == -1)
        {
            printf("send to esi error");
            exit(1);
        }
        else
        {
            printf("\nsent bytes : (%d) \n",numbytes);
        }
    }
    else
    {
        to_esi_flag=0;
    }

}
