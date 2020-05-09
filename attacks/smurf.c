// https://stackoverflow.com/questions/13620607/creating-ip-network-packets

/* send icmp packet example */
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <linux/ip.h>
#include <linux/icmp.h>

unsigned short in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


int main(int argc, char* argv[]) {

    if (argc != 4) printf("usage: ./send_ping <dest ip> <source_ip> <number of packets to send>\n"), exit(1);

    struct iphdr *ip, *ip_reply;
    struct icmphdr* icmp;
    struct sockaddr_in connection;
    char *dst_addr = argv[1];
    char *src_addr = argv[2];
    char *packet, *buffer;
    int sockfd, optval, addrlen;
    int i, n = atoi(argv[3]);

    // printf("dest: %s, src: %s\n", dst_addr, src_addr); exit(0);

    packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr)); // create packet (which contains IP and ICMP header)
    buffer = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr)); 
    ip = (struct iphdr*) packet; // points to IP header
    icmp = (struct icmphdr*) (packet + sizeof(struct iphdr)); // points to the ICMP packet

    ip->ihl         = 5;  // size of the header; it's just 5
    ip->version     = 4;  // IPv4
    ip->tot_len     = sizeof(struct iphdr) + sizeof(struct icmphdr); // length of the ip header and icmp header combined
    ip->protocol    = IPPROTO_ICMP; // use ICMP
    ip->saddr       = inet_addr(src_addr); // this is the one that needs to be spoofed
    ip->daddr       = inet_addr(dst_addr); // dest is just an intermediary
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr)); //checksum of JUST IP

    icmp->type      = ICMP_ECHO; // just want to ping
    icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr)); // checksum of JUST icmp

    /* open ICMP socket */
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
     /* IP_HDRINCL must be set on the socket so that the kernel does not attempt 
     *  to automatically add a default ip header to the packet*/
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

    for (i = 0; i < n; i++) {
        connection.sin_family       = AF_INET;
        connection.sin_addr.s_addr  = ip->daddr;
        sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
        printf("Sent %d byte packet to %s\n", ip->tot_len, dst_addr);
        // exit(0);
        // addrlen = sizeof(connection);
        // if (recvfrom(sockfd, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&connection, &addrlen) == -1) perror("recv");
        // else {
        //     char *cp;
        //     ip_reply = (struct iphdr*) buffer;
        //     cp = (char *)&ip_reply->saddr;
        //     printf("Received %d byte reply from %u.%u.%u.%u:\n", ntohs(ip_reply->tot_len), cp[0]&0xff, cp[1]&0xff, cp[2]&0xff, cp[3]&0xff);
        //     printf("ID: %d\n", ntohs(ip_reply->id));
        //     printf("TTL: %d\n", ip_reply->ttl);
        // }
    }
    return 0;
}

