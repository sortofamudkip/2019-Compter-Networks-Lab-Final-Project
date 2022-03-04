# 2019 Compter Networks Lab Final Project
 
My portion of our team's CNL Final Project: **A Survey on the Efficiency of SDN-based Defense Mechanisms Against Different Types of DDoS Attacks.**

The environment is mininet, using the tree topology depth = 2, fanout = 8 (i.e. 64 switches and 9 switches), with the `--nat` option enabled in order to allow for internet access (for DNS attack). Wireshark is used for debugging purposes.

The controller changes for each defense; the simplest one is the `baseline.py` file.

All of the attack/detection methods come from [**here**](https://www.researchgate.net/publication/313222794_DDoS_Attack_Detection_and_Mitigation_Using_SDN_Methods_Practices_and_Solutions).

I wrote the following parts:
* `attacks/`: two types of DDOS attacks. Mostly done using Scapy.
    * `dns_atk.py`: **DNS attack** (in Python).
    * `smurf.py`: **Smurf attack** (in Python). `smurf.c` is the C version.
 
*  `ryu/`: the controller, which specifies the detection method. 
    *  `baseline.py`, for the **baseline detection method**. A combination of the other `s*.py` files inside. `traffic.txt` contains a sample output of the network activity.
    *  `conrate.py`, for the **connection rate detection method**.

*  `mnet/` and `scripts/`: inside are some simple topologies and simple scripts to start the mininet. These are unused, as the project uses the 64-host tree network in the CLI as shown above.

The `presentation/` directory contains the files used during the presentation.
