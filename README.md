# P4 Code for probabilistic traffic-burst detection with ALBUS

The following P4 code was used in the paper 'ALBUS: a Probabilistic Monitoring Algorithm to Counter Burst Flood Attacks' by Simon Scherrer, Jo Vliegen, Arish Sateesan, Hsu-Chun Hsiao, Nele Mentens, and Adrian Perrig, published at the International Symposium or Reliable Distributed Systems (SRDS) in 2023.


# Source Code

This repository contains the following source code:

- `albus.p4`: P4 code for the ALBUS flow monitor that runs on the P4-enabled Mininet switch.
- `p4app.json`: Configuration file to set up the Mininet topology on the p4-learning VM.
- `albus_controller.py`: Python code for the controller that interacts with the Mininet switch. This controller performs configuration tasks, which mostly works via rule installation in the match-action tables of the P4 switch. Importantly, the controller also receives the five-tuple of a provably malicious flow from the switch. This five-tuple is then used as the match criterion in a blacklist rule.
- `albus_send.py`/`packet_generator.py`: Scripts to generate traffic for testing and evaluating the project implementation (see below). These scripts have been adapted from Exercise 04 'Count-Min Sketch' of the [p4-learning utilities](https://github.com/nsg-ethz/p4-learning/tree/master/exercises/07-Count-Min-Sketch).

# Environment Setup

This implementation was developed for the p4-utils VM, which can be installed as documented in the corresponding [Wiki](https://nsg-ethz.github.io/p4-utils/installation.html#virtual-machine).

# Running Instructions for CROFT Experiment

1.  Copy the code to the p4-utils VM.
2.  `cd` to the directory with the code.
3.  Start the Mininet CLI with access to the P4-enabled switch using
```
sudo p4run --conf p4app.json
```
4. When Mininet is ready, start up the controller in another terminal:
```
python albus_controller.py
```
5. Run the test with the command below. The command will simulate 100 flows, where there is 1 pulsating flow
sending one pulse per second with overuse ratio 2 and pulse width of 2^18 = 262'144 microseconds (approximately 0.25 seconds).
The experiment will take 2.1 seconds such that the pulsating flow sends two pulses in total.
```
mininet> h1 python3 albus-send.py --n-hh 1 --n-sf 99 --our 2 --intv 0.262144 --len 2.1
```
At some point, the controller will announce that it received flow 
`('44.101.177.245', '155.183.88.74', '55538', '52578', '6')`, which is the pulsating flow (It is also output by `albus_send.sh`).
There is a small probability that the flow is not found in the first try; in that case, the command above should be repeated.

6. Shut down the ALBUS controller using Ctrl-C and the Mininet CLI using Ctrl-D.
