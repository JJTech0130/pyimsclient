#!/bin/bash
sudo python3 swu_emulator.py \
    --imsi=310280197204423 \
    --dest=107.122.31.81 \
    --modem=http://10.118.55.211:8080 \
    -M 310 -N 280 \
    -a ims 
