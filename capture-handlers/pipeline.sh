#!/bin/bash

########## Settings ##########
export INTERFACE=eth0 # Change this to your network interface
export REQUESTS_NUM=3 # Number of requests to capture per link
export INDEX=1 # The number to add as a prefix to the trace number
##############################

######## Directories #########
export CWD=$(pwd)
export LINKS_DIR=links # Path to the links directory
export DATA_DIR=data # Path to the directory where the raw data will be stored
export OUTPUT_DIR=output # Path to the directory where the processed data will be stored (png files)
##############################

# Capture the data
python $CWD/capture-handlers/capture.py -i $INTERFACE -l $LINKS_DIR -o $DATA_DIR -n $REQUESTS_NUM -x $INDEX

# Convert pcap to csv
python $CWD/capture-handlers/convert.py -d $DATA_DIR

# Prepare the data and generate png files
python $CWD/capture-handlers/prepare.py -d $DATA_DIR -o $OUTPUT_DIR