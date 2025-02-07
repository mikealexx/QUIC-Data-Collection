# QUIC Data Collection and Preparation

This repository provides a pipeline for capturing, converting, and preparing QUIC traffic data for machine learning or further analysis. It automates the process of extracting QUIC packets, filtering useful information, and generating images from network traces in three major steps:
1) Create traces by issuing requests to webpages and capturing the traffic using tshark.
2) Convert the `PCAP` files to `CSV` flles and filter the packets containing QUIC traffic.
3) Prepare the image dataset - create `PNG` files from the `CSV` files.

## **Installation**

### **1. Install `wget`**
Ensure `wget` is installed to download Chrome:
```bash
sudo update && sudo apt upgrade
sudo apt install wget
```

### **2. Install Google Chrome**
Download and install Google Chrome:
```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```

Verify that Chrome is installed:
```bash
google-chrome --version
```

Set the following alias for the chrome command:
```bash
alias chrome="google-chrome"
```

### **3. Install TShark**
TShark is required for packet capture. Install it using:
```bash
sudo apt install tshark
```

### **4. Clone the Repository**
Clone the repository and `cd` into it:
```bash
git clone https://github.com/mikealexx/QUIC-Data-Collection.git
cd QUIC-Data-Collection
```

### **5. Set Up a Virtual Environment (Recommended)**
Using a virtual environment is a good practice to keep dependencies isolated:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### **6. Install Python Dependencies**
Install all required Python packages from `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## **Usage**
After downloading the repository, you can either **run the steps manually** or **use a bash script** to automate the pipeline.

### **Automated Execution using a Bash Script**
Instead of running each step manually, you can use a Bash script.

#### **Step 1: Edit the Script File to Modify it**
```bash
nano run_pipeline.sh
```

#### **Step 2: Modify the Script**
Edit `run_pipeline.sh` to include your preferred settings and directories.
```bash
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
```

#### **Step 3: Execute the Script**
Give execution permission and run the script:
```bash
chmod +x run_pipeline.sh
./run_pipeline.sh
```

This will **automate the full pipeline** from traffic capture to image generation.

---

### **Manual Execution**
#### **Step 1: Capture QUIC Traffic**
Run the `capture.py` script to capture network traffic:
```bash
python3 capture-handlers/capture.py -i [network interface] \
                                    -l [links directory] \
                                    -o [output directory] \
                                    -n [number of requests per link] \
                                    -x [index prefix for traces]
```
The parameters are as follows:
- `-i (--interface)` Is the used network interface that will be used.
- `-l (--links-dir)` Is the path to the directory containing the `links.txt` files. The directory will should contain sub-directories for each website and in each website's sub-directory the `links.txt` file will be stored.
- `-o (--output-dir)` Is the path to the directory where the raw data will be stored.
- `-n (--requests_num)` The number of requests to send to each link.
- `-x (--index)` The number to add as a prefix to the trace number. Default value is 0.

**Example:**
```bash
python3 capture-handlers/capture.py -i eth0 -l /links -o /raw_data -n 10 -x 0
```

#### **Step 2: Convert Raw Captured Data**
Convert the raw captured `.pcap` files into a structured format:
```bash
python3 capture-handlers/convert.py -d [raw data directory]
```
The parameters are as follows:
- `-d (--data-dir)` The path to the directory containing the captured data from the previous step.

**Example:**
```bash
python3 capture-handlers/convert.py -d /raw_data
```

#### **Step 3: Prepare the Data for Analysis**
Process the converted data and generate PNG images:
```bash
python3 capture-handlers/prepare.py -d [raw data directory] -o [output directory]
```
The parameters are as follows:
- `-d (--data-dir)` The path to the directory containing the captured data from the previous steps.
- `-o (--output-dir)` The path to the directory where the `PNG` files will be stored.

**Example:**
```bash
python3 capture-handlers/prepare.py -d /raw_data -o /processed_images
```

---

## **Conclusion**
This pipeline provides an efficient way to collect, process, and visualize QUIC network traffic data. Whether you run it manually or automate it via a script, it simplifies the workflow for QUIC data analysis.

For any issues or questions, feel free to open an issue in the repository! 🚀
