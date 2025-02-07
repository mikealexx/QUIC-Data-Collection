import os, argparse, subprocess, logging

logging.basicConfig(level=logging.INFO)



def find_pcap_files(data_dir):
    '''
    Find all pcap files in the data directory (including subdirectories)

    Args:
        data_dir: path to the directory containing captured data

    Returns:
        pcap_files: list of paths to pcap files
    '''
    pcap_files = []
    for root, dirs, files in os.walk(data_dir):
        for file in files:
            if file.endswith('.pcap'):
                pcap_files.append(os.path.join(root, file))
    return pcap_files



def main(args):
    '''
    Convert pcap files to csv

    Args:
        args: command line arguments

    Returns:
        None
    '''
    pcap_files = find_pcap_files(args.data_dir)
    print("++++++++++++++++++++++++++++++++++++++++++++++")
    logging.info(f"Found {len(pcap_files)} pcap files - converting to csv")
    print("++++++++++++++++++++++++++++++++++++++++++++++")
    parallel_processes = 5
    while len(pcap_files) > 0:
        num_of_files = min(parallel_processes, len(pcap_files))
        logging.info(f"{num_of_files} files left to convert")
        print("----------------------------------------------")
        requests = [f"""tshark -r {file} -R quic -2 -T fields -e frame.number -e frame.time_relative -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e ip.proto -e _ws.col.Info -E header=y -E separator=, -E quote=d -E occurrence=f -o tls.keylog_file:{file.replace('.pcap', '.key')} > {file[:-5]}.csv""" for file in pcap_files[:num_of_files]]
        processes = [subprocess.Popen(request, shell=True, executable='/bin/bash') for request in requests]
        for process in processes:
            process.wait()
        pcap_files = pcap_files[num_of_files:]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert pcap to csv')
    parser.add_argument('--data-dir', "-d", type=str, help='path to directory containing captured data', required=True)
    args = parser.parse_args()
    main(args)