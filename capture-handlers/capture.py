import argparse, logging, os, subprocess, signal
from time import sleep

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def start_tshark(interface, pcap_filename):
    command = f'tshark -i {interface} -w {pcap_filename} -Y "quic"'
    return subprocess.Popen(command, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

def stop_tshark(tshark):
    os.killpg(os.getpgid(tshark.pid), signal.SIGTERM)

def get_links(links_dir):
    websites = {}
    
    for root, dirs, files in os.walk(links_dir):
        if 'links.txt' in files:
            last_dir = os.path.basename(root)
            file_path = os.path.join(root, 'links.txt')
            with open(file_path, 'r', encoding='utf-8') as file:
                links = [line.strip() for line in file if line.strip()]
                if links:
                    websites[last_dir] = links
    
    return websites

def capture(interface, website, link, output_dir, request_index):
    link = link.replace('/', '_')
    website_dir = os.path.join(output_dir, f'{website}')
    link_dir = os.path.join(website_dir, f'{link}')
    os.makedirs(link_dir, exist_ok=True)
    filename = os.path.join(link_dir, f'{link}_{request_index}')
    json_filename = f'{filename}.json'
    pcap_filename = f'{filename}.pcap'

    request = f"SSLKEYLOGFILE={filename}.key google-chrome --no-sandbox " \
              "--headless " \
              "--autoplay-policy=no-user-gesture-required " \
              "--dump-dom " \
              "--disable-gpu " \
              "--enable-logging " \
              "--enable-quic " \
              "--disable-application-cache " \
              "--incognito " \
              "--new-window " \
              "--v=3 " \
              f"--log-net-log={json_filename} " \
              f"{link} " \
              f"> /dev/null " \
              f"2> /dev/null"
    
    # create ssl key log file
    subprocess.run(f'touch {filename}.key', shell=True, executable='/bin/bash')

    # start tshark
    logger.info(f'Starting tshark on {interface}')
    tshark = start_tshark(interface, pcap_filename)
    sleep(5)

    # start request
    logger.info(f'Starting request {request_index} to {link}')
    try:
        p = subprocess.run(request, shell=True, executable='/bin/bash', timeout=1200)

    except subprocess.TimeoutExpired:
        logger.error(f'Request {request_index} to {link} timed out')

    logger.info(f'Request {request_index} to {link} completed')
    sleep(5)

    # stop tshark
    logger.info(f'Stopping tshark on {interface}')
    stop_tshark(tshark)



def main(args):
    interface = args.interface
    links_dir = args.links_dir
    output_dir = args.output_dir
    requests_number = args.requests_number

    websites = get_links(links_dir)
    os.makedirs(f'{output_dir}', exist_ok=True)
    
    for i in range(requests_number):
        for website, links in websites.items():
            os.makedirs(os.path.join(output_dir, f'{website}'), exist_ok=True)
            for link in links:
                capture(interface, website, link, output_dir, i)  

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Capture QUIC packets')
    parser.add_argument('--interface', type=str, help='Interface to capture packets on', default='eth0')
    parser.add_argument('--links-dir', type=str, help='Path to the directory containing the links', required=True)
    parser.add_argument('--output-dir', type=str, help='Path to the directory to store the captured packets', required=True)
    parser.add_argument('--requests-number', type=int, help='Number of requests to capture for each link', default=100)

    args = parser.parse_args()
    main(args)