import argparse, os, subprocess, signal, logging
from time import sleep

logging.basicConfig(level=logging.INFO)



def get_links(links_dir):
    '''
    Get all links from the links directory

    Args:
        links_dir: path to the directory containing links (can contain subdirectories)

    Returns:
        links: dictionary containing links for each website
    '''
    links = {}
    for root, dirs, files in os.walk(links_dir):
        for dir in dirs:
            links_file = links_dir + f'/{dir}/links.txt'
            with open(links_file, 'r') as f:
                links_read = f.readlines()
                links[dir] = [link.strip() for link in links_read]
    return links



def create_website_dir(root_dir, link):
    '''
    Creates a directory for a given website inside the data directory

    Args:
        root_dir: data directory
        link: website to create directory for

    Returns:
        path: path to the created directory
    '''
    print("----------------------------------------------")
    logging.info(f"Creating directory for {link}")
    print("----------------------------------------------")
    path = os.getcwd() + f'/{root_dir}/{link}'
    if not os.path.exists(path):
        os.makedirs(path)
    return path



def create_link_dir(website_dir, link):
    '''
    Creates a directory for a given link inside the website directory

    Args:
        website_dir: website directory
        link: link to create directory for

    Returns:
        path: path to the created directory
    '''
    path = website_dir + f'/{link}'
    if not os.path.exists(path):
        os.makedirs(path)
    return path



def run_tshark(interface, output_file):
    '''
    Runs tshark to capture packets

    Args:
        interface: interface to capture packets from
        output_file: file to store captured packets

    Returns:
        process: tshark process
    '''
    command = f'tshark -i {interface} -w {output_file}'
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    return process



def kill_tshark(process):
    '''
    Kills the tshark process

    Args:
        process: process to kill

    Returns:
        None
    '''
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    sleep(3)
    subprocess.run('pkill -15 -f tshark', shell=True, executable='/bin/bash')



def capture(interface, website_dir, request_id, link, index):
    '''
    Capture packets for a given link and save them in the website directory

    Args:
        interface: interface to capture packets from
        website_dir: directory to store captured data
        request_id: id of the request
        link: link to capture packets from
        index: index of the request

    Returns:
        None
    '''
    logging.info(f"Capturing {link} - {request_id}")
    link_dir_name = link.replace('/', '_')
    link_dir = create_link_dir(website_dir, link_dir_name)
    filename = link_dir + f'{os.path.sep}{link_dir_name}-{index}{request_id}'
    json_file = f'{filename}.json'
    pcap_file = f'{filename}.pcap'

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
              f"--log-net-log={json_file} " \
              f"{link} " \
              f"> /dev/null " \
              f"2> /dev/null"
    
    subprocess.run(f'touch {filename}.key', shell=True, executable='/bin/bash', )
    tshark_process = run_tshark(interface, f'{pcap_file}')
    sleep(5)
    try:
        p = subprocess.run(request, shell=True, executable='/bin/bash', timeout=1200)

    except subprocess.TimeoutExpired:
        print("Timeout")

    sleep(5)
    kill_tshark(tshark_process)



def main(args):
    '''
    Main function to capture packets

    Args:
        args: command line arguments

    Returns:
        None
    '''
    interface = args.interface
    links_dir = args.links_dir
    output_dir = args.output_dir
    requests_num = args.requests_num
    index = args.index

    links = get_links(links_dir)
    links = {k: v for k, v in links.items() if len(v) > 0}
    for i in range(requests_num):
        for website in links:
            website_dir = create_website_dir(output_dir, website)
            print("==============================================")
            for link in links[website]:
                capture(interface, website_dir, i, link, index)
                print("==============================================")



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Capture packets')
    parser.add_argument('--interface', '-i', type=str, help='interface to capture packets from', required=True)
    parser.add_argument('--links-dir', '-l', type=str, help='path to directory containing links', required=True)
    parser.add_argument('--output-dir', '-o', type=str, help='output directory to store captured data', required=True)
    parser.add_argument('--requests-num', '-n', type=int, help='number of requests to capture per link', required=True)
    parser.add_argument('--index', '-x', type=int, help='index of the request', default=0)
    args = parser.parse_args()
    main(args)