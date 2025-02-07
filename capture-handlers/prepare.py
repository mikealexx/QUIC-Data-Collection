import json, os, argparse, logging
import numpy as np
import pandas as pd
from PIL import Image
from matplotlib import cm
from event_types_list import event_type
from urllib.parse import urlparse


logging.basicConfig(level=logging.INFO)
MAX_PACKET_LENGTH = 1500



def get_hosts_from_domain(json_file):
    """
    return the hosts names from the json_file name.
    """
    domain = json_file.split(os.path.sep)[-1]
    
    # replace _ with / in the domain name
    domain = domain.replace("_", "/")
    domain = urlparse(domain).netloc
    hosts = domain.split(".")
    hosts = hosts[1:-1] if len(hosts) > 2 else hosts[:-1]
    return hosts



def get_quic_connection_ids(json_file):
    """
    go over all the lines in the json file and return a list of the connection_id
    that correspond to events of type QUIC
    """
    print("==============================================")
    logging.info(f"Getting quic connection ids from {json_file}")
    print("----------------------------------------------")
    quic_connection_ids = []
    events_ids = []  # the event_ids of quic sessions that will later be used to find the quic connection ids

    hosts = get_hosts_from_domain(json_file)
    with open(json_file, 'r') as f:
        data = json.load(f)
        for event in data['events']:
            if 'type' in event:
                if 'QUIC' in event_type[event['type']]:
                    if 'params' in event:
                        if 'host' in event['params']:
                            for host in hosts:
                                if host in event['params']['host']:
                                    quic_connection_ids.append(event['params']['connection_id'])
                                    logging.info(f"Found quic connection id: {event['params']['connection_id']}")
                                    print("----------------------------------------------")
                                    break
        if len(quic_connection_ids) == 0:
            if len(events_ids):
                for event in data['events']:
                    if event['type'] < len(event_type) and event_type[event['type']] == 'QUIC_SESSION':
                        if 'source' in event:
                            if event['source']['id'] in events_ids:
                                if 'params' in event:
                                    if 'connection_id' in event['params']:
                                        quic_connection_ids.append(event['params']['connection_id'])
                                        logging.info(f"Found quic connection id: {event['params']['connection_id']}")
                                        print("----------------------------------------------")

            
    return list(set(quic_connection_ids))



def clean_pcap_csv(csv_path, json_path, n_streams, client_ip="127.0.0.1", server_ip="127.0.0.2", save=False,
                   save_path=None):
    """
    Assumes server_stream_timestamps is a list of dictionaries.
     Each dict represent a Timestamp object of a specific server stream.
     The Dict structure is:
        {
        "Stream_id":<int>,
        "Accept_time":<float>,
        "Close_time":<float>
        }
    """
    data = pd.read_csv(csv_path)
    # change the column name from _ws.col.info to _ws.col.Info if _ws.col.info exists
    if '_ws.col.info' in data.columns:
        data.rename(columns={'_ws.col.info': '_ws.col.Info'}, inplace=True)
        
    if data.size == 0:
        return None
    
    quic_connection_ids = get_quic_connection_ids(json_path)
    if len(quic_connection_ids) == 0:
        return None
    
    # check if ip.src is an empty column
    ip_column = "ip"
    if data["ip.src"].isnull().all():
        ip_column = "ipv6"

    # client_ip = data["ip.src"][0]
    client_ip = list(data[data["_ws.col.Info"].str.contains(f"DCID={quic_connection_ids[0]}")][f"{ip_column}.src"])[0]
    # server_ips = data.loc[data["ip.src"] != client_ip]
    server_ips_quic = []
    for id in quic_connection_ids:
        server_ips_quic += list(set(data[data["_ws.col.Info"].str.contains(f"DCID={id}")][f"{ip_column}.dst"]))
    
    # remove entries from server_ips_quic that are equal to client_ip
    server_ips_quic = [ip for ip in server_ips_quic if ip != client_ip]

    if len(server_ips_quic) == 0:
        return None
    print(server_ips_quic)
    server_packets = data[data[f'{ip_column}.src'].isin(server_ips_quic)]
    server_header_packets = server_packets[server_packets["_ws.col.Info"].str.contains("HEADERS")]
    server_ip = server_header_packets[f"{ip_column}.src"].value_counts().idxmax() if server_header_packets.size > 0 else None
    if server_ip is None:
        return None

    valid_client = (data[f'{ip_column}.src'] == client_ip) & (data[f'{ip_column}.dst'] == server_ip)
    valid_server = (data[f'{ip_column}.dst'] == client_ip) & (data[f'{ip_column}.src'] == server_ip)
    valid_data = data[valid_client | valid_server]
    server_stream_timestamps = data['frame.time_relative']

    first = valid_data['frame.time_relative'].min()

    def label(row):
        """a header sent means that there's data that is going to be sent, and in our
        case it means that and object is going to be sent."""
        # return the number of of times the word "HEADERS" appeared in row["_ws.col.Info"]
        return row["_ws.col.Info"].count("HEADERS")
            
    def label_packet_direction(row):
        """
        We set the direction for each packet. This function is used to label the packets.
        0 - client to server
        1 - server to client
        """
        if row[f'{ip_column}.src'] == client_ip:
            return 0
        else:
            return 1

    valid_data['object_started'] = valid_data.apply(func=lambda row: label(row=row), axis=1)
    valid_data['Server_src'] = valid_data.apply(func=lambda row: label_packet_direction(row=row), axis=1)
    clean_data = valid_data[['frame.time_relative', 'frame.len', f'{ip_column}.src', f'{ip_column}.dst', 'Server_src', 'object_started']]

    clean_data.rename(columns={'frame.time_relative': 'Time', 'frame.len': 'Length', f'{ip_column}.src': 'Source',
                               f'{ip_column}.dst': 'Destination'}, inplace=True)
    if save:
        clean_data.to_csv(save_path)

    return clean_data



def load_timestamps(timestamps_paths):
    res = []
    for path_t in timestamps_paths:
        with open(path_t, 'r') as f:
            res.append(json.loads(f.read()))
    return res



def prepare_folders(path):
    path = fr"{os.path.sep}".join(path.split(fr"{os.path.sep}")[:-1])
    if not os.path.exists(path):
        os.makedirs(path)



def save_image(image, path):
    img = Image.fromarray(np.uint8(cm.gist_earth(image) * 255)).transpose(Image.FLIP_TOP_BOTTOM)

    # normalized = (image - image.min()) * 255 / (image.max() - image.min())
    # img = Image.fromarray(np.uint8(normalized), mode='L').transpose(Image.FLIP_TOP_BOTTOM)

    img.save(path)



def window_data_to_multi_hist(data, time_bins, length_bins, window_size, trace = None, current_time = None):
    """
    Given the data of a window, convert it to a histogram.
    The histogram is in RGB scale.
    R - packets from the server to the client (generally the objects data)
    G - packets from the client to the server (generally ACK messages)
    B - the aggregated number of packet from both directions, over the whole trace.
    :param data: the data of the current window
    :param time_bins: number of time bins in the histogram (width of the image)
    :param length_bins: number of length bins in the histogram (height of the image)
    :param window_size: size of the window in seconds
    :param trace: the whole trace, used for the aggregated number of packets
    :param current_time: the current time of the window, used for the aggregated number of packets
    """
    hist = np.zeros((length_bins, time_bins, 3))

    dt_step = window_size / time_bins
    dl_step = MAX_PACKET_LENGTH / length_bins
    for x, dt in enumerate(np.arange(start=0, stop=window_size, step=dt_step)):
        for y, dl in enumerate(np.arange(start=0, stop=MAX_PACKET_LENGTH, step=dl_step)):
            relevant_time = (data['Time'] >= dt) & (data['Time'] < dt + dt_step)
            server_relevant_length = (data['Length'] > dl) & (data['Length'] <= dl + dl_step) & (
                    data['Server_src'] == 1)
            client_relevant_length = (data['Length'] > dl) & (data['Length'] <= dl + dl_step) & (
                    data['Server_src'] == 0)
            
            aggregated_relevant_time = (trace['Time'] < current_time + dt + dt_step)
            aggregated_relevant_length = (trace['Length'] > dl) & (trace['Length'] <= dl + dl_step)

            hist[y][x][0] = np.sum(
                relevant_time & server_relevant_length)  # red for packets from the server to the client (generally the video data)
            hist[y][x][1] = np.sum(
                relevant_time & client_relevant_length)  # green for packets from the client to the server (generally ACK messages)

    return hist



def multi_hist_to_rg_image(image, path):
    """
    convert the histogram to an RG image, without the G channel.
    """
    if image[:, :, 0].max() != image[:, :, 0].min():
        image[:, :, 0] = (image[:, :, 0] - image[:, :, 0].min()) * 255 / (image[:, :, 0].max() - image[:, :, 0].min())
    if image[:, :, 1].max() != image[:, :, 1].min():
        image[:, :, 1] = (image[:, :, 1] - image[:, :, 1].min()) * 255 / (image[:, :, 1].max() - image[:, :, 1].min())
    
    image[:, :, 2] = 0
    img = Image.fromarray(np.uint8(image), mode="RGB").transpose(Image.FLIP_TOP_BOTTOM)
    img.save(path)



def window_data_to_hist(data, time_bins, length_bins, window_size, trace = None, current_time = None):
    """
    Given the data of a window, convert it to a histogram.
    The histogram is in gray scale,
    where the value of each pixel is the number of packets in the corresponding bin
    (the relevant time and packet length bin).
    """
    hist = np.zeros((length_bins, time_bins))

    dt_step = window_size / time_bins
    dl_step = MAX_PACKET_LENGTH / length_bins
    for x, dt in enumerate(np.arange(start=0, stop=window_size, step=dt_step)):
        for y, dl in enumerate(np.arange(start=0, stop=MAX_PACKET_LENGTH, step=dl_step)):
            relevant_time = (data['Time'] >= dt) & (data['Time'] < dt + dt_step)
            relevant_length = (data['Length'] > dl) & (data['Length'] <= dl + dl_step)
            count = np.sum(relevant_time & relevant_length)
            hist[y][x] = count

    return hist



def print_hist(hist):
    for x in range(hist.shape[0]):
        for y in range(hist.shape[1]):
            print(hist[x][y][2], end=" ")
        print()



def section_to_windows_images(base_save_path, window_size, overlap, windows_indexes, section, time_bins,
                              length_bins, to_hist=window_data_to_hist, save=save_image):
    """
    create windows from section and save them as images in base_save_path
    :param base_save_path: base path to save the windows (flowpics)
    :param window_size: size of the window in seconds
    :param overlap: overlap between windows in percentange
    :param windows_indexes: dict of indexes for each label, assigns an index to each window, used for naming the files
    :param section: section to create windows from. This is a pandas DataFrame containing packet data with timestamps and other relevant information
    :param label: label of the sectionm the label will be used for all windows created from this section
    :param time_bins: number of time bins in the histogram (width of the image)
    :param length_bins: number of length bins in the histogram (height of the image)
    :param to_hist: function that converts the window data to a histogram
    :param save: function that saves the image
    """
    info = section['Time'].agg(['min', 'max'])
    step_size = (1 - overlap) * window_size
    start = info['min']
    stop = info['max']

    if stop - start >= window_size:
        print("----------------------------------------------")
        for dt in np.arange(start=start, stop=stop, step=step_size):
            logging.info(f"Creating window from {dt} to {dt + window_size}")
            relevant_indexes = (section['Time'] >= dt) & (section['Time'] < dt + window_size)
            window_data = pd.DataFrame(section[relevant_indexes])
            window_data['Time'] -= dt
            image = to_hist(data=window_data,
                            time_bins=time_bins,
                            length_bins=length_bins,
                            window_size=window_size,
                            trace=section,
                            current_time=dt+window_size)
            
            # the label is the number of headers in the window, sent from the server to the client
            # which is the sum of the values in the row object_started, where Server_src is 1
            label = np.sum(window_data[window_data['Server_src'] == 1]['object_started'])     
            save_path = fr"{base_save_path}{os.path.sep}{window_size}{os.path.sep}{overlap}{os.path.sep}{label}{os.path.sep}{windows_indexes[1]}.png"
            print(save_path)
            windows_indexes[1] += 1
            prepare_folders(path=save_path)
            save(image=image, path=save_path)
            logging.info(f"Saved window {save_path}")
            print("----------------------------------------------")



def change_root_dir(path, new_root):
    return os.path.sep.join([new_root] + path.split(os.path.sep)[1:])



def find_csv_files(dir):
    csv_files = []
    for root, dirs, files in os.walk(dir):
        for file in files:
            if file.endswith('.csv'):
                csv_files.append(os.path.join(root, file))
    return csv_files



def main(args):
    files = find_csv_files(args.files)
    for csv_file in files:
        json_file = csv_file.replace(".csv", ".json")
        base_save_path = fr"{csv_file[:-4]}_colored_windows"
        base_save_path = change_root_dir(base_save_path, args.save_path)
        clean_csv_save_path = f"{csv_file[:-4]}_clean.csv"
        
        # check if the clean csv file already exists
        if os.path.exists(clean_csv_save_path):
            print(f"clean csv file {clean_csv_save_path} already exists")
            continue

        print("==============================================")
        logging.info(f"Cleaning {csv_file}")
        data = clean_pcap_csv(csv_path=csv_file,
                              json_path=json_file,
                              n_streams=1,
                              save=True,
                              save_path=clean_csv_save_path)
        print("----------------------------------------------")
        
        if data is None:
            print("file is empty")
            continue

        window_sizes = [0.1, 0.3]
        overlaps = [0.9, 0]

        for window_size in window_sizes:
            for overlap in overlaps:
                section_to_windows_images(base_save_path=base_save_path,
                                            window_size=window_size,
                                            overlap=overlap,
                                            windows_indexes={1: 0},
                                            section=data,
                                            time_bins=32,
                                            length_bins=32,
                                            to_hist=window_data_to_multi_hist,
                                            save=multi_hist_to_rg_image)
    print("==============================================")



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="preprocessing parameters")
    parser.add_argument("--save_path", help="A path to save the flowpics."
                                        " The images will save in '{res_path}{os.path.sep}{n_streams}'")
    parser.add_argument('--files', help="dir for files")
    parser.add_argument('--zip_folder', default="", help="The folder that contains the zips, each zip contains the traces of a webserver")
    args = parser.parse_args()

    main(args)
