from flask import Flask, render_template
from System.codeCNN import get_accuracy, predict_user_input
from scapy.all import *
from flask_socketio import SocketIO
import threading
import socket
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
socketio = SocketIO(app)

# Retrieve and format the model accuracy
accuracy = get_accuracy()
accuracy = accuracy * 100
accuracy = "{:.2f}".format(accuracy)

# A list to store analyzed packet data for display
traffic_data = []

# A dictionary to store information about IP addresses
ip_stats = {}

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def time_diff(start_time):
    return time.time() - start_time

def analyze_packet(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            local_ip = get_local_ip()

            # Initialize IP stats if not already present
            if ip_src not in ip_stats:
                ip_stats[ip_src] = {
                    'count': 0,
                    'srv_count': 0,
                    'last_time': time.time(),
                    'flags': set(),
                    'dst_host_count': 0,
                    'dst_host_srv_count': 0
                }

            # Update IP stats
            ip_stats[ip_src]['count'] += 1
            ip_stats[ip_src]['srv_count'] += 1 if ip_dst == local_ip else 0
            ip_stats[ip_src]['dst_host_count'] += 1
            ip_stats[ip_src]['dst_host_srv_count'] += 1 if ip_dst == local_ip else 0
            ip_stats[ip_src]['flags'].add(packet[IP].flags)

            # Calculate additional features for prediction
            current_time = time.time()
            time_elapsed = time_diff(ip_stats[ip_src]['last_time'])
            same_srv_rate = ip_stats[ip_src]['srv_count'] / max(1, ip_stats[ip_src]['count'])
            dst_host_same_srv_rate = ip_stats[ip_src]['dst_host_srv_count'] / max(1, ip_stats[ip_src]['dst_host_count'])

            # Reset stats if time elapsed is greater than 60 seconds
            if time_elapsed > 60:
                ip_stats[ip_src]['count'] = 0
                ip_stats[ip_src]['srv_count'] = 0
                ip_stats[ip_src]['last_time'] = current_time

            # Prepare the input for the model
            user_input_example = {
                'protocol_type': str(protocol),
                'flag': str(packet[IP].flags),
                'src_bytes': len(packet[IP]),
                'dst_bytes': len(packet[IP]),
                'hot': len(ip_stats[ip_src]['flags']),
                'count': ip_stats[ip_src]['count'],
                'srv_count': ip_stats[ip_src]['srv_count'],
                'same_srv_rate': same_srv_rate,
                'dst_host_count': ip_stats[ip_src]['dst_host_count'],
                'dst_host_srv_count': ip_stats[ip_src]['dst_host_srv_count'],
                'dst_host_same_srv_rate': dst_host_same_srv_rate,
                'dst_host_diff_srv_rate': 1 - dst_host_same_srv_rate,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_rerror_rate': 0.0
            }

            predicted_class = predict_user_input(user_input_example)
            intrusion_detected = predicted_class == [0]

            
            traffic_data.append({
                'protocol': protocol,
                'src': ip_src,
                'src_bytes': len(packet[IP]),
                'intruder': intrusion_detected
            })

    except Exception as e:
        print(f"Error analyzing packet: {e}")
    return None

def run_network_monitor(interface):
    def packet_handler(packet):
        analyze_packet(packet)
    
    print(f"Starting network monitor on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0)

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('values.html', title='Prediction', accuracy=accuracy)

@app.route('/update_traffic_data')
def update_traffic_data():
    return render_template('_traffic_table.html', traffic=traffic_data)

if __name__ == "__main__":
    interface = "wlp2s0"  

    # Start the network monitor in a background thread
    monitor_thread = threading.Thread(target=run_network_monitor, args=(interface,))
    monitor_thread.daemon = True
    monitor_thread.start()

    socketio.run(app, debug=True)
