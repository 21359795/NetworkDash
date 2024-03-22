import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from scapy.layers.inet import TCP, UDP
from scapy.all import rdpcap

app = dash.Dash('NetworkDash')

# Load initial data from PCAP file
packets = rdpcap('/Users/alita/Documents/apptest1/iperf-mptcp-0-0.pcap')
packet_index = 0
max_packets_per_update = 100

initialiseTrace = go.Scatter(
    x=[packet.time for packet in packets[:max_packets_per_update]],
    y=[packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport for packet in packets[:max_packets_per_update] if packet.haslayer(TCP) or packet.haslayer(UDP)],
    mode='lines',
    marker=dict(color='skyblue'),
    name='Destination Port'
)

initialiseLayout = go.Layout(
    xaxis=dict(title='Timestamp'),
    yaxis=dict(title='Destination Port'),
    title='Destination Port vs. Timestamp',
    showlegend=True
)
# Writing titles and subtittles
app.layout = html.Div([
    html.H1("Network Traffic Analysis Dashboard", style={'textAlign': 'center'}),  # Title
    html.H2("Live Graph", style={'textAlign': 'center', 'color': 'gray'}),  # Subtitle
    dcc.Graph(id='graph', figure={'data': [initialiseTrace], 'layout': initialiseLayout}),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # in milliseconds
        n_intervals=0
    ),
    html.Div(id='pie-chart-container'), 
    html.Div([
        html.P("The line graph above shows the distribution of destination ports over time using the PCAP file iperf-mptcp-0-0.pcap which is a sample capture that uses iperf between client and hosts with two interfaces and a linux implementation which leads to many destination ports being open this could lead to vulnerabilities due to vulnerable ports."),
        html.P("The pie chart below displays the distribution of packet protocols, including TCP, UDP, SSH, and FTP, some of theses ports are concidered vulnerable including SSH and FTP but this pie chart is just a sample."),
        html.P("Made by Ali Rashid")
    ]) 
]) # Writing sentences for explanation 

@app.callback(
    [Output('graph', 'figure'),
     Output('pie-chart-container', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_graph(n_intervals):
    global packet_index
    global packets

    # Determine the range of packets to process and plot
    start_index = packet_index
    end_index = min(packet_index + max_packets_per_update, len(packets))

    # Process packets within the range
    destinPorts = []
    timestampL = []
    for packet in packets[start_index:end_index]:
        if packet.haslayer(TCP):
            destinPorts.append(packet[TCP].dport)
        elif packet.haslayer(UDP):
            destinPorts.append(packet[UDP].dport)
        timestampL.append(packet.time)

    # Update the trace
    trace = go.Scatter(
        x=timestampL,
        y=destinPorts,
        mode='lines',
        marker=dict(color='skyblue'),
        name='Destination Port'
    )

    # Update packet index for next iteration
    packet_index = end_index

    # If packet index reaches the end, reset it to repeat
    if packet_index >= len(packets):
        packet_index = 0

    # Counting the number of packets for each protocol
    tcp_amount = sum(1 for packet in packets if packet.haslayer(TCP))
    udp_amount = sum(1 for packet in packets if packet.haslayer(UDP))
    ssh_amount = sum(1 for packet in packets if packet.haslayer(TCP) and packet[TCP].dport == 22)
    ftp_amount = sum(1 for packet in packets if packet.haslayer(TCP) and packet[TCP].dport == 21)

    # Creating pie chart data
    pieChart = dcc.Graph(
        id='pie-chart',
        figure={
            'data': [
                go.Pie(
                    labels=['TCP', 'UDP', 'SSH', 'FTP'],
                    values=[tcp_amount, udp_amount, ssh_amount, ftp_amount],
                    hole=0.5
                )
            ],
            'layout': go.Layout(
                title='Packet Protocols Pie Chart'
            )
        }
    )

    return {'data': [trace], 'layout': initialiseLayout}, pieChart

if __name__ == '__main__':
    app.run_server(debug=True) 
