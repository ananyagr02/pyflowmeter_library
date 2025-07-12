from scapy.sendrecv import AsyncSniffer

# Assuming flow_session is in the same package/directory structure
from .flow_session import generate_session_class


def create_sniffer(
    input_file=None,
    input_interface=None,
    server_endpoint=None,
    verbose=False,
    to_csv=False,
    output_file=None,
    sending_interval=1,
    packet_chunk_size=500  # <--- ADDED: Parameter to specify chunk size, defaults to 500
):
    """
    Creates and configures an AsyncSniffer instance with a custom FlowSession.

    Args:
        input_file (str, optional): Path to a .pcap file for offline analysis. Defaults to None.
        input_interface (str, optional): Network interface to sniff on for live capture. Defaults to None.
        server_endpoint (str, optional): URL endpoint to send flow data to. Defaults to None.
        verbose (bool, optional): If True, print verbose output. Defaults to False.
        to_csv (bool, optional): If True, save flow data to CSV files. Defaults to False.
        output_file (str, optional): Base path for output CSV files (e.g., 'capture.csv').
                                     Chunk numbers will be added (e.g., 'capture_chunk_1.csv').
                                     Required if to_csv is True. Defaults to None.
        sending_interval (int, optional): Interval in seconds to send data to the server
                                          (if server_endpoint is set). Defaults to 1.
        packet_chunk_size (int, optional): Number of packets to process before writing
                                           a chunk of flows to a new CSV file.
                                           Only applies if to_csv is True. Defaults to 500.

    Returns:
        scapy.sendrecv.AsyncSniffer: Configured sniffer instance.

    Raises:
        AssertionError: If to_csv is True but output_file is None.
    """
    assert (to_csv is False) or (output_file is not None), \
        "output_file must be specified if to_csv is True"

    # Generate the custom session class, passing all necessary parameters
    NewFlowSession = generate_session_class(
        server_endpoint=server_endpoint,
        verbose=verbose,
        to_csv=to_csv,
        output_file=output_file,
        sending_interval=sending_interval,
        packet_chunk_size=packet_chunk_size  # <--- PASSED: The chunk size is forwarded
    )

    # Define the filter for IP traffic (TCP or UDP)
    packet_filter = "ip and (tcp or udp)"

    if input_file is not None:
        # Create sniffer for offline pcap file analysis
        print(f"Creating sniffer for offline file: {input_file}")
        return AsyncSniffer(
            offline=input_file,
            filter=packet_filter,
            prn=None,  # Let the session handle packet processing
            session=NewFlowSession,
            store=False, # Don't store packets in memory, let session process
        )
    elif input_interface is not None:
        # Create sniffer for live interface capture
        print(f"Creating sniffer for interface: {input_interface}")
        return AsyncSniffer(
            iface=input_interface,
            filter=packet_filter,
            prn=None,  # Let the session handle packet processing
            session=NewFlowSession,
            store=False, # Don't store packets in memory, let session process
        )
    else:
        raise ValueError("Either input_file or input_interface must be specified")
