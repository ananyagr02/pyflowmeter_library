# from scapy.sendrecv import AsyncSniffer

# # Import the modified generate_session_class
# from .flow_session import generate_session_class


# def create_sniffer(
#     input_file=None, input_interface=None, server_endpoint=None, verbose=False, to_csv=False,
#     # Original output_file parameter remains, can be used to derive dir/base if not explicit
#     output_file=None,
#     sending_interval=1,
#     # --- Add new arguments for chunking ---
#     output_dir=None, # Specify directory for chunked output
#     base_filename="traffic_features", # Specify base name for chunk files
#     batch_size=500 # Number of flows per chunk
#     # --- End new arguments ---
# ):
#     # --- Update assertions based on new arguments ---
#     # If to_csv is True, we need a destination specified.
#     # generate_session_class handles deriving dir/base and disabling to_csv if needed.
#     # The assertion here just checks that *something* is provided if CSV is requested.
#     assert (not to_csv) or (output_file is not None or output_dir is not None), \
#            "If to_csv is True, you must provide either output_file (to derive path/name) or both output_dir and base_filename."

#     # --- Use the modified generate_session_class ---
#     # Pass ALL potential configuration arguments to generate_session_class.
#     # generate_session_class validates paths and injects them into the session class.
#     NewFlowSession = generate_session_class(
#         server_endpoint=server_endpoint,
#         verbose=verbose,
#         to_csv=to_csv,
#         output_file=output_file, # Pass original output_file
#         sending_interval=sending_interval,
#         # --- Pass chunking config ---
#         output_dir=output_dir, # Pass explicit directory (or None)
#         base_filename=base_filename, # Pass explicit base filename (or default)
#         batch_size=batch_size, # Pass explicit batch size (or default)
#         # --- End chunking config ---
#     )

#     # The rest remains the same - initialize and return the AsyncSniffer
#     if input_file is not None:
#         # Offline capture (from a pcap file)
#         print(f"create_sniffer: Initializing AsyncSniffer for offline capture from '{input_file}'")
#         return AsyncSniffer(
#             offline=input_file,
#             filter="ip and (tcp or udp)", # Apply filter
#             prn=None, # Use default prn (packet processing handled by session)
#             session=NewFlowSession, # Use our custom session class
#             store=False, # Don't store packets in memory
#         )
#     else:
#         # Online capture (from an interface)
#         print(f"create_sniffer: Initializing AsyncSniffer for online capture on interface '{input_interface}'")
#         return AsyncSniffer(
#             iface=input_interface, # Specify interface
#             filter="ip and (tcp or udp)", # Apply filter
#             prn=None, # Use default prn
#             session=NewFlowSession, # Use our custom session class
#             store=False, # Don't store packets in memory
#         )


# ## original code below
# from scapy.sendrecv import AsyncSniffer

# from .flow_session import generate_session_class


# def create_sniffer(
#     input_file=None, input_interface=None, server_endpoint=None, verbose=False, to_csv=False,
#     output_file=None, sending_interval=1
# ):
#     assert (to_csv == False) or (output_file is not None)

#     NewFlowSession = generate_session_class(server_endpoint, verbose, to_csv, output_file, sending_interval)

#     if input_file is not None:
#         return AsyncSniffer(
#             offline=input_file,
#             filter="ip and (tcp or udp)",
#             prn=None,
#             session=NewFlowSession,
#             store=False,
#         )
#     else:
#         return AsyncSniffer(
#             iface=input_interface,
#             filter="ip and (tcp or udp)",
#             prn=None,
#             session=NewFlowSession,
#             store=False,
#         )




# sniffer.py

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
