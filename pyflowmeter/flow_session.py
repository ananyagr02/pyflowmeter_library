import time
import os # Import os for path manipulation
from threading import Thread, Lock
import csv

from scapy.sessions import DefaultSession

from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow

import requests


EXPIRED_UPDATE = 40
SENDING_INTERVAL = 1

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        # self.csv_line = 0 # This will be reset for each new file
        self.packets_count = 0 # Total packets across all chunks
        
        # --- Chunking Logic Variables ---
        self.packet_chunk_size = kwargs.pop("packet_chunk_size", 500) # Get chunk size, default to 500
        self.chunk_number = 1 # Start with chunk 1
        self.current_chunk_packets = 0 # Packets in the current chunk
        self._current_csv_file = None # To hold the current file object
        self.csv_writer = None # To hold the current csv writer
        self.csv_line = 0 # To track header writing per file
        # ---------------------------------


        self.GARBAGE_COLLECT_PACKETS = 10000 if self.server_endpoint is None else 500 # Original GC trigger - may not be needed for writing now
        
        print(f"Server Endpoint: {self.server_endpoint}")
        print(f"To CSV: {self.to_csv}, Output File: {self.output_file}")
        print(f"Packet Chunk Size: {self.packet_chunk_size}")


        self.lock = Lock() 
        
        if self.server_endpoint is not None:
            thread = Thread(target=self.send_flows_to_server)
            thread.start()
        
        # Don't open the file here, will open per chunk
        if self.to_csv:
            self._open_new_csv() # Open the first CSV file

        super(FlowSession, self).__init__(*args, **kwargs)

    def _open_new_csv(self):
        """Opens a new CSV file for the current chunk."""
        if self._current_csv_file:
            self._current_csv_file.close() # Close previous file if any

        base, ext = os.path.splitext(self.output_file)
        chunk_filename = f"{base}_chunk_{self.chunk_number}{ext}"
        
        print(f"Opening new CSV: {chunk_filename}")
        self._current_csv_file = open(chunk_filename, "w", newline='') # Use newline='' for csv
        self.csv_writer = csv.writer(self._current_csv_file)
        self.csv_line = 0 # Reset line counter for the new file


    def _process_chunk(self):
        """Writes collected flows to the current CSV, closes it, and prepares for the next chunk."""
        if not self.to_csv:
            return # Only process chunks if writing to CSV

        print(f"Processing Chunk {self.chunk_number} ({self.current_chunk_packets} packets)")

        # Write current flows
        self.garbage_collect() # This writes flows and clears self.flows

        # Increment chunk number and reset packet count for the next chunk
        self.chunk_number += 1
        self.current_chunk_packets = 0

        # Open the next CSV file
        self._open_new_csv()


    def send_flows_to_server(self):
        while True:
            # Note: This part is separate from CSV chunking
            # Flows sent to server might not align with CSV chunks
            if len(self.flows) != 0:
                with self.lock:
                    flows = list(self.flows.values())
                # self.garbage_collect() # Original GC might interfere with chunking flows before writing to CSV
                data = {'flows': [flow.get_data() for flow in flows]}
                
                # Optional: Clear flows after sending to server if you don't need them for CSV anymore
                # Or modify garbage_collect to handle both server/csv logic carefully
                # For now, garbage_collect is tied to CSV writing in _process_chunk
                
                try:
                    requests.post(self.server_endpoint, json=data)
                    print(f"Sent {len(flows)} flows to server")
                except requests.exceptions.RequestException as e:
                    print(f"Error sending flows to server: {e}")

            time.sleep(self.sending_interval)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff (timeout reached).
        print("Sniffing finished. Processing final chunk...")
        
        # Process and write any remaining flows in the last chunk
        if self.to_csv and len(self.flows) > 0:
            print(f"Writing final partial chunk {self.chunk_number} ({self.current_chunk_packets} packets)...")
            self.garbage_collect() # Writes remaining flows

        # Close the last opened CSV file
        if self.to_csv and self._current_csv_file:
            self._current_csv_file.close()
            print(f"Closed final CSV file for chunk {self.chunk_number}")

        # The original method returns packets if not sniffing with session, 
        # but with a session, it likely returns None or the list of packets.
        # We mainly care about the cleanup happening here.
        return super(FlowSession, self).toPacketList()
    

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            # print("Error processing packet key:", e) # Optional: debug logging
            return # Skip packet if key extraction fails

        self.packets_count += 1 # Total packets counter


        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            try:
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                with self.lock:
                    self.flows[(packet_flow_key, count)] = flow
                if self.verbose:
                     print(f'New flow created for packet {self.packets_count} ({self.current_chunk_packets + 1}/{self.packet_chunk_size})')
            except Exception as e:
                 # print(f"Error creating flow for packet {self.packets_count}: {e}") # Optional: debug logging
                 return # Skip if flow creation fails


        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    try:
                        flow = Flow(packet, direction)
                        with self.lock:
                            self.flows[(packet_flow_key, count)] = flow
                        if self.verbose:
                            print(f'New flow instance created due to delay for packet {self.packets_count}')
                    except Exception as e:
                         # print(f"Error creating delayed flow for packet {self.packets_count}: {e}") # Optional: debug logging
                         return # Skip if flow creation fails
                    break # Exit while loop after creating new flow instance
        
        # Removed the FIN flag garbage_collect trigger to adhere to chunking

        try:
            # Add packet to the found or newly created flow
            flow.add_packet(packet, direction)
            self.current_chunk_packets += 1 # Increment packet counter for the current chunk

            if self.verbose:
                print(f'Packet {self.packets_count} added to flow. Current chunk packets: {self.current_chunk_packets}/{self.packet_chunk_size}')

            # --- Chunking Trigger ---
            # Trigger chunk processing if packet count for the current chunk is reached
            if self.to_csv and self.current_chunk_packets >= self.packet_chunk_size:
                 self._process_chunk()
            # ------------------------


            # Original garbage_collect trigger (excluding the packet count one, keeping duration if desired, but user implies strict chunking by count)
            # if flow.duration > 120:
            #     # print(f"Flow duration > 120s, triggering garbage_collect.")
            #     # Note: Triggering GC here will write/clear only flows meeting criteria, 
            #     # potentially splitting data for this flow across writes. 
            #     # For strict chunking, it might be better to rely only on _process_chunk.
            #     # Let's remove this trigger for strict chunking by count.
            #     pass 

        except Exception as e:
            print(f"Error adding packet to flow or processing chunk for packet {self.packets_count}: {e}")
            # Decide how to handle errors: skip packet, log, etc. For now, just print and continue.
            # This prevents a single bad packet/flow from crashing the sniffer.


    def get_flows(self) -> list:
        # Note: This returns current flows, which might only be a partial chunk
        with self.lock:
            return list(self.flows.values())
    
    def write_data_csv(self):
        """Writes the current collection of flows to the currently open CSV file."""
        # Assumes _open_new_csv has been called and self.csv_writer is valid
        if not self.csv_writer:
            print("Error: csv_writer is not initialized.")
            return

        flows_to_write = []
        with self.lock:
             # Create a list of flows to iterate outside the lock if needed, 
             # but iterating directly while holding the lock for a short time is fine.
             # Converting to list ensures we iterate over a snapshot.
             flows_to_write = list(self.flows.values())

        # Assume header is consistent across flows for simplicity based on original code
        # In reality, might need to handle flows with different features/data shapes
        if self.csv_line == 0 and flows_to_write:
            # Write header only if this is the first line in the current file
            # and there are flows to write (avoids writing header to empty files)
            try:
                # Get keys from the first flow's data for the header
                header = flows_to_write[0].get_data().keys()
                self.csv_writer.writerow(header)
                self.csv_line += 1
            except Exception as e:
                 print(f"Error writing CSV header: {e}")
                 # Decide error handling: skip, log, etc.

        for flow in flows_to_write:
            try:
                data = flow.get_data()
                self.csv_writer.writerow(data.values())
                self.csv_line += 1
            except Exception as e:
                print(f"Error writing flow data to CSV: {e}")
                # Decide error handling: skip this flow, log, etc.


        # print(f"Wrote {len(flows_to_write)} flows to CSV. Total lines in current file: {self.csv_line}")


    def garbage_collect(self) -> None:
        """Writes current flows to CSV (if enabled) and clears the flow dictionary."""
        # This method is now primarily called by _process_chunk and toPacketList
        # to finalize the current batch of flows.
        
        if self.to_csv:
            self.write_data_csv()

        with self.lock:
            # print(f"Clearing {len(self.flows)} flows after garbage collection.")
            self.flows = {} # Clear the dictionary for the next chunk or end of sniff



def generate_session_class(server_endpoint, verbose, to_csv, output_file, sending_interval, packet_chunk_size=500):
    """
    Generates a FlowSession class customized with parameters.
    Added packet_chunk_size.
    """
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "server_endpoint": server_endpoint,
            "verbose": verbose,
            "to_csv": to_csv,
            "output_file": output_file,
            "sending_interval": sending_interval,
            "packet_chunk_size": packet_chunk_size # Pass the chunk size
        },
    )
