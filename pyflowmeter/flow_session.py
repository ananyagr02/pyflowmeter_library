##original code below
# import time
# from threading import Thread, Lock
# import csv

# from scapy.sessions import DefaultSession

# from .features.context.packet_direction import PacketDirection
# from .features.context.packet_flow_key import get_packet_flow_key
# from .flow import Flow

# import requests


# EXPIRED_UPDATE = 40
# SENDING_INTERVAL = 1

# class FlowSession(DefaultSession):
#     """Creates a list of network flows."""

#     def __init__(self, *args, **kwargs):
#         self.flows = {}
#         self.csv_line = 0
#         self.packets_count = 0
#         self.GARBAGE_COLLECT_PACKETS = 10000 if self.server_endpoint is None else 100

#         print(self.server_endpoint)
#         self.lock = Lock() 
#         if self.server_endpoint is not None:
#             thread = Thread(target=self.send_flows_to_server)
#             thread.start()
        
#         if self.to_csv:
#             output = open(self.output_file, "w")
#             self.csv_writer = csv.writer(output)

#         super(FlowSession, self).__init__(*args, **kwargs)

#     def send_flows_to_server(self):
#         while True:
#             if len(self.flows) != 0:
#                 with self.lock:
#                     flows = list(self.flows.values())
#                 self.garbage_collect()
#                 data = {'flows': [flow.get_data() for flow in flows]}
#                 requests.post(self.server_endpoint, json=data)
#             time.sleep(self.sending_interval)

#     def toPacketList(self):
#         # Sniffer finished all the packets it needed to sniff.
#         # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
#         self.garbage_collect()
#         return super(FlowSession, self).toPacketList()
    

#     def on_packet_received(self, packet):
#         count = 0
#         direction = PacketDirection.FORWARD

#         try:
#             # Creates a key variable to check
#             packet_flow_key = get_packet_flow_key(packet, direction)
#             flow = self.flows.get((packet_flow_key, count))
#         except Exception:
#             return

#         self.packets_count += 1
#         if self.verbose:
#             print('New packet received. Count: ' + str(self.packets_count))

#         # If there is no forward flow with a count of 0
#         if flow is None:
#             # There might be one of it in reverse
#             direction = PacketDirection.REVERSE
#             packet_flow_key = get_packet_flow_key(packet, direction)
#             flow = self.flows.get((packet_flow_key, count))

#         if flow is None:
#             # If no flow exists create a new flow
#             direction = PacketDirection.FORWARD
#             flow = Flow(packet, direction)
#             packet_flow_key = get_packet_flow_key(packet, direction)
#             with self.lock:
#                 self.flows[(packet_flow_key, count)] = flow

#         elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
#             # If the packet exists in the flow but the packet is sent
#             # after too much of a delay than it is a part of a new flow.
#             expired = EXPIRED_UPDATE
#             while (packet.time - flow.latest_timestamp) > expired:
#                 count += 1
#                 expired += EXPIRED_UPDATE
#                 flow = self.flows.get((packet_flow_key, count))

#                 if flow is None:
#                     flow = Flow(packet, direction)
#                     with self.lock:
#                         self.flows[(packet_flow_key, count)] = flow
#                     break
#         elif "F" in str(packet.flags):
#             # If it has FIN flag then early collect flow and continue
#             flow.add_packet(packet, direction)
#             # self.garbage_collect(packet.time)                    
#             return

#         flow.add_packet(packet, direction)

#         if self.packets_count % self.GARBAGE_COLLECT_PACKETS == 0 or (
#             flow.duration > 120 
#         ):
#             self.garbage_collect()

#     def get_flows(self) -> list:
#         return self.flows.values()
    
#     def write_data_csv(self):
#         with self.lock:
#             flows = list(self.flows.values())
#         for flow in flows:
#             data = flow.get_data()

#             if self.csv_line == 0:
#                 self.csv_writer.writerow(data.keys())

#             self.csv_writer.writerow(data.values())
#             self.csv_line += 1

#     def garbage_collect(self) -> None:
#         if self.to_csv:
#             self.write_data_csv()
#         with self.lock:
#             self.flows = {}



# def generate_session_class(server_endpoint, verbose, to_csv, output_file, sending_interval):
#     return type(
#         "NewFlowSession",
#         (FlowSession,),
#         {
#             "server_endpoint": server_endpoint,
#             "verbose": verbose,
#             "to_csv": to_csv,
#             "output_file": output_file,
#             "sending_interval": sending_interval
#         },
#     )























# import time
# import os # Added os for path joining and directory creation
# from threading import Thread, Lock
# import csv # Keep csv
# from enum import Enum # Assuming PacketDirection is an Enum, need to import it
# import sys
# from scapy.sessions import DefaultSession

# from .features.context.packet_direction import PacketDirection
# from .features.context.packet_flow_key import get_packet_flow_key
# from .flow import Flow # Assuming Flow is in pyflowmeter/flow.py

# import requests # Keep requests if server endpoint is used

# # Define constants used in the class. Assume these are available globally or defined here.
# # Based on your original code, let's use module-level constants.
# EXPIRED_UPDATE = 40
# SENDING_INTERVAL = 1
# GARBAGE_COLLECT_PACKETS_DEFAULT = 10000
# GARBAGE_COLLECT_PACKETS_SERVER = 100
# FLOW_DURATION_TIMEOUT_CONST = 120


# class FlowSession(DefaultSession):
#     """Creates a list of network flows with optional chunked CSV output."""

#     def __init__(self, *args, **kwargs):
#         # --- Access configuration attributes injected by generate_session_class ---
#         # These are set as *class* attributes, accessible as self.attribute_name
#         # DO NOT use kwargs.pop() for these; kwargs will contain other things Scapy needs.
#         # Access them directly via 'self.'
#         self.output_dir = self.output_dir # This attribute is set on the class by generate_session_class
#         self.base_filename = self.base_filename # This attribute is set on the class by generate_session_class
#         self.batch_size = self.batch_size # This attribute is set on the class by generate_session_class
#         self.server_endpoint = self.server_endpoint # This attribute is set on the class by generate_session_class
#         self.sending_interval = self.sending_interval # This attribute is set on the class by generate_session_class
#         self.verbose = self.verbose # This attribute is set on the class by generate_session_class
#         self.to_csv = self.to_csv # <--- Correctly access the to_csv flag from class attribute
#         self.output_file = self.output_file # Original output_file parameter (class attribute)
#         # --- End accessing config ---


#         self.flows = {} # Dictionary to store active flows
#         self.csv_line = 0 # Original pyflowmeter line counter (less relevant for chunking now)
#         self.packets_count = 0 # Total packets processed by this session instance

#         # GARBAGE_COLLECT_PACKETS determines how often cleanup/writing is attempted
#         # Access self.server_endpoint directly now
#         self.GARBAGE_COLLECT_PACKETS = GARBAGE_COLLECT_PACKETS_SERVER if self.server_endpoint is not None else GARBAGE_COLLECT_PACKETS_DEFAULT


#         # Access attributes directly for printing
#         print(f"FlowSession initialized. Server endpoint: {self.server_endpoint}, To CSV: {self.to_csv}")
#         print(f"Chunking Config: Dir='{self.output_dir}', Base='{self.base_filename}', Batch Size={self.batch_size}")


#         self.lock = Lock() # Use Lock for thread safety when accessing self.flows

#         # Start server sending thread if endpoint is configured
#         # Access self.server_endpoint and self.sending_interval directly
#         if self.server_endpoint is not None:
#             thread = Thread(target=self.send_flows_to_server)
#             thread.daemon = True # Set thread as daemon so it doesn't prevent script exit
#             thread.start()

#         # --- File handling setup for chunking ---
#         # Initialize variables for chunking state
#         # We defer opening the first file until the first flow data is ready.
#         self._csv_file_handle = None # Internal file handle for current chunk
#         self._csv_writer = None      # Internal DictWriter for current chunk
#         self._current_flow_count_in_chunk = 0 # Counter for flows written to current chunk file
#         self._current_chunk_index = 0    # Counter for chunk file number (starts at 0, first file is _chunk_1)
#         self._csv_header = None # Store header names once determined from the first flow data

#         # Ensure output directory exists IF CSV output is enabled AND we have a directory specified
#         # Access self.to_csv and self.output_dir directly
#         if self.to_csv and self.output_dir and self.output_dir != "None" and self.output_dir is not None: # Check output_dir is not None or the string "None"
#             try:
#                 # Create the directory if it doesn't exist. exist_ok=True prevents error if it exists.
#                 os.makedirs(self.output_dir, exist_ok=True)
#                 print(f"FlowSession: Output directory created/verified: '{self.output_dir}'")
#             except Exception as e:
#                 print(f"FlowSession: FATAL: Failed to create output directory '{self.output_dir}': {e}. Disabling CSV output.", file=sys.stderr)
#                 self.to_csv = False # Disable CSV output if directory cannot be created
#         elif self.to_csv: # If to_csv is True but output_dir is not valid (None or "None")
#              print(f"FlowSession: Warning: to_csv is True but output_dir is not valid ('{self.output_dir}'). Disabling CSV output.", file=sys.stderr)
#              self.to_csv = False # Disable CSV output if directory is not valid


#         # --- Call superclass init last ---
#         # Pass remaining kwargs to the superclass constructor.
#         # The parameters injected by generate_session_class (like output_dir, to_csv, etc.)
#         # should NOT be in kwargs at this point if they were already set as class attributes.
#         super(FlowSession, self).__init__(*args, **kwargs)


#     # --- Add method to open the next CSV chunk ---
#     def _open_next_csv_chunk(self):
#         """Closes the current CSV file and opens a new one with an incremented name.
#            Requires self._csv_header to be already populated.
#         """
#         # Check if CSV writing is enabled and configuration is valid before proceeding
#         if not self.to_csv or not self.output_dir or self.output_dir == "None" or self.base_filename is None or self._csv_header is None:
#             # If header is not known yet, this call shouldn't happen.
#             # If output_dir/base_filename is missing, writing is impossible.
#             print("FlowSession: Cannot open new chunk. CSV output not fully configured or header not known.", file=sys.stderr)
#             self.to_csv = False # Ensure CSV writing is off
#             return # Cannot proceed

#         # Close the previous file if it was open
#         if self._csv_file_handle:
#             print(f"FlowSession: Closing chunk file: {self._csv_file_handle.name}")
#             try:
#                 self._csv_file_handle.flush() # Ensure buffered data is written
#                 os.fsync(self._csv_file_handle.fileno()) # Ensure data is on disk (more reliable than just flush)
#                 self._csv_file_handle.close()
#             except Exception as e: # Catch potential errors during closing/flushing
#                 print(f"FlowSession: Error closing file {self._csv_file_handle.name}: {e}", file=sys.stderr)
#             self._csv_file_handle = None
#             self._csv_writer = None # Reset writer as well

#         # Increment chunk index and prepare the next file path
#         self._current_chunk_index += 1
#         chunk_filename = f"{self.base_filename}_chunk_{self._current_chunk_index}.csv"
#         chunk_filepath = os.path.join(self.output_dir, chunk_filename)

#         print(f"FlowSession: Attempting to open new chunk file: {chunk_filepath}")

#         try:
#             # Open the new file in write mode. newline='' is critical for csv module.
#             self._csv_file_handle = open(chunk_filepath, 'w', newline='', encoding='utf-8')
#             # Create the writer using the already determined header
#             self._csv_writer = csv.DictWriter(self._csv_file_handle, fieldnames=self._csv_header)

#             # Write the header row to the new file
#             self._csv_writer.writeheader()

#             # Reset flow counter for the new chunk file
#             self._current_flow_count_in_chunk = 0

#             print(f"FlowSession: Successfully opened and wrote header for chunk {self._current_chunk_index}")

#         except Exception as e: # Catch any errors during file opening/writing header
#             print(f"FlowSession: FATAL: Failed to open/write header for new CSV file {chunk_filepath}: {e}. Disabling CSV output.", file=sys.stderr)
#             # Clean up file handle if it was partially opened
#             if self._csv_file_handle:
#                 try: self._csv_file_handle.close()
#                 except: pass
#             self._csv_file_handle = None
#             self._csv_writer = None
#             self.to_csv = False # Disable further CSV output attempts


#     # --- Method to write a single flow's data and manage chunking ---
#     def _write_single_flow_to_csv(self, flow_data):
#         """Writes a single flow's data to the current CSV chunk and handles splitting."""
#         # Check if CSV writing is enabled and configuration is valid
#         if not self.to_csv or not self.output_dir or self.output_dir == "None" or self.base_filename is None or self.batch_size <= 0:
#              # CSV writing is disabled or badly configured
#              return # Do nothing if not configured properly

#         try:
#             # If header is not set yet (first flow being written ever), set it from this flow's data
#             # Then, open the very first chunk file and write the header.
#             if self._csv_header is None:
#                  print("FlowSession: First flow data received. Determining CSV header...")
#                  # Use keys from the first flow's data as the header
#                  self._csv_header = list(flow_data.keys())
#                  print(f"FlowSession: Determined header with {len(self._csv_header)} fields.")
#                  # Now that we have the header, open the first chunk file and create the writer
#                  try:
#                      self._open_next_csv_chunk()
#                      # _open_next_csv_chunk already sets _current_flow_count_in_chunk to 0 if successful
#                  except Exception:
#                       # _open_next_csv_chunk logs its own error and sets self.to_csv = False.
#                       # If opening the first file failed, we cannot write this flow.
#                       print("FlowSession: Failed to open first CSV chunk. Cannot write initial flow data.", file=sys.stderr)
#                       return # Exit the method


#             # Check again if writer/handle are valid after attempting to open the first file
#             if self._csv_writer is None or self._csv_file_handle is None:
#                  # This means opening the file failed somewhere along the way.
#                  print("FlowSession: Warning: Writer not available for writing single flow. Skipping.", file=sys.stderr)
#                  self.to_csv = False # Ensure off if somehow writer is missing
#                  return # Cannot write

#             # Prepare data for DictWriter, ensuring all header keys are present.
#             # Use str() to handle potential non-string/non-numeric types gracefully.
#             # Use the stored header keys to construct the row data dictionary.
#             row_data = {key: str(flow_data.get(key, '')) for key in self._csv_header}

#             # Write the row to the current CSV file chunk
#             self._csv_writer.writerow(row_data)
#             self._current_flow_count_in_chunk += 1

#             # Optional: Flush buffer more frequently (can impact performance, adds robustness against crashes)
#             # self._csv_file_handle.flush()
#             # os.fsync(self._csv_file_handle.fileno())


#             # Check if batch size is reached AFTER writing the row
#             # Only split if we have a valid batch_size threshold (> 0)
#             if self.batch_size > 0 and self._current_flow_count_in_chunk >= self.batch_size:
#                 print(f"FlowSession: Batch size {self.batch_size} reached for chunk {self._current_chunk_index}. Splitting CSV.")
#                 try:
#                     # Open the next chunk file. This also closes the current one.
#                     self._open_next_csv_chunk()
#                     # If _open_next_csv_chunk failed, it prints an error and sets self.to_csv = False.
#                 except Exception:
#                     # _open_next_csv_chunk prints its own error. Just ensure we stop processing if it failed.
#                     pass # Error already handled by _open_next_csv_chunk


#         except ValueError as e:
#             print(f"FlowSession: Error writing row to CSV (ValueError - keys might not match header?): {e}. Header: {self._csv_header}", file=sys.stderr)
#             # Log the error but continue, one bad flow shouldn't stop everything
#         except Exception as e: # Catch any other unexpected errors during writing
#             print(f"FlowSession: An unexpected error occurred while writing CSV row: {e}", file=sys.stderr)
#             # Log the error but continue


#     # send_flows_to_server method - Called by the sending thread (if enabled)
#     # It gets data and sends. It calls garbage_collect().
#     # write_data_csv (which now calls _write_single_flow_to_csv) handles CSV output.
#     def send_flows_to_server(self):
#         # Existing logic for sending to server
#         # This method runs in a separate thread. It needs to interact with self.flows safely using the lock.
#         # It calls get_data() and garbage_collect() (as per original code structure).
#         while True:
#             flows_to_process_for_sending = []
#             with self.lock:
#                  if self.server_endpoint is not None and len(self.flows) > 0:
#                      # Decide how often to send/clear. Maybe based on flow count or time?
#                      # Original code seems to send everything then garbage collect periodically.
#                      # Let's stick to the original logic: process all flows in self.flows periodically
#                      flows_to_process_for_sending = list(self.flows.values()) # Take a snapshot for sending


#             if flows_to_process_for_sending:
#                 try:
#                     # print(f"FlowSession: Preparing {len(flows_to_process_for_sending)} flows for sending.") # Debug
#                     data = {'flows': [flow.get_data() for flow in flows_to_process_for_sending]} # get_data called here for sending
#                     # print("FlowSession: Sending data to server endpoint.") # Debug
#                     requests.post(self.server_endpoint, json=data)
#                     # print("FlowSession: Successfully sent flows to server.") # Debug
#                 except Exception as e:
#                      print(f"FlowSession: Error sending data to server: {e}", file=sys.stderr)

#                 # Original code structure *might* have called garbage_collect after sending.
#                 # However, garbage_collect's primary job is processing finished flows (writing/clearing).
#                 # Let's rely on the packet-based or duration-based triggers in on_packet_received to call garbage_collect.
#                 # The sending thread primarily *sends* data from self.flows, it shouldn't clear self.flows itself unless it's specifically
#                 # processing flows that are *finished AND ready to send and clear*.
#                 # Given the ambiguity, let's assume the sending thread *only* sends data and the garbage_collect is triggered elsewhere.
#                 # REMOVE any original garbage_collect() call from this send_flows_to_server method if it existed.

#             time.sleep(self.sending_interval) # Sleep based on sending interval


#     def toPacketList(self):
#         # This method is called by AsyncSniffer when it stops (either normally or via stop()).
#         # It's the final cleanup point within the session thread.
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform a final garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         # This calls write_data_csv internally if to_csv is True.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)


#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         # Note: Original code called super(FlowSession, self).toPacketList()
#         # Let's keep that as it might be necessary for Scapy's state.
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList() # Return whatever the parent does


#     # --- Add a method to explicitly close the current chunk file ---
#     # This method is called internally by _open_next_csv_chunk and toPacketList.
#     def _close_current_csv_chunk(self):
#         """Explicitly closes the current CSV file if it's open."""
#         if self._csv_file_handle:
#             print(f"FlowSession: Explicitly closing final chunk file: {self._csv_file_handle.name}")
#             try:
#                 self._csv_file_handle.flush()
#                 os.fsync(self._csv_file_handle.fileno())
#                 self._csv_file_handle.close()
#             except Exception as e: # Catch any errors during close/flush
#                 print(f"FlowSession: Error closing final file {self._csv_file_handle.name}: {e}", file=sys.stderr)
#             self._csv_file_handle = None
#             self._csv_writer = None
#             # No need to reset counters here, they track overall state for the session duration


#     def on_packet_received(self, packet):
#         # This method is called by AsyncSniffer for every packet received.
#         # It identifies/updates the flow for the packet and may trigger garbage_collect.
#         # Keep original flow identification logic, but add error handling around operations.
#         count = 0
#         direction = PacketDirection.FORWARD # Initial assumption

#         # --- Flow Identification Logic ---
#         # This logic is critical to PyFlowmeter's flow tracking. Keep it as is but add error handling.
#         try:
#             # Attempt FORWARD lookup
#             packet_flow_key = get_packet_flow_key(packet, direction)
#             flow = self.flows.get((packet_flow_key, count))
#         except Exception as e:
#             print(f"FlowSession: Error getting packet flow key (initial): {e}", file=sys.stderr)
#             return # Skip packet if key extraction fails

#         if flow is None:
#             # Attempt REVERSE lookup if not found in forward
#             direction = PacketDirection.REVERSE
#             try: # Catch errors in get_packet_flow_key for reverse direction
#                 packet_flow_key_rev = get_packet_flow_key(packet, direction) # Need key for reverse lookup
#                 flow = self.flows.get((packet_flow_key_rev, count)) # Use key_rev for lookup
#             except Exception as e:
#                 print(f"FlowSession: Error getting packet flow key (reverse): {e}", file=sys.stderr)
#                 return # Skip packet if reverse key extraction fails

#             if flow is None:
#                  # If not found in either direction, create a new flow (defaulting to FORWARD)
#                  direction = PacketDirection.FORWARD # Default direction for new flow if not found
#                  try: # Catch errors in Flow initialization
#                      new_flow_instance = Flow(packet, direction) # Create flow with determined direction
#                      # Use the key derived for the direction the flow was ultimately created under
#                      packet_flow_key_final = get_packet_flow_key(packet, direction)
#                      with self.lock: # Use lock when modifying the flows dictionary
#                         self.flows[(packet_flow_key_final, count)] = new_flow_instance # Store with final key/count
#                      flow = new_flow_instance # Update 'flow' reference to the new instance found/created

#                  except Exception as e:
#                      print(f"FlowSession: Error creating new Flow object: {e}", file=sys.stderr)
#                      return # Skip packet if flow creation fails

#             # If flow was found in REVERSE, 'direction' is already updated to REVERSE
#             # If flow was NOT found and created as FORWARD, 'direction' is updated to FORWARD above

#         # If flow was found initially in FORWARD, 'direction' is still FORWARD
#         # So, 'direction' variable now holds the direction of the flow instance 'flow'

#         # --- Handle flow expiry (original logic) ---
#         # This logic determines if a packet arriving after a long delay belongs to the *same* flow
#         # or a *new* flow instance with an incremented count.
#         # Keep this logic as it is central to PyFlowmeter's flow definition, but add error handling.
#         # The loop inside the elif relies on finding flows with incremented 'count' using the base key.
#         # Let's add error handling and keep the structure.
#         try: # Wrap the expiry check and flow update logic in a try block
#             # Check if the packet arrives after the expiry threshold (using EXPIRED_UPDATE constant)
#             if (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
#                  # If the packet arrives after the expiry threshold, check for subsequent flow instances (with incremented count)
#                  expired = EXPIRED_UPDATE
#                  current_count = count # Start check from the current count of the found/created flow
#                  base_key_for_expiry_check = get_packet_flow_key(packet, direction) # Use the key/direction this flow is under

#                  while (packet.time - flow.latest_timestamp) > expired:
#                      current_count += 1 # Increment the flow instance count
#                      expired += EXPIRED_UPDATE # Increment the time threshold

#                      # Attempt to get the flow for the next count value using the base key
#                      flow_check = self.flows.get((base_key_for_expiry_check, current_count))

#                      if flow_check is None:
#                          # If flow instance with incremented count doesn't exist, create it
#                          # Use the direction this flow was found under (or defaulted) for creating the new flow instance
#                          try: # Catch errors in Flow initialization
#                              new_flow_instance = Flow(packet, direction)
#                              with self.lock: # Use lock when modifying the flows dictionary
#                                  self.flows[(base_key_for_expiry_check, current_count)] = new_flow_instance
#                              flow = new_flow_instance # Update 'flow' reference to the new instance
#                              count = current_count # Update 'count' reference as well
#                          except Exception as e:
#                              print(f"FlowSession: Error creating new Flow object during expiry check: {e}", file=sys.stderr)
#                              return # Skip packet if flow creation fails
#                          break # Found/created the correct flow instance, break the while loop

#                      # If flow instance exists (flow_check is not None), update 'flow' reference to it
#                      flow = flow_check # Update 'flow' reference for add_packet below
#                      count = current_count # Update 'count' reference as well


#         except Exception as e:
#              print(f"FlowSession: Error handling flow expiry logic: {e}", file=sys.stderr)
#              return # Skip packet if expiry logic fails


#         # --- Add the packet to the flow ---
#         # Now that the correct 'flow' object and 'direction' are determined, add the packet.
#         try:
#              flow.add_packet(packet, direction) # Use the determined flow object and direction
#              self.packets_count += 1 # Increment total packet counter for the session AFTER successfully adding the packet

#         except Exception as e:
#              print(f"FlowSession: Error adding packet to flow {getattr(flow, 'src_ip', 'N/A')}:{getattr(flow, 'src_port', 'N/A')}->{getattr(flow, 'dest_ip', 'N/A')}:{getattr(flow, 'dest_port', 'N/A')}: {e}", file=sys.stderr)
#              # Decide if failure to add a packet should stop the session or just skip the packet.
#              # Skipping the packet seems safer.
#              return


#         # --- Check for garbage collection triggers ---
#         # Trigger garbage_collect based on packet count or flow duration
#         # Use defined constants for triggers
#         GARBAGE_COLLECT_PACKETS_TRIGGER = GARBAGE_COLLECT_PACKETS_SERVER if self.server_endpoint is not None else GARBAGE_COLLECT_PACKETS_DEFAULT
#         FLOW_DURATION_TIMEOUT_TRIGGER = FLOW_DURATION_TIMEOUT_CONST

#         # Use a lock when checking flow.duration as it's accessed from the packet thread
#         # The flow object itself might need internal locks if its attributes are modified concurrently.
#         # Assuming Flow object's internal state is updated safely by add_packet.
#         # Accessing flow.duration here *should* be safe if Flow object is well-designed.

#         if self.packets_count > 0 and self.packets_count % GARBAGE_COLLECT_PACKETS_TRIGGER == 0:
#             # Trigger GC based on total packets processed
#              print(f"FlowSession: Triggering garbage_collect due to total packets ({self.packets_count}).") # Debug
#              try:
#                   self.garbage_collect()
#              except Exception as e:
#                   print(f"FlowSession: Error during garbage_collect triggered by packet count: {e}", file=sys.stderr)
#                   # Log and continue.

#         # Note: The flow.duration trigger in the original code
#         # (flow.duration > 120) implies checking the duration of the *current* flow.
#         # This could trigger GC frequently for long-lived flows.
#         # This trigger needs careful consideration relative to how often GC should run.
#         # Let's keep it for now as it was in the original code, but note it might be chatty/inefficient.
#         # Add a check that flow object exists before checking duration, though it should always exist here.
#         elif flow and hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_TRIGGER:
#              print(f"FlowSession: Triggering garbage_collect due to flow duration ({flow.duration:.2f}s).") # Debug
#              try:
#                   self.garbage_collect()
#              except Exception as e:
#                   print(f"FlowSession: Error during garbage_collect triggered by flow duration: {e}", file=sys.stderr)
#                   # Log and continue.


#     def get_flows(self) -> list:
#         # This method might be called externally if the sniffer exposes it.
#         # It returns a list of currently active flows.
#         # Note: It doesn't process or clear flows.
#         with self.lock: # Use lock for thread-safe access
#              return list(self.flows.values())


#     # --- Modified write_data_csv to use _write_single_flow_to_csv and DictWriter ---
#     # This method now contains the logic to identify and process finished flows.
#     def write_data_csv(self):
#         """Identifies finished flows, gets their data, writes them to CSV chunks, and removes them."""
#         # This method is called by garbage_collect.
#         if not self.to_csv or not self.output_dir:
#              # CSV output is disabled or directory not set
#              return

#         # --- Identify flows ready for output in this garbage collection cycle ---
#         finished_flows_for_writing = []
#         keys_to_remove_after_processing = []
#         current_time = time.time() # Get current time for timeout checks

#         # Use defined constants for criteria
#         FLOW_IDLE_TIMEOUT_COLLECTION = EXPIRED_UPDATE
#         FLOW_DURATION_TIMEOUT_COLLECTION = FLOW_DURATION_TIMEOUT_CONST

#         with self.lock: # Lock the flows dictionary while iterating and deciding what to process/remove
#             # Iterate over a copy of items to allow modification during iteration
#             for key, flow in list(self.flows.items()):
#                 is_finished = False

#                 # Criterion 1: Flow Duration Timeout
#                 if hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 2: Idle Timeout (if no packet received recently)
#                 # Needs flow.latest_timestamp attribute
#                 elif hasattr(flow, 'latest_timestamp') and (current_time - flow.latest_timestamp) > FLOW_IDLE_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 3: Explicit Flags (like FIN/RST - needs state in Flow object, not shown)
#                 # if hasattr(flow, '_is_finished_by_flag') and flow._is_finished_by_flag:
#                 #     is_finished = True

#                 # Add other finish criteria if needed by PyFlowmeter (e.g., maximum packet count per flow instance?)

#                 # If the flow is considered finished in this cycle
#                 if is_finished:
#                     try:
#                         # Get the data for the finished flow - this is where features are calculated
#                         finished_flow_data = flow.get_data()
#                         finished_flows_data_to_write.append(finished_flow_data) # Collect data for writing
#                         keys_to_remove_after_processing.append(key) # Mark key for removal *if data extraction succeeds*
#                         # print(f"DEBUG GC: Collected data for finished flow {key}.") # Optional debug
#                     except Exception as e:
#                          # Catch errors during data retrieval (e.g., ZeroDivisionError, though hopefully fixed in flow_bytes)
#                          print(f"FlowSession: Error getting data for finished flow {key}: {e}. Skipping flow write and removal.", file=sys.stderr)
#                          # Do NOT add to keys_to_remove_after_processing if data extraction failed.
#                          # This flow will remain in self.flows and might be attempted again later.


#         # --- Write the collected finished flows data to CSV chunks ---
#         if not finished_flows_data_to_write:
#             # No finished flows with successfully extracted data to write in this cycle
#             # print("DEBUG: write_data_csv found finished flows, but none had data ready for writing.") # Optional debug
#             return # Nothing to write

#         # Process each collected flow data dictionary
#         # This loop calls _write_single_flow_to_csv for each dictionary and handles chunking/splitting
#         for flow_data in finished_flows_data_to_write:
#             try:
#                 # Write this flow's data to the current CSV chunk and handle splitting
#                 self._write_single_flow_to_csv(flow_data)
#             except Exception as e:
#                  # Catch errors during the actual writing process (e.g., IOError)
#                  print(f"FlowSession: Error writing collected flow data to CSV: {e}. Skipping this flow for writing.", file=sys.stderr)
#                  # Log the error and continue processing the next flow data dictionary.
#                  # The flow that generated this data *was* already marked for removal if data extraction succeeded.


#         # --- Remove the successfully identified finished flows from the main dictionary ---
#         # We remove flows whose data *was successfully extracted* and *attempted* to be written.
#         # Flows where get_data() failed were NOT added to finished_flows_data_to_write and thus not marked for removal.
#         with self.lock: # Lock while modifying the main dictionary
#             for key in keys_to_remove_after_processing:
#                 # Check if the key still exists before deleting (handle potential concurrent modifications or flows that failed to write later)
#                 if key in self.flows:
#                      # print(f"DEBUG GC: Removing finished flow {key} from dictionary after processing attempt.") # Optional debug
#                      del self.flows[key]

#         # print(f"FlowSession: write_data_csv cycle finished. {len(finished_flows_data_to_write)} flows processed and removed.") # Optional debug


#     def garbage_collect(self) -> None:
#         # This method is triggered by on_packet_received (packet count or duration) or toPacketList or the sending thread.
#         # Its primary purpose is to trigger the processing and writing of *finished* flows.
#         # write_data_csv now contains the logic to identify finished flows, get their data, write them, and remove them from self.flows.

#         # --- Process finished flows (write to CSV if enabled) ---
#         # write_data_csv contains the core logic now.
#         if self.to_csv or self.server_endpoint is not None:
#              # Only run GC if there's a reason to process flows (CSV or Server endpoint)
#              # write_data_csv handles CSV. Server sending needs a separate mechanism if it uses finished flows.
#              # Let's just call write_data_csv here if CSV is enabled.
#              # If server sending also relies on the same garbage_collect logic, this needs redesign.
#              # Assuming write_data_csv is the main processing step triggered by GC.
#              try:
#                   # Call the method that processes finished flows, writes them, and removes them.
#                   # write_data_csv internally uses the lock when accessing self.flows.
#                   self.write_data_csv()
#              except Exception as e:
#                   print(f"FlowSession: Error caught during write_data_csv call in garbage_collect: {e}", file=sys.stderr)
#                   # Log and continue.

#         # --- Original code had `self.flows = {}` here ---
#         # This has been replaced by the logic within write_data_csv to remove only processed flows.
#         # So, do NOT clear self.flows = {} here anymore.


#     # --- toPacketList method (Called by AsyncSniffer on stop) ---
#     def toPacketList(self):
#         """Called by AsyncSniffer when it stops. Ensures final cleanup."""
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform one last garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         # garbage_collect calls write_data_csv if to_csv is True, which processes *finished* flows, writes them, and removes them.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)


#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         # This is crucial to save any data that didn't fill a complete batch.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList() # Return whatever the parent does


#     # --- Close method (Optional - might be called by other session types) ---
#     # Scapy's AsyncSniffer calls toPacketList, which handles our cleanup now.
#     # Keeping a 'close' method is good practice if other parts of PyFlowmeter or Scapy
#     # might expect it, but based on your snippets, toPacketList seems the primary stop handler.
#     # Let's just ensure toPacketList handles the cleanup. This separate 'close' might not be strictly needed.
#     # Keeping it as a potential entry point for future compatibility or if called by other code.
#     def close(self):
#          print("FlowSession: close() method called.")
#          # Delegate cleanup to toPacketList if possible, or duplicate cleanup logic
#          # Calling toPacketList seems safest as it includes final GC and closing.
#          try:
#              self.toPacketList()
#          except Exception as e:
#               print(f"FlowSession: Error during close() calling toPacketList: {e}", file=sys.stderr)
#          print("FlowSession: close() method finished.")


# # --- generate_session_class remains the same ---
# # This function creates the class and injects configuration as class attributes.
# def generate_session_class(
#     server_endpoint=None, verbose=False, to_csv=False,
#     output_file=None, # Original output_file parameter
#     sending_interval=1,
#     # --- Add new arguments for chunking ---
#     output_dir=None, # Specify directory for chunked output
#     base_filename="traffic_features", # Specify base name for chunk files
#     batch_size=100 # Number of flows per chunk
#     # --- End new arguments ---
# ):
#     # Purpose: Create and return a FlowSession class with configuration injected as class attributes.

#     # --- Logic to derive output_dir and base_filename if not explicitly provided ---
#     # If output_dir is None but to_csv is True, try to use the directory of output_file.
#     final_output_dir = output_dir
#     if final_output_dir is None and to_csv and output_file:
#         # Get the directory part of output_file. Use "." if output_file has no directory.
#         final_output_dir = os.path.dirname(output_file)
#         if not final_output_dir: # Handles cases like "output.csv" -> dirname is ""
#             final_output_dir = "." # Use current directory

#     # If base_filename is the default AND output_file is provided, try to derive base_filename.
#     final_base_filename = base_filename
#     if final_base_filename == "traffic_features" and to_csv and output_file:
#          # Get the filename part without extension
#          final_base_filename = os.path.splitext(os.path.basename(output_file))[0]
#          if not final_base_filename: # Handles cases like "." or ""
#              final_base_filename = "traffic_features" # Fallback to default


#     # --- Final check and potential disabling of to_csv ---
#     # If to_csv is requested, but we still can't determine a valid output directory, disable it.
#     if to_csv and (final_output_dir is None or final_output_dir == "" or final_output_dir == "None"): # Include check for string "None" if that's a possibility
#          print("Warning: 'to_csv' is True but no valid output directory could be determined after processing output_file/output_dir. Disabling CSV output.", file=sys.stderr)
#          to_csv = False # Cannot write CSV without a directory


#     # --- Inject ALL relevant configuration parameters as class attributes ---
#     # FlowSession.__init__ will then access these as attributes.
#     return type(
#         "NewFlowSession",
#         (FlowSession,),
#         {
#             # Inject all config parameters so FlowSession instance can access them
#             "server_endpoint": server_endpoint,
#             "verbose": verbose,
#             "to_csv": to_csv, # This is the validated to_csv flag
#             "output_file": output_file, # Keep original output_file parameter
#             "sending_interval": sending_interval,
#             # --- Inject chunking config ---
#             "output_dir": final_output_dir, # This is the validated directory path
#             "base_filename": final_base_filename, # This is the validated base filename
#             "batch_size": batch_size,
#             # --- End chunking config ---

#             # Pass other potential kwargs through if DefaultSession uses them directly?
#             # The super(*args, **kwargs) in FlowSession.__init__ handles this.
#         },
#     )
































































































# import time
# import os # Added os for path joining and directory creation
# from threading import Thread, Lock
# import csv # Keep csv
# from enum import Enum # Assuming PacketDirection is an Enum, need to import it

# from scapy.sessions import DefaultSession

# from .features.context.packet_direction import PacketDirection
# from .features.context.packet_flow_key import get_packet_flow_key
# from .flow import Flow # Assuming Flow is in pyflowmeter/flow.py

# import requests # Keep requests if server endpoint is used

# # Define constants used in the class. Assume these are available globally or defined here.
# # Based on your original code, let's use module-level constants for clarity.
# EXPIRED_UPDATE = 40
# SENDING_INTERVAL = 1
# GARBAGE_COLLECT_PACKETS_DEFAULT = 10000
# GARBAGE_COLLECT_PACKETS_SERVER = 100
# FLOW_DURATION_TIMEOUT_CONST = 120


# class FlowSession(DefaultSession):
#     """Creates a list of network flows with optional chunked CSV output."""

#     def __init__(self, *args, **kwargs):
#         # --- Access configuration attributes injected by generate_session_class ---
#         # These are set as *class* attributes by generate_session_class.
#         # Access them directly via 'self.attribute_name'.
#         # DO NOT use kwargs.pop() for these; kwargs will contain other parameters for the superclass.

#         self.output_dir = self.output_dir # Access the class attribute
#         self.base_filename = self.base_filename # Access the class attribute
#         self.batch_size = self.batch_size # Access the class attribute
#         self.server_endpoint = self.server_endpoint # Access the class attribute
#         self.sending_interval = self.sending_interval # Access the class attribute
#         self.verbose = self.verbose # Access the class attribute
#         self.to_csv = self.to_csv # <--- Correctly access the to_csv flag from class attribute
#         self.output_file = self.output_file # Original output_file parameter (class attribute)
#         # --- End accessing config ---


#         self.flows = {} # Dictionary to store active flows
#         self.csv_line = 0 # Original pyflowmeter line counter (less relevant for chunking now)
#         self.packets_count = 0 # Total packets processed by this session instance

#         # GARBAGE_COLLECT_PACKETS determines how often cleanup/writing is attempted
#         # Access self.server_endpoint directly now
#         self.GARBAGE_COLLECT_PACKETS = GARBAGE_COLLECT_PACKETS_SERVER if self.server_endpoint is not None else GARBAGE_COLLECT_PACKETS_DEFAULT


#         # Access attributes directly for printing
#         print(f"FlowSession initialized. Server endpoint: {self.server_endpoint}, To CSV: {self.to_csv}")
#         print(f"Chunking Config: Dir='{self.output_dir}', Base='{self.base_filename}', Batch Size={self.batch_size}")


#         self.lock = Lock() # Use Lock for thread safety when accessing self.flows

#         # Start server sending thread if endpoint is configured
#         # Access self.server_endpoint and self.sending_interval directly
#         if self.server_endpoint is not None:
#             thread = Thread(target=self.send_flows_to_server)
#             thread.daemon = True # Set thread as daemon so it doesn't prevent script exit
#             thread.start()

#         # --- File handling setup for chunking ---
#         # Initialize variables for chunking state
#         # We defer opening the first file until the first flow data is ready.
#         self._csv_file_handle = None # Internal file handle for current chunk
#         self._csv_writer = None      # Internal DictWriter for current chunk
#         self._current_flow_count_in_chunk = 0 # Counter for flows written to current chunk file
#         self._current_chunk_index = 0    # Counter for chunk file number (starts at 0, first file is _chunk_1)
#         self._csv_header = None # Store header names once determined from the first flow data

#         # Ensure output directory exists IF CSV output is enabled AND we have a directory specified
#         # Access self.to_csv and self.output_dir directly
#         if self.to_csv and self.output_dir and self.output_dir != "None" and self.output_dir is not None: # Check output_dir is not None or the string "None"
#             try:
#                 # Create the directory if it doesn't exist. exist_ok=True prevents error if it exists.
#                 os.makedirs(self.output_dir, exist_ok=True)
#                 print(f"FlowSession: Output directory created/verified: '{self.output_dir}'")
#             except Exception as e:
#                 print(f"FlowSession: FATAL: Failed to create output directory '{self.output_dir}': {e}. Disabling CSV output.", file=sys.stderr)
#                 self.to_csv = False # Disable CSV output if directory cannot be created
#         elif self.to_csv: # If to_csv is True but output_dir is not valid (None or "None")
#              print(f"FlowSession: Warning: to_csv is True but output_dir is not valid ('{self.output_dir}'). Disabling CSV output.", file=sys.stderr)
#              self.to_csv = False # Disable CSV output if directory is not valid


#         # --- Call superclass init last ---
#         # Pass remaining kwargs to the superclass constructor.
#         # The parameters injected by generate_session_class (like output_dir, to_csv, etc.)
#         # should NOT be in kwargs at this point if they were already set as class attributes.
#         super(FlowSession, self).__init__(*args, **kwargs)


#     # --- Add method to open the next CSV chunk ---
#     def _open_next_csv_chunk(self):
#         """Closes the current CSV file and opens a new one with an incremented name.
#            Requires self._csv_header to be already populated.
#         """
#         # Check if CSV writing is enabled and configuration is valid before proceeding
#         if not self.to_csv or not self.output_dir or self.output_dir == "None" or self.base_filename is None or self._csv_header is None:
#             # If header is not known yet, this call shouldn't happen.
#             # If output_dir/base_filename is missing, writing is impossible.
#             print("FlowSession: Cannot open new chunk. CSV output not fully configured or header not known.", file=sys.stderr)
#             self.to_csv = False # Ensure CSV writing is off
#             return # Cannot proceed

#         # Close the previous file if it was open
#         if self._csv_file_handle:
#             print(f"FlowSession: Closing chunk file: {self._csv_file_handle.name}")
#             try:
#                 self._csv_file_handle.flush() # Ensure buffered data is written
#                 os.fsync(self._csv_file_handle.fileno()) # Ensure data is on disk (more reliable than just flush)
#                 self._csv_file_handle.close()
#             except Exception as e: # Catch potential errors during closing/flushing
#                 print(f"FlowSession: Error closing file {self._csv_file_handle.name}: {e}", file=sys.stderr)
#             self._csv_file_handle = None
#             self._csv_writer = None # Reset writer as well

#         # Increment chunk index and prepare the next file path
#         self._current_chunk_index += 1
#         chunk_filename = f"{self.base_filename}_chunk_{self._current_chunk_index}.csv"
#         chunk_filepath = os.path.join(self.output_dir, chunk_filename)

#         print(f"FlowSession: Attempting to open new chunk file: {chunk_filepath}")

#         try:
#             # Open the new file in write mode. newline='' is critical for csv module.
#             self._csv_file_handle = open(chunk_filepath, 'w', newline='', encoding='utf-8')
#             # Create the writer using the already determined header
#             self._csv_writer = csv.DictWriter(self._csv_file_handle, fieldnames=self._csv_header)

#             # Write the header row to the new file
#             self._csv_writer.writeheader()

#             # Reset flow counter for the new chunk file
#             self._current_flow_count_in_chunk = 0

#             print(f"FlowSession: Successfully opened and wrote header for chunk {self._current_chunk_index}")

#         except Exception as e: # Catch any errors during file opening/writing header
#             print(f"FlowSession: FATAL: Failed to open/write header for new CSV file {chunk_filepath}: {e}. Disabling CSV output.", file=sys.stderr)
#             # Clean up file handle if it was partially opened
#             if self._csv_file_handle:
#                 try: self._csv_file_handle.close()
#                 except: pass
#             self._csv_file_handle = None
#             self._csv_writer = None
#             self.to_csv = False # Disable further CSV output attempts


#     # --- Method to write a single flow's data and manage chunking ---
#     def _write_single_flow_to_csv(self, flow_data):
#         """Writes a single flow's data to the current CSV chunk and handles splitting."""
#         # Check if CSV writing is enabled and configuration is valid
#         if not self.to_csv or not self.output_dir or self.output_dir == "None" or self.base_filename is None or self.batch_size <= 0:
#              # CSV writing is disabled or badly configured
#              return # Do nothing if not configured properly

#         try:
#             # If header is not set yet (first flow being written ever), set it from this flow's data
#             # Then, open the very first chunk file and write the header.
#             if self._csv_header is None:
#                  print("FlowSession: First flow data received. Determining CSV header...")
#                  # Use keys from the first flow's data as the header
#                  self._csv_header = list(flow_data.keys())
#                  print(f"FlowSession: Determined header with {len(self._csv_header)} fields.")
#                  # Now that we have the header, open the first chunk file and create the writer
#                  try:
#                      self._open_next_csv_chunk()
#                      # _open_next_csv_chunk already sets _current_flow_count_in_chunk to 0 if successful
#                  except Exception:
#                       # _open_next_csv_chunk logs its own error and sets self.to_csv = False.
#                       # If opening the first file failed, we cannot write this flow.
#                       print("FlowSession: Failed to open first CSV chunk. Cannot write initial flow data.", file=sys.stderr)
#                       return # Exit the method


#             # Check again if writer/handle are valid after attempting to open the first file
#             if self._csv_writer is None or self._csv_file_handle is None:
#                  # This means opening the file failed somewhere along the way.
#                  print("FlowSession: Warning: Writer not available for writing single flow. Skipping.", file=sys.stderr)
#                  self.to_csv = False # Ensure off if somehow writer is missing
#                  return # Cannot write

#             # Prepare data for DictWriter, ensuring all header keys are present.
#             # Use str() to handle potential non-string/non-numeric types gracefully.
#             # Use the stored header keys to construct the row data dictionary.
#             row_data = {key: str(flow_data.get(key, '')) for key in self._csv_header}

#             # Write the row to the current CSV file chunk
#             self._csv_writer.writerow(row_data)
#             self._current_flow_count_in_chunk += 1

#             # Optional: Flush buffer more frequently (can impact performance, adds robustness against crashes)
#             # self._csv_file_handle.flush()
#             # os.fsync(self._csv_file_handle.fileno())


#             # Check if batch size is reached AFTER writing the row
#             # Only split if we have a valid batch_size threshold (> 0)
#             if self.batch_size > 0 and self._current_flow_count_in_chunk >= self.batch_size:
#                 print(f"FlowSession: Batch size {self.batch_size} reached for chunk {self._current_chunk_index}. Splitting CSV.")
#                 try:
#                     # Open the next chunk file. This also closes the current one.
#                     self._open_next_csv_chunk()
#                     # If _open_next_csv_chunk failed, it prints an error and sets self.to_csv = False.
#                 except Exception:
#                     # _open_next_csv_chunk logs its own errors. Just ensure we stop processing if it failed.
#                     pass # Error already handled by _open_next_csv_chunk


#         except ValueError as e:
#             print(f"FlowSession: Error writing row to CSV (ValueError - keys might not match header?): {e}. Header: {self._csv_header}", file=sys.stderr)
#             # Log the error but continue, one bad flow shouldn't stop everything
#         except Exception as e: # Catch any other unexpected errors during writing
#             print(f"FlowSession: An unexpected error occurred while writing CSV row: {e}", file=sys.stderr)
#             # Log the error but continue


#     # send_flows_to_server method - Called by the sending thread (if enabled)
#     # It gets data and sends. It calls garbage_collect().
#     # write_data_csv (which now calls _write_single_flow_to_csv) handles CSV output.
#     def send_flows_to_server(self):
#         # Existing logic for sending to server
#         # This method runs in a separate thread. It needs to interact with self.flows safely using the lock.
#         # It calls get_data() and garbage_collect() (as per original code structure).
#         while True:
#             flows_to_process_for_sending = []
#             with self.lock:
#                  if self.server_endpoint is not None and len(self.flows) > 0:
#                      # Decide how often to send/clear. Maybe based on flow count or time?
#                      # Original code seems to process all flows in self.flows periodically for sending.
#                      # This might conflict with garbage_collect's intended behavior (processing FINISHED flows).
#                      # Assuming the original intent was to send *all* current flows periodically...
#                      flows_to_process_for_sending = list(self.flows.values()) # Take a snapshot for sending


#             if flows_to_process_for_sending:
#                 try:
#                     # print(f"FlowSession: Preparing {len(flows_to_process_for_sending)} flows for sending.") # Debug
#                     data = {'flows': [flow.get_data() for flow in flows_to_process_for_sending]} # get_data called here for sending
#                     # print("FlowSession: Sending data to server endpoint.") # Debug
#                     requests.post(self.server_endpoint, json=data)
#                     # print("FlowSession: Successfully sent flows to server.") # Debug
#                 except Exception as e:
#                      print(f"FlowSession: Error sending data to server: {e}", file=sys.stderr)

#                 # Original code structure *might* have called garbage_collect after sending.
#                 # However, garbage_collect's primary job is processing finished flows (writing/clearing).
#                 # Let's rely on the packet-based or duration-based triggers in on_packet_received to call garbage_collect.
#                 # The sending thread primarily *sends* data from self.flows, it shouldn't clear self.flows itself unless it's specifically
#                 # processing flows that are *finished AND ready to send and clear*.
#                 # Given the ambiguity, let's assume the sending thread *only* sends data and the garbage_collect is triggered elsewhere.
#                 # REMOVE any original garbage_collect() call from this send_flows_to_server method if it existed.

#             time.sleep(self.sending_interval) # Sleep based on sending interval


#     def toPacketList(self):
#         # This method is called by AsyncSniffer when it stops (either normally or via stop()).
#         # It's the final cleanup point within the session thread.
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform a final garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         # This calls write_data_csv internally if to_csv is True.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)


#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList() # Return whatever the parent does


#     # --- Add a method to explicitly close the current chunk file ---
#     # This method is called internally by _open_next_csv_chunk and toPacketList.
#     def _close_current_csv_chunk(self):
#         """Explicitly closes the current CSV file if it's open."""
#         if self._csv_file_handle:
#             print(f"FlowSession: Explicitly closing final chunk file: {self._csv_file_handle.name}")
#             try:
#                 self._csv_file_handle.flush()
#                 os.fsync(self._csv_file_handle.fileno())
#                 self._csv_file_handle.close()
#             except Exception as e: # Catch any errors during close/flush
#                 print(f"FlowSession: Error closing final file {self._csv_file_handle.name}: {e}", file=sys.stderr)
#             self._csv_file_handle = None
#             self._csv_writer = None
#             # No need to reset counters here, they track overall state for the session duration


#     def on_packet_received(self, packet):
#         # This method is called by AsyncSniffer for every packet received.
#         # It identifies/updates the flow for the packet and may trigger garbage_collect.
#         # Keep original flow identification logic, but add error handling around operations.
#         count = 0
#         direction = PacketDirection.FORWARD # Initial assumption

#         # --- Flow Identification Logic ---
#         # This logic is critical to PyFlowmeter's flow tracking. Keep it as is but add error handling.
#         try:
#             # Attempt FORWARD lookup
#             packet_flow_key = get_packet_flow_key(packet, direction)
#             flow = self.flows.get((packet_flow_key, count))
#         except Exception as e:
#             print(f"FlowSession: Error getting packet flow key (initial): {e}", file=sys.stderr)
#             return # Skip packet if key extraction fails

#         if flow is None:
#             # Attempt REVERSE lookup if not found in forward
#             direction = PacketDirection.REVERSE
#             try: # Catch errors in get_packet_flow_key for reverse direction
#                 packet_flow_key_rev = get_packet_flow_key(packet, direction) # Need key for reverse lookup
#                 flow = self.flows.get((packet_flow_key_rev, count)) # Use key_rev for lookup
#             except Exception as e:
#                 print(f"FlowSession: Error getting packet flow key (reverse): {e}", file=sys.stderr)
#                 return # Skip packet if reverse key extraction fails

#             if flow is None:
#                  # If not found in either direction, create a new flow (defaulting to FORWARD)
#                  direction = PacketDirection.FORWARD # Default direction for new flow if not found
#                  try: # Catch errors in Flow initialization
#                      new_flow_instance = Flow(packet, direction) # Create flow with determined direction
#                      # Use the key derived for the direction the flow was ultimately created under
#                      packet_flow_key_final = get_packet_flow_key(packet, direction)
#                      with self.lock: # Use lock when modifying the flows dictionary
#                         self.flows[(packet_flow_key_final, count)] = new_flow_instance # Store with final key/count
#                      flow = new_flow_instance # Update 'flow' reference to the new instance found/created

#                  except Exception as e:
#                      print(f"FlowSession: Error creating new Flow object: {e}", file=sys.stderr)
#                      return # Skip packet if flow creation fails

#             # If flow was found in REVERSE, 'direction' is already updated to REVERSE
#             # If flow was NOT found and created as FORWARD, 'direction' is updated to FORWARD above

#         # If flow was found initially in FORWARD, 'direction' is still FORWARD
#         # So, 'direction' variable now holds the direction of the flow instance 'flow'

#         # --- Handle flow expiry (original logic) ---
#         # This logic determines if a packet arriving after a long delay belongs to the *same* flow
#         # or a *new* flow instance with an incremented count.
#         # Keep this logic as it is central to PyFlowmeter's flow definition, but add error handling.
#         # The loop inside the elif relies on finding flows with incremented 'count' using the base key.
#         # Let's add error handling and keep the structure.
#         try: # Wrap the expiry check and flow update logic in a try block
#             # Check if the packet arrives after the expiry threshold (using EXPIRED_UPDATE constant)
#             if (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
#                  # If the packet arrives after the expiry threshold, check for subsequent flow instances (with incremented count)
#                  expired = EXPIRED_UPDATE
#                  current_count = count # Start check from the current count of the found/created flow
#                  base_key_for_expiry_check = get_packet_flow_key(packet, direction) # Use the key/direction this flow is under

#                  while (packet.time - flow.latest_timestamp) > expired:
#                      current_count += 1 # Increment the flow instance count
#                      expired += EXPIRED_UPDATE # Increment the time threshold

#                      # Attempt to get the flow for the next count value using the base key
#                      flow_check = self.flows.get((base_key_for_expiry_check, current_count))

#                      if flow_check is None:
#                          # If flow instance with incremented count doesn't exist, create it
#                          # Use the direction this flow was found under (or defaulted) for creating the new flow instance
#                          try: # Catch errors in Flow initialization
#                              new_flow_instance = Flow(packet, direction)
#                              with self.lock: # Use lock when modifying the flows dictionary
#                                  self.flows[(base_key_for_expiry_check, current_count)] = new_flow_instance
#                              flow = new_flow_instance # Update 'flow' reference to the new instance
#                              count = current_count # Update 'count' reference as well
#                          except Exception as e:
#                              print(f"FlowSession: Error creating new Flow object during expiry check: {e}", file=sys.stderr)
#                              return # Skip packet if flow creation fails
#                          break # Found/created the correct flow instance, break the while loop

#                      # If flow instance exists (flow_check is not None), update 'flow' reference to it
#                      flow = flow_check # Update 'flow' reference for add_packet below
#                      count = current_count # Update 'count' reference as well


#         except Exception as e:
#              print(f"FlowSession: Error handling flow expiry logic: {e}", file=sys.stderr)
#              return # Skip packet if expiry logic fails


#         # --- Add the packet to the flow ---
#         # Now that the correct 'flow' object and 'direction' are determined, add the packet.
#         try:
#              flow.add_packet(packet, direction) # Use the determined flow object and direction
#              self.packets_count += 1 # Increment total packet counter for the session AFTER successfully adding the packet

#         except Exception as e:
#              print(f"FlowSession: Error adding packet to flow {getattr(flow, 'src_ip', 'N/A')}:{getattr(flow, 'src_port', 'N/A')}->{getattr(flow, 'dest_ip', 'N/A')}:{getattr(flow, 'dest_port', 'N/A')}: {e}", file=sys.stderr)
#              # Decide if failure to add a packet should stop the session or just skip the packet.
#              # Skipping the packet seems safer.
#              return


#         # --- Check for garbage collection triggers ---
#         # Trigger garbage_collect based on packet count or flow duration
#         # Use defined constants for triggers
#         GARBAGE_COLLECT_PACKETS_TRIGGER = GARBAGE_COLLECT_PACKETS_SERVER if self.server_endpoint is not None else GARBAGE_COLLECT_PACKETS_DEFAULT
#         FLOW_DURATION_TIMEOUT_TRIGGER = FLOW_DURATION_TIMEOUT_CONST

#         # Use a lock when checking flow.duration as it's accessed from the packet thread
#         # The flow object itself might need internal locks if its attributes are modified concurrently.
#         # Assuming Flow object's internal state is updated safely by add_packet.
#         # Accessing flow.duration here *should* be safe if Flow object is well-designed.

#         if self.packets_count > 0 and self.packets_count % GARBAGE_COLLECT_PACKETS_TRIGGER == 0:
#             # Trigger GC based on total packets processed
#              print(f"FlowSession: Triggering garbage_collect due to total packets ({self.packets_count}).") # Debug
#              try:
#                   self.garbage_collect()
#              except Exception as e:
#                   print(f"FlowSession: Error during garbage_collect triggered by packet count: {e}", file=sys.stderr)
#                   # Log and continue.

#         # Note: The flow.duration trigger in the original code
#         # (flow.duration > 120) implies checking the duration of the *current* flow.
#         # This could trigger GC frequently for long-lived flows.
#         # This trigger needs careful consideration relative to how often GC should run.
#         # Let's keep it for now as it was in the original code, but note it might be chatty/inefficient.
#         # Add a check that flow object exists before checking duration, though it should always exist here.
#         elif flow and hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_TRIGGER:
#              print(f"FlowSession: Triggering garbage_collect due to flow duration ({flow.duration:.2f}s).") # Debug
#              try:
#                   self.garbage_collect()
#              except Exception as e:
#                   print(f"FlowSession: Error during garbage_collect triggered by flow duration: {e}", file=sys.stderr)
#                   # Log and continue.


#     def get_flows(self) -> list:
#         # This method might be called externally if the sniffer exposes it.
#         # It returns a list of currently active flows.
#         # Note: It doesn't process or clear flows.
#         with self.lock: # Use lock for thread-safe access
#              return list(self.flows.values())


#     # --- Modified write_data_csv (Final Version, called by garbage_collect) ---
#     # This method now contains the logic to identify and process finished flows.
#     def write_data_csv(self):
#         """Identifies finished flows, gets their data, writes them to CSV chunks, and removes them."""
#         # This method is called by garbage_collect.
#         if not self.to_csv or not self.output_dir:
#              # CSV output is disabled or directory not set
#              return

#         # --- Identify flows ready for output in this garbage collection cycle ---
#         finished_flows_for_writing = []
#         keys_to_remove_after_processing = []
#         current_time = time.time() # Get current time for timeout checks

#         # Use defined constants for criteria
#         FLOW_IDLE_TIMEOUT_COLLECTION = EXPIRED_UPDATE
#         FLOW_DURATION_TIMEOUT_COLLECTION = FLOW_DURATION_TIMEOUT_CONST

#         with self.lock: # Lock the flows dictionary while iterating and deciding what to process/remove
#             # Iterate over a copy of items to allow modification during iteration
#             for key, flow in list(self.flows.items()):
#                 is_finished = False

#                 # Criterion 1: Flow Duration Timeout
#                 if hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 2: Idle Timeout (if no packet received recently)
#                 # Needs flow.latest_timestamp attribute
#                 elif hasattr(flow, 'latest_timestamp') and (current_time - flow.latest_timestamp) > FLOW_IDLE_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 3: Explicit Flags (like FIN/RST - needs state in Flow object, not shown)
#                 # if hasattr(flow, '_is_finished_by_flag') and flow._is_finished_by_flag:
#                 #     is_finished = True

#                 # Add other finish criteria if needed by PyFlowmeter (e.g., maximum packet count per flow instance?)

#                 # If the flow is considered finished in this cycle
#                 if is_finished:
#                     try:
#                         # Get the data for the finished flow - this is where features are calculated
#                         finished_flow_data = flow.get_data()
#                         finished_flows_data_to_write.append(finished_flow_data) # Collect data for writing
#                         keys_to_remove_after_processing.append(key) # Mark key for removal *if data extraction succeeds*
#                         # print(f"DEBUG GC: Collected data for finished flow {key}.") # Optional debug
#                     except Exception as e:
#                          # Catch errors during data retrieval (e.g., ZeroDivisionError, though hopefully fixed in flow_bytes)
#                          print(f"FlowSession: Error getting data for finished flow {key}: {e}. Skipping flow write and removal.", file=sys.stderr)
#                          # Do NOT add to keys_to_remove_after_processing if data extraction failed.
#                          # This flow will remain in self.flows and might be attempted again later.


#         # --- Write the collected finished flows data to CSV chunks ---
#         if not finished_flows_data_to_write:
#             # No finished flows with successfully extracted data to write in this cycle
#             # print("DEBUG: write_data_csv found finished flows, but none had data ready for writing.") # Optional debug
#             return # Nothing to write

#         # Process each collected flow data dictionary
#         # This loop calls _write_single_flow_to_csv for each dictionary and handles chunking/splitting
#         for flow_data in finished_flows_data_to_write:
#             try:
#                 # Write this flow's data to the current CSV chunk and handle splitting
#                 self._write_single_flow_to_csv(flow_data)
#             except Exception as e:
#                  # Catch errors during the actual writing process (e.g., IOError)
#                  print(f"FlowSession: Error writing collected flow data to CSV: {e}. Skipping this flow for writing.", file=sys.stderr)
#                  # Log the error and continue processing the next flow data dictionary.
#                  # The flow that generated this data *was* already marked for removal if data extraction succeeded.


#         # --- Remove the successfully identified finished flows from the main dictionary ---
#         # We remove flows whose data *was successfully extracted* and *attempted* to be written.
#         # Flows where get_data() failed were NOT added to finished_flows_data_to_write and thus not marked for removal.
#         with self.lock: # Lock while modifying the main dictionary
#             for key in keys_to_remove_after_processing:
#                 # Check if the key still exists before deleting (handle potential concurrent modifications or flows that failed to write later)
#                 if key in self.flows:
#                      # print(f"DEBUG GC: Removing finished flow {key} from dictionary after processing attempt.") # Optional debug
#                      del self.flows[key]

#         # print(f"FlowSession: write_data_csv cycle finished. {len(finished_flows_data_to_write)} flows processed and removed.") # Optional debug


#     def garbage_collect(self) -> None:
#         # This method is triggered by on_packet_received (packet count or duration) or toPacketList or the sending thread.
#         # Its primary purpose is to trigger the processing and writing of *finished* flows.
#         # write_data_csv now contains the logic to identify finished flows, get their data, write them, and remove them from self.flows.

#         # --- Process finished flows (write to CSV if enabled) ---
#         # write_data_csv contains the core logic now.
#         if self.to_csv or self.server_endpoint is not None:
#              # Only run GC if there's a reason to process flows (CSV or Server endpoint)
#              # write_data_csv handles CSV. Server sending needs a separate mechanism if it uses finished flows.
#              # Let's just call write_data_csv here if CSV is enabled.
#              # If server sending also relies on the same garbage_collect logic, this needs redesign.
#              # Assuming write_data_csv is the main processing step triggered by GC.
#              try:
#                   # Call the method that processes finished flows, writes them, and removes them.
#                   # write_data_csv internally uses the lock when accessing self.flows.
#                   self.write_data_csv()
#              except Exception as e:
#                   print(f"FlowSession: Error caught during write_data_csv call in garbage_collect: {e}", file=sys.stderr)
#                   # Log and continue.

#         # --- Original code had `self.flows = {}` here ---
#         # This has been replaced by the logic within write_data_csv to remove only processed flows.
#         # So, do NOT clear self.flows = {} here anymore.


#     # --- toPacketList method (Called by AsyncSniffer on stop) ---
#     def toPacketList(self):
#         """Called by AsyncSniffer when it stops. Ensures final cleanup."""
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform one last garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         # garbage_collect calls write_data_csv if to_csv is True, which processes *finished* flows, writes them, and removes them.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)


#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList() # Return whatever the parent does


#     # --- Close method (Optional - might be called by other session types) ---
#     # Scapy's AsyncSniffer calls toPacketList, which handles our cleanup now.
#     # Keeping a 'close' method is good practice if other parts of PyFlowmeter or Scapy
#     # might expect it, but based on your snippets, toPacketList seems the primary stop handler.
#     # Let's just ensure toPacketList handles the cleanup. This separate 'close' might not be strictly needed.
#     # Keeping it as a potential entry point for future compatibility or if called by other code.
#     def close(self):
#          print("FlowSession: close() method called.")
#          # Delegate cleanup to toPacketList if possible, or duplicate cleanup logic
#          # Calling toPacketList seems safest as it includes final GC and closing.
#          try:
#              self.toPacketList()
#          except Exception as e:
#               print(f"FlowSession: Error during close() calling toPacketList: {e}", file=sys.stderr)
#          print("FlowSession: close() method finished.")


#     # --- get_flows method (Assuming this exists and is called by sending thread or externally) ---
#     # Based on the send_flows_to_server snippet, this might be called.
#     def get_flows(self) -> list:
#         # Returns a list of *active* flows. Does NOT process or clear them.
#         with self.lock: # Use lock for thread-safe access
#              return list(self.flows.values())

#     # --- write_data_csv method (Final Version, called by garbage_collect) ---
#     # This method identifies finished flows, gets their data, writes them, and removes them.
#     def write_data_csv(self):
#         """Identifies finished flows, gets their data, writes them to CSV chunks, and removes them."""
#         # This method is called by garbage_collect.
#         if not self.to_csv or not self.output_dir:
#              # CSV output is disabled or directory not set
#              return

#         # --- Identify flows ready for output in this garbage collection cycle ---
#         finished_flows_for_writing = []
#         keys_to_remove_after_processing = []
#         current_time = time.time() # Get current time for timeout checks

#         # Use defined constants for criteria
#         FLOW_IDLE_TIMEOUT_COLLECTION = EXPIRED_UPDATE
#         FLOW_DURATION_TIMEOUT_COLLECTION = FLOW_DURATION_TIMEOUT_CONST

#         with self.lock: # Lock the flows dictionary while iterating and deciding what to process/remove
#             # Iterate over a copy of items to allow modification during iteration
#             for key, flow in list(self.flows.items()):
#                 is_finished = False

#                 # Criterion 1: Flow Duration Timeout
#                 if hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 2: Idle Timeout (if no packet received recently)
#                 # Needs flow.latest_timestamp attribute
#                 elif hasattr(flow, 'latest_timestamp') and (current_time - flow.latest_timestamp) > FLOW_IDLE_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 3: Explicit Flags (like FIN/RST - needs state in Flow object, not shown)
#                 # if hasattr(flow, '_is_finished_by_flag') and flow._is_finished_by_flag:
#                 #     is_finished = True

#                 # Add other finish criteria if needed by PyFlowmeter (e.g., maximum packet count per flow instance?)

#                 # If the flow is considered finished in this cycle
#                 if is_finished:
#                     try:
#                         # Get the data for the finished flow - this is where features are calculated
#                         finished_flow_data = flow.get_data()
#                         finished_flows_data_to_write.append(finished_flow_data) # Collect data for writing
#                         keys_to_remove_after_processing.append(key) # Mark key for removal *if data extraction succeeds*
#                         # print(f"DEBUG GC: Collected data for finished flow {key}.") # Optional debug
#                     except Exception as e:
#                          # Catch errors during data retrieval (e.g., ZeroDivisionError, though hopefully fixed in flow_bytes)
#                          print(f"FlowSession: Error getting data for finished flow {key}: {e}. Skipping flow write and removal.", file=sys.stderr)
#                          # Do NOT add to keys_to_remove_after_processing if data extraction failed.
#                          # This flow will remain in self.flows and might be attempted again later.


#         # --- Write the collected finished flows data to CSV chunks ---
#         if not finished_flows_data_to_write:
#             # No finished flows with successfully extracted data to write in this cycle
#             # print("DEBUG: write_data_csv found finished flows, but none had data ready for writing.") # Optional debug
#             return # Nothing to write

#         # Process each collected flow data dictionary
#         # This loop calls _write_single_flow_to_csv for each dictionary and handles chunking/splitting
#         for flow_data in finished_flows_data_to_write:
#             try:
#                 # Write this flow's data to the current CSV chunk and handle splitting
#                 self._write_single_flow_to_csv(flow_data)
#             except Exception as e:
#                  # Catch errors during the actual writing process (e.g., IOError)
#                  print(f"FlowSession: Error writing collected flow data to CSV: {e}. Skipping this flow for writing.", file=sys.stderr)
#                  # Log the error and continue processing the next flow data dictionary.
#                  # The flow that generated this data *was* already marked for removal if data extraction succeeded.


#         # --- Remove the successfully identified finished flows from the main dictionary ---
#         # We remove flows whose data *was successfully extracted* and *attempted* to be written.
#         # Flows where get_data() failed were NOT added to finished_flows_data_to_write and thus not marked for removal.
#         with self.lock: # Lock while modifying the main dictionary
#             for key in keys_to_remove_after_processing:
#                 # Check if the key still exists before deleting (handle potential concurrent modifications or flows that failed to write later)
#                 if key in self.flows:
#                      # print(f"DEBUG GC: Removing finished flow {key} from dictionary after processing attempt.") # Optional debug
#                      del self.flows[key]

#         # print(f"FlowSession: write_data_csv cycle finished. {len(finished_flows_data_to_write)} flows processed and removed.") # Optional debug


#     def garbage_collect(self) -> None:
#         # This method is triggered by on_packet_received (packet count or duration) or toPacketList or the sending thread.
#         # Its primary purpose is to trigger the processing and writing of *finished* flows.
#         # write_data_csv now contains the logic to identify finished flows, get their data, write them, and remove them from self.flows.

#         # --- Process finished flows (write to CSV if enabled) ---
#         # write_data_csv contains the core logic now.
#         if self.to_csv or self.server_endpoint is not None:
#              # Only run GC if there's a reason to process flows (CSV or Server endpoint)
#              # write_data_csv handles CSV. Server sending needs a separate mechanism if it uses finished flows.
#              # Let's just call write_data_csv here if CSV is enabled.
#              # If server sending also relies on the same garbage_collect logic, this needs redesign.
#              # Assuming write_data_csv is the main processing step triggered by GC.
#              try:
#                   # Call the method that processes finished flows, writes them, and removes them.
#                   # write_data_csv internally uses the lock when accessing self.flows.
#                   self.write_data_csv()
#              except Exception as e:
#                   print(f"FlowSession: Error caught during write_data_csv call in garbage_collect: {e}", file=sys.stderr)
#                   # Log and continue.

#         # --- Original code had `self.flows = {}` here ---
#         # This has been replaced by the logic within write_data_csv to remove only processed flows.
#         # So, do NOT clear self.flows = {} here anymore.


#     # --- toPacketList method (Called by AsyncSniffer on stop) ---
#     def toPacketList(self):
#         """Called by AsyncSniffer when it stops. Ensures final cleanup."""
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform one last garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         # garbage_collect calls write_data_csv if to_csv is True, which processes *finished* flows, writes them, and removes them.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)


#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         # This is crucial to save any data that didn't fill a complete batch.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList() # Return whatever the parent does


#     # --- Close method (Optional - might be called by other session types) ---
#     # Scapy's AsyncSniffer calls toPacketList, which handles our cleanup now.
#     # Keeping a 'close' method is good practice if other parts of PyFlowmeter or Scapy
#     # might expect it, but based on your snippets, toPacketList seems the primary stop handler.
#     # Let's just ensure toPacketList handles the cleanup. This separate 'close' might not be strictly needed.
#     # Keeping it as a potential entry entry point for future compatibility or if called by other code.
#     def close(self):
#          print("FlowSession: close() method called.")
#          # Delegate cleanup to toPacketList if possible, or duplicate cleanup logic
#          # Calling toPacketList seems safest as it includes final GC and closing.
#          try:
#              self.toPacketList()
#          except Exception as e:
#               print(f"FlowSession: Error during close() calling toPacketList: {e}", file=sys.stderr)
#          print("FlowSession: close() method finished.")


#     # --- get_flows method (Assuming this exists and is called by sending thread or externally) ---
#     # Based on the send_flows_to_server snippet, this might be called.
#     def get_flows(self) -> list:
#         # Returns a list of *active* flows. Does NOT process or clear them.
#         with self.lock: # Use lock for thread-safe access
#              return list(self.flows.values())

#     # --- write_data_csv method (Final Version, called by garbage_collect) ---
#     # This method identifies finished flows, gets their data, writes them, and removes them.
#     def write_data_csv(self):
#         """Identifies finished flows, gets their data, writes them to CSV chunks, and removes them."""
#         # This method is called by garbage_collect.
#         if not self.to_csv or not self.output_dir:
#              # CSV output is disabled or directory not set
#              # print("DEBUG: write_data_csv called but CSV output is disabled.") # Optional debug
#              return

#         # --- Identify flows ready for output in this garbage collection cycle ---
#         finished_flows_data_to_write = []
#         keys_to_remove_after_processing = []
#         current_time = time.time() # Get current time for timeout checks

#         # Use defined constants for criteria
#         FLOW_IDLE_TIMEOUT_COLLECTION = EXPIRED_UPDATE
#         FLOW_DURATION_TIMEOUT_COLLECTION = FLOW_DURATION_TIMEOUT_CONST

#         with self.lock: # Lock the flows dictionary while iterating and deciding what to process/remove
#             # Iterate over a copy of items to allow modification during iteration
#             for key, flow in list(self.flows.items()):
#                 is_finished = False

#                 # Criterion 1: Flow Duration Timeout
#                 if hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 2: Idle Timeout (if no packet received recently)
#                 # Needs flow.latest_timestamp attribute
#                 elif hasattr(flow, 'latest_timestamp') and (current_time - flow.latest_timestamp) > FLOW_IDLE_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 3: Explicit Flags (like FIN/RST - needs state in Flow object, not shown)
#                 # if hasattr(flow, '_is_finished_by_flag') and flow._is_finished_by_flag:
#                 #     is_finished = True

#                 # Add other finish criteria if needed by PyFlowmeter (e.g., maximum packet count per flow instance?)

#                 # If the flow is considered finished in this cycle
#                 if is_finished:
#                     try:
#                         # Get the data for the finished flow - this is where features are calculated
#                         finished_flow_data = flow.get_data()
#                         finished_flows_data_to_write.append(finished_flow_data) # Collect data for writing
#                         keys_to_remove_after_processing.append(key) # Mark key for removal *if data extraction succeeds*
#                         # print(f"DEBUG GC: Collected data for finished flow {key}.") # Optional debug
#                     except Exception as e:
#                          # Catch errors during data retrieval (e.g., ZeroDivisionError, though hopefully fixed in flow_bytes)
#                          print(f"FlowSession: Error getting data for finished flow {key}: {e}. Skipping flow write and removal.", file=sys.stderr)
#                          # Do NOT add to keys_to_remove_after_processing if data extraction failed.
#                          # This flow will remain in self.flows and might be attempted again later.


#         # --- Write the collected finished flows data to CSV chunks ---
#         if not finished_flows_data_to_write:
#             # No finished flows with successfully extracted data to write in this cycle
#             # print("DEBUG: write_data_csv found finished flows, but none had data ready for writing.") # Optional debug
#             return # Nothing to write

#         # Process each collected flow data dictionary
#         # This loop calls _write_single_flow_to_csv for each dictionary and handles chunking/splitting
#         for flow_data in finished_flows_data_to_write:
#             try:
#                 # Write this flow's data to the current CSV chunk and handle splitting
#                 self._write_single_flow_to_csv(flow_data)
#             except Exception as e:
#                  # Catch errors during the actual writing process (e.g., IOError)
#                  print(f"FlowSession: Error writing collected flow data to CSV: {e}. Skipping this flow for writing.", file=sys.stderr)
#                  # Log the error and continue processing the next flow data dictionary.
#                  # The flow that generated this data *was* already marked for removal if data extraction succeeded.


#         # --- Remove the successfully identified finished flows from the main dictionary ---
#         # We remove flows whose data *was successfully extracted* and *attempted* to be written.
#         # Flows where get_data() failed were NOT added to finished_flows_data_to_write and thus not marked for removal.
#         with self.lock: # Lock while modifying the main dictionary
#             for key in keys_to_remove_after_processing:
#                 # Check if the key still exists before deleting (handle potential concurrent modifications or flows that failed to write later)
#                 if key in self.flows:
#                      # print(f"DEBUG GC: Removing finished flow {key} from dictionary after processing attempt.") # Optional debug
#                      del self.flows[key]

#         # print(f"FlowSession: write_data_csv cycle finished. {len(finished_flows_data_to_write)} flows processed and removed.") # Optional debug


#     def garbage_collect(self) -> None:
#         # This method is triggered by on_packet_received (packet count or duration) or toPacketList or the sending thread.
#         # Its primary purpose is to trigger the processing and writing of *finished* flows.
#         # write_data_csv now contains the logic to identify finished flows, get their data, write them, and remove them from self.flows.

#         # --- Process finished flows (write to CSV if enabled) ---
#         # write_data_csv contains the core logic now.
#         if self.to_csv or self.server_endpoint is not None:
#              # Only run GC if there's a reason to process flows (CSV or Server endpoint)
#              # write_data_csv handles CSV. Server sending needs a separate mechanism if it uses finished flows.
#              # Let's just call write_data_csv here if CSV is enabled.
#              # If server sending also relies on the same garbage_collect logic, this needs redesign.
#              # Assuming write_data_csv is the main processing step triggered by GC.
#              try:
#                   # Call the method that processes finished flows, writes them, and removes them.
#                   # write_data_csv internally uses the lock when accessing self.flows.
#                   self.write_data_csv()
#              except Exception as e:
#                   print(f"FlowSession: Error caught during write_data_csv call in garbage_collect: {e}", file=sys.stderr)
#                   # Log and continue.

#         # --- Original code had `self.flows = {}` here ---
#         # This has been replaced by the logic within write_data_csv to remove only processed flows.
#         # So, do NOT clear self.flows = {} here anymore.


#     # --- toPacketList method (Called by AsyncSniffer on stop) ---
#     def toPacketList(self):
#         """Called by AsyncSniffer when it stops. Ensures final cleanup."""
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform one last garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         # garbage_collect calls write_data_csv if to_csv is True, which processes *finished* flows, writes them, and removes them.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)


#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         # This is crucial to save any data that didn't fill a complete batch.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList() # Return whatever the parent does


#     # --- Close method (Optional - might be called by other session types) ---
#     # Scapy's AsyncSniffer calls toPacketList, which handles our cleanup now.
#     # Keeping a 'close' method is good practice if other parts of PyFlowmeter or Scapy
#     # might expect it, but based on your snippets, toPacketList seems the primary stop handler.
#     # Let's just ensure toPacketList handles the cleanup. This separate 'close' might not be strictly needed.
#     # Keeping it as a potential entry point for future compatibility or if called by other code.
#     def close(self):
#          print("FlowSession: close() method called.")
#          # Delegate cleanup to toPacketList if possible, or duplicate cleanup logic
#          # Calling toPacketList seems safest as it includes final GC and closing.
#          try:
#              self.toPacketList()
#          except Exception as e:
#               print(f"FlowSession: Error during close() calling toPacketList: {e}", file=sys.stderr)
#          print("FlowSession: close() method finished.")


#     # --- get_flows method (Assuming this exists and is called by sending thread or externally) ---
#     # Based on the send_flows_to_server snippet, this might be called.
#     def get_flows(self) -> list:
#         # Returns a list of *active* flows. Does NOT process or clear them.
#         with self.lock: # Use lock for thread-safe access
#              return list(self.flows.values())

#     # --- write_data_csv method (Final Version, called by garbage_collect) ---
#     # This method identifies finished flows, gets their data, writes them, and removes them.
#     def write_data_csv(self):
#         """Identifies finished flows, gets their data, writes them to CSV chunks, and removes them."""
#         # This method is called by garbage_collect.
#         if not self.to_csv or not self.output_dir:
#              # CSV output is disabled or directory not set
#              return

#         # --- Identify flows ready for output in this garbage collection cycle ---
#         finished_flows_data_to_write = []
#         keys_to_remove_after_processing = []
#         current_time = time.time() # Get current time for timeout checks

#         # Use defined constants for criteria
#         FLOW_IDLE_TIMEOUT_COLLECTION = EXPIRED_UPDATE
#         FLOW_DURATION_TIMEOUT_COLLECTION = FLOW_DURATION_TIMEOUT_CONST

#         with self.lock: # Lock the flows dictionary while iterating and deciding what to process/remove
#             # Iterate over a copy of items to allow modification during iteration
#             for key, flow in list(self.flows.items()):
#                 is_finished = False

#                 # Criterion 1: Flow Duration Timeout
#                 if hasattr(flow, 'duration') and flow.duration > FLOW_DURATION_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 2: Idle Timeout (if no packet received recently)
#                 # Needs flow.latest_timestamp attribute
#                 elif hasattr(flow, 'latest_timestamp') and (current_time - flow.latest_timestamp) > FLOW_IDLE_TIMEOUT_COLLECTION:
#                      is_finished = True
#                 # Criterion 3: Explicit Flags (like FIN/RST - needs state in Flow object, not shown)
#                 # if hasattr(flow, '_is_finished_by_flag') and flow._is_finished_by_flag:
#                 #     is_finished = True

#                 # Add other finish criteria if needed by PyFlowmeter (e.g., maximum packet count per flow instance?)

#                 # If the flow is considered finished in this cycle
#                 if is_finished:
#                     try:
#                         # Get the data for the finished flow - this is where features are calculated
#                         finished_flow_data = flow.get_data()
#                         finished_flows_data_to_write.append(finished_flow_data) # Collect data for writing
#                         keys_to_remove_after_processing.append(key) # Mark key for removal *if data extraction succeeds*
#                         # print(f"DEBUG GC: Collected data for finished flow {key}.") # Optional debug
#                     except Exception as e:
#                          # Catch errors during data retrieval (e.g., ZeroDivisionError, though hopefully fixed in flow_bytes)
#                          print(f"FlowSession: Error getting data for finished flow {key}: {e}. Skipping flow write and removal.", file=sys.stderr)
#                          # Do NOT add to keys_to_remove_after_processing if data extraction failed.
#                          # This flow will remain in self.flows and might be attempted again later.


#         # --- Write the collected finished flows data to CSV chunks ---
#         if not finished_flows_data_to_write:
#             # No finished flows with successfully extracted data to write in this cycle
#             return

#         # Process each collected flow data dictionary
#         # This loop calls _write_single_flow_to_csv for each dictionary and handles chunking/splitting
#         for flow_data in finished_flows_data_to_write:
#             try:
#                 # Write this flow's data to the current CSV chunk and handle splitting
#                 self._write_single_flow_to_csv(flow_data)
#             except Exception as e:
#                  # Catch errors during the actual writing process (e.g., IOError)
#                  print(f"FlowSession: Error writing collected flow data to CSV: {e}. Skipping this flow for writing.", file=sys.stderr)
#                  # Log the error and continue processing the next flow data dictionary.
#                  # The flow that generated this data *was* already marked for removal if data extraction succeeded.


#         # --- Remove the successfully identified finished flows from the main dictionary ---
#         # We remove flows whose data *was successfully extracted* and *attempted* to be written.
#         # Flows where get_data() failed were NOT added to finished_flows_data_to_write and thus not marked for removal.
#         with self.lock: # Lock while modifying the main dictionary
#             for key in keys_to_remove_after_processing:
#                 # Check if the key still exists before deleting (handle potential concurrent modifications or flows that failed to write later)
#                 if key in self.flows:
#                      del self.flows[key]

#     def garbage_collect(self) -> None:
#         # This method is triggered by on_packet_received (packet count or duration) or toPacketList or the sending thread.
#         # Its primary purpose is to trigger the processing and writing of *finished* flows.
#         # write_data_csv now contains the logic to identify finished flows, get their data, write them, and remove them from self.flows.

#         # --- Process finished flows (write to CSV if enabled) ---
#         # write_data_csv contains the core logic now.
#         if self.to_csv or self.server_endpoint is not None:
#              # Only run GC if there's a reason to process flows (CSV or Server endpoint)
#              try:
#                   # Call the method that processes finished flows, writes them, and removes them.
#                   self.write_data_csv()
#              except Exception as e:
#                   print(f"FlowSession: Error caught during write_data_csv call in garbage_collect: {e}", file=sys.stderr)
#                   # Log and continue.

#     # --- toPacketList method (Called by AsyncSniffer on stop) ---
#     def toPacketList(self):
#         """Called by AsyncSniffer when it stops. Ensures final cleanup."""
#         print("FlowSession: toPacketList called (sniffer stopping). Performing final cleanup...")

#         # Perform one last garbage collection cycle to process any flows that finished
#         # but weren't written by the periodic triggers before the stop signal.
#         try:
#              self.garbage_collect()
#         except Exception as e:
#              print(f"FlowSession: Error during final garbage_collect in toPacketList: {e}", file=sys.stderr)

#         # Explicitly close the last open file AFTER the final garbage collection cycle.
#         self._close_current_csv_chunk()

#         # Call parent class method toPacketList (likely does final Scapy processing)
#         print("FlowSession: Calling super().toPacketList()...")
#         return super(FlowSession, self).toPacketList()


#     # --- Close method (Optional - might be called by other session types) ---
#     # Scapy's AsyncSniffer calls toPacketList, which handles our cleanup now.
#     # Keeping a 'close' method is good practice if other parts of PyFlowmeter or Scapy
#     # might expect it, but based on your snippets, toPacketList seems the primary stop handler.
#     def close(self):
#          print("FlowSession: close() method called.")
#          # Delegate cleanup to toPacketList if possible, or duplicate cleanup logic
#          try:
#              self.toPacketList()
#          except Exception as e:
#               print(f"FlowSession: Error during close() calling toPacketList: {e}", file=sys.stderr)
#          print("FlowSession: close() method finished.")

#     # --- get_flows method (Assuming this exists and is called by sending thread or externally) ---
#     def get_flows(self) -> list:
#         # Returns a list of *active* flows. Does NOT process or clear them.
#         with self.lock:
#              return list(self.flows.values())







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