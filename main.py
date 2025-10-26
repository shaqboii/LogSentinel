import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import pyshark
import google.generativeai as genai
import ctypes
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import textwrap

# Fix blurry text on high-DPI displays (Windows)
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

genai.configure(api_key="AIzaSyC_4C8CbBsIRR9Raka9FUbGJ6VR0v35rZ8")


# Store parsed packets and summaries
parsed_packets = []
packet_summaries = []
packet_details = []  # Store detailed packet information
expanded_packets = {}  # Track which packets are expanded

# Query Google AI
def query_google_ai(prompt, model="gemini-2.5-flash"):
    try:
        model = genai.GenerativeModel(model)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error querying Google AI: {e}"


def open_pcap_file():
    file_path = filedialog.askopenfilename(
        title="Select a PCAP file",
        filetypes=[("PCAP files", "*.pcap *.pcapng *.cap*"), ("All files", "*.*")]
    )
    if file_path:
        label.config(text=f"Selected: {file_path}")
        display_packet_summary(file_path)

def display_packet_summary(file_path):
    global parsed_packets, packet_summaries, packet_details, expanded_packets
    parsed_packets = []
    packet_summaries = []
    packet_details = []
    expanded_packets = {}

    try:
        capture = pyshark.FileCapture(file_path)
        tree.delete(*tree.get_children())  # Clear previous entries

        packet_count = 0
        for packet in capture:
            try:
                src_port = dst_port = "N/A"
                extra_info = []
                tcp_flags = []
                
                packet_time = packet.sniff_time if hasattr(packet, 'sniff_time') else 'N/A'
                source = destination = protocol = 'N/A'
                length = str(packet.length) if hasattr(packet, 'length') else 'N/A'
                
                # Collect detailed information
                details = {}
                details['Frame Info'] = {}
                details['Frame Info']['Frame Number'] = packet_count + 1
                details['Frame Info']['Frame Length'] = length
                details['Frame Info']['Capture Time'] = str(packet_time)
                
                if hasattr(packet, 'frame_info'):
                    if hasattr(packet.frame_info, 'time_epoch'):
                        details['Frame Info']['Epoch Time'] = packet.frame_info.time_epoch
                    if hasattr(packet.frame_info, 'protocols'):
                        details['Frame Info']['Protocols in Frame'] = packet.frame_info.protocols

                if hasattr(packet, 'ip'):
                    source = packet.ip.src
                    destination = packet.ip.dst
                    protocol = packet.highest_layer
                    
                    details['IP Layer'] = {}
                    details['IP Layer']['Version'] = getattr(packet.ip, 'version', 'N/A')
                    details['IP Layer']['Header Length'] = getattr(packet.ip, 'hdr_len', 'N/A')
                    details['IP Layer']['TTL'] = getattr(packet.ip, 'ttl', 'N/A')
                    details['IP Layer']['Protocol'] = getattr(packet.ip, 'proto', 'N/A')
                    details['IP Layer']['Checksum'] = getattr(packet.ip, 'checksum', 'N/A')
                    details['IP Layer']['Flags'] = getattr(packet.ip, 'flags', 'N/A')
                    details['IP Layer']['Fragment Offset'] = getattr(packet.ip, 'frag_offset', 'N/A')
                    details['IP Layer']['Identification'] = getattr(packet.ip, 'id', 'N/A')
                    
                elif hasattr(packet, 'ipv6'):
                    source = packet.ipv6.src
                    destination = packet.ipv6.dst
                    protocol = packet.highest_layer
                    
                    details['IPv6 Layer'] = {}
                    details['IPv6 Layer']['Version'] = getattr(packet.ipv6, 'version', 'N/A')
                    details['IPv6 Layer']['Traffic Class'] = getattr(packet.ipv6, 'tclass', 'N/A')
                    details['IPv6 Layer']['Flow Label'] = getattr(packet.ipv6, 'flow', 'N/A')
                    details['IPv6 Layer']['Payload Length'] = getattr(packet.ipv6, 'plen', 'N/A')
                    details['IPv6 Layer']['Next Header'] = getattr(packet.ipv6, 'nxt', 'N/A')
                    details['IPv6 Layer']['Hop Limit'] = getattr(packet.ipv6, 'hlim', 'N/A')
                    
                elif hasattr(packet, 'arp'):
                    source = getattr(packet.arp, 'src_proto_ipv4', 'N/A')
                    destination = getattr(packet.arp, 'dst_proto_ipv4', 'N/A')
                    protocol = 'ARP'
                    
                    details['ARP Layer'] = {}
                    details['ARP Layer']['Hardware Type'] = getattr(packet.arp, 'hw_type', 'N/A')
                    details['ARP Layer']['Protocol Type'] = getattr(packet.arp, 'proto_type', 'N/A')
                    details['ARP Layer']['Operation'] = getattr(packet.arp, 'opcode', 'N/A')
                    details['ARP Layer']['Sender MAC'] = getattr(packet.arp, 'src_hw_mac', 'N/A')
                    details['ARP Layer']['Sender IP'] = getattr(packet.arp, 'src_proto_ipv4', 'N/A')
                    details['ARP Layer']['Target MAC'] = getattr(packet.arp, 'dst_hw_mac', 'N/A')
                    details['ARP Layer']['Target IP'] = getattr(packet.arp, 'dst_proto_ipv4', 'N/A')
                else:
                    protocol = getattr(packet, 'highest_layer', 'N/A')

                # Ethernet layer info
                if hasattr(packet, 'eth'):
                    details['Ethernet Layer'] = {}
                    details['Ethernet Layer']['Source MAC'] = getattr(packet.eth, 'src', 'N/A')
                    details['Ethernet Layer']['Destination MAC'] = getattr(packet.eth, 'dst', 'N/A')
                    details['Ethernet Layer']['Type'] = getattr(packet.eth, 'type', 'N/A')

                # TCP/UDP ports
                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    
                    details['TCP Layer'] = {}
                    details['TCP Layer']['Source Port'] = src_port
                    details['TCP Layer']['Destination Port'] = dst_port
                    details['TCP Layer']['Sequence Number'] = getattr(packet.tcp, 'seq', 'N/A')
                    details['TCP Layer']['Acknowledgment Number'] = getattr(packet.tcp, 'ack', 'N/A')
                    details['TCP Layer']['Header Length'] = getattr(packet.tcp, 'hdr_len', 'N/A')
                    details['TCP Layer']['Window Size'] = getattr(packet.tcp, 'window_size', 'N/A')
                    details['TCP Layer']['Checksum'] = getattr(packet.tcp, 'checksum', 'N/A')
                    details['TCP Layer']['Urgent Pointer'] = getattr(packet.tcp, 'urgent_pointer', 'N/A')

                    tcp_flags = []
                    if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                        tcp_flags.append("SYN")
                    if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1':
                        tcp_flags.append("ACK")
                    if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                        tcp_flags.append("FIN")
                    if hasattr(packet.tcp, 'flags_rst') and packet.tcp.flags_rst == '1':
                        tcp_flags.append("RST")
                    if hasattr(packet.tcp, 'flags_push') and packet.tcp.flags_push == '1':
                        tcp_flags.append("PSH")
                    if hasattr(packet.tcp, 'flags_urg') and packet.tcp.flags_urg == '1':
                        tcp_flags.append("URG")

                    if tcp_flags:
                        details['TCP Layer']['Flags'] = ', '.join(tcp_flags)
                        extra_info.append(f"TCP Control Flags: {', '.join(tcp_flags)}")

                elif hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
                    protocol = packet.highest_layer
                    
                    details['UDP Layer'] = {}
                    details['UDP Layer']['Source Port'] = src_port
                    details['UDP Layer']['Destination Port'] = dst_port
                    details['UDP Layer']['Length'] = getattr(packet.udp, 'length', 'N/A')
                    details['UDP Layer']['Checksum'] = getattr(packet.udp, 'checksum', 'N/A')
                    
                    if hasattr(packet.udp, 'flags'):
                        flags = packet.udp.flags
                        details['UDP Layer']['Flags'] = flags
                        extra_info.append(f"UDP Flags: {flags}")

                # Application layer protocols
                if hasattr(packet, 'dns'):
                    details['DNS Layer'] = {}
                    if hasattr(packet.dns, 'qry_name'):
                        details['DNS Layer']['Query Name'] = packet.dns.qry_name
                        extra_info.append(f"DNS Query: {packet.dns.qry_name}")
                    if hasattr(packet.dns, 'qry_type'):
                        details['DNS Layer']['Query Type'] = packet.dns.qry_type
                    if hasattr(packet.dns, 'flags'):
                        details['DNS Layer']['Flags'] = packet.dns.flags
                    if hasattr(packet.dns, 'id'):
                        details['DNS Layer']['Transaction ID'] = packet.dns.id

                if hasattr(packet, 'http'):
                    details['HTTP Layer'] = {}
                    if hasattr(packet.http, 'request_method'):
                        details['HTTP Layer']['Request Method'] = packet.http.request_method
                        extra_info.append(f"HTTP Method: {packet.http.request_method}")
                    if hasattr(packet.http, 'request_uri'):
                        details['HTTP Layer']['Request URI'] = packet.http.request_uri
                    if hasattr(packet.http, 'host'):
                        details['HTTP Layer']['Host'] = packet.http.host
                    if hasattr(packet.http, 'user_agent'):
                        details['HTTP Layer']['User Agent'] = packet.http.user_agent
                    if hasattr(packet.http, 'response_code'):
                        details['HTTP Layer']['Response Code'] = packet.http.response_code

                if hasattr(packet, 'tls'):
                    details['TLS Layer'] = {}
                    if hasattr(packet.tls, 'record_version'):
                        details['TLS Layer']['Record Version'] = packet.tls.record_version
                        extra_info.append(f"TLS Version: {packet.tls.record_version}")
                    if hasattr(packet.tls, 'handshake_type'):
                        details['TLS Layer']['Handshake Type'] = packet.tls.handshake_type
                    if hasattr(packet.tls, 'handshake_version'):
                        details['TLS Layer']['Handshake Version'] = packet.tls.handshake_version

                if hasattr(packet, 'icmp'):
                    details['ICMP Layer'] = {}
                    details['ICMP Layer']['Type'] = getattr(packet.icmp, 'type', 'N/A')
                    details['ICMP Layer']['Code'] = getattr(packet.icmp, 'code', 'N/A')
                    details['ICMP Layer']['Checksum'] = getattr(packet.icmp, 'checksum', 'N/A')

                layers = [layer.layer_name for layer in packet.layers]
                details['All Layers'] = ', '.join(layers)
                extra_info.append(f"Layers: {', '.join(layers)}")

                
                row = (
                    packet_count + 1,
                    packet_time,
                    source,
                    src_port,
                    destination,
                    dst_port,
                    protocol,
                    length
                )
                parsed_packets.append(row)
                packet_details.append(details)

                summary = (f"Packet #{packet_count + 1}: {protocol} from {source}:{src_port} to {destination}:{dst_port}, "
                          f"{length} bytes at {packet_time}")
                if extra_info:
                    summary += " | " + " | ".join(extra_info)
                
                packet_summaries.append(summary)

                row_tag = "evenrow" if packet_count % 2 == 0 else "oddrow"
                tree.insert("", "end", values=row, tags=(row_tag,))

                packet_count += 1

                if packet_count % 10 == 0:
                    root.update_idletasks()
                if packet_count >= 100:
                    break

            except Exception as e:
                print(f"Error parsing packet {packet_count}: {e}")
                packet_count += 1

        capture.close()
        label.config(text=f"Loaded {packet_count} packets from {file_path}")
        print(f"Total packets loaded: {packet_count}")

    except Exception as e:
        label.config(text=f"Error: {e}")
        print(f"Detailed error: {e}")
        import traceback
        traceback.print_exc()

def scan_for_critical_packets():
    if not packet_summaries:
        messagebox.showinfo("Scan Results", "No packets loaded.")
        return

    # Build a single prompt for all packets
    prompt = (
        "Rate the risk of each packet below from 1 to 100. Return only the ratings in order, one per line:\n\n"
    )
    for i, summary in enumerate(packet_summaries):
        prompt += f"Packet {i+1}: {summary}\n"

    response = query_google_ai(prompt)

    # Parse ratings from response
    lines = response.strip().splitlines()
    ratings = []
    for line in lines:
        try:
            rating = int(''.join(filter(str.isdigit, line.strip())))
            ratings.append(rating)
        except:
            ratings.append(0)

    # Apply tags based on rating
    for i, rating in enumerate(ratings):
        try:
            item_id = tree.get_children()[i]
            if rating >= 80:
                tree.item(item_id, tags=("critical_packet",))
            elif rating >= 50:
                tree.item(item_id, tags=("warning_packet",))
        except IndexError:
            continue

    messagebox.showinfo("Scan Complete", "Packets have been scanned and flagged.")

def build_detailed_summary():
    summaries = []
    for i, details in enumerate(packet_details):
        lines = [f"Packet #{i+1}:"]
        for layer, data in details.items():
            lines.append(f"  {layer}:")
            if isinstance(data, dict):
                for k, v in data.items():
                    lines.append(f"    {k}: {v}")
            else:
                lines.append(f"    {data}")
        summaries.append("\n".join(lines))
    return "\n\n".join(summaries)



def export_ai_report():
    if not packet_summaries:
        messagebox.showinfo("Export Report", "No packets loaded.")
        return

    # Ask AI for overall summary
    prompt = (
        "Summarize the following network traffic. Highlight any suspicious activity and give a risk rating:\n\n"
        + build_detailed_summary()
    )
    overall_summary = query_google_ai(prompt)

    # Create PDF
    filename = f"AI_PCAP_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50

    def draw_text(text, indent=40, max_width=90):
        nonlocal y
        wrapper = textwrap.TextWrapper(width=max_width)
        lines = wrapper.wrap(text)
        for line in lines:
            c.drawString(indent, y, line)
            y -= 15
            if y < 50:
                c.showPage()
                y = height - 50


    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "AI-Powered PCAP Report")
    y -= 30

    # Timestamp
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 30

    # Overall Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Overall Traffic Summary:")
    y -= 20
    c.setFont("Helvetica", 10)
    draw_text(overall_summary)

    # Flagged Packets
    c.setFont("Helvetica-Bold", 12)
    y -= 30
    c.drawString(40, y, "Flagged Packets:")
    y -= 20
    c.setFont("Helvetica", 10)

    for i, item_id in enumerate(tree.get_children()):
        tags = tree.item(item_id, "tags")
        if "critical_packet" in tags or "warning_packet" in tags:
            values = tree.item(item_id, "values")
            rating_tag = "CRITICAL" if "critical_packet" in tags else "WARNING"
            draw_text(f"{rating_tag} - Packet #{values[0]} | {values[2]}:{values[3]} → {values[4]}:{values[5]} | {values[6]} | {values[7]} bytes")

    c.save()
    messagebox.showinfo("Export Complete", f"Report saved as {filename}")

def filter_packets(search_term):
    tree.delete(*tree.get_children())
    term = search_term.lower()
    row_count = 0
    for row in parsed_packets:
        if any(term in str(cell).lower() for cell in row):
            row_tag = "evenrow" if row_count % 2 == 0 else "oddrow"
            tree.insert("", "end", values=row, tags=(row_tag,))
            row_count += 1

def show_ai_summary():
    if not packet_summaries:
        messagebox.showinfo("AI Summary", "No packets loaded.")
        return

    # Build initial prompt
    prompt = (
        "Analyze the following network traffic. Summarize what is happening overall, "
        "highlight any high-risk or suspicious activity, and give a risk rating from 1 to 100:\n\n"
        + build_detailed_summary()
    )
    initial_response = query_google_ai(prompt)

    # Create chat window
    chat_window = tk.Toplevel(root)
    chat_window.title("AI Traffic Summary")
    chat_window.geometry("900x700")
    chat_window.configure(bg=bg_color)

    # Chat layout
    info_frame = tk.Frame(chat_window, bg=accent_color, padx=10, pady=8)
    info_frame.pack(fill="x", padx=10, pady=10)
    info_label = tk.Label(info_frame, text="Overall Traffic Summary", bg=accent_color, fg=fg_color, font=("Segoe UI", 9))
    info_label.pack()

    chat_frame = tk.Frame(chat_window, bg=bg_color)
    chat_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    chat_canvas = tk.Canvas(chat_frame, bg=bg_color, highlightthickness=0)
    scrollbar = tk.Scrollbar(chat_frame, orient="vertical", command=chat_canvas.yview)
    scrollbar.pack(side="right", fill="y")
    chat_canvas.pack(side="left", fill="both", expand=True)
    chat_canvas.configure(yscrollcommand=scrollbar.set)

    scrollable_frame = tk.Frame(chat_canvas, bg=bg_color)
    window_id = chat_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    def resize_canvas(event):
        canvas_width = event.width
        chat_canvas.itemconfig(window_id, width=canvas_width)

    scrollable_frame.bind("<Configure>", lambda e: chat_canvas.configure(scrollregion=chat_canvas.bbox("all")))
    chat_canvas.bind("<Configure>", resize_canvas)

    def on_mousewheel(event):
        chat_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    chat_canvas.bind_all("<MouseWheel>", on_mousewheel)

    def on_close():
        chat_canvas.unbind_all("<MouseWheel>")
        chat_window.destroy()

    chat_window.protocol("WM_DELETE_WINDOW", on_close)

    # Conversation history
    conversation_history = []

    def add_message(text, is_user=False):
        msg_frame = tk.Frame(scrollable_frame, bg=bg_color)
        msg_frame.pack(fill="x", padx=10, pady=5)

        bubble_container = tk.Frame(msg_frame, bg=bg_color)
        bubble_container.pack(anchor="e" if is_user else "w", fill="x")

        bubble = tk.Label(
            bubble_container,
            text=text,
            bg="#007acc" if is_user else "#2d2d2d",
            fg=fg_color,
            font=("Segoe UI", 10),
            wraplength=400,
            justify="left",
            padx=15,
            pady=10
        )
        bubble.pack(anchor="e" if is_user else "w", ipadx=10, ipady=5)

        chat_canvas.update_idletasks()
        chat_canvas.yview_moveto(1.0)

    def send_message():
        user_input = input_box.get().strip()
        if not user_input:
            return

        input_box.delete(0, tk.END)
        add_message(user_input, is_user=True)

        # Typing indicator
        typing_frame = tk.Frame(scrollable_frame, bg=bg_color)
        typing_frame.pack(fill="x", padx=10, pady=5)
        typing_container = tk.Frame(typing_frame, bg=bg_color)
        typing_container.pack(anchor="w")
        typing_bubble = tk.Label(
            typing_container,
            text="AI is typing...",
            bg="#2d2d2d",
            fg="#888888",
            font=("Segoe UI", 10, "italic"),
            padx=15,
            pady=10,
            wraplength=400,
            justify="left"
        )
        typing_bubble.pack(anchor="w")
        chat_window.update()

        # Build prompt with full history
        context = "You are analyzing a full PCAP file. Here is the detailed traffic information:\n\n"
        context += build_detailed_summary()
        context += "\n\nConversation so far:\n"
        for msg in conversation_history:
            context += f"{msg}\n"
        context += f"\nUser: {user_input}\nAI:"

        response = query_google_ai(context)
        conversation_history.append(f"User: {user_input}")
        conversation_history.append(f"AI: {response}")

        typing_frame.destroy()
        add_message(response, is_user=False)

    # Input area
    input_frame = tk.Frame(chat_window, bg=bg_color)
    input_frame.pack(fill="x", padx=10, pady=(0, 10))

    input_box = tk.Entry(input_frame, bg=accent_color, fg=fg_color,
                         insertbackground=fg_color, font=("Segoe UI", 10),
                         relief="flat", bd=0, highlightthickness=2,
                         highlightbackground=accent_color, highlightcolor=highlight_color)
    input_box.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=8)
    input_box.bind("<Return>", lambda e: send_message())

    send_btn = tk.Button(input_frame, text="Send", command=send_message,
                         bg=highlight_color, fg=fg_color, font=("Segoe UI", 10, "bold"),
                         padx=20, pady=8, cursor="hand2", relief="flat", bd=0)
    send_btn.pack(side="right")

    # Suggested questions
    suggestions_frame = tk.Frame(chat_window, bg=bg_color)
    suggestions_frame.pack(fill="x", padx=10, pady=(0, 10))

    suggestions = [
        "Is there any suspicious traffic?",
        "What protocols are most common?",
        "What should I investigate first?"
    ]

    def ask_suggestion(question):
        input_box.delete(0, tk.END)
        input_box.insert(0, question)
        send_message()

    for suggestion in suggestions:
        btn = tk.Button(suggestions_frame, text=suggestion,
                        command=lambda q=suggestion: ask_suggestion(q),
                        bg=accent_color, fg="#aaaaaa", font=("Segoe UI", 9),
                        relief="flat", padx=10, pady=5, cursor="hand2")
        btn.pack(side="left", padx=3)

    # Show initial AI summary
    conversation_history.append(f"AI (Initial Summary): {initial_response}")
    add_message(initial_response, is_user=False)
    input_box.focus()


def toggle_packet_details():
    selected = tree.focus()
    if not selected:
        messagebox.showinfo("Packet Details", "Please select a packet first.")
        return

    item_tags = tree.item(selected, "tags")
    if "detail" in item_tags:
        return

    values = tree.item(selected, "values")
    packet_num = int(values[0]) - 1
    if packet_num >= len(packet_details):
        messagebox.showerror("Error", "Packet details not available.")
        return

    if selected in expanded_packets:
        for detail_item in expanded_packets[selected]:
            tree.delete(detail_item)
        del expanded_packets[selected]
    else:
        details = packet_details[packet_num]
        detail_items = []

        parent = tree.parent(selected)
        index = tree.index(selected)
        insert_index = index + 1

        # Map layers to column indices
        layer_to_column_index = {
            "Frame Info": 0,
            "IP Layer": 1,
            "IPv6 Layer": 1,
            "ARP Layer": 1,
            "Ethernet Layer": 2,
            "TCP Layer": 3,
            "UDP Layer": 3,
            "DNS Layer": 4,
            "HTTP Layer": 4,
            "TLS Layer": 5,
            "ICMP Layer": 5
        }

        # Group key-value pairs by column
        column_rows = {}  # key: column index, value: list of strings
        for layer_name, layer_data in details.items():
            if layer_name in layer_to_column_index:
                idx = layer_to_column_index[layer_name]
                if idx not in column_rows:
                    column_rows[idx] = []
                column_rows[idx].append(f"{layer_name}:")
                if isinstance(layer_data, dict):
                    for k, v in layer_data.items():
                        column_rows[idx].append(f"  {k}: {v}")
                else:
                    column_rows[idx].append(f"  {layer_data}")
                column_rows[idx].append("")  # spacer

        # Determine max number of rows needed
        max_rows = max(len(rows) for rows in column_rows.values()) if column_rows else 0

        # Build and insert each row
        for i in range(max_rows):
            row_values = []
            for col in range(len(tree["columns"])):
                if col in column_rows and i < len(column_rows[col]):
                    row_values.append(column_rows[col][i])
                else:
                    row_values.append("")
            detail_item = tree.insert("", insert_index, values=row_values, tags=("detail", "detail_data"))
            detail_items.append(detail_item)
            insert_index += 1

        expanded_packets[selected] = detail_items


def analyze_selected_packet():
    selected = tree.focus()
    if not selected:
        messagebox.showinfo("AI Insight", "Please select a packet first.")
        return

    values = tree.item(selected, "values")
    packet_num = int(values[0]) - 1  # Get packet index
    
    if packet_num >= len(packet_details):
        messagebox.showerror("Error", "Packet details not available.")
        return
    
    # Pass both header values AND full details
    open_chat_window(values, packet_details[packet_num])


def open_chat_window(packet_values, packet_detail_dict):
    chat_window = tk.Toplevel(root)
    chat_window.title(f"AI Analysis - Packet #{packet_values[0]}")
    chat_window.geometry("900x700")
    chat_window.configure(bg=bg_color)
    
    # Format detailed packet info for AI
    def format_packet_details():
        lines = []
        for layer, data in packet_detail_dict.items():
            lines.append(f"\n{layer}:")
            if isinstance(data, dict):
                for k, v in data.items():
                    lines.append(f"  {k}: {v}")
            else:
                lines.append(f"  {data}")
        return "\n".join(lines)
    
    detailed_info = format_packet_details()
    
    # Packet info display at top
    info_frame = tk.Frame(chat_window, bg=accent_color, padx=10, pady=8)
    info_frame.pack(fill="x", padx=10, pady=10)
    
    info_text = f"Packet #{packet_values[0]} | {packet_values[6]} | {packet_values[2]}:{packet_values[3]} → {packet_values[4]}:{packet_values[5]} | {packet_values[7]} bytes"
    info_label = tk.Label(info_frame, text=info_text, bg=accent_color, fg=fg_color, font=("Segoe UI", 9))
    info_label.pack()
    
    # Chat display area
    chat_frame = tk.Frame(chat_window, bg=bg_color)
    chat_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    chat_canvas = tk.Canvas(chat_frame, bg=bg_color, highlightthickness=0)
    scrollbar = tk.Scrollbar(chat_frame, orient="vertical", command=chat_canvas.yview)
    scrollbar.pack(side="right", fill="y")

    chat_canvas.pack(side="left", fill="both", expand=True)
    chat_canvas.configure(yscrollcommand=scrollbar.set)

    scrollable_frame = tk.Frame(chat_canvas, bg=bg_color)
    window_id = chat_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    def resize_canvas(event):
        canvas_width = event.width
        chat_canvas.itemconfig(window_id, width=canvas_width)

    scrollable_frame.bind("<Configure>", lambda e: chat_canvas.configure(scrollregion=chat_canvas.bbox("all")))
    chat_canvas.bind("<Configure>", resize_canvas)
    
    # Enable mousewheel scrolling
    def on_mousewheel(event):
        chat_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    chat_canvas.bind_all("<MouseWheel>", on_mousewheel)
    
    # Unbind when window closes
    def on_close():
        chat_canvas.unbind_all("<MouseWheel>")
        chat_window.destroy()
    
    chat_window.protocol("WM_DELETE_WINDOW", on_close)
    
    # Store conversation history
    conversation_history = []
    
    def add_message(text, is_user=False):
        msg_frame = tk.Frame(scrollable_frame, bg=bg_color)
        msg_frame.pack(fill="x", padx=10, pady=5)

        bubble_container = tk.Frame(msg_frame, bg=bg_color)
        bubble_container.pack(anchor="e" if is_user else "w", fill="x")

        bubble = tk.Label(
            bubble_container,
            text=text,
            bg="#007acc" if is_user else "#2d2d2d",
            fg=fg_color,
            font=("Segoe UI", 10),
            wraplength=400,
            justify="left",
            padx=15,
            pady=10
        )
        bubble.pack(anchor="e" if is_user else "w", ipadx=10, ipady=5)

        chat_canvas.update_idletasks()
        chat_canvas.yview_moveto(1.0)
    
    def send_message():
        user_input = input_box.get().strip()
        if not user_input:
            return

        input_box.delete(0, tk.END)
        add_message(user_input, is_user=True)

        # Show typing indicator
        typing_frame = tk.Frame(scrollable_frame, bg=bg_color)
        typing_frame.pack(fill="x", padx=10, pady=5)

        typing_container = tk.Frame(typing_frame, bg=bg_color)
        typing_container.pack(anchor="w")

        typing_bubble = tk.Label(
            typing_container,
            text="AI is typing...",
            bg="#2d2d2d",
            fg="#888888",
            font=("Segoe UI", 10, "italic"),
            padx=15,
            pady=10,
            wraplength=400,
            justify="left"
        )
        typing_bubble.pack(anchor="w")
        chat_window.update()

        # Build prompt with FULL packet details
        context = f"""You are analyzing a network packet with the following information:

**Basic Headers:**
- Packet #: {packet_values[0]}
- Time: {packet_values[1]}
- Source: {packet_values[2]}:{packet_values[3]}
- Destination: {packet_values[4]}:{packet_values[5]}
- Protocol: {packet_values[6]}
- Length: {packet_values[7]} bytes

**Detailed Packet Information:**
{detailed_info}

Conversation so far:
"""
        for msg in conversation_history:
            context += f"{msg}\n"

        context += f"\nUser question: {user_input}\n\nRespond briefly and clearly using the detailed packet information above."

        # Query AI with dynamic prompt
        response = query_google_ai(context)
        conversation_history.append(f"User: {user_input}")
        conversation_history.append(f"AI: {response}")

        # Remove typing indicator
        typing_frame.destroy()

        # Add AI response
        add_message(response, is_user=False)
    
    # Input area
    input_frame = tk.Frame(chat_window, bg=bg_color)
    input_frame.pack(fill="x", padx=10, pady=(0, 10))
    
    input_box = tk.Entry(input_frame, bg=accent_color, fg=fg_color, 
                        insertbackground=fg_color, font=("Segoe UI", 10),
                        relief="flat", bd=0, highlightthickness=2, 
                        highlightbackground=accent_color, highlightcolor=highlight_color)
    input_box.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=8)
    input_box.bind("<Return>", lambda e: send_message())
    
    send_btn = tk.Button(input_frame, text="Send", command=send_message,
                        bg=highlight_color, fg=fg_color, font=("Segoe UI", 10, "bold"),
                        padx=20, pady=8, cursor="hand2", relief="flat", bd=0)
    send_btn.pack(side="right")
    
    # Suggested questions
    suggestions_frame = tk.Frame(chat_window, bg=bg_color)
    suggestions_frame.pack(fill="x", padx=10, pady=(0, 10))
    
    suggestions = [
        "Is this packet suspicious?",
        "What application uses this?",
        "Should I be concerned?"
    ]
    
    def ask_suggestion(question):
        input_box.delete(0, tk.END)
        input_box.insert(0, question)
        send_message()
    
    for suggestion in suggestions:
        btn = tk.Button(suggestions_frame, text=suggestion, 
                       command=lambda q=suggestion: ask_suggestion(q),
                       bg=accent_color, fg="#aaaaaa", font=("Segoe UI", 9),
                       relief="flat", padx=10, pady=5, cursor="hand2")
        btn.pack(side="left", padx=3)
    
    # Send initial analysis with full details
    initial_prompt = f"""Briefly analyze this network packet and give a risk rating (1–100):

**Basic Headers:**
- Packet #: {packet_values[0]}
- Time: {packet_values[1]}
- Source: {packet_values[2]}:{packet_values[3]}
- Destination: {packet_values[4]}:{packet_values[5]}
- Protocol: {packet_values[6]}
- Length: {packet_values[7]} bytes

**Detailed Information:**
{detailed_info}

Provide a concise summary of what this packet is doing and any security concerns."""
    
    initial_response = query_google_ai(initial_prompt)
    conversation_history.append(f"AI (Initial Analysis): {initial_response}")
    add_message(initial_response, is_user=False)
    
    input_box.focus()


# Colors
bg_color = "#1e1e1e"
fg_color = "#ffffff"
accent_color = "#3a3a3a"
highlight_color = "#007acc"

# GUI setup
root = tk.Tk()
root.title("PCAP Analyzer")
root.state('zoomed')  # Opens in windowed full screen (maximized)
root.configure(bg=bg_color)

# Styling
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
    background=bg_color,
    foreground=fg_color,
    fieldbackground=bg_color,
    rowheight=25,
    font=('Segoe UI', 10)
)
style.map("Treeview",
    background=[("selected", highlight_color)],
    foreground=[("selected", fg_color)]
)
style.configure("Treeview.Heading",
    background=accent_color,
    foreground=fg_color,
    font=('Segoe UI', 10, 'bold')
)

# Custom tag styles for detail rows
def configure_detail_tags():
    tree.tag_configure("detail", background="#252525", foreground="#aaaaaa")
    tree.tag_configure("detail_header", background="#252525", foreground="#00aaff", font=('Consolas', 9, 'bold'))
    tree.tag_configure("detail_data", background="#252525", foreground="#cccccc", font=('Consolas', 9))
    tree.tag_configure("detail_footer", background="#252525", foreground="#555555")
    tree.tag_configure("critical_packet", background="#550000", foreground="#ff4444")
    tree.tag_configure("warning_packet", background="#554400", foreground="#ffff88")


# Search bar
search_frame = tk.Frame(root, bg=bg_color)
search_frame.pack(pady=10)

search_label = tk.Label(search_frame, text="Search:", bg=bg_color, fg=fg_color)
search_label.pack(side=tk.LEFT, padx=(0, 5))

search_entry = tk.Entry(search_frame, width=40, bg=accent_color, fg=fg_color, insertbackground=fg_color)
search_entry.pack(side=tk.LEFT)

search_button = tk.Button(search_frame, text="Filter", command=lambda: filter_packets(search_entry.get()),
                          bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
search_button.pack(side=tk.LEFT, padx=(5, 0))

# File open button
button = tk.Button(root, text="Open PCAP File", command=open_pcap_file,
                   bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
button.pack(pady=10)

# Status label
label = tk.Label(root, text="No file selected", bg=bg_color, fg=fg_color)
label.pack()

# Packet table
columns = ("Packet #", "Time (UTC)", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Length (Size in bytes)")
tree = ttk.Treeview(root, columns=columns, show="headings", style="Treeview")

# Set column widths based on content needs
column_widths = {
    "Packet #": 80,
    "Time (UTC)": 180,
    "Source IP": 140,
    "Source Port": 100,
    "Destination IP": 140,
    "Destination Port": 120,
    "Protocol": 100,
    "Length (Size in bytes)": 150
}

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=column_widths[col], anchor="center")
tree.pack(expand=True, fill="both")

# Configure tag colors for zebra striping - THIS MUST COME AFTER TREE CREATION
tree.tag_configure("evenrow", background="#2a2a2a")
tree.tag_configure("oddrow", background=bg_color)
configure_detail_tags()

# Add double-click binding to show packet details
tree.bind("<Double-Button-1>", lambda e: toggle_packet_details())

# Button frame
button_frame = tk.Frame(root, bg=bg_color)
button_frame.pack(pady=10)

# AI buttons
details_button = tk.Button(button_frame, text="Toggle Packet Details", command=toggle_packet_details,
                      bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
details_button.pack(side=tk.LEFT, padx=5)

ai_button = tk.Button(button_frame, text="Get AI Insight", command=analyze_selected_packet,
                      bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
ai_button.pack(side=tk.LEFT, padx=5)

summary_button = tk.Button(button_frame, text="Summarize All with AI", command=show_ai_summary,
                           bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
summary_button.pack(side=tk.LEFT, padx=5)

# Scan for critical packets button
scan_button = tk.Button(button_frame, text="Scan for Critical Packets", command=scan_for_critical_packets,
                        bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
scan_button.pack(side=tk.LEFT, padx=5)

# Button to export ai report
report_button = tk.Button(button_frame, text="Export AI Report", command=export_ai_report,
                          bg=accent_color, fg=fg_color, activebackground=highlight_color, activeforeground=fg_color)
report_button.pack(side=tk.LEFT, padx=5)


root.mainloop()