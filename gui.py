import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import csv
import threading
import time
import scapy.all as scapy
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
from matplotlib.figure import Figure
import queue
import subprocess
import os
import sys
from datetime import datetime

# Import the PacketCapture class
from nids import PacketCapture

class NetworkMonitorGUI:
    def __init__(self, root):
        """Initialize the Network Monitor GUI application"""
        self.root = root
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Create a style
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TButton", padding=6, relief="flat", background="#3498db")
        style.configure("Red.TButton", foreground="white", background="#e74c3c")
        style.configure("Green.TButton", foreground="white", background="#2ecc71")
        
        # Initialize packet capture
        self.packet_capture = PacketCapture(
            callback_log=self.log_message,
            callback_threat=self.handle_threat,
            callback_stats=self.update_stats
        )
        
        # Initialize interface variables
        self.capture_running = False
        self.selected_interface = tk.StringVar()
        self.filter_string = tk.StringVar()
        self.promiscuous_mode = tk.BooleanVar(value=True)
        
        # Stats variables
        self.packets_captured = 0
        self.packets_per_second = 0
        self.threats_detected = 0
        self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        
        # Queue for thread-safe GUI updates
        self.log_queue = queue.Queue()
        self.threat_queue = queue.Queue()
        
        # Create the main layout
        self.create_ui()
        
        # Start the queue processing
        self.root.after(100, self.process_queues)
        
        # Get available interfaces
        self.get_interfaces()

    def create_ui(self):
        """Create the user interface"""
        # Create a notebook (tabbed interface)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        dashboard_frame = ttk.Frame(notebook)
        threats_frame = ttk.Frame(notebook)
        settings_frame = ttk.Frame(notebook)
        
        notebook.add(dashboard_frame, text="Dashboard")
        notebook.add(threats_frame, text="Threat Monitor")
        notebook.add(settings_frame, text="Settings")
        
        # Setup each tab
        self.setup_dashboard(dashboard_frame)
        self.setup_threat_monitor(threats_frame)
        self.setup_settings(settings_frame)

    def setup_dashboard(self, parent):
        """Set up the dashboard tab"""
        # Top control panel
        control_frame = ttk.LabelFrame(parent, text="Capture Controls")
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.selected_interface, width=30)
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Add refresh button for interfaces
        refresh_button = ttk.Button(control_frame, text="↻", width=3, command=self.get_interfaces)
        refresh_button.grid(row=0, column=2, padx=2, pady=5, sticky=tk.W)
        
        # Filter string
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_string, width=30)
        filter_entry.grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        
        # Promiscuous mode checkbox
        promiscuous_check = ttk.Checkbutton(control_frame, text="Promiscuous Mode", variable=self.promiscuous_mode)
        promiscuous_check.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)
        
        # Start/Stop buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", 
                                       command=self.start_capture, style="Green.TButton")
        self.start_button.grid(row=0, column=6, padx=5, pady=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", 
                                      command=self.stop_capture, style="Red.TButton", state=tk.DISABLED)
        self.stop_button.grid(row=0, column=7, padx=5, pady=5)
        
        # Export button
        export_button = ttk.Button(control_frame, text="Export Logs", command=self.export_logs)
        export_button.grid(row=0, column=8, padx=5, pady=5)
        
        # Main content area with stats and visualizations
        content_frame = ttk.Frame(parent)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left side - Stats & Log
        left_frame = ttk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Stats panel
        stats_frame = ttk.LabelFrame(left_frame, text="Network Statistics")
        stats_frame.pack(fill=tk.X, pady=5)
        
        # Stats labels
        self.packets_label = ttk.Label(stats_frame, text="Packets Captured: 0")
        self.packets_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.pps_label = ttk.Label(stats_frame, text="Packets/sec: 0")
        self.pps_label.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        self.threats_label = ttk.Label(stats_frame, text="Threats Detected: 0")
        self.threats_label.grid(row=0, column=2, padx=10, pady=5, sticky=tk.W)
        
        self.active_ips_label = ttk.Label(stats_frame, text="Active IPs: 0")
        self.active_ips_label.grid(row=0, column=3, padx=10, pady=5, sticky=tk.W)
        
        # Log panel
        log_frame = ttk.LabelFrame(left_frame, text="Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Right side - Visualizations
        right_frame = ttk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Protocol distribution chart
        protocol_frame = ttk.LabelFrame(right_frame, text="Protocol Distribution")
        protocol_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.fig_protocol = Figure(figsize=(5, 4), dpi=100)
        self.ax_protocol = self.fig_protocol.add_subplot(111)
        self.canvas_protocol = FigureCanvasTkAgg(self.fig_protocol, protocol_frame)
        self.canvas_protocol.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Traffic chart
        traffic_frame = ttk.LabelFrame(right_frame, text="Traffic Over Time")
        traffic_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.fig_traffic = Figure(figsize=(5, 4), dpi=100)
        self.ax_traffic = self.fig_traffic.add_subplot(111)
        self.canvas_traffic = FigureCanvasTkAgg(self.fig_traffic, traffic_frame)
        self.canvas_traffic.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize the traffic data
        self.traffic_data = {
            "timestamps": [],
            "packet_counts": []
        }
        
        # Start the animation for charts
        self.ani_protocol = animation.FuncAnimation(
        self.fig_protocol, self.update_protocol_chart, interval=1000, save_count=100)  
        self.ani_traffic = animation.FuncAnimation(
        self.fig_traffic, self.update_traffic_chart, interval=1000, save_count=100)  


    def setup_threat_monitor(self, parent):
        """Set up the threat monitor tab with enhanced filtering"""
        # Top controls for threat monitoring
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Filter controls
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.threat_filter = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.threat_filter, width=30)
        filter_entry.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # Filter type (contains, exact, starts with, ends with)
        self.filter_type = tk.StringVar(value="contains")
        filter_type_combo = ttk.Combobox(control_frame, textvariable=self.filter_type, 
                                       values=["contains", "exact match", "starts with", "ends with"],
                                       state="readonly", width=12)
        filter_type_combo.grid(row=0, column=2, padx=5, sticky=tk.W)
        
        # Filter column selection
        ttk.Label(control_frame, text="in column:").grid(row=0, column=3, padx=5, sticky=tk.W)
        self.filter_column = tk.StringVar(value="All")
        filter_col_combo = ttk.Combobox(control_frame, textvariable=self.filter_column, 
                                       values=["All", "Timestamp", "Source IP", "Destination IP", 
                                               "Protocol", "Threat Level", "Threat Type"],
                                       state="readonly", width=15)
        filter_col_combo.grid(row=0, column=4, padx=5, sticky=tk.W)
        
        # Case sensitivity
        self.case_sensitive = tk.BooleanVar(value=False)
        case_check = ttk.Checkbutton(control_frame, text="Case Sensitive", variable=self.case_sensitive)
        case_check.grid(row=0, column=5, padx=5, sticky=tk.W)
        
        # Filter buttons
        filter_button = ttk.Button(control_frame, text="Apply Filter", command=self.apply_threat_filter)
        filter_button.grid(row=0, column=6, padx=5)
        
        clear_filter_button = ttk.Button(control_frame, text="Clear Filter", command=self.clear_threat_filter)
        clear_filter_button.grid(row=0, column=7, padx=5)
        
        # Advanced filter button
        adv_filter_button = ttk.Button(control_frame, text="Advanced Filter", command=self.show_advanced_filter)
        adv_filter_button.grid(row=0, column=8, padx=5)
        
        # Clear threats button
        clear_button = ttk.Button(control_frame, text="Clear Threats", command=self.clear_threats)
        clear_button.grid(row=0, column=9, padx=5)
        
        # Threat list
        threats_frame = ttk.LabelFrame(parent, text="Detected Threats")
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for threats with sortable columns
        columns = ("timestamp", "src_ip", "dst_ip", "protocol", "threat_level", "threat_type")
        self.threat_tree = ttk.Treeview(threats_frame, columns=columns, show="headings")
        
        # Define headings with sort capability
        for col in columns:
            self.threat_tree.heading(col, text=col.replace("_", " ").title(), 
                                    command=lambda c=col: self.sort_threat_tree(c))
            self.threat_tree.column(col, width=150, anchor=tk.W)
        
        # Adjust column widths
        self.threat_tree.column("timestamp", width=180)
        self.threat_tree.column("threat_type", width=250)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_tree.pack(fill=tk.BOTH, expand=True)
        
        # Threat details frame
        details_frame = ttk.LabelFrame(parent, text="Threat Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.config(state=tk.DISABLED)
        
        # Bind selection event to show details
        self.threat_tree.bind("<<TreeviewSelect>>", self.show_threat_details)
        
        # Add blacklist section
        blacklist_frame = ttk.LabelFrame(parent, text="IP Blacklisting")
        blacklist_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(blacklist_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.blacklist_ip = tk.StringVar()
        blacklist_entry = ttk.Entry(blacklist_frame, textvariable=self.blacklist_ip, width=20)
        blacklist_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        add_ip_button = ttk.Button(blacklist_frame, text="Add to Blacklist", 
                                   command=self.add_to_blacklist)
        add_ip_button.grid(row=0, column=2, padx=5, pady=5)
        
        # Add right-click menu for threats
        self.threat_menu = tk.Menu(self.threat_tree, tearoff=0)
        self.threat_menu.add_command(label="Copy IP", command=self.copy_selected_ip)
        self.threat_menu.add_command(label="Copy All Details", command=self.copy_threat_details)
        self.threat_menu.add_separator()
        self.threat_menu.add_command(label="Filter by Source IP", 
                                    command=lambda: self.filter_by_column("src_ip"))
        self.threat_menu.add_command(label="Filter by Destination IP", 
                                    command=lambda: self.filter_by_column("dst_ip"))
        self.threat_menu.add_command(label="Filter by Protocol", 
                                    command=lambda: self.filter_by_column("protocol"))
        self.threat_menu.add_command(label="Filter by Threat Type", 
                                    command=lambda: self.filter_by_column("threat_type"))
        self.threat_menu.add_separator()
        self.threat_menu.add_command(label="Add IP to Blacklist", command=self.blacklist_selected_ip)
        
        self.threat_tree.bind("<Button-3>", self.show_threat_menu)

    def setup_settings(self, parent):
        """Set up the settings tab"""
        # General settings section
        general_frame = ttk.LabelFrame(parent, text="General Settings")
        general_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add auto-save option
        self.auto_save = tk.BooleanVar(value=False)
        autosave_check = ttk.Checkbutton(general_frame, text="Auto-save logs on exit", 
                                         variable=self.auto_save)
        autosave_check.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        # Add signature management section
        signature_frame = ttk.LabelFrame(parent, text="Signature Management")
        signature_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Signature type selection
        ttk.Label(signature_frame, text="Category:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.signature_category = tk.StringVar(value="sql_injection")
        categories = ["sql_injection", "xss", "port_scan", "dos", "command_injection", 
                     "path_traversal", "web_shell", "buffer_overflow", "ldap_injection",
                     "xml_injection", "csrf", "ssi_injection", "file_inclusion", "custom"]
        category_combo = ttk.Combobox(signature_frame, textvariable=self.signature_category, 
                                                                    values=categories, state="readonly")
        category_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Signature pattern
        ttk.Label(signature_frame, text="Pattern:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.signature_pattern = tk.StringVar()
        pattern_entry = ttk.Entry(signature_frame, textvariable=self.signature_pattern, width=50)
        pattern_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Description
        ttk.Label(signature_frame, text="Description:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.signature_description = tk.StringVar()
        description_entry = ttk.Entry(signature_frame, textvariable=self.signature_description, width=50)
        description_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Severity level
        ttk.Label(signature_frame, text="Severity:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.signature_severity = tk.StringVar(value="medium")
        severity_combo = ttk.Combobox(signature_frame, textvariable=self.signature_severity, 
                                     values=["low", "medium", "high", "critical"], state="readonly")
        severity_combo.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Add signature button
        add_sig_button = ttk.Button(signature_frame, text="Add Signature", 
                                   command=self.add_signature)
        add_sig_button.grid(row=4, column=0, padx=5, pady=10)
        
        # Current signatures list
        ttk.Label(signature_frame, text="Current Signatures:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        
        # Create treeview for signatures
        columns = ("category", "pattern", "severity", "description")
        self.signature_tree = ttk.Treeview(signature_frame, columns=columns, show="headings", height=10)
        
        # Define headings
        self.signature_tree.heading("category", text="Category")
        self.signature_tree.heading("pattern", text="Pattern")
        self.signature_tree.heading("severity", text="Severity")
        self.signature_tree.heading("description", text="Description")
        
        # Define columns
        self.signature_tree.column("category", width=100)
        self.signature_tree.column("pattern", width=300)
        self.signature_tree.column("severity", width=80)
        self.signature_tree.column("description", width=300)
        
        # Add scrollbar
        sig_scrollbar = ttk.Scrollbar(signature_frame, orient=tk.VERTICAL, command=self.signature_tree.yview)
        self.signature_tree.configure(yscroll=sig_scrollbar.set)
        sig_scrollbar.grid(row=6, column=2, sticky='ns')
        self.signature_tree.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')
        
        # Delete signature button
        delete_sig_button = ttk.Button(signature_frame, text="Delete Selected", 
                                      command=self.delete_signature)
        delete_sig_button.grid(row=7, column=0, padx=5, pady=10)
        
        # Load signatures button
        load_sig_button = ttk.Button(signature_frame, text="Load Signatures", 
                                    command=self.load_signatures)
        load_sig_button.grid(row=7, column=1, padx=5, pady=10, sticky=tk.W)
        
        # Load the signatures
        self.load_signatures()
        
        # Configure row and column weights for resizing
        signature_frame.grid_columnconfigure(1, weight=1)
        signature_frame.grid_rowconfigure(6, weight=1)

    def sort_threat_tree(self, col):
        """Sort treeview by column"""
        data = [(self.threat_tree.set(child, col), child) 
                for child in self.threat_tree.get_children('')]
        
        # Try to sort numerically if possible
        try:
            data.sort(key=lambda t: int(t[0]))
        except ValueError:
            data.sort()
        
        # Reverse the order if already sorted
        if self.threat_tree.heading(col, "text").endswith("↑"):
            data.reverse()
            self.threat_tree.heading(col, text=col.replace("_", " ").title() + " ↓")
        else:
            self.threat_tree.heading(col, text=col.replace("_", " ").title() + " ↑")
        
        # Rearrange items in sorted positions
        for index, (val, child) in enumerate(data):
            self.threat_tree.move(child, '', index)

    def filter_by_column(self, column):
        """Filter by a specific column from context menu"""
        selected_items = self.threat_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.threat_tree.item(item, "values")
        
        # Map column names to treeview columns
        column_map = {
            "timestamp": 0,
            "src_ip": 1,
            "dst_ip": 2,
            "protocol": 3,
            "threat_level": 4,
            "threat_type": 5
        }
        
        col_index = column_map.get(column, 0)
        filter_value = values[col_index]
        
        self.filter_column.set(column.replace("_", " ").title())
        self.threat_filter.set(filter_value)
        self.filter_type.set("exact match")
        self.apply_threat_filter()

    def show_advanced_filter(self):
        """Show advanced filter dialog"""
        adv_filter = tk.Toplevel(self.root)
        adv_filter.title("Advanced Threat Filter")
        adv_filter.geometry("500x400")
        
        # Source IP filter
        ttk.Label(adv_filter, text="Source IP:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.src_ip_filter = tk.StringVar()
        ttk.Entry(adv_filter, textvariable=self.src_ip_filter).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Destination IP filter
        ttk.Label(adv_filter, text="Destination IP:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.dst_ip_filter = tk.StringVar()
        ttk.Entry(adv_filter, textvariable=self.dst_ip_filter).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Protocol filter
        ttk.Label(adv_filter, text="Protocol:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.protocol_filter = tk.StringVar()
        ttk.Combobox(adv_filter, textvariable=self.protocol_filter, 
                    values=["", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Threat level filter
        ttk.Label(adv_filter, text="Threat Level:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.threat_level_filter = tk.StringVar()
        ttk.Combobox(adv_filter, textvariable=self.threat_level_filter, 
                    values=["", "low", "medium", "high", "critical"]).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Threat type filter
        ttk.Label(adv_filter, text="Threat Type:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.threat_type_filter = tk.StringVar()
        ttk.Entry(adv_filter, textvariable=self.threat_type_filter).grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Time range filter
        ttk.Label(adv_filter, text="Time Range:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        time_frame = ttk.Frame(adv_filter)
        time_frame.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        
        self.time_range = tk.StringVar(value="all")
        ttk.Radiobutton(time_frame, text="All", variable=self.time_range, value="all").pack(side=tk.LEFT)
        ttk.Radiobutton(time_frame, text="Last hour", variable=self.time_range, value="1h").pack(side=tk.LEFT)
        ttk.Radiobutton(time_frame, text="Last 24h", variable=self.time_range, value="24h").pack(side=tk.LEFT)
        ttk.Radiobutton(time_frame, text="Custom", variable=self.time_range, value="custom").pack(side=tk.LEFT)
        
        # Apply and Cancel buttons
        button_frame = ttk.Frame(adv_filter)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Apply", command=lambda: self.apply_advanced_filter(adv_filter)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=adv_filter.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset", command=self.reset_advanced_filters).pack(side=tk.LEFT, padx=5)

    def apply_advanced_filter(self, window):
        """Apply advanced filters"""
        filters = {
            "src_ip": self.src_ip_filter.get().strip(),
            "dst_ip": self.dst_ip_filter.get().strip(),
            "protocol": self.protocol_filter.get().strip(),
            "threat_level": self.threat_level_filter.get().strip(),
            "threat_type": self.threat_type_filter.get().strip(),
            "time_range": self.time_range.get()
        }
        
        # Apply the filters
        for item in self.threat_tree.get_children():
            values = self.threat_tree.item(item, "values")
            show_item = True
            
            # Check each filter
            if filters["src_ip"] and filters["src_ip"] not in values[1]:
                show_item = False
            if filters["dst_ip"] and filters["dst_ip"] not in values[2]:
                show_item = False
            if filters["protocol"] and filters["protocol"].upper() not in values[3].upper():
                show_item = False
            if filters["threat_level"] and filters["threat_level"].lower() not in values[4].lower():
                show_item = False
            if filters["threat_type"] and filters["threat_type"].lower() not in values[5].lower():
                show_item = False
            
            # Time range filter (simplified example)
            if filters["time_range"] != "all":
                try:
                    timestamp = datetime.strptime(values[0], "%Y-%m-%d %H:%M:%S")
                    now = datetime.now()
                    
                    if filters["time_range"] == "1h" and (now - timestamp).total_seconds() > 3600:
                        show_item = False
                    elif filters["time_range"] == "24h" and (now - timestamp).total_seconds() > 86400:
                        show_item = False
                except:
                    pass
            
            if show_item:
                self.threat_tree.reattach(item, "", "end")
            else:
                self.threat_tree.detach(item)
        
        window.destroy()
        self.log_message("Applied advanced filters", level="info")

    def reset_advanced_filters(self):
        """Reset all advanced filters"""
        self.src_ip_filter.set("")
        self.dst_ip_filter.set("")
        self.protocol_filter.set("")
        self.threat_level_filter.set("")
        self.threat_type_filter.set("")
        self.time_range.set("all")
        self.log_message("Reset advanced filters", level="info")

    def get_interfaces(self):
        """Get available network interfaces and add common Wi-Fi/Ethernet interfaces"""
        try:
            # Get interfaces from scapy
            raw_interfaces = scapy.get_if_list()
        
            # Create a list of interfaces with labels
            labeled_interfaces = []
        
            # Add detected interfaces with appropriate labels
            for iface in raw_interfaces:
                if iface.startswith(('wlan', 'wlp', 'wl', 'wifi', 'ath', 'ra')):
                    labeled_interfaces.append(f"Wi-Fi: {iface}")
                elif iface.startswith(('eth', 'en', 'enp', 'ens', 'em', 'ep', 'net')):
                    labeled_interfaces.append(f"Ethernet: {iface}")
                else:
                    labeled_interfaces.append(f"Other: {iface}")
        
            # On Windows, add common Wi-Fi adapters
            if os.name == 'nt':
                # Add your specific adapter
                labeled_interfaces.append("Wi-Fi: Intel(R) Dual Band Wireless-AC 8260")
            
                # Add other common adapters
                common_adapters = [
                "Wi-Fi: Intel(R) Wireless-AC",
                "Wi-Fi: Realtek RTL8822BE Wireless LAN",
                "Wi-Fi: Qualcomm QCA",
                "Wi-Fi: Broadcom 802.11",
                "Ethernet: Intel(R) Ethernet Connection",
                "Ethernet: Realtek PCIe GbE Family Controller"
                ]
            
                for adapter in common_adapters:
                    if adapter not in labeled_interfaces:
                        labeled_interfaces.append(adapter)
        
            # Update the combobox with labeled interfaces
            self.interface_combo['values'] = labeled_interfaces
        
            # Set default interface if available
            if labeled_interfaces:
                self.selected_interface.set(labeled_interfaces[0])
            
            # Log detected interfaces
            self.log_message(f"Detected {len(raw_interfaces)} interfaces: {', '.join(raw_interfaces)}", level="info")
            self.log_message(f"Available interfaces for capture: {len(labeled_interfaces)}", level="info")
        
        except Exception as e:
            self.log_message(f"Error getting interfaces: {str(e)}", level="error")

    def start_capture(self):
        """Start packet capture"""
        if not self.selected_interface.get():
            messagebox.showerror("Error", "Please select a network interface")
            return
            
        try:
            # Update UI state
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.capture_running = True
            
            # Reset counters
            self.packets_captured = 0
            self.packets_per_second = 0
            self.threats_detected = 0
            self.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
            
            # Extract the actual interface name from the labeled interface
            selected_interface = self.selected_interface.get()
            if ":" in selected_interface:
                # Extract the interface name after the label (e.g., "Wi-Fi: wlan0" -> "wlan0")
                interface_name = selected_interface.split(":", 1)[1].strip()
            else:
                interface_name = selected_interface
            
            # Start capture in a separate thread
            self.log_message(f"Starting packet capture on interface '{interface_name}'...", level="info")
            
            # Configure the packet capture
            self.packet_capture.configure(
                interface=interface_name,
                filter_str=self.filter_string.get(),
                promisc=self.promiscuous_mode.get()
            )
            
            # Start the capture thread
            self.capture_thread = threading.Thread(target=self.packet_capture.start_capture)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Start the stats update thread
            self.stats_thread = threading.Thread(target=self.update_stats_thread)
            self.stats_thread.daemon = True
            self.stats_thread.start()
            
            self.log_message(f"Capture started on interface {interface_name}", level="info")
            
        except Exception as e:
            self.log_message(f"Error starting capture: {str(e)}", level="error")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.capture_running = False

    def stop_capture(self):
        """Stop packet capture"""
        try:
            self.capture_running = False
            self.packet_capture.stop_capture()
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_message("Packet capture stopped", level="info")
        except Exception as e:
            self.log_message(f"Error stopping capture: {str(e)}", level="error")

    def update_stats_thread(self):
        """Thread to update statistics periodically"""
        last_count = 0
        
        while self.capture_running:
            # Calculate packets per second
            current_count = self.packets_captured
            self.packets_per_second = current_count - last_count
            last_count = current_count
            
            # Update traffic data for chart
            timestamp = time.time()
            self.traffic_data["timestamps"].append(timestamp)
            self.traffic_data["packet_counts"].append(self.packets_per_second)
            
            # Keep only the last 60 seconds of data
            if len(self.traffic_data["timestamps"]) > 60:
                self.traffic_data["timestamps"] = self.traffic_data["timestamps"][-60:]
                self.traffic_data["packet_counts"] = self.traffic_data["packet_counts"][-60:]
            
            time.sleep(1)

    def update_stats(self, stats_data):
        """Update statistics from packet capture"""
        self.packets_captured = stats_data.get("total_packets", 0)
        
        # Update protocol stats
        for protocol, count in stats_data.get("protocols", {}).items():
            if protocol in self.protocol_stats:
                self.protocol_stats[protocol] = count
            else:
                self.protocol_stats["Other"] += count
        
        # Update UI labels
        self.packets_label.config(text=f"Packets Captured: {self.packets_captured}")
        self.pps_label.config(text=f"Packets/sec: {self.packets_per_second}")
        self.threats_label.config(text=f"Threats Detected: {self.threats_detected}")
        self.active_ips_label.config(text=f"Active IPs: {len(stats_data.get('active_ips', []))}")

    def update_protocol_chart(self, frame):
        """Update the protocol distribution chart"""
        self.ax_protocol.clear()
        labels = list(self.protocol_stats.keys())
        sizes = list(self.protocol_stats.values())
        
        if sum(sizes) > 0:  # Only create pie chart if we have data
            self.ax_protocol.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            self.ax_protocol.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        
        self.ax_protocol.set_title('Protocol Distribution')
        return self.ax_protocol,

    def update_traffic_chart(self, frame):
        """Update the traffic over time chart"""
        self.ax_traffic.clear()
        
        if self.traffic_data["timestamps"]:
            # Convert timestamps to relative time (seconds ago)
            now = time.time()
            relative_times = [t - now for t in self.traffic_data["timestamps"]]
            
            self.ax_traffic.plot(relative_times, self.traffic_data["packet_counts"])
            self.ax_traffic.set_xlim(min(relative_times), max(relative_times) + 1)
            self.ax_traffic.set_xlabel('Time (seconds ago)')
            self.ax_traffic.set_ylabel('Packets/sec')
            self.ax_traffic.set_title('Network Traffic')
            self.ax_traffic.grid(True)
        
        return self.ax_traffic,

    def log_message(self, message, level="info"):
        """Add a message to the log queue"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "message": message
        }
        self.log_queue.put(log_entry)

    def handle_threat(self, threat_data):
        """Handle a detected threat"""
        self.threats_detected += 1
        self.threat_queue.put(threat_data)

    def process_queues(self):
        """Process message queues for thread-safe UI updates"""
        # Process log messages
        while not self.log_queue.empty():
            try:
                log_entry = self.log_queue.get_nowait()
                self.display_log_message(log_entry)
            except queue.Empty:
                break
        
        # Process threat messages
        while not self.threat_queue.empty():
            try:
                threat_data = self.threat_queue.get_nowait()
                self.display_threat(threat_data)
            except queue.Empty:
                break
        
        # Schedule the next queue check
        self.root.after(100, self.process_queues)

    def display_log_message(self, log_entry):
        """Display a log message in the log text widget"""
        timestamp = log_entry["timestamp"]
        level = log_entry["level"].upper()
        message = log_entry["message"]
        
        # Define colors for different log levels
        level_colors = {
            "INFO": "blue",
            "WARNING": "orange",
            "ERROR": "red",
            "THREAT": "purple"
        }
        
        color = level_colors.get(level, "black")
        
        # Enable text widget for editing
        self.log_text.config(state=tk.NORMAL)
        
        # Insert timestamp
        self.log_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        
        # Insert level with appropriate color
        self.log_text.insert(tk.END, f"[{level}] ", f"{level.lower()}_tag")
        self.log_text.tag_configure(f"{level.lower()}_tag", foreground=color)
        
        # Insert message and newline
        self.log_text.insert(tk.END, f"{message}\n")
        
        # Auto-scroll to the end
        self.log_text.see(tk.END)
        
        # Disable text widget for editing
        self.log_text.config(state=tk.DISABLED)

    def display_threat(self, threat_data):
        """Display a threat in the threat treeview"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Insert into treeview
        item_id = self.threat_tree.insert("", tk.END, values=(
            timestamp,
            threat_data.get("src_ip", "Unknown"),
            threat_data.get("dst_ip", "Unknown"),
            threat_data.get("protocol", "Unknown"),
            threat_data.get("severity", "Unknown"),
            threat_data.get("type", "Unknown")
        ))
        
        # Color-code based on severity
        severity = threat_data.get("severity", "medium").lower()
        if severity == "high" or severity == "critical":
            self.threat_tree.item(item_id, tags=("high",))
        elif severity == "medium":
            self.threat_tree.item(item_id, tags=("medium",))
        else:
            self.threat_tree.item(item_id, tags=("low",))
        
        # Configure tag colors
        self.threat_tree.tag_configure("high", background="#ffcccc")
        self.threat_tree.tag_configure("medium", background="#ffffcc")
        self.threat_tree.tag_configure("low", background="#ccffcc")
        
        # Log the threat
        self.log_message(f"Threat detected: {threat_data.get('type')} from {threat_data.get('src_ip')}", level="threat")

    def show_threat_details(self, event):
        """Show details for the selected threat"""
        selected_items = self.threat_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.threat_tree.item(item, "values")
        
        # Enable text widget for editing
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        # Format and display details
        self.details_text.insert(tk.END, f"Timestamp: {values[0]}\n")
        self.details_text.insert(tk.END, f"Source IP: {values[1]}\n")
        self.details_text.insert(tk.END, f"Destination IP: {values[2]}\n")
        self.details_text.insert(tk.END, f"Protocol: {values[3]}\n")
        self.details_text.insert(tk.END, f"Threat Level: {values[4]}\n")
        self.details_text.insert(tk.END, f"Threat Type: {values[5]}\n")
        
        # Disable text widget for editing
        self.details_text.config(state=tk.DISABLED)

    def show_threat_menu(self, event):
        """Show context menu for threats"""
        selected_items = self.threat_tree.selection()
        if selected_items:
            self.threat_menu.post(event.x_root, event.y_root)

    def copy_selected_ip(self):
        """Copy the IP from selected threat to clipboard"""
        selected_items = self.threat_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.threat_tree.item(item, "values")
        src_ip = values[1]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(src_ip)
        self.log_message(f"Copied IP {src_ip} to clipboard", level="info")

    def copy_threat_details(self):
        """Copy all details of selected threat to clipboard"""
        selected_items = self.threat_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.threat_tree.item(item, "values")
        
        details = "\n".join([
            f"Timestamp: {values[0]}",
            f"Source IP: {values[1]}",
            f"Destination IP: {values[2]}",
            f"Protocol: {values[3]}",
            f"Threat Level: {values[4]}",
            f"Threat Type: {values[5]}"
        ])
        
        self.root.clipboard_clear()
        self.root.clipboard_append(details)
        self.log_message("Copied threat details to clipboard", level="info")

    def blacklist_selected_ip(self):
        """Add the IP from selected threat to blacklist"""
        selected_items = self.threat_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        values = self.threat_tree.item(item, "values")
        src_ip = values[1]
        
        self.blacklist_ip.set(src_ip)
        self.add_to_blacklist()

    def add_to_blacklist(self):
        """Add an IP to the blacklist"""
        ip = self.blacklist_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
            
        try:
            # Add to the packet capture blacklist
            self.packet_capture.add_to_blacklist(ip)
            self.log_message(f"Added {ip} to blacklist", level="info")
            self.blacklist_ip.set("")  # Clear the entry
        except Exception as e:
            self.log_message(f"Error adding to blacklist: {str(e)}", level="error")

    def apply_threat_filter(self):
        """Apply filter to threat list with enhanced options"""
        filter_text = self.threat_filter.get()
        column = self.filter_column.get()
        filter_type = self.filter_type.get()
        case_sensitive = self.case_sensitive.get()
        
        if not filter_text and column == "All":
            self.clear_threat_filter()
            return
        
        # Prepare filter text
        if not case_sensitive:
            filter_text = filter_text.lower()
        
        # Map column names to treeview columns
        column_map = {
            "All": None,
            "Timestamp": 0,
            "Source IP": 1,
            "Destination IP": 2,
            "Protocol": 3,
            "Threat Level": 4,
            "Threat Type": 5
        }
        
        col_index = column_map.get(column)
        
        # Show all items first
        for item in self.threat_tree.get_children():
            self.threat_tree.reattach(item, "", "end")
        
        # Filter items based on criteria
        for item in self.threat_tree.get_children():
            values = self.threat_tree.item(item, "values")
            match = False
            
            if col_index is None:  # Search all columns
                for value in values:
                    value_str = str(value) if case_sensitive else str(value).lower()
                    if self._match_filter(filter_text, value_str, filter_type):
                        match = True
                        break
            else:  # Search specific column
                value_str = str(values[col_index]) if case_sensitive else str(values[col_index]).lower()
                match = self._match_filter(filter_text, value_str, filter_type)
            
            if not match:
                self.threat_tree.detach(item)
        
        self.log_message(f"Applied filter: {filter_type} '{filter_text}' in {column}", level="info")

    def _match_filter(self, filter_text, value_str, filter_type):
        """Helper method to match filter based on type"""
        if filter_type == "contains":
            return filter_text in value_str
        elif filter_type == "exact match":
            return filter_text == value_str
        elif filter_type == "starts with":
            return value_str.startswith(filter_text)
        elif filter_type == "ends with":
            return value_str.endswith(filter_text)
        return False

    def clear_threat_filter(self):
        """Clear threat filter and show all items"""
        self.threat_filter.set("")
        for item in self.threat_tree.get_children():
            self.threat_tree.reattach(item, "", "end")

    def clear_threats(self):
        """Clear all threats from the threat view"""
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        self.log_message("Cleared threat display", level="info")

    def add_signature(self):
        """Add a new signature to the database"""
        category = self.signature_category.get()
        pattern = self.signature_pattern.get().strip()
        description = self.signature_description.get().strip()
        severity = self.signature_severity.get()
        
        if not pattern:
            messagebox.showerror("Error", "Pattern cannot be empty")
            return
            
        try:
            # Add to the packet capture signatures
            self.packet_capture.add_signature(category, pattern, description, severity)
            self.log_message(f"Added new {category} signature", level="info")
            
            # Clear the form
            self.signature_pattern.set("")
            self.signature_description.set("")
            
            # Reload signatures
            self.load_signatures()
        except Exception as e:
            self.log_message(f"Error adding signature: {str(e)}", level="error")

    def delete_signature(self):
        """Delete the selected signature"""
        selected_items = self.signature_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "Please select a signature to delete")
            return
            
        item = selected_items[0]
        values = self.signature_tree.item(item, "values")
        category = values[0]
        pattern = values[1]
        
        try:
            # Remove from the packet capture signatures
            self.packet_capture.delete_signature(category, pattern)
            self.log_message(f"Deleted {category} signature", level="info")
            
            # Reload signatures
            self.load_signatures()
        except Exception as e:
            self.log_message(f"Error deleting signature: {str(e)}", level="error")

    def load_signatures(self):
        """Load signatures into the treeview"""
        # Clear existing items
        for item in self.signature_tree.get_children():
            self.signature_tree.delete(item)
            
        try:
            # Get signatures from packet capture
            signatures = self.packet_capture.get_signatures()
            
            # Add to treeview
            for sig in signatures:
                self.signature_tree.insert("", tk.END, values=(
                    sig.get("category", ""),
                    sig.get("pattern", ""),
                    sig.get("severity", ""),
                    sig.get("description", "")
                ))
                
        except Exception as e:
            self.log_message(f"Error loading signatures: {str(e)}", level="error")

    def export_logs(self):
        """Export logs to a file"""
        # Get the current timestamp for the default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"nids_logs_{timestamp}.txt"
    
        # Ask user for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_filename,
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ],
            title="Export Logs"
        )
    
        if not filename:  # User cancelled
            return
    
        try:
            # Get all log content
            self.log_text.config(state=tk.NORMAL)  # Enable editing to get content
            log_content = self.log_text.get(1.0, tk.END)
            self.log_text.config(state=tk.DISABLED)  # Disable editing again
        
            # Determine file type from extension
            if filename.lower().endswith('.json'):
                # Convert logs to JSON format
                logs = []
                for line in log_content.split('\n'):
                    if line.strip():
                        parts = line.split(']', 2)
                        if len(parts) >= 3:
                            timestamp = parts[0][1:].strip()
                            level = parts[1][1:].strip()
                            message = parts[2].strip()
                            logs.append({
                                "timestamp": timestamp,
                                "level": level,
                                "message": message
                            })
            
                with open(filename, 'w') as f:
                    json.dump(logs, f, indent=4)
        
            elif filename.lower().endswith('.csv'):
                # Convert logs to CSV format
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Level", "Message"])
                
                    for line in log_content.split('\n'):
                        if line.strip():
                            parts = line.split(']', 2)
                            if len(parts) >= 3:
                                timestamp = parts[0][1:].strip()
                                level = parts[1][1:].strip()
                                message = parts[2].strip()
                                writer.writerow([timestamp, level, message])
            else:
                # Default to plain text
                with open(filename, 'w') as f:
                    f.write(log_content)
        
            self.log_message(f"Logs exported successfully to {filename}", level="info")
            messagebox.showinfo("Export Successful", f"Logs were saved to:\n{filename}")
    
        except Exception as e:
            self.log_message(f"Error exporting logs: {str(e)}", level="error")
            messagebox.showerror("Export Error", f"Failed to save logs:\n{str(e)}")
            
    def on_closing(self):
        """Handle window closing event"""
        if hasattr(self, 'capture_running') and self.capture_running:
            if messagebox.askyesno("Confirm", "Capture is running. Stop and exit?"):
                self.stop_capture()
            else:
                return
                
        if hasattr(self, 'auto_save') and self.auto_save.get():
            self.export_logs()
            
        self.root.destroy()

def main():
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()