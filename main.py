import sys
from logger import log_info
from detector import Detector
from packet_capture import PacketCapture

def main():
    log_info("==================================================")
    log_info("   Network Intrusion Detection System (Backend)   ")
    log_info("==================================================")
    log_info("Initializing NIDS components...")
    
    # Initialize detector instance
    detector = Detector()
    
    # Initialize packet capture with detector callback
    sniffer = PacketCapture(callback=detector.process_packet)
    
    try:
        # Start capture - this blocks indefinitely
        sniffer.start()
    except KeyboardInterrupt:
        print("")
        log_info("NIDS shut down by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
