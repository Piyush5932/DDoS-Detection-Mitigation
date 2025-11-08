import socket
import time
import threading

class SimpleController:
    def __init__(self, host='127.0.0.1', port=6653):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connection_counts = {}
        self.blocked_sources = set()
        self.lock = threading.Lock()
        self.running = False

    def _handle_client(self, conn, addr):
        print(f"Connection from {addr}")
        ip_addr = addr[0]

        with self.lock:
            if ip_addr in self.blocked_sources:
                print(f"Blocked connection attempt from {ip_addr}")
                conn.close()
                return

            current_time = time.time()
            if ip_addr not in self.connection_counts:
                self.connection_counts[ip_addr] = []
            
            # Remove timestamps older than 1 second
            self.connection_counts[ip_addr] = [t for t in self.connection_counts[ip_addr] if current_time - t <= 1]
            self.connection_counts[ip_addr].append(current_time)
            
            rate = len(self.connection_counts[ip_addr])
            
            # Simple DDoS detection logic
            if rate > 10: # More than 10 connections per second
                print(f"ATTACK DETECTED: TCP Flood from {ip_addr} (Rate: {rate:.2f} pps)")
                self.blocked_sources.add(ip_addr)
                print(f"BLOCKING SOURCE: {ip_addr}")

        try:
            while self.running:
                data = conn.recv(1024)
                if not data:
                    break
        except ConnectionResetError:
            print(f"Connection reset by {addr}")
        finally:
            conn.close()

    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"Controller listening on {self.host}:{self.port}")
        self.running = True
        
        while self.running:
            try:
                conn, addr = self.sock.accept()
                client_thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except OSError:
                break # Socket closed

    def stop(self):
        self.running = False
        self.sock.close()
        print("Controller stopped.")

if __name__ == '__main__':
    controller = SimpleController()
    try:
        controller.start()
    except KeyboardInterrupt:
        controller.stop()