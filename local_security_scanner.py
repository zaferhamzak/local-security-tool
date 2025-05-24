#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import ipaddress
import sys
from rich.console import Console
from rich.table import Table
from datetime import datetime
import socket
import netifaces

console = Console()

def get_network():
    """Yerel ağ adresini otomatik tespit eder"""
    try:
        # Varsayılan ağ arayüzünü bul
        default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        # IP adresini al
        ip_info = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Network adresini hesapla
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        console.print(f"[red]Ağ adresi tespit edilemedi: {e}[/red]")
        sys.exit(1)

def scan_network(network):
    """ARP taraması yaparak ağdaki cihazları tespit eder"""
    console.print(f"\n[bold blue]Ağ taraması başlatılıyor: {network}[/bold blue]")
    
    # ARP isteği oluştur
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        # ARP isteğini gönder ve cevapları al
        result = srp(packet, timeout=3, verbose=0)[0]
        
        # Sonuçları tabloya ekle
        table = Table(title="Tespit Edilen Cihazlar")
        table.add_column("IP Adresi", style="cyan")
        table.add_column("MAC Adresi", style="magenta")
        table.add_column("Üretici", style="green")
        
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
        # MAC adreslerine göre üretici bilgisini al
        for device in devices:
            try:
                hostname = socket.gethostbyaddr(device['ip'])[0]
            except:
                hostname = "Bilinmiyor"
            table.add_row(device['ip'], device['mac'], hostname)
        
        console.print(table)
        console.print(f"\n[green]Toplam {len(devices)} cihaz tespit edildi.[/green]")
        
        # Sonuçları dosyaya kaydet
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.txt"
        with open(filename, 'w') as f:
            f.write(f"Tarama Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Taranan Ağ: {network}\n")
            f.write(f"Tespit Edilen Cihaz Sayısı: {len(devices)}\n\n")
            for device in devices:
                f.write(f"IP: {device['ip']}\n")
                f.write(f"MAC: {device['mac']}\n")
                f.write(f"Hostname: {socket.gethostbyaddr(device['ip'])[0] if 'hostname' in locals() else 'Bilinmiyor'}\n")
                f.write("-" * 50 + "\n")
        
        console.print(f"\n[blue]Tarama sonuçları {filename} dosyasına kaydedildi.[/blue]")
        
    except Exception as e:
        console.print(f"[red]Tarama sırasında hata oluştu: {e}[/red]")
        sys.exit(1)

def main():
    console.print("[bold yellow]Yerel Ağ Güvenlik Tarayıcısı[/bold yellow]")
    console.print("=" * 50)
    
    # Ağ adresini otomatik tespit et
    network = get_network()
    
    # Taramayı başlat
    scan_network(network)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Program kullanıcı tarafından sonlandırıldı.[/yellow]")
        sys.exit(0) 