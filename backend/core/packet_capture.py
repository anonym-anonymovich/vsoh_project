import scapy.all as scapy
from threading import Thread, Event
import time
import logging
from collections import defaultdict
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class PacketCapture:
    """Класс захват и анализ пакетов"""
    
    def __init__(self, interface: str = "eth0", filter_expr: str = "not arp and not dns"):
        """
        Сетевой интерфейс для мониторинга
        BPF фильтр для захвата пакетов
        """
        self.interface = interface
        self.filter_expr = filter_expr
        self.running = Event()
        self.packet_count = 0
        self.start_time = None
        self.devices = defaultdict(lambda: {
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'packet_count': 0,
            'data_volume': 0,
            'src_ips': set(),
            'dst_ips': set(),
            'ports': set(),
            'protocols': set(),
            'anomalies': []
        })
        self.capture_thread = None
        self.callback = None
        
        # Инициализация Scapy
        scapy.conf.verb = 0
    
    def set_callback(self, callback):
        """ функция для обработки пакетов"""
        self.callback = callback
    
    def _process_packet(self, packet):
        """Обработка одного пакета"""
        try:
            self.packet_count += 1
            
            # Извлечение MAC-адресов
            if packet.haslayer(scapy.Ether):
                src_mac = packet[scapy.Ether].src
                dst_mac = packet[scapy.Ether].dst
                
                # Обновление статистики для источника
                if src_mac != "00:00:00:00:00:00":
                    self._update_device_stats(src_mac, packet, "src")
                
                # Обновление статистики для получателя
                if dst_mac != "00:00:00:00:00:00":
                    self._update_device_stats(dst_mac, packet, "dst")
                
            
                if self.callback:
                    self.callback(packet, src_mac, dst_mac)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_device_stats(self, mac: str, packet, direction: str):
        """Обновление статистики для устройства"""
        device = self.devices[mac]
        device['packet_count'] += 1
        device['last_seen'] = datetime.now()
        
        # Обновление данных
        if packet.haslayer(scapy.Raw):
            data_len = len(packet[scapy.Raw].load)
            device['data_volume'] += data_len
        
        # Обновление ип и портов
        if packet.haslayer(scapy.IP):
            if direction == "src":
                src_ip = packet[scapy.IP].src
                device['src_ips'].add(src_ip)
            else:
                dst_ip = packet[scapy.IP].dst
                device['dst_ips'].add(dst_ip)
        
        # Обновление протоколов и портов
        if packet.haslayer(scapy.TCP):
            device['protocols'].add('TCP')
            if direction == "src":
                device['ports'].add(packet[scapy.TCP].sport)
            else:
                device['ports'].add(packet[scapy.TCP].dport)
        
        elif packet.haslayer(scapy.UDP):
            device['protocols'].add('UDP')
            if direction == "src":
                device['ports'].add(packet[scapy.UDP].sport)
            else:
                device['ports'].add(packet[scapy.UDP].dport)
    
    def _capture_packets(self):
        """цикл захвата пакетов"""
        logger.info(f"Starting packet capture on interface: {self.interface}")
        self.start_time = datetime.now()
        
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.filter_expr,
                store=False,
                stop_filter=lambda x: not self.running.is_set()
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.running.clear()
    
    def start_capture(self):
        """Запуск захват пакетов"""
        if self.running.is_set():
            logger.warning("Packet capture is already running")
            return
        
        self.running.set()
        self.capture_thread = Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        logger.info("Packet capture started")
    
    def stop_capture(self):
        """Остановк захвата пакетов"""
        if not self.running.is_set():
            logger.warning("Packet capture is not running")
            return
        
        self.running.clear()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5.0)
            if self.capture_thread.is_alive():
                logger.warning("Capture thread did not terminate gracefully")
        
        logger.info("Packet capture stopped")
    
    def get_device_stats(self, mac: str = None) -> Dict[str, Any]:
        """статистика по устройствам"""
        if mac:
            return dict(self.devices.get(mac, {}))
        
        return {mac: dict(stats) for mac, stats in self.devices.items()}
    
    def get_packet_count(self) -> int:
        """ количество захваченных пакетов"""
        return self.packet_count
    
    def get_uptime(self) -> str:
        """Получение времени работы системы"""
        if not self.start_time:
            return "00:00:00"
        
        uptime = datetime.now() - self.start_time
        return str(uptime).split('.')[0]
    
    def get_active_devices(self) -> List[Dict[str, Any]]:
        """Получение списка активных устройств"""
        active_devices = []
        current_time = datetime.now()
        
        for mac, stats in self.devices.items():
            # Считаем устройство активным
            if current_time - stats['last_seen'] < timedelta(minutes=5):
                device_info = {
                    'mac': mac,
                    'ip': next(iter(stats['dst_ips']), 'Unknown') if stats['dst_ips'] else 'Unknown',
                    'vendor': self._get_vendor(mac),
                    'device_type': self._classify_device(stats),
                    'packet_count': stats['packet_count'],
                    'data_volume': stats['data_volume'],
                    'last_seen': stats['last_seen'].isoformat(),
                    'risk_score': len(stats['anomalies']) * 10,
                    'anomalies': stats['anomalies'][-5:]  # Последние 5 аномалий
                }
                active_devices.append(device_info)
        
        return active_devices
    
    def _get_vendor(self, mac: str) -> str:
        """Определение производителя по MAC-адресу (упрощенная версия)"""
  
        return "Unknown Vendor"
    
    def _classify_device(self, device_stats: Dict[str, Any]) -> str:
        """типа устройств на основе статистики"""
        ports = device_stats['ports']
        protocols = device_stats['protocols']
        
        # Правила
        if 554 in ports or 8854 in ports:
            return "Camera"
        elif 1883 in ports or 8883 in ports:
            return "MQTT Device"
        elif 80 in ports or 443 in ports:
            if 'TCP' in protocols and len(ports) > 5:
                return "Smart Hub"
            return "Web Device"
        elif 5353 in ports:
            return "Smart Home Device"
        
        return "Unknown IoT"
