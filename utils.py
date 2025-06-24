import curses
import psutil
import os
import time
import platform
from datetime import datetime

# Variabile globale pentru statistici CPU
_prev_cpu_times = None
_prev_cpu_time = None

# Variabile globale pentru statistici rețea
_prev_net_io = None
_prev_net_time = None

def init_colors():
    """Inițializează paleta de culori pentru interfața curses"""
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Verde
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Galben
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)    # Roșu

def draw_progress_bar(stdscr, y, x, width, percent, label):
    """Desenează o bară de progres cu culori corespunzătoare"""
    try:
        # Asigură-te că procentajul este între 0 și 100
        percent = max(0.0, min(100.0, percent))
        
        # Calculează numărul de caractere umplute
        filled = int(width * percent / 100)
        bar = '█' * filled + '░' * (width - filled)
        
        # Alege culoarea în funcție de procentaj
        if percent > 80:
            color = curses.color_pair(3)  # Roșu
        elif percent > 60:
            color = curses.color_pair(2)  # Galben
        else:
            color = curses.color_pair(1)  # Verde
            
        # Formatează textul
        text = f"{label:4s}: [{bar}] {percent:5.1f}%"
        stdscr.addstr(y, x, text, color)
    except curses.error:
        pass

def reset_cpu_stats():
    """Resetează statisticile CPU pentru recalculare"""
    global _prev_cpu_times, _prev_cpu_time
    _prev_cpu_times = None
    _prev_cpu_time = None

def get_cpu_usage():
    """
    Calculează utilizarea reală a CPU-ului la nivel de sistem
    folosind diferențele de timp între măsurători
    """
    global _prev_cpu_times, _prev_cpu_time
    
    try:
        # Obține timpii curenti de CPU
        current_cpu_times = psutil.cpu_times()
        current_time = time.time()
        
        if _prev_cpu_times is None or _prev_cpu_time is None:
            # Prima apelare, inițializează valorile
            _prev_cpu_times = current_cpu_times
            _prev_cpu_time = current_time
            return 0.0
        
        # Calculează diferența de timp
        time_diff = current_time - _prev_cpu_time
        if time_diff <= 0:
            return 0.0
        
        # Calculează diferențele de utilizare CPU
        user_diff = current_cpu_times.user - _prev_cpu_times.user
        system_diff = current_cpu_times.system - _prev_cpu_times.system
        idle_diff = current_cpu_times.idle - _prev_cpu_times.idle
        
        # Calculează timpul total de CPU
        total_diff = user_diff + system_diff + idle_diff
        if total_diff <= 0:
            return 0.0
        
        # Calculează procentajul de utilizare
        # (timp activ / timp total) * 100
        active_diff = user_diff + system_diff
        cpu_percent = (active_diff / total_diff) * 100
        
        # Actualizează valorile anterioare
        _prev_cpu_times = current_cpu_times
        _prev_cpu_time = current_time
        
        return min(100.0, cpu_percent)
        
    except Exception:
        return 0.0

def reset_network_stats():
    """Resetează statisticile de rețea pentru recalculare"""
    global _prev_net_io, _prev_net_time
    _prev_net_io = None
    _prev_net_time = None

def get_network_usage_percent(max_speed_mbps=100):
    """
    Calculează utilizarea rețelei ca procent din viteza maximă așteptată
    
    Args:
        max_speed_mbps: Viteza maximă așteptată în Mbps (implicit 100)
    
    Returns:
        Procentul utilizării rețelei (0-100)
    """
    global _prev_net_io, _prev_net_time
    
    try:
        current_net_io = psutil.net_io_counters()
        if current_net_io is None:
            return 0.0
            
        current_time = time.time()
        
        if _prev_net_io is None or _prev_net_time is None:
            # Prima apelare, inițializează și returnează 0
            _prev_net_io = current_net_io
            _prev_net_time = current_time
            return 0.0
        
        # Calculează diferența de timp
        time_diff = current_time - _prev_net_time
        if time_diff <= 0:
            return 0.0
        
        # Calculează bytes transferați pe secundă
        bytes_sent_per_sec = max(0, (current_net_io.bytes_sent - _prev_net_io.bytes_sent) / time_diff)
        bytes_recv_per_sec = max(0, (current_net_io.bytes_recv - _prev_net_io.bytes_recv) / time_diff)
        total_bytes_per_sec = bytes_sent_per_sec + bytes_recv_per_sec
        
        # Convertește în Mbps (1 byte = 8 bits, 1 Mbps = 1,000,000 bits/sec)
        mbps = (total_bytes_per_sec * 8) / 1_000_000
        
        # Calculează procentul din viteza maximă
        percent = min(100.0, (mbps / max_speed_mbps) * 100)
        
        # Actualizează valorile anterioare
        _prev_net_io = current_net_io
        _prev_net_time = current_time
        
        return percent
        
    except Exception:
        return 0.0

def get_load_average():
    """Obține load average-ul sistemului, compatibil cross-platform"""
    try:
        if platform.system() == "Windows":
            # Pe Windows, folosim CPU usage ca aproximare pentru load
            return [psutil.cpu_percent(interval=None)] * 3
        else:
            # Pe Unix/Linux/macOS
            return list(os.getloadavg())
    except Exception:
        return [0.0, 0.0, 0.0]

def get_disk_usage(path='/'):
    """Obține utilizarea discului pentru calea specificată"""
    try:
        disk = psutil.disk_usage(path)
        return (disk.used / disk.total) * 100
    except Exception:
        return 0.0

def draw_system_stats(stdscr):
    """Desenează statisticile sistemului cu gestionare robustă a erorilor"""
    try:
        # Obține statisticile cu gestionare individuală a erorilor
        
        # Folosim noua metodă precisă pentru CPU
        try:
            cpu_percent = get_cpu_usage()
        except Exception:
            cpu_percent = 0.0
            
        try:
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
        except Exception:
            mem_percent = 0.0
            
        try:
            disk_percent = get_disk_usage('/')
        except Exception:
            disk_percent = 0.0
            
        try:
            net_percent = get_network_usage_percent()
        except Exception:
            net_percent = 0.0
            
        try:
            uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
            uptime_str = str(uptime).split('.')[0]  # Elimină microsecondle
        except Exception:
            uptime_str = "N/A"
            
        try:
            process_count = len(psutil.pids())
        except Exception:
            process_count = 0

        # Desenează barele de progres
        draw_progress_bar(stdscr, 1, 2, 30, cpu_percent, "CPU")
        draw_progress_bar(stdscr, 2, 2, 30, mem_percent, "RAM")
        draw_progress_bar(stdscr, 3, 2, 30, disk_percent, "DISK")
        draw_progress_bar(stdscr, 4, 2, 30, net_percent, "NET")

        # Informații suplimentare
        try:
            stdscr.addstr(1, 40, f"Procese: {process_count}")
        except curses.error:
            pass
            
        try:
            stdscr.addstr(2, 40, f"Uptime: {uptime_str}")
        except curses.error:
            pass
            
        try:
            load_avg = get_load_average()
            load_str = ' '.join(f'{x:.2f}' for x in load_avg)
            stdscr.addstr(3, 40, f"Load: {load_str}")
        except curses.error:
            pass
            
    except Exception:
        # Fallback în caz de eroare generală
        try:
            stdscr.addstr(1, 2, "Eroare la obținerea statisticilor sistemului")
        except curses.error:
            pass
