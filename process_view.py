import curses
import psutil
import time
from datetime import datetime

def format_memory(bytes_value):
    """Formatează memoria în unități citibile (KB, MB, GB, TB)"""
    if bytes_value < 1024:
        return f"{bytes_value}B"
    elif bytes_value < 1024 * 1024:
        return f"{bytes_value/1024:.1f}K"
    elif bytes_value < 1024 * 1024 * 1024:
        return f"{bytes_value/(1024*1024):.1f}M"
    elif bytes_value < 1024 * 1024 * 1024 * 1024:
        return f"{bytes_value/(1024*1024*1024):.1f}G"
    else:
        return f"{bytes_value/(1024*1024*1024*1024):.1f}T"

def format_time_duration(timestamp):
    """Formatează timpul de rulare al unui proces"""
    try:
        start_time = datetime.fromtimestamp(timestamp)
        duration = datetime.now() - start_time
        
        if duration.days > 0:
            return f"{duration.days}d {duration.seconds//3600}h"
        elif duration.seconds > 3600:
            return f"{duration.seconds//3600}h {(duration.seconds%3600)//60}m"
        elif duration.seconds > 60:
            return f"{duration.seconds//60}m {duration.seconds%60}s"
        else:
            return f"{duration.seconds}s"
    except:
        return "???"

def get_process_status_symbol(proc):
    """Returnează un simbol pentru starea procesului"""
    try:
        status = proc.status()
        symbols = {
            'running': '●',
            'sleeping': '○',
            'disk-sleep': '◐',
            'stopped': '◻',
            'zombie': '☠',
            'idle': '◯'
        }
        return symbols.get(status, '?')
    except:
        return '?'

def calculate_cpu_percent(proc, prev_cpu_times):
    """Calculează utilizarea reală a CPU-ului pentru un proces"""
    try:
        pid = proc.pid
        current_times = proc.cpu_times()
        current_time = time.time()
        
        if pid in prev_cpu_times:
            prev_times, prev_time = prev_cpu_times[pid]
            
            # Calculează diferența de timp
            time_diff = current_time - prev_time
            if time_diff <= 0:
                return 0.0
                
            # Calculează diferența de utilizare CPU
            cpu_diff = (
                (current_times.user - prev_times.user) +
                (current_times.system - prev_times.system)
            )
            
            # Calculează procentul (utilizare CPU / timp total * număr nuclee)
            cpu_percent = (cpu_diff / time_diff) * 100
            
            return min(100.0, cpu_percent)
        
        return 0.0
    except:
        return 0.0

def collect_processes_with_cpu(monitor):
    """Colectează procesele cu măsurarea corectă a CPU"""
    processes = []
    suspicious_count = 0
    current_time = time.time()
    
    # Inițializează dicționarul de timpi CPU anteriori
    prev_cpu_times = {}
    if hasattr(monitor, 'cpu_times_cache'):
        prev_cpu_times = monitor.cpu_times_cache
    
    # Actualizează cache-ul pentru timpi CPU
    new_cpu_times_cache = {}
    
    # Procesează toate procesele
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
        try:
            # Obține informații de bază
            info = proc.as_dict(attrs=['pid', 'name', 'memory_percent', 
                                     'cmdline', 'username', 'create_time'])
            
            # Calculează utilizarea CPU
            cpu_percent = calculate_cpu_percent(proc, prev_cpu_times)
            info['cpu_percent'] = cpu_percent
            
            # Salvează timpii CPU pentru următorul calcul
            new_cpu_times_cache[proc.pid] = (proc.cpu_times(), current_time)
            
            # Verifică dacă procesul este suspicios
            is_suspicious = monitor.detector.is_suspicious_process(proc)
            
            if monitor.show_only_suspicious and not is_suspicious:
                continue
                
            processes.append((proc, is_suspicious, info))
            if is_suspicious:
                suspicious_count += 1
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Actualizează cache-ul în monitor pentru următorul refresh
    monitor.cpu_times_cache = new_cpu_times_cache
    
    return processes, suspicious_count

def find_selected_process_in_list(processes, selected_pid):
    """Găsește indexul procesului selectat în lista curentă de procese"""
    if selected_pid is None:
        return None
        
    for idx, (proc, is_suspicious, info) in enumerate(processes):
        if info.get('pid') == selected_pid:
            return idx
    return None

def draw_process_header(stdscr, y, width, monitor):
    """Desenează header-ul pentru lista de procese"""
    try:
        # Linia de titlu
        title = f"PROCESE {'(DOAR SUSPICIOASE)' if monitor.show_only_suspicious else '(TOATE)'}"
        sort_info = f"Sortat după: {monitor.sort_by.upper()} {'↓' if monitor.sort_reverse else '↑'}"
        
        stdscr.addstr(y, 2, title, curses.A_BOLD | curses.color_pair(2))
        stdscr.addstr(y, width - len(sort_info) - 2, sort_info, curses.A_DIM)
        
        # Linia separator
        stdscr.addstr(y + 1, 2, "─" * (width - 4))
        
        # Header-ul coloanelor
        header = f"{'ST':<2} {'PID':<8} {'USER':<10} {'NAME':<18} {'CPU%':<6} {'MEM%':<6} {'VMEM':<8} {'TIME':<6} CMD"
        stdscr.addstr(y + 2, 2, header, curses.A_BOLD)
        
        return y + 3
    except curses.error:
        return y + 3

def draw_process_details(stdscr, y, width, proc_info, is_selected=False, is_suspicious=False):
    """Desenează detaliile unui proces"""
    try:
        proc, is_susp, info = proc_info
        pid = info.get('pid', 0)
        name = info.get('name', 'UNKNOWN')[:17]
        cpu = info.get('cpu_percent', 0)
        mem = info.get('memory_percent', 0)
        user = info.get('username', 'UNKNOWN')[:9]
        create_time = info.get('create_time', 0)
        
        # Obține informații suplimentare
        try:
            proc_obj = psutil.Process(pid)
            memory_info = proc_obj.memory_info()
            vmem = format_memory(memory_info.vms)
            status_symbol = get_process_status_symbol(proc_obj)
            runtime = format_time_duration(create_time)
        except:
            vmem = "???"
            status_symbol = "?"
            runtime = "???"
        
        # Comandă truncată
        cmdline = info.get('cmdline', [])
        if cmdline:
            cmd = ' '.join(cmdline)
        else:
            cmd = f"[{name}]"
        
        cmd_width = width - 65
        if len(cmd) > cmd_width:
            cmd = cmd[:cmd_width-3] + "..."
        
        # Determină culoarea
        color = curses.A_NORMAL
        if is_selected:
            color = curses.color_pair(2) | curses.A_REVERSE
        elif is_suspicious:
            color = curses.color_pair(3) | curses.A_BOLD
        elif cpu > 80:
            color = curses.color_pair(3)
        elif cpu > 50:
            color = curses.color_pair(2)
        elif mem > 80:
            color = curses.color_pair(3)
        
        # Desenează linia procesului
        line = f"{status_symbol:<2} {pid:<8} {user:<10} {name:<18} {cpu:<6.1f} {mem:<6.1f} {vmem:<8} {runtime:<6} {cmd}"
        stdscr.addstr(y, 2, line[:width-4], color)
        
        return True
    except curses.error:
        return False

def draw_selected_process_panel(stdscr, height, width, selected_proc_info):
    """Desenează panoul cu procesul selectat și copiii săi în partea dreaptă"""
    try:
        if not selected_proc_info:
            return
            
        proc, is_susp, info = selected_proc_info
        
        # Calculăm lățimea panoului (1/3 din ecran)
        panel_width = width // 3
        panel_x = width - panel_width
        panel_height = height - 8  # Lasă spațiu pentru header și footer
        
        # Desenează rama panoului
        for y in range(6, height - 2):
            try:
                stdscr.addstr(y, panel_x - 1, "│", curses.color_pair(1))
            except curses.error:
                pass
        
        # Header panoul
        pid = info.get('pid', 0)
        name = info.get('name', 'UNKNOWN')
        
        try:
            header_text = f" PROCESUL SELECTAT: {name} ({pid}) "
            stdscr.addstr(6, panel_x, header_text[:panel_width-2], curses.A_BOLD | curses.color_pair(2))
            stdscr.addstr(7, panel_x, "─" * (panel_width - 2))
        except curses.error:
            pass
        
        # Informații despre proces
        current_y = 8
        try:
            proc_obj = psutil.Process(pid)
            
            # Informații de bază
            user = info.get('username', 'UNKNOWN')
            status = proc_obj.status()
            cpu = info.get('cpu_percent', 0)
            mem = info.get('memory_percent', 0)
            
            stdscr.addstr(current_y, panel_x, f"User: {user}", curses.A_BOLD)
            stdscr.addstr(current_y + 1, panel_x, f"Status: {status}")
            stdscr.addstr(current_y + 2, panel_x, f"CPU: {cpu:.1f}%")
            stdscr.addstr(current_y + 3, panel_x, f"MEM: {mem:.1f}%")
            
            current_y += 5
            
            # Separator pentru copii
            stdscr.addstr(current_y, panel_x, "PROCESE COPIL:", curses.A_BOLD | curses.color_pair(2))
            stdscr.addstr(current_y + 1, panel_x, "─" * (panel_width - 2))
            current_y += 2
            
            # Afișează procesele copil (maxim 10 pentru performanță)
            try:
                children = proc_obj.children(recursive=True)  # Recursiv pentru toți copiii
                
                if not children:
                    stdscr.addstr(current_y, panel_x, "Nu are procese copil", curses.color_pair(1))
                else:
                    # Afișează până la maxim 10 copii
                    max_children = min(len(children), 10)
                    
                    for i, child in enumerate(children[:max_children]):
                        try:
                            # Folosește oneshot pentru eficiență
                            with child.oneshot():
                                child_pid = child.pid
                                child_name = child.name()[:12]
                                child_cpu = child.cpu_percent(interval=0)  # Nu bloca
                                child_mem = child.memory_percent()
                            
                            # Determină nivelul de indentare
                            indent = "├─" if i < len(children) - 1 else "└─"
                            
                            line = f"{indent} {child_pid} {child_name[:10]}"
                            stdscr.addstr(current_y + i, panel_x, line[:panel_width-2], curses.color_pair(1))
                            
                            # Afișează CPU/MEM pe linia următoare dacă încape
                            if current_y + i + 1 < height - 3:
                                stats = f"   CPU: {child_cpu:.1f}% MEM: {child_mem:.1f}%"
                                stdscr.addstr(current_y + i + 1, panel_x, stats[:panel_width-2], curses.A_DIM)
                                current_y += 1
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    # Afișează numărul total dacă sunt mai mulți
                    if len(children) > max_children:
                        remaining = len(children) - max_children
                        try:
                            stdscr.addstr(current_y + max_children, panel_x, 
                                        f"... și încă {remaining} copii", curses.A_DIM)
                        except curses.error:
                            pass
                            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                stdscr.addstr(current_y, panel_x, "Eroare la citirea copiilor", curses.color_pair(3))
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            stdscr.addstr(current_y, panel_x, "Procesul nu mai există", curses.color_pair(3))
            
    except curses.error:
        pass

def draw_process_info_panel(stdscr, height, width, selected_proc_info):
    """Desenează panoul cu informații detaliate despre procesul selectat"""
    try:
        if not selected_proc_info:
            return
            
        proc, is_susp, info = selected_proc_info
        pid = info.get('pid', 0)
        
        try:
            proc_obj = psutil.Process(pid)
            
            # Calculăm lățimea disponibilă (2/3 din ecran pentru că panoul lateral ocupă 1/3)
            available_width = (width * 2) // 3
            
            # Poziția panoului (în partea de jos a secțiunii principale)
            panel_height = 4
            panel_y = height - panel_height - 1
            
            # Desenează rama panoului
            stdscr.addstr(panel_y - 1, 2, "─" * (available_width - 4))
            stdscr.addstr(panel_y, 2, f"DETALII PROCES PID={pid}", curses.A_BOLD | curses.color_pair(2))
            
            # Comandă completă
            cmdline = ' '.join(info.get('cmdline', []))
            if cmdline:
                cmd_display = cmdline[:available_width-10]
                if len(cmdline) > available_width-10:
                    cmd_display += "..."
                stdscr.addstr(panel_y + 1, 4, f"CMD: {cmd_display}")
            
            # Fișiere și conexiuni
            try:
                open_files = len(proc_obj.open_files())
                connections = len(proc_obj.connections())
                threads = proc_obj.num_threads()
                
                stats_line = f"Fișiere: {open_files} | Conexiuni: {connections} | Thread-uri: {threads}"
                stdscr.addstr(panel_y + 2, 4, stats_line[:available_width-8])
            except:
                pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            stdscr.addstr(panel_y + 1, 4, "Procesul nu mai există sau accesul este refuzat", 
                         curses.color_pair(3))
            
    except curses.error:
        pass

def draw_process_list(stdscr, height, width, monitor):
    """Funcția principală pentru desenarea listei de procese"""
    try:
        # Calculăm lățimea zonei pentru lista de procese
        has_selected = hasattr(monitor, 'selected_process_pid') and monitor.selected_process_pid is not None
        list_width = (width * 2) // 3 if has_selected else width
        
        # Colectează procesele cu măsurarea corectă a CPU
        processes, suspicious_count = collect_processes_with_cpu(monitor)
        
        # Sortează procesele
        sort_key = 'cpu_percent' if monitor.sort_by == 'cpu' else 'memory_percent'
        processes.sort(key=lambda x: x[2].get(sort_key, 0), reverse=monitor.sort_reverse)
        
        # Găsește procesul selectat în lista nouă (stabilizează selecția)
        if has_selected:
            new_selected_index = find_selected_process_in_list(processes, monitor.selected_process_pid)
            if new_selected_index is not None:
                monitor.selected_process_index = new_selected_index
            else:
                # Procesul selectat nu mai există
                monitor.selected_process_pid = None
                monitor.selected_process_index = None
                has_selected = False
                list_width = width
        
        # Desenează header-ul
        current_y = draw_process_header(stdscr, 6, list_width, monitor)
        
        # Afișează statistici
        stats_text = f"Total: {len(processes)} | Suspicioase: {suspicious_count}"
        if monitor.show_only_suspicious:
            stats_text += " | Mod: DOAR SUSPICIOASE"
            
        try:
            stdscr.addstr(current_y - 1, list_width - len(stats_text) - 2, stats_text, curses.A_DIM)
        except curses.error:
            pass
        
        # Calculează zona de afișare
        info_panel_height = 5 if has_selected else 0
        available_height = height - current_y - 3 - info_panel_height
        
        # Ajustează scroll offset-ul pentru a menține procesul selectat vizibil
        if monitor.selected_process_index is not None:
            if monitor.selected_process_index >= len(processes):
                monitor.selected_process_index = max(0, len(processes) - 1)
            
            # Auto-scroll pentru a menține procesul selectat vizibil
            if monitor.selected_process_index < monitor.process_scroll_offset:
                monitor.process_scroll_offset = monitor.selected_process_index
            elif monitor.selected_process_index >= monitor.process_scroll_offset + available_height:
                monitor.process_scroll_offset = monitor.selected_process_index - available_height + 1
        
        # Desenează procesele vizibile
        visible_processes = processes[monitor.process_scroll_offset:
                                   monitor.process_scroll_offset + available_height]
        
        y = current_y
        for idx, proc_info in enumerate(visible_processes):
            global_idx = idx + monitor.process_scroll_offset
            is_selected = (monitor.selected_process_index == global_idx)
            is_suspicious = proc_info[1]
            
            if not draw_process_details(stdscr, y, list_width, proc_info, is_selected, is_suspicious):
                break
                
            y += 1
            
            if y >= height - info_panel_height - 3:
                break
        
        # Desenează panourile cu informații detaliate
        if has_selected and monitor.selected_process_index is not None and monitor.selected_process_index < len(processes):
            selected_proc_info = processes[monitor.selected_process_index]
            draw_process_info_panel(stdscr, height, width, selected_proc_info)
            draw_selected_process_panel(stdscr, height, width, selected_proc_info)
        
        # Desenează indicatorul de scroll
        if len(processes) > available_height:
            scroll_pos = int((monitor.process_scroll_offset / len(processes)) * available_height)
            scroll_size = max(1, int((available_height / len(processes)) * available_height))
            
            scroll_x = list_width - 2 if has_selected else width - 2
            
            for i in range(available_height):
                char = '█' if scroll_pos <= i < scroll_pos + scroll_size else '░'
                try:
                    stdscr.addstr(current_y + i, scroll_x, char, curses.A_DIM)
                except curses.error:
                    pass
        
        # Ajutoare pentru taste
        help_text = "TAB:schimbă | ↑/↓:navighează | ENTER:selectează/deselectează | S:suspicioase | C:CPU | M:MEM | R:inversează"
        try:
            stdscr.addstr(height - 1, 2, help_text[:width-4], curses.A_DIM)
        except curses.error:
            pass
            
    except Exception as e:
        try:
            stdscr.addstr(height - 3, 2, f"Eroare afișare procese: {str(e)[:60]}", 
                         curses.color_pair(3))
        except curses.error:
            pass

# Funcții pentru gestionarea selecției stabile de procese
def select_process(monitor, process_index, processes):
    """Selectează un proces și salvează PID-ul pentru selecție stabilă"""
    if 0 <= process_index < len(processes):
        selected_proc = processes[process_index]
        monitor.selected_process_pid = selected_proc[2].get('pid')
        monitor.selected_process_index = process_index
        return True
    return False

def deselect_process(monitor):
    """Deselectează procesul curent"""
    monitor.selected_process_pid = None
    monitor.selected_process_index = None

def handle_process_navigation(monitor, processes, key):
    """Gestionează navigarea prin lista de procese"""
    if not processes:
        return
        
    if key == curses.KEY_UP:
        if monitor.selected_process_index is None:
            select_process(monitor, 0, processes)
        elif monitor.selected_process_index > 0:
            select_process(monitor, monitor.selected_process_index - 1, processes)
            
    elif key == curses.KEY_DOWN:
        if monitor.selected_process_index is None:
            select_process(monitor, 0, processes)
        elif monitor.selected_process_index < len(processes) - 1:
            select_process(monitor, monitor.selected_process_index + 1, processes)
