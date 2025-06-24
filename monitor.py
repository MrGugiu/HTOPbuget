import curses
import time
import psutil
import gc
from datetime import datetime
from core.detector import SuspiciousActivityDetector
from ui.utils import init_colors, draw_system_stats
from ui.process_view import draw_process_list, select_process, deselect_process, handle_process_navigation, collect_processes_with_cpu
from ui.log_view import draw_suspicious_logs

class SystemMonitor:
    def __init__(self):
        self.detector = SuspiciousActivityDetector()
        self.current_tab = 0
        self.show_only_suspicious = False
        self.suspicious_logs = []
        self.log_scroll_offset = 0
        self.process_scroll_offset = 0
        self.selected_process_index = None
        self.selected_process_pid = None
        self.last_log_scan = 0
        self.sort_by = 'cpu'
        self.sort_reverse = True
        self.log_filter = 'ALL'
        self.show_full_process_info = True
        self.show_help = False
        self.processes_cache = []
        self.last_process_refresh = 0
        self.process_refresh_interval = 1.5
        self.last_gc_run = 0
        self.last_cpu_measurement = 0  # Track last CPU measurement time

    def refresh_logs(self, force_full=False):
        """Refresh logs without resetting cache on partial scans"""
        # Only reset seen logs on full scan
        if force_full:
            self.detector.seen_logs.clear()
            
        self.suspicious_logs = self.detector.scan_logs(force_full_scan=force_full)
        self.log_scroll_offset = 0
        self.last_log_scan = time.time()

    def clear_log_cache(self):
        self.detector.seen_logs.clear()
        self.detector.debug_stats.clear()
        self.refresh_logs(force_full=True)

    def cycle_log_filter(self):
        filters = ['ALL', 'CRITICAL', 'SECURITY', 'NETWORK', 'SYSTEM', 'WARNING']
        current_index = filters.index(self.log_filter) if self.log_filter in filters else 0
        self.log_filter = filters[(current_index + 1) % len(filters)]
        self.log_scroll_offset = 0

    def refresh_processes(self, force=False):
        """Refresh process list with frequency control"""
        current_time = time.time()
        if force or current_time - self.last_process_refresh > self.process_refresh_interval:
            self.processes_cache, _ = collect_processes_with_cpu(self)
            self.last_process_refresh = current_time
            
            # Periodic garbage collection
            if current_time - self.last_gc_run > 30:
                gc.collect()
                self.last_gc_run = current_time
                
            return True
        return False

    def get_current_processes(self):
        """Return current process list, sorted according to settings"""
        sort_key = 'cpu_percent' if self.sort_by == 'cpu' else 'memory_percent'
        sorted_processes = sorted(self.processes_cache, 
                                key=lambda x: x[2].get(sort_key, 0), 
                                reverse=self.sort_reverse)
        return sorted_processes

    def handle_process_selection_keys(self, key):
        """Handle keys for process selection"""
        current_processes = self.get_current_processes()
        
        if key == curses.KEY_UP:
            handle_process_navigation(self, current_processes, curses.KEY_UP)
        elif key == curses.KEY_DOWN:
            handle_process_navigation(self, current_processes, curses.KEY_DOWN)
        elif key == ord('\n'):  # ENTER
            if self.selected_process_index is not None:
                deselect_process(self)
            else:
                # Select first process if none selected
                if current_processes:
                    select_process(self, 0, current_processes)

    def handle_process_sorting_keys(self, key):
        """Handle keys for process sorting"""
        if key in [ord('c'), ord('C')]:
            self.sort_by = 'cpu'
            # Keep selected process after sort change
            if self.selected_process_pid:
                current_processes = self.get_current_processes()
                for idx, (proc, is_susp, info) in enumerate(current_processes):
                    if info.get('pid') == self.selected_process_pid:
                        self.selected_process_index = idx
                        break
        elif key in [ord('m'), ord('M')]:
            self.sort_by = 'memory'
            # Keep selected process after sort change
            if self.selected_process_pid:
                current_processes = self.get_current_processes()
                for idx, (proc, is_susp, info) in enumerate(current_processes):
                    if info.get('pid') == self.selected_process_pid:
                        self.selected_process_index = idx
                        break
        elif key in [ord('r'), ord('R')]:
            self.sort_reverse = not self.sort_reverse
            # Keep selected process after sort reversal
            if self.selected_process_pid:
                current_processes = self.get_current_processes()
                for idx, (proc, is_susp, info) in enumerate(current_processes):
                    if info.get('pid') == self.selected_process_pid:
                        self.selected_process_index = idx
                        break

    def draw_help_overlay(self, stdscr, height, width):
        """Display help overlay"""
        try:
            # Calculate help window dimensions
            help_height = min(22, height - 4)
            help_width = min(75, width - 4)
            start_y = (height - help_height) // 2
            start_x = (width - help_width) // 2

            # Draw background
            for y in range(start_y, start_y + help_height):
                stdscr.addstr(y, start_x, " " * help_width, curses.color_pair(2))

            # Title
            title = "AJUTOR - COMENZI DISPONIBILE"
            stdscr.addstr(start_y + 1, start_x + (help_width - len(title)) // 2, 
                         title, curses.A_BOLD | curses.color_pair(2))

            # Commands
            commands = [
                "",
                "NAVIGARE GENERALĂ:",
                "  TAB          - Schimbă între tab-uri (Procese/Log-uri)",
                "  Q sau ESC    - Ieșire din aplicație",
                "  H            - Afișează/ascunde acest ajutor",
                "",
                "TAB PROCESE:",
                "  ↑/↓          - Navighează prin lista de procese",
                "  ENTER        - Selectează/deselectează proces",
                "  S            - Comută afișarea doar a proceselor suspicioase",
                "  C            - Sortează după utilizarea CPU",
                "  M            - Sortează după utilizarea memoriei",
                "  R            - Inversează ordinea de sortare",
                "  P            - Comută afișarea informațiilor detaliate",
                "  F5           - Reîmprospătează lista de procese manual",
                "",
                "TAB LOG-URI:",
                "  ↑/↓          - Navighează prin log-uri",
                "  F            - Ciclează prin filtrele de log-uri",
                "  Shift+F      - Reîmprospătează log-urile (scan complet)",
                "  R            - Reîmprospătează log-urile (scan rapid)",
                "  D            - Șterge cache-ul de log-uri",
                "",
                "NOTĂ: Procesul selectat rămâne fix chiar dacă lista se reordonează.",
                "",
                "Apasă orice tastă pentru a închide..."
            ]

            for i, cmd in enumerate(commands):
                if start_y + 2 + i < start_y + help_height - 1:
                    if cmd.startswith("  "):
                        stdscr.addstr(start_y + 2 + i, start_x + 2, cmd, curses.A_NORMAL)
                    elif cmd.endswith(":"):
                        stdscr.addstr(start_y + 2 + i, start_x + 2, cmd, curses.A_BOLD)
                    elif cmd.startswith("NOTĂ:"):
                        stdscr.addstr(start_y + 2 + i, start_x + 2, cmd, curses.A_BOLD | curses.color_pair(2))
                    else:
                        stdscr.addstr(start_y + 2 + i, start_x + 2, cmd, curses.A_DIM)

            # Border
            for y in range(start_y, start_y + help_height):
                stdscr.addstr(y, start_x, "│", curses.color_pair(2))
                stdscr.addstr(y, start_x + help_width - 1, "│", curses.color_pair(2))
            
            stdscr.addstr(start_y, start_x, "┌" + "─" * (help_width - 2) + "┐", curses.color_pair(2))
            stdscr.addstr(start_y + help_height - 1, start_x, "└" + "─" * (help_width - 2) + "┘", curses.color_pair(2))

        except curses.error:
            pass

    def run(self, stdscr):
        init_colors()
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(1000)
        self.refresh_logs(force_full=True)  # Initial full scan
        self.refresh_processes(force=True)

        while True:
            height, width = stdscr.getmaxyx()
            stdscr.clear()

            # Refresh logs periodically but keep existing entries
            if self.current_tab == 1 and time.time() - self.last_log_scan > 30:
                self.refresh_logs(force_full=False)

            # Refresh processes
            if self.current_tab == 0:
                self.refresh_processes()

            # Draw system stats
            draw_system_stats(stdscr)

            # Draw current tab content
            if not self.show_help:
                if self.current_tab == 0:
                    draw_process_list(stdscr, height, width, self)
                elif self.current_tab == 1:
                    draw_suspicious_logs(stdscr, height, width, self)

                # Status bar
                tab_name = "Procese" if self.current_tab == 0 else "Log-uri"
                status_parts = [
                    f"Monitor Sistem",
                    f"{datetime.now().strftime('%H:%M:%S')}",
                    f"Tab: {tab_name}",
                ]
                
                if self.current_tab == 0:
                    if self.selected_process_pid:
                        status_parts.append(f"PID selectat: {self.selected_process_pid}")
                    status_parts.append(f"Sortare: {self.sort_by.upper()}")
                    if self.show_only_suspicious:
                        status_parts.append("DOAR SUSPICIOASE")
                
                status_parts.append("H=Ajutor")
                status = " | ".join(status_parts)
                
                try:
                    stdscr.addstr(height - 2, 2, status[:width-4], curses.A_DIM)
                except curses.error:
                    pass
            else:
                self.draw_help_overlay(stdscr, height, width)

            stdscr.refresh()
            key = stdscr.getch()

            # Key handling
            if key in [ord('q'), ord('Q'), 27]:
                break
            elif key in [ord('h'), ord('H')]:
                self.show_help = not self.show_help
            elif self.show_help and key != -1:
                self.show_help = False
            elif key == ord('\t'):
                self.current_tab = (self.current_tab + 1) % 2
                self.log_scroll_offset = 0
                self.process_scroll_offset = 0
            elif key == 265:  # F5
                if self.current_tab == 0:
                    self.refresh_processes(force=True)
            elif self.current_tab == 0:
                if key in [curses.KEY_UP, curses.KEY_DOWN, ord('\n')]:
                    self.handle_process_selection_keys(key)
                elif key in [ord('c'), ord('C'), ord('m'), ord('M'), ord('r'), ord('R')]:
                    self.handle_process_sorting_keys(key)
                elif key in [ord('s'), ord('S')]:
                    self.show_only_suspicious = not self.show_only_suspicious
                    deselect_process(self)
                    self.process_scroll_offset = 0
                    self.refresh_processes(force=True)
                elif key in [ord('p'), ord('P')]:
                    self.show_full_process_info = not self.show_full_process_info
            elif self.current_tab == 1:
                if key == curses.KEY_UP:
                    self.log_scroll_offset = max(0, self.log_scroll_offset - 1)
                elif key == curses.KEY_DOWN:
                    self.log_scroll_offset += 1
                elif key in [ord('r'), ord('R')]:
                    self.refresh_logs(force_full=False)
                elif key in [ord('f'), ord('F')]:
                    if key == ord('F'):  # Shift+F
                        self.refresh_logs(force_full=True)
                    else:
                        self.cycle_log_filter()
                elif key in [ord('d'), ord('D')]:
                    self.detector.seen_logs.clear()  # Clear cache but keep current logs

            time.sleep(0.05)
   
