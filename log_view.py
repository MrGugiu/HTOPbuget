import curses
from datetime import datetime

def format_log_category(categories):
    """Format log categories for display"""
    if not categories:
        return "UNKNOWN"
    
    priority_order = ['CRITICAL', 'SECURITY', 'NETWORK', 'SYSTEM', 'WARNING']
    for priority in priority_order:
        if priority in categories:
            return priority
    return categories[0]

def get_category_color(category):
    """Return color for a log category"""
    colors = {
        'CRITICAL': curses.color_pair(3) | curses.A_BOLD,  # Red bold
        'SECURITY': curses.color_pair(3),                   # Red
        'NETWORK': curses.color_pair(2),                    # Yellow
        'SYSTEM': curses.color_pair(1),                     # Green
        'WARNING': curses.color_pair(2) | curses.A_DIM,    # Yellow dimmed
    }
    return colors.get(category, curses.A_NORMAL)

def draw_log_header(stdscr, y, width, monitor):
    """Draw header for the log list"""
    try:
        # Title with current filter
        filter_text = f"({monitor.log_filter})" if monitor.log_filter != 'ALL' else "(TOATE)"
        title = f"LOG-URI SUSPICIOASE {filter_text}"
        
        # Update information
        last_scan_text = f"Ultima scan: {datetime.fromtimestamp(monitor.last_log_scan).strftime('%H:%M:%S')}" if monitor.last_log_scan > 0 else "Niciun scan"
        
        stdscr.addstr(y, 2, title, curses.A_BOLD | curses.color_pair(2))
        stdscr.addstr(y, width - len(last_scan_text) - 2, last_scan_text, curses.A_DIM)
        
        # Separator line
        stdscr.addstr(y + 1, 2, "─" * (width - 4))
        
        # Column headers
        header = f"{'TIMP':<8} {'TIP':<9} {'FIȘIER':<12} {'CONȚINUT'}"
        stdscr.addstr(y + 2, 2, header, curses.A_BOLD)
        
        return y + 3
    except curses.error:
        return y + 3

def draw_log_entry(stdscr, y, width, log_entry, is_highlighted=False):
    """Draw a log entry"""
    try:
        timestamp = log_entry.get('timestamp', '??:??:??')
        categories = log_entry.get('categories', [])
        file_name = log_entry.get('file', 'unknown')[:11]
        content = log_entry.get('content', '')
        
        # Determine main category and color
        main_category = format_log_category(categories)
        color = get_category_color(main_category)
        
        if is_highlighted:
            color |= curses.A_REVERSE
        
        # Calculate available space for content
        content_width = width - 35
        if len(content) > content_width:
            truncated_content = content[:content_width - 3] + "..."
            truncated = True
        else:
            truncated_content = content
            truncated = False
        
        # Format the line
        line = f"{timestamp:<8} {main_category:<9} {file_name:<12} {truncated_content}"
        
        stdscr.addstr(y, 2, line[:width-4], color)
        
        # Add truncation indicator if needed
        if truncated:
            try:
                stdscr.addstr(y, width-2, "»", curses.color_pair(2))
            except:
                pass
                
        return True
        
    except curses.error:
        return False

def draw_log_statistics(stdscr, y, width, monitor):
    """Draw log statistics"""
    try:
        if not hasattr(monitor.detector, 'debug_stats'):
            return y
        
        stats = monitor.detector.debug_stats
        
        # General statistics
        total_entries = stats.get('total_entries', 0)
        returned_entries = stats.get('returned_entries', 0)
        cache_size = stats.get('cache_size', 0)
        
        stats_line = f"Total găsite: {total_entries} | Afișate: {returned_entries} | Cache: {cache_size}"
        
        stdscr.addstr(y, 2, "STATISTICI:", curses.A_BOLD)
        stdscr.addstr(y + 1, 2, stats_line, curses.A_DIM)
        
        # Statistics by category
        if hasattr(monitor.detector, 'log_categories'):
            categories = monitor.detector.log_categories
            y += 3
            
            stdscr.addstr(y, 2, "PE CATEGORII:", curses.A_BOLD)
            y += 1
            
            for category, entries in categories.items():
                if entries:
                    color = get_category_color(category)
                    category_line = f"  {category}: {len(entries)} intrări"
                    stdscr.addstr(y, 2, category_line, color)
                    y += 1
                    
                    if y >= stdscr.getmaxyx()[0] - 3:
                        break
        
        return y
    except curses.error:
        return y

def draw_log_details_panel(stdscr, height, width, selected_log):
    """Draw panel with details of the selected log"""
    try:
        if not selected_log:
            return
            
        # Panel position (at the bottom)
        panel_height = min(12, height - 10)  # Max 12 lines
        panel_y = height - panel_height - 1
        
        # Draw panel border
        stdscr.addstr(panel_y - 1, 2, "─" * (width - 4))
        stdscr.addstr(panel_y, 2, "DETALII LOG SELECTAT", curses.A_BOLD | curses.color_pair(2))
        
        # Basic info
        timestamp = selected_log.get('timestamp', 'N/A')
        file_name = selected_log.get('file', 'N/A')
        categories = selected_log.get('categories', [])
        
        stdscr.addstr(panel_y + 1, 4, f"Timp: {timestamp}")
        stdscr.addstr(panel_y + 1, 20, f"Fișier: {file_name}")
        stdscr.addstr(panel_y + 1, 40, f"Categorii: {', '.join(categories)}")
        
        # Full content
        content = selected_log.get('content', '')
        raw_line = selected_log.get('raw_line', content)
        
        stdscr.addstr(panel_y + 3, 4, "CONȚINUT COMPLET:", curses.A_BOLD)
        
        # Split content into multiple lines if needed
        content_lines = []
        content_width = width - 8
        
        # Split the raw_line into chunks of content_width
        start = 0
        while start < len(raw_line):
            end = start + content_width
            if end > len(raw_line):
                end = len(raw_line)
            content_lines.append(raw_line[start:end])
            start = end
        
        # Display as many lines as fit in the panel
        max_lines = panel_height - 4
        for i, line in enumerate(content_lines[:max_lines]):
            if panel_y + 4 + i < height - 1:
                stdscr.addstr(panel_y + 4 + i, 4, line, curses.A_DIM)
        
        if len(content_lines) > max_lines:
            remaining = len(content_lines) - max_lines
            stdscr.addstr(panel_y + 4 + max_lines, 4, 
                         f"... și încă {remaining} linii", 
                         curses.A_DIM)
            
    except curses.error:
        pass

def draw_suspicious_logs(stdscr, height, width, monitor):
    """Main function for drawing suspicious logs"""
    try:
        # Filter logs by current filter
        if monitor.log_filter == 'ALL':
            filtered_logs = monitor.suspicious_logs
        else:
            filtered_logs = [
                log for log in monitor.suspicious_logs 
                if monitor.log_filter in log.get('categories', [])
            ]
        
        # Draw header
        current_y = draw_log_header(stdscr, 6, width, monitor)
        
        # Statistics
        stats_text = f"Filtrate: {len(filtered_logs)} din {len(monitor.suspicious_logs)}"
        if monitor.log_filter != 'ALL':
            stats_text += f" | Filtru: {monitor.log_filter}"
            
        try:
            stdscr.addstr(current_y - 1, width - len(stats_text) - 2, stats_text, curses.A_DIM)
        except curses.error:
            pass
        
        # Calculate display area
        stats_panel_height = 12  # Space for statistics
        available_height = height - current_y - 3 - stats_panel_height
        
        # Adjust scroll offset
        if monitor.log_scroll_offset >= len(filtered_logs):
            monitor.log_scroll_offset = max(0, len(filtered_logs) - 1)
        
        # Draw visible logs
        visible_logs = filtered_logs[monitor.log_scroll_offset:
                                   monitor.log_scroll_offset + available_height]
        
        y = current_y
        for idx, log_entry in enumerate(visible_logs):
            # For now, we don't have log selection, but we can add it later
            is_highlighted = False  # Can be implemented later
            
            if not draw_log_entry(stdscr, y, width, log_entry, is_highlighted):
                break
                
            y += 1
            
            if y >= height - stats_panel_height - 3:
                break
        
        # Draw scroll indicator
        if len(filtered_logs) > available_height:
            scroll_pos = int((monitor.log_scroll_offset / len(filtered_logs)) * available_height)
            scroll_size = max(1, int((available_height / len(filtered_logs)) * available_height))
            
            for i in range(available_height):
                char = '█' if scroll_pos <= i < scroll_pos + scroll_size else '░'
                try:
                    stdscr.addstr(current_y + i, width - 2, char, curses.A_DIM)
                except curses.error:
                    pass
        
        # Draw statistics at the bottom
        stats_y = height - stats_panel_height
        draw_log_statistics(stdscr, stats_y, width, monitor)
        
        # Draw details panel for the selected log (if any)
        # Note: In this version, we don't have log selection, so we skip it.
        # But if we add log selection, we can call draw_log_details_panel here.
        
        # Message if no logs
        if not filtered_logs:
            no_logs_msg = "Niciun log suspicios găsit"
            if monitor.log_filter != 'ALL':
                no_logs_msg += f" pentru filtrul {monitor.log_filter}"
            try:
                stdscr.addstr(current_y + 2, (width - len(no_logs_msg)) // 2, 
                             no_logs_msg, curses.A_DIM)
            except curses.error:
                pass
        
        # Key help
        help_text = "TAB:schimbă | ↑/↓:navighează | F:filtru | R:reîmprospătează | Shift+F:scan complet | D:curăță cache"
        try:
            stdscr.addstr(height - 1, 2, help_text[:width-4], curses.A_DIM)
        except curses.error:
            pass
            
    except Exception as e:
        try:
            stdscr.addstr(height - 3, 2, f"Eroare afișare log-uri: {str(e)[:60]}", 
                         curses.color_pair(3))
        except curses.error:
            pass
