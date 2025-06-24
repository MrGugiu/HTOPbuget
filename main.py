import curses
import os
import sys
from pathlib import Path

# Adăugare path pentru importuri
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Verifică și creează structura de foldere dacă nu există
def ensure_directory_structure():
    """Creează structura de directoare necesară"""
    dirs_to_create = ['core', 'ui']
    
    for dir_name in dirs_to_create:
        dir_path = current_dir / dir_name
        if not dir_path.exists():
            print(f"📁 Creez directorul: {dir_path}")
            dir_path.mkdir(exist_ok=True)
        
        # Creează __init__.py dacă nu există
        init_file = dir_path / '__init__.py'
        if not init_file.exists():
            init_file.touch()

        # Creează fișiere esențiale dacă nu există
        essential_files = {
            'core': ['detector.py', 'monitor.py'],
            'ui': ['utils.py', 'process_view.py', 'log_view.py']
        }
        
        for file in essential_files[dir_name]:
            file_path = dir_path / file
            if not file_path.exists():
                file_path.touch()

def check_file_structure():
    """Verifică dacă toate fișierele necesare există"""
    required_files = {
        'core/detector.py': 'Modulul de detectare activitate suspicioasă',
        'core/monitor.py': 'Modulul principal de monitorizare',
        'ui/utils.py': 'Utilitare pentru interfața curses',
        'ui/process_view.py': 'Vizualizarea proceselor',
        'ui/log_view.py': 'Vizualizarea log-urilor'
    }
    
    missing_files = []
    for file_path, description in required_files.items():
        full_path = current_dir / file_path
        if not full_path.exists():
            missing_files.append((file_path, description))
    
    if missing_files:
        print("❌ Fișiere lipsă:")
        for file_path, description in missing_files:
            print(f"   - {file_path}: {description}")
        print("\n🔧 Asigură-te că ai toate fișierele în structura corectă:")
        print("   monitor_sistem/")
        print("   ├── main.py")
        print("   ├── core/")
        print("   │   ├── __init__.py")  
        print("   │   ├── detector.py")
        print("   │   └── monitor.py")
        print("   └── ui/")
        print("       ├── __init__.py")
        print("       ├── utils.py")
        print("       ├── process_view.py")
        print("       └── log_view.py")
        return False
    
    return True

def check_dependencies():
    """Verifică dacă toate dependențele sunt instalate"""
    try:
        import psutil
        import re
        import glob
        return True
    except ImportError as e:
        print(f"❌ Dependență lipsă: {e}")
        print("\n🔧 Pentru a instala dependențele necesare:")
        print("   sudo apt-get update")
        print("   sudo apt-get install python3-psutil")
        print("   pip3 install psutil")
        print("\n   SAU pentru Ubuntu/Debian:")
        print("   sudo apt install python3-pip")
        print("   pip3 install psutil")
        return False

def check_permissions():
    """Verifică permisiunile și oferă informații utile"""
    is_root = os.geteuid() == 0
    
    if not is_root:
        print("⚠️  ATENȚIE: Aplicația nu rulează cu permisiuni root.")
        print("📂 Unele log-uri și informații despre procese ar putea fi indisponibile.")
        print("🔧 Pentru acces complet, rulează cu: sudo python3 main.py")
        print("💡 Poți continua fără root, dar cu funcționalitate limitată.\n")
    else:
        print("✅ Rulează cu permisiuni root - acces complet disponibil.\n")
    
    return is_root

def check_terminal_size():
    """Verifică dimensiunea terminalului"""
    try:
        import shutil
        cols, lines = shutil.get_terminal_size()
        
        if cols < 80 or lines < 24:
            print("⚠️  ATENȚIE: Terminalul este prea mic!")
            print(f"   Dimensiune curentă: {cols}x{lines}")
            print("   Dimensiune minimă recomandată: 80x24")
            print("\n🔧 Mărește terminalul sau micșorează fontul pentru cea mai bună experiență")
            return False
        return True
    except:
        return True

def print_welcome():
    """Afișează mesajul de bun venit cu instrucțiuni"""
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                🔍 MONITOR SISTEM LINUX 🔍                      ║")
    print("║                     Versiune Optimizată                       ║")
    print("╠═══════════════════════════════════════════════════════════════╣")
    print("║ FUNCȚIONALITĂȚI:                                              ║")
    print("║ • Monitorizare procese în timp real                           ║")
    print("║ • Selectare proces + afișare procese copil                    ║")
    print("║ • Detectare activitate suspicioasă                            ║")
    print("║ • Analiză log-uri de sistem                                   ║")
    print("║ • Filtrare și sortare avansată                                ║")
    print("╠═══════════════════════════════════════════════════════════════╣")
    print("║ COMENZI RAPIDE:                                               ║")
    print("║ • TAB: Schimbare între tab-uri                                ║")
    print("║ • ↑/↓: Navigare / Selectare proces                            ║")
    print("║ • S: Afișare doar procese suspicioase                         ║")
    print("║ • C/M: Sortare după CPU/Memorie                               ║")
    print("║ • F: Filtrare log-uri                                         ║")
    print("║ • H: Ajutor                                                   ║")
    print("║ • Q/ESC: Ieșire                                               ║")
    print("╚═══════════════════════════════════════════════════════════════╝")

def main():
    """Funcția principală a aplicației"""
    try:
        print_welcome()
        
        # Verificare și creare structură de directoare
        ensure_directory_structure()
        
        # Verificare structura de fișiere
        if not check_file_structure():
            return 1
        
        # Verificare dependențe
        if not check_dependencies():
            return 1
        
        # Verificare permisiuni
        check_permissions()
        
        # Verificare dimensiune terminal
        if not check_terminal_size():
            print("\n💡 Poți continua, dar interfața ar putea fi afectată")

        # Confirmare pornire
        try:
            response = input("\n🚀 Apasă Enter pentru a porni monitorul sau Ctrl+C pentru a ieși...")
            if response.lower() in ['n', 'no', 'nu']:
                print("👋 Aplicația a fost anulată de utilizator.")
                return 0
        except KeyboardInterrupt:
            print("\n👋 Aplicația a fost anulată de utilizator.")
            return 0
        
        # Import dinamic după verificări
        try:
            print("\n🔄 Încărcare module...")
            from core.monitor import SystemMonitor
        except ImportError as e:
            print(f"\n❌ Eroare la importul modulelor: {e}")
            print("🔧 Verifică că toate fișierele sunt în locul corect și că nu conțin erori de sintaxă.")
            
            # Debugging avansat cu flag
            if '-d' in sys.argv or '--debug' in sys.argv:
                print("\n🐛 Detalii debugging:")
                import traceback
                traceback.print_exc()
                
            return 1
        
        # Inițializare și pornire monitor
        print("🔄 Inițializare monitor sistem...")
        monitor = SystemMonitor()
        
        # Pornire interfață curses
        print("🎯 Pornire interfață...")
        try:
            curses.wrapper(monitor.run)
            
        except KeyboardInterrupt:
            print("\n👋 Monitor oprit de utilizator.")
        except curses.error as e:
            print(f"\n❌ Eroare în interfața curses: {e}")
            print("\n🔧 Verificări recomandate:")
            print("   1. Terminalul suportă curses (majoritatea terminaloarelor moderne)")
            print("   2. Dimensiunea terminalului este suficientă (min 80x24)")
            print("   3. Nu rulezi în medii care nu suportă curses (ex: unele IDE)")
            return 1
            
    except KeyboardInterrupt:
        print("\n👋 Aplicația a fost oprită de utilizator.")
        return 0
    except Exception as e:
        print(f"\n❌ Eroare critică: {e}")
        print("\n🔧 Verificări recomandate:")
        print("   1. Toate bibliotecile necesare sunt instalate")
        print("   2. Permisiunile sunt corecte")
        print("   3. Structura de fișiere este completă")
        
        # Debugging avansat cu flag
        if '-d' in sys.argv or '--debug' in sys.argv:
            print("\n🐛 Detalii debugging:")
            import traceback
            traceback.print_exc()
            
        return 1
    
    print("\n✅ Monitor sistem închis cu succes.")
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
