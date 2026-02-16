""""
Project Structure Setup Script
Run this ONCE to organize your project correctly
"""
import os
import shutil
from pathlib import Path

def setup_project():
    """Setup correct folder structure"""
    
    print("\n" + "="*60)
    print("🔧 SETTING UP PROJECT STRUCTURE")
    print("="*60)
    
    # Get project root (current directory)
    root = Path.cwd()
    print(f"\n📂 Project Root: {root}")
    
    # Define required folders
    required_folders = {
        'models': root / 'models',
        'db': root / 'db',
        'venv': root / 'venv'
    }
    
    # Create folders if they don't exist
    print("\n📁 Creating folders...")
    for name, path in required_folders.items():
        if not path.exists():
            path.mkdir(exist_ok=True)
            print(f"  ✓ Created: {name}/")
        else:
            print(f"  ✓ Exists: {name}/")
    
    # Clean up nested/duplicate folders
    print("\n🧹 Cleaning up nested folders...")
    
    # Remove model/db if it exists
    model_db = root / 'model' / 'db'
    if model_db.exists():
        print(f"  ✗ Removing: model/db/")
        shutil.rmtree(model_db, ignore_errors=True)
    
    # Remove model/models if it exists
    model_models = root / 'model' / 'models'
    if model_models.exists():
        print(f"  ✗ Removing: model/models/")
        shutil.rmtree(model_models, ignore_errors=True)
    
    # Remove empty model folder if it exists
    model_folder = root / 'model'
    if model_folder.exists():
        try:
            # Move any .py files to root first
            for py_file in model_folder.glob('*.py'):
                dest = root / py_file.name
                if not dest.exists():
                    shutil.move(str(py_file), str(dest))
                    print(f"  ↑ Moved: {py_file.name} to root")
            
            # Remove model folder if empty
            if not any(model_folder.iterdir()):
                model_folder.rmdir()
                print(f"  ✓ Removed empty: model/")
        except:
            pass
    
    # Remove dbsql folder if it exists
    dbsql_folder = root / 'dbsql'
    if dbsql_folder.exists():
        print(f"  ✗ Removing: dbsql/")
        shutil.rmtree(dbsql_folder, ignore_errors=True)
    
    # Check for required files in root
    print("\n📄 Checking required files...")
    required_files = {
        'core_engine.py': 'Main analysis engine',
        'database.py': 'Database logic',
        'requirements.txt': 'Python dependencies',
        '.gitignore': 'Git ignore rules'
    }
    
    for filename, description in required_files.items():
        filepath = root / filename
        if filepath.exists():
            print(f"  ✓ {filename:20s} - {description}")
        else:
            print(f"  ✗ {filename:20s} - MISSING!")
    
    # Check demo.py (optional)
    if (root / 'demo.py').exists():
        print(f"  ✓ {'demo.py':20s} - Optional examples")
    
    # Display final structure
    print("\n" + "="*60)
    print("📊 FINAL PROJECT STRUCTURE")
    print("="*60)
    print("""
THINKBEFOREWECLICK/
│
├── core_engine.py          ✓ Main engine
├── database.py             ✓ Database logic
├── demo.py                 ✓ Examples (optional)
├── requirements.txt        ✓ Dependencies
├── .gitignore              ✓ Git rules
│
├── models/                 ✓ ML models saved here
│   ├── risk_model.pkl
│   ├── risk_type_model.pkl
│   └── anomaly_model.pkl
│
├── db/                     ✓ Database folder
│   └── url_risk.db         (created on first run)
│
├── venv/                   ✓ Virtual environment
├── .vscode/                (IDE settings)
└── __pycache__/            (Python cache)
""")
    
    # Final instructions
    print("="*60)
    print("✅ SETUP COMPLETE!")
    print("="*60)
    print("\n📝 Next Steps:")
    print("  1. Ensure all files are in root folder")
    print("  2. Run: python core_engine.py")
    print("  3. Analyze 30+ URLs to train models")
    print("\n💡 Tip: Models will be saved in models/ folder")
    print("💡 Tip: Database will be in db/url_risk.db")
    print("="*60 + "\n")


if __name__ == "__main__":
    try:
        setup_project()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Please run this script from the ThinkBeforeWeClick folder")