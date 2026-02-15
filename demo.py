#!/usr/bin/env python3
"""
AI-Powered URL Risk Detection System
Interactive Demo with Manual Labeling
"""

from core_engine import analyze_url, display_result, show_stats, train_models
from database import update_labels, get_record_count
import sys

def print_header():
    print("\n" + "="*60)
    print("AI-POWERED URL RISK DETECTION SYSTEM")
    print("Cache-First | Multi-Model ML | Auto-Learning")
    print("="*60)

def main_menu():
    """Interactive CLI menu"""
    print_header()
    show_stats()
    
    while True:
        print("\n" + "-"*60)
        print("OPTIONS:")
        print("  1. Analyze URL")
        print("  2. Analyze URL with Manual Labeling")
        print("  3. Show Statistics")
        print("  4. Trigger Manual Training")
        print("  5. Exit")
        print("-"*60)
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            analyze_mode()
        elif choice == '2':
            analyze_with_labeling()
        elif choice == '3':
            show_stats()
        elif choice == '4':
            manual_training()
        elif choice == '5':
            print("\n✓ Exiting system")
            break
        else:
            print("⚠ Invalid option")

def analyze_mode():
    """Simple analysis mode"""
    print("\n" + "="*60)
    print("URL ANALYSIS MODE")
    print("="*60)
    
    url = input("\nEnter URL to analyze: ").strip()
    
    if not url:
        print("⚠ No URL provided")
        return
    
    result = analyze_url(url)
    display_result(result)

def analyze_with_labeling():
    """Analysis with manual label correction"""
    print("\n" + "="*60)
    print("URL ANALYSIS WITH MANUAL LABELING")
    print("="*60)
    
    url = input("\nEnter URL to analyze: ").strip()
    
    if not url:
        print("⚠ No URL provided")
        return
    
    result = analyze_url(url)
    display_result(result)
    
    print("\n" + "-"*60)
    print("MANUAL LABELING (Optional)")
    print("-"*60)
    
    correct = input("\nIs the prediction correct? (y/n/skip): ").strip().lower()
    
    if correct == 'n':
        print("\nProvide correct labels:")
        
        # Get risk level
        print("\nRisk Level:")
        print("  0 = Low Risk")
        print("  1 = High Risk")
        risk_label_input = input("Enter correct risk level (0/1): ").strip()
        
        if risk_label_input not in ['0', '1']:
            print("⚠ Invalid risk level, skipping")
            return
        
        risk_label = int(risk_label_input)
        
        # Get risk type
        print("\nRisk Type:")
        print("  Examples: Phishing, Malware, Financial Scam, Betting, General Suspicious, Safe")
        risk_type = input("Enter correct risk type: ").strip()
        
        if not risk_type:
            print("⚠ No risk type provided, skipping")
            return
        
        # Update database
        success = update_labels(url, risk_label, risk_type)
        
        if success:
            print(f"\n✓ Labels updated in database")
            print(f"  Risk Level: {risk_label} ({'High' if risk_label == 1 else 'Low'})")
            print(f"  Risk Type: {risk_type}")
            
            # Check if should retrain
            count = get_record_count()
            if count >= 50 and count % 100 == 0:
                retrain = input("\n⚡ Auto-retrain threshold reached. Train now? (y/n): ").strip().lower()
                if retrain == 'y':
                    train_models()
        else:
            print("✗ Failed to update labels")
    
    elif correct == 'y':
        print("✓ Prediction confirmed as correct")
    
    else:
        print("⊘ Skipped manual labeling")

def manual_training():
    """Manually trigger training"""
    print("\n" + "="*60)
    print("MANUAL TRAINING")
    print("="*60)
    
    count = get_record_count()
    print(f"\nCurrent database size: {count} records")
    
    if count < 50:
        print(f"⚠ Warning: Less than 50 samples (have {count})")
        proceed = input("Train anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            print("⊘ Training cancelled")
            return
    
    confirm = input("\nProceed with training? (y/n): ").strip().lower()
    
    if confirm == 'y':
        train_models()
    else:
        print("⊘ Training cancelled")

def quick_test():
    """Quick test for demonstration"""
    print_header()
    
    print("\nQUICK TEST MODE")
    print("="*60)
    
    test_urls = [
        "https://www.google.com",
        "http://verify-paypal-login-secure.tk/account?otp=123",
    ]
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        result = analyze_url(url)
        display_result(result)
        input("Press Enter to continue...")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        quick_test()
    else:
        try:
            main_menu()
        except KeyboardInterrupt:
            print("\n\n⊘ Interrupted by user")
        except Exception as e:
            print(f"\n✗ Error: {e}")