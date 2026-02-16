"""
DEMO - URL Risk Analysis System
This file demonstrates:
1. How to use the core_engine as a module
2. Batch URL analysis
3. Manual label correction for active learning
4. Custom training scenarios

NOTE: This file is NOT required for core_engine.py to function.
It's purely educational/demonstrative.
"""

from core_engine import analyze_url, display_result, train_models, show_stats
from database import update_labels, get_record_count

# ============================================================================
# DEMO: Basic Usage
# ============================================================================

def demo_basic_analysis():
    """Demonstrate basic URL analysis"""
    print("\n" + "="*70)
    print("DEMO 1: Basic URL Analysis")
    print("="*70)
    
    test_urls = [
        "https://secure-paypal-verify.tk/login",
        "https://google.com",
        "http://192.168.1.1/admin",
        "https://free-bitcoin-claim-now.xyz/urgent",
        "https://github.com"
    ]
    
    for url in test_urls:
        result = analyze_url(url)
        display_result(result)


# ============================================================================
# DEMO: Batch Analysis
# ============================================================================

def demo_batch_analysis():
    """Demonstrate batch processing of URLs"""
    print("\n" + "="*70)
    print("DEMO 2: Batch URL Analysis")
    print("="*70)
    
    urls = [
        "https://amazon-prize-winner.ml/claim",
        "https://bank-security-update.ga/verify",
        "https://stackoverflow.com",
        "https://suspicious-login-verify.xyz",
        "https://linkedin.com"
    ]
    
    results = []
    for url in urls:
        result = analyze_url(url)
        results.append(result)
    
    # Summary
    print("\n" + "="*70)
    print("BATCH ANALYSIS SUMMARY")
    print("="*70)
    
    high_risk = [r for r in results if r.get('risk_level') in ['High', 'Critical']]
    medium_risk = [r for r in results if r.get('risk_level') == 'Medium']
    low_risk = [r for r in results if r.get('risk_level') == 'Low']
    
    print(f"\nTotal analyzed: {len(results)}")
    print(f"High risk: {len(high_risk)}")
    print(f"Medium risk: {len(medium_risk)}")
    print(f"Low risk: {len(low_risk)}")
    
    if high_risk:
        print("\n⚠️  HIGH RISK URLS:")
        for r in high_risk:
            print(f"  • {r['url']}")
            print(f"    Type: {r['risk_type']}, Severity: {r['risk_severity_index']}/100")


# ============================================================================
# DEMO: Manual Label Correction (Active Learning)
# ============================================================================

def demo_label_correction():
    """
    Demonstrate manual label correction
    Useful for improving model accuracy with human feedback
    """
    print("\n" + "="*70)
    print("DEMO 3: Manual Label Correction")
    print("="*70)
    
    # Analyze a URL
    url = "https://example-suspicious-site.com"
    result = analyze_url(url)
    display_result(result)
    
    # Simulate human correction
    print("\n📝 Simulating manual correction...")
    print(f"   System predicted: {result['risk_level']} / {result['risk_type']}")
    print(f"   Human corrects to: High / Phishing")
    
    # Update labels
    risk_level_map = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
    update_labels(url, risk_level_map['High'], 'Phishing')
    
    print("✓ Labels updated in database")
    print("💡 Next training will incorporate this correction")


# ============================================================================
# DEMO: Force Training
# ============================================================================

def demo_force_training():
    """Demonstrate manual training trigger"""
    print("\n" + "="*70)
    print("DEMO 4: Manual Model Training")
    print("="*70)
    
    count = get_record_count()
    print(f"\nCurrent database records: {count}")
    
    if count >= 30:
        print("✓ Sufficient data available")
        print("🔧 Initiating training...")
        train_models()
    else:
        print(f"⚠ Need {30 - count} more samples for training")
        print("💡 Analyze more URLs to build training dataset")


# ============================================================================
# DEMO: Integration Example
# ============================================================================

def demo_api_integration():
    """
    Demonstrate how to integrate core_engine into an API/service
    """
    print("\n" + "="*70)
    print("DEMO 5: API Integration Pattern")
    print("="*70)
    
    # Simulate API endpoint
    def check_url_safety(url):
        """Simulated API endpoint"""
        result = analyze_url(url)
        
        # Return API-friendly format
        return {
            'url': result['url'],
            'is_safe': result['risk_level'] == 'Low',
            'risk_score': result['risk_severity_index'],
            'risk_category': result['risk_type'],
            'reason': result['why_risk'],
            'confidence': result['confidence_percent']
        }
    
    # Test API
    test_url = "https://secure-banking-login.tk/verify"
    api_response = check_url_safety(test_url)
    
    print("\nAPI Response Format:")
    import json
    print(json.dumps(api_response, indent=2))


# ============================================================================
# MAIN DEMO RUNNER
# ============================================================================

def run_all_demos():
    """Run all demonstrations"""
    print("\n" + "="*70)
    print("🎓 URL RISK ANALYSIS - DEMONSTRATION MODE")
    print("="*70)
    
    demos = [
        ("Basic Analysis", demo_basic_analysis),
        ("Batch Analysis", demo_batch_analysis),
        ("Label Correction", demo_label_correction),
        ("Force Training", demo_force_training),
        ("API Integration", demo_api_integration)
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos) + 1}. Run all demos")
    print(f"  {len(demos) + 2}. Show system stats")
    print("  0. Exit")
    
    while True:
        try:
            choice = input("\nSelect demo (0-7): ").strip()
            
            if choice == '0':
                print("Exiting demo mode")
                break
            
            if choice == str(len(demos) + 1):
                for name, demo_func in demos:
                    print(f"\n{'='*70}")
                    print(f"Running: {name}")
                    print(f"{'='*70}")
                    demo_func()
                break
            
            if choice == str(len(demos) + 2):
                show_stats()
                continue
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(demos):
                    name, demo_func = demos[idx]
                    print(f"\n{'='*70}")
                    print(f"Running: {name}")
                    print(f"{'='*70}")
                    demo_func()
                else:
                    print("Invalid choice")
            except ValueError:
                print("Please enter a number")
                
        except KeyboardInterrupt:
            print("\n\nDemo interrupted")
            break


if __name__ == "__main__":
    run_all_demos()