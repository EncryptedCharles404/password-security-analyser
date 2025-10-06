import hashlib
import requests
import re
import matplotlib.pyplot as plt
from collections import Counter
import time

class PasswordAnalyzer:
    """Analyzes password strength and checks breach databases."""

    def __init__(self):
        self.results = []

    def check_pwned_password(self, password):
        """Check if password appears in Have I Been Pwned database."""
        # Hash the password using SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        # Query the API (k-anonymity - only sends first 5 chars)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = response.text.splitlines()
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except:
            return -1  # Error occurred

    def analyze_strength(self, password):
        """Analyze password strength based on composition."""
        score = 0
        feedback = []

        # Length check
        length = len(password)
        if length >= 12:
            score += 3
        elif length >= 8:
            score += 2
        else:
            feedback.append("Too short (< 8 chars)")

        # Complexity checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("No lowercase letters")

        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("No uppercase letters")

        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("No numbers")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 2
        else:
            feedback.append("No special characters")

        # Determine strength level
        if score >= 7:
            strength = "Strong"
        elif score >= 4:
            strength = "Moderate"
        else:
            strength = "Weak"

        return strength, score, feedback

    def analyze_file(self, filename):
        """Analyze all passwords in a file."""
        print(f"[*] Starting analysis of {filename}\n")

        try:
            with open(filename, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Error: File '{filename}' not found")
            return

        for idx, password in enumerate(passwords, 1):
            print(f"[{idx}/{len(passwords)}] Analyzing password...")

            # Check strength
            strength, score, feedback = self.analyze_strength(password)

            # Check if breached
            breach_count = self.check_pwned_password(password)
            time.sleep(0.5)  # Be respectful to the API

            # Store results
            result = {
                'password': '*' * len(password),  # Mask for privacy
                'length': len(password),
                'strength': strength,
                'score': score,
                'breached': breach_count > 0,
                'breach_count': breach_count if breach_count > 0 else 0,
                'feedback': feedback
            }
            self.results.append(result)

            # Print summary
            breach_status = f"⚠️  BREACHED ({breach_count:,} times)" if breach_count > 0 else "✓ Not found in breaches"
            print(f"    Strength: {strength} | {breach_status}\n")

        print("[✓] Analysis complete!\n")

    def generate_report(self):
        """Generate visual report of findings."""
        if not self.results:
            print("[!] No results to report")
            return

        # Create visualizations
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Password Security Analysis Report', fontsize=16, fontweight='bold')

        # 1. Strength distribution
        strengths = [r['strength'] for r in self.results]
        strength_counts = Counter(strengths)
        colors_strength = {'Strong': '#2ecc71', 'Moderate': '#f39c12', 'Weak': '#e74c3c'}
        ax1.bar(strength_counts.keys(), strength_counts.values(),
                color=[colors_strength[k] for k in strength_counts.keys()])
        ax1.set_title('Password Strength Distribution')
        ax1.set_ylabel('Count')

        # 2. Breach status
        breached = sum(1 for r in self.results if r['breached'])
        not_breached = len(self.results) - breached
        ax2.pie([breached, not_breached], labels=['Breached', 'Not Breached'],
                autopct='%1.1f%%', colors=['#e74c3c', '#2ecc71'], startangle=90)
        ax2.set_title('Breach Status')

        # 3. Password length distribution
        lengths = [r['length'] for r in self.results]
        ax3.hist(lengths, bins=range(min(lengths), max(lengths)+2),
                 color='#3498db', edgecolor='black')
        ax3.set_title('Password Length Distribution')
        ax3.set_xlabel('Length (characters)')
        ax3.set_ylabel('Count')

        # 4. Security score distribution
        scores = [r['score'] for r in self.results]
        ax4.hist(scores, bins=range(0, max(scores)+2),
                 color='#9b59b6', edgecolor='black')
        ax4.set_title('Security Score Distribution')
        ax4.set_xlabel('Score')
        ax4.set_ylabel('Count')

        plt.tight_layout()
        plt.savefig('security_report.png', dpi=300, bbox_inches='tight')
        print("[✓] Report saved as 'security_report.png'")
        plt.show()

        # Print detailed findings
        print("\n" + "="*60)
        print("DETAILED FINDINGS")
        print("="*60)

        print(f"\nTotal passwords analyzed: {len(self.results)}")
        print(f"Breached passwords: {breached} ({breached/len(self.results)*100:.1f}%)")

        print("\n⚠️  CRITICAL: Passwords found in breach databases:")
        for r in self.results:
            if r['breached']:
                print(f"  • {r['password']} - Found {r['breach_count']:,} times")

        print("\n📊 Strength Summary:")
        for strength, count in strength_counts.items():
            print(f"  • {strength}: {count} ({count/len(self.results)*100:.1f}%)")

def main():
    """Main execution function."""
    print("="*60)
    print("PASSWORD SECURITY ANALYZER")
    print("="*60)
    print("\n⚠️  WARNING: Only use dummy/test passwords!")
    print("Never analyze real passwords you actually use.\n")

    analyzer = PasswordAnalyzer()
    analyzer.analyze_file('sample_passwords.txt')
    analyzer.generate_report()

    print("\n[✓] Analysis complete! Check 'security_report.png' for visuals.\n")

if __name__ == "__main__":
    main()