# detector.py
#
# This module implements the signal extraction layer of the Email Threat Scorer.
#
# Architecture decision:
#   Each detector is an independent class that inherits from BaseDetector.
#   This follows the Open/Closed Principle, the system is open for extensions
#   (adding new detectors) and modifications without requiring changes to the 
#   existing scoring logic. 
#
#   The design ensures zero coupling between the scorer and specific detector 
#   implementations. the scorer relies solely on the standardized Data Contract, 
#   making the engine highly modular and maintainable.
#
# Security note:
#   All detectors receive sanitized input from main.py.
#   Raw email content is never passed directly to the LLM —
#   only the structured DetectionResult objects are, preventing prompt injection.

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionResult:
    """
    Standardized output from every detector.

    risk_score : 0-100 contribution from this detector alone
    flags      : red flags found — shown to the user as ✗ bullets
    passed     : green flags — shown to the user as ✓ bullets
    """
    detector_name: str
    risk_score: int
    flags: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

# BASE CLASS
# Defines the interface every detector must implement.
# Using ABC ensures no detector can be instantiated without analyze().

class BaseDetector(ABC):
    """
    Abstract base class for all email threat detectors.

    All detectors receive the same 6 inputs and return a DetectionResult.
    This help the scorer to treat all detectors identically therefore
    it never needs to know which detector it's talking to.
    """

    @abstractmethod
    def analyze(
        self,
        subject: str,
        sender: str,
        reply_to: Optional[str],
        body: str,
        spf: Optional[str],
        dkim: Optional[str],
    ) -> DetectionResult:
        pass



# DETECTOR 1: Authentication
#
# Checks cryptographic email authentication headers.
# These are the most reliable signals because they cannot be faked
# by manipulating email content or injecting text into the body.
#
# SPF: Sender Policy Framework: did this email come from an IP
#         that the domain owner authorized?
#         This checks if the email was sent from a server that the owner of the domain actually uses
#
# DKIM: This is a digital signature that proves the email wasn’t changed or "opened" by someone else while it was on its way
#  If the seal is broken or missing, the email can't be trusted.

class AuthenticationDetector(BaseDetector):

    def analyze(self, subject, sender, reply_to, body, spf, dkim) -> DetectionResult:
        flags  = []
        passed = []
        score  = 0

        # SPF check
        # 'pass' means the sending server is authorized by the domain owner
        # 'fail' or missing means the sender identity is not known for sure
        if spf and 'pass' in spf.lower():
            passed.append("Sender verified, this email came from a server authorised by the domain owner")
        else:
            flags.append("Sender not verified, anyone could be pretending to be this person or company")
            score += 35
        
        # DKIM check
        # If the signature exists and is long enough to be real
        if dkim and len(dkim) > 10:
            passed.append("Email integrity confirmed, this message has a valid digital signature")
        # If the signature is missing or looks fake
        else:
            flags.append("No digital signature, we can't confirm if this message was altered or changed after it was sent")
            score += 25
            
        # return the results 
        return DetectionResult(
            detector_name="Authentication",
            risk_score=min(score, 100),
            flags=flags,
            passed=passed,
        )


# DETECTOR 2: Sender Identity
#
# Checks for sender identity manipulation techniques
#
# The From header can contain fake name alongside the
# real email address.
#
# A lot of phishing emails set Reply-To to a different domain so that
# replies go to the attacker instead of the spoofed sender. The email
# looks like it came from your bank for example, but when you reply it goes to an attacker.
#   
# Legitimate companies send from their own domain mail servers.


class SenderDetector(BaseDetector):

    # Well-known brands that are frequently impersonated in phishing
    KNOWN_BRANDS = [
        'paypal', 'google', 'amazon', 'apple', 'microsoft',
        'netflix', 'facebook', 'instagram', 'bank', 'chase',
        'wellsfargo', 'linkedin', 'dropbox', 'docusign',
        'zoom', 'icloud', 'outlook', 'fedex', 'ups', 'dhl',
        'irs', 'hmrc', 'intuit', 'quickbooks',
    ]

    # Free email providers, legitimate businesses don't use these
    FREE_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'aol.com', 'protonmail.com', 'icloud.com', 'mail.com',
        'yandex.com', 'gmx.com',
    }

    def analyze(self, subject, sender, reply_to, body, spf, dkim) -> DetectionResult:
        flags  = []
        passed = []
        score  = 0

        sender_domain = self._extract_domain(sender)
        display_name  = self._extract_display_name(sender)

        # Check if display name contains a known brand but the actual sending domain does not match that brand
        if display_name:
            for brand in self.KNOWN_BRANDS:
                if brand in display_name.lower() and brand not in sender_domain.lower():
                    flags.append(
                        f"Display name '{display_name}' impersonates "
                        f"'{brand}' but email is from '{sender_domain}'"
                    )
                    score += 50
                    break
            else:
                passed.append("Sender name matches the actual email address")

        # If Reply-To is set and its domain differs from the sender's domain, any reply goes directly to the attacker
        if reply_to:
            reply_domain = self._extract_domain(reply_to)
            if reply_domain and reply_domain != sender_domain:
                flags.append(
                    f"Reply-To '{reply_domain}' differs from sender "
                    f"'{sender_domain}', replies go to a different address"
                )
                score += 35

                # Extra weight if reply-to is a free provider
                if reply_domain in self.FREE_PROVIDERS:
                    flags.append(
                        f"Reply-To uses free email provider '{reply_domain}' "
                        f"— highly suspicious for a business sender"
                    )
                    score += 15
        else:
            passed.append("Replies go to the original sender, no redirection detected")

        # A known brand name in the display name combined with a free provider sending domain 
        if sender_domain in self.FREE_PROVIDERS and display_name:
            for brand in self.KNOWN_BRANDS:
                if brand in display_name.lower():
                    flags.append(
                        f"'{brand}' email sent from free provider "
                        f"'{sender_domain}', legitimate companies use their own domains"
                    )
                    score += 25
                    break
        # return the results
        return DetectionResult(
            detector_name="Sender Identity",
            risk_score=min(score, 100),
            flags=flags,
            passed=passed,
        )

    # Look for the '@' symbol and grab everything that follows it (the domain)
    def _extract_domain(self, email_str: str) -> str:
        """Extracts the domain part from an email address string."""
        match = re.search(r'@([\w.\-]+)', email_str)
        return match.group(1).lower() if match else ''

    def _extract_display_name(self, sender: str) -> str:
        """Extracts the display name from a 'Name <email>' formatted string."""
        match = re.match(r'^"?([^"<]+)"?\s*<', sender)
        return match.group(1).strip() if match else ''


# DETECTOR 3: Content, suspicious words
#
# Categories covered:
#   - Requests for sensitive personal information
#   - Tech support scam language
#   - Bank or credit card scam language
#   - General urgency phrases
#   - Language mismatch (email claims to be from English business
#     but contains patterns typical of non-native writing)

class ContentDetector(BaseDetector):

    # General urgency and fear based phrases
    URGENCY_PHRASES = [
        r'\burgent\b',
        r'\bimergency\b',           
        r'\bimmediately\b',
        r'\bhurry\b',               
        r'\bact now\b',
        r'\bact fast\b',
        r'\bverify.{0,20}(now|immediately|today)\b',
        r'\byour account.{0,20}(suspended|closed|terminated|locked)\b',
        r'\blimited time\b',
        r'\bwithin 24 hours\b',
        r'\bwithin \d+ hours\b',
        r'\byou have until (tomorrow|today|\d)',  
        r'\bbefore (tomorrow|today|midnight|end of day)\b',
        r'\bdeadline.{0,20}(today|tomorrow|tonight)\b',
        r'\bclick here\b',
        r'\bconfirm your\b',
        r'\bsuspicious activity\b',
        r'\bunusual sign.?in\b',
        r'\bfailure to (respond|verify|confirm)\b',
        r'\byour (password|account).{0,20}expir',
        r'\baction required\b',
        r'\bimmediate action\b',
        r'\byour (access|account).{0,20}(will be|has been) (revoked|disabled)\b',
        r'\blast (chance|warning|notice)\b',
        r'\bdo not ignore\b',
        r'\brespond (immediately|now|today|asap)\b',
    ]

    # Tech support scam
    TECH_SUPPORT_SCAM = [
        r'\byour (computer|pc|device|windows|mac).{0,30}(infected|virus|hacked|compromised)\b',
        r'\bcall.{0,20}(microsoft|apple|google|support).{0,20}(immediately|now|today)\b',
        r'\btech(nical)? support\b.{0,40}\b(call|number|helpline)\b',
        r'\bwarning.{0,30}(virus|malware|spyware|trojan)\b',
        r'\byour (license|subscription).{0,20}(expired|expiring)\b',
        r'\bremote (access|assistance|session)\b',
        r'\b(toll.?free|1-800|1-888).{0,20}(support|help|service)\b',
        r'\bdo not (restart|shut down|turn off) your (computer|pc|device)\b',
    ]

    # Bank and financial scams
    BANK_SCAM_PHRASES = [
        r'\b(debit|credit) card.{0,30}(blocked|suspended|frozen|flagged)\b',
        r'\bunauthorized (transaction|charge|payment|transfer)\b',
        r'\byour (bank|account).{0,20}(hold|freeze|suspend)\b',
        r'\bverify.{0,20}(bank|account|card|payment)\b',
        r'\b(refund|reimbursement).{0,30}(pending|approved|process)\b',
        r'\btransfer.{0,20}(funds|money|amount)\b',
        r'\bgift card.{0,30}(payment|purchase|send)\b',  
        r'\bwire transfer\b',
        r'\byour (invoice|payment).{0,20}(overdue|past due|outstanding)\b',
    ]

    # Requests for sensitive personal information, services may not ask for these over email
    SENSITIVE_INFO_PATTERNS = [
        r'\b(social security|ssn)\b',
        r'\b(password|passcode|pin)\b.{0,30}(enter|provide|confirm|send)\b',
        r'\bcredit card.{0,20}(number|details|info)\b',
        r'\b(date of birth|dob)\b',
        r'\bbank (account|routing) number\b',
        r'\bmother\'?s maiden name\b',
        r'\bsecurity (question|answer)\b',
        r'\bpassport (number|details)\b',
        r'\bfull (name|address).{0,20}(confirm|verify|provide)\b',
    ]

    # Language mismatch patterns, phrasing unusual for native English
    LANGUAGE_MISMATCH_PATTERNS = [
        r'\bdear (valued|esteemed) (customer|client|user|member)\b',
        r'\bkindly (click|confirm|verify|provide|update)\b',
        r'\bdo the needful\b',
        r'\brevert back\b',
        r'\brevert (to us|us back)\b',
        r'\byour (good)?self\b',
        r'\bwe are (write|writing) to (inform|notify) you\b',
        r'\bplease to \w+\b',
        r'\bbefore \d+ hours\b',
    ]

    def analyze(self, subject, sender, reply_to, body, spf, dkim) -> DetectionResult:
        flags  = []
        passed = []
        score  = 0

        full_text = f"{subject} {body}"

         # ask for sensative data from the user
        sensitive_hits = self._count_matches(self.SENSITIVE_INFO_PATTERNS, full_text)
        if sensitive_hits >= 1:
            flags.append("Requests personal data, legitimate companies never ask for passwords, card numbers, or IDs over email")
            score += 180

        # financial scam 
        bank_hits = self._count_matches(self.BANK_SCAM_PHRASES, full_text)
        if bank_hits >= 2:
            flags.append("This email uses tactics common in fake bank or credit card alerts")
            score += 100
        elif bank_hits == 1:
            flags.append("Possible financial scam, some language resembles fake payment or banking alerts")
            score += 45

        # urgancey phrases used
        urgency_hits = self._count_matches(self.URGENCY_PHRASES, full_text)
        if urgency_hits >= 3:
            flags.append("High-pressure language, may be suspicious")
            score += 35
        elif urgency_hits >= 1:
            flags.append("Urgent tone, this email is pushing you to act quickly")
            score += 15
        else:
            passed.append("No pressure tactics detected, the tone of this email seems normal")

        # Tech support scam 
        tech_hits = self._count_matches(self.TECH_SUPPORT_SCAM, full_text)
        if tech_hits >= 2:
            flags.append("This email tries to convince you your device is infected or in danger")
            score += 40
        elif tech_hits == 1:
            flags.append("Possible tech scam, some language in this email resembles fake tech support messages")
            score += 25

        # Language mismatch (weakest signal)
        lang_hits = self._count_matches(self.LANGUAGE_MISMATCH_PATTERNS, full_text)
        if lang_hits >= 2:
            flags.append(
                "Unusual writing style, the wording feels unnatural or templated")
            score += 15
        elif lang_hits == 1:
            flags.append("Slightly unusual wording, some phrases sound unnatural for a legitimate business")
            score += 5

        # return the results
        return DetectionResult(
            detector_name="Content & Urgency",
            risk_score=min(score, 100),
            flags=flags,
            passed=passed,
        )

    # This function scans the email text (subject and body) to see how many suspicious phrases from our lists appear
    def _count_matches(self, patterns: list[str], text: str) -> int:
        """Counts how many patterns match in the given text."""
        return sum(
            1 for p in patterns
            if re.search(p, text, re.IGNORECASE)
        )



# DETECTOR 4: Links and URLs
#
# Analyzes URLs found in the email body.
# do not click links, verify URLs, be suspicious of shortened URLs, check for domain mismatches.

class LinkDetector(BaseDetector):

    # TLDs heavily associated with phishing and spam infrastructure
    # These are cheap, easy to register, and rarely used by legitimate businesses
    SUSPICIOUS_TLDS = {
        '.xyz', '.top', '.click', '.loan', '.gq',
        '.tk', '.ml', '.cf', '.ga', '.pw',
        '.work', '.date', '.racing', '.win', '.bid',
    }

    # Known URL shorteners used a lot because they completely hide the real destination 
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
        'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
        'shorturl.at', 'tiny.cc', 'rb.gy', 'cutt.ly',
        'tr.im', 'snip.ly', 'bl.ink', 'short.io',
        'lnkd.in', 'amzn.to', 'youtu.be',
    }

    # File extensions that can execute code or deliver malware
    # when downloaded, should never be linked to in a legitimate email
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.msi', '.vbs',
        '.ps1', '.scr', '.jar', '.js', '.hta',
        '.zip', '.rar', '.7z', '.iso', '.dmg',
        '.doc', '.xls', '.ppt',  
    ]

    def analyze(self, subject, sender, reply_to, body, spf, dkim) -> DetectionResult:
        flags  = []
        passed = []
        score  = 0

        # Extract raw domains and full URLs separately
        raw_domains = re.findall(r'https?://([^\s/>"\']+)', body)
        full_urls   = re.findall(r'https?://[^\s>"\']+', body)
        url_count   = len(raw_domains)

        # Suspicious TLDs 
        suspicious_tld = [
            d for d in raw_domains
            if '.' + d.split('.')[-1].lower() in self.SUSPICIOUS_TLDS
        ]
        if suspicious_tld:
            flags.append(
              f"Suspicious link domain — this email links to a web address commonly associated with scams: "
                 f"{', '.join(set(suspicious_tld))}"
              )
            score += 70

        # URL shorteners 
        shorteners_found = [
            d for d in raw_domains
            if any(d.lower() == s or d.lower().startswith(s + '/') for s in self.URL_SHORTENERS)
        ]
        if shorteners_found:
            flags.append(
                f"Link destination hidden, one or more links use a shortener that conceals where you will actually land: "
                f"{', '.join(set(shorteners_found))}"
            )
            score += 80

        # Dangerous file extensions 
        dangerous = [
            url for url in full_urls
            if any(url.lower().split('?')[0].endswith(ext) for ext in self.DANGEROUS_EXTENSIONS)
        ]
        if dangerous:
            flags.append(
                f"Dangerous download link, this email links directly to a file that could harm your device: "
                f"{', '.join(dangerous)}"
            )
            score += 100

        # Excessive link count 
        if url_count > 5:
            flags.append(f"This email contains high number of links: ({url_count})")
            score += 15
        elif url_count == 0:
            passed.append("No links found in this email")
        else:
            passed.append("Links look clean, no suspicious destinations or shorteners detected")

        # Visible text vs actual URL mismatch 
        mismatch_flags = self._check_link_text_mismatch(body)
        if mismatch_flags:
            flags.extend(mismatch_flags)
            score += 50

        return DetectionResult(
            detector_name="Links & URLs",
            risk_score=min(score, 100),
            flags=flags,
            passed=passed,
        )

    def _check_link_text_mismatch(self, body: str) -> list[str]:
        """
        Detects disguised links where the visible text looks like a
        legitimate URL but the actual href points somewhere different.

        """
        mismatches = []

        # Find all anchor tags with href and text content
        anchor_pattern = re.compile(
            r'<a\s+[^>]*href=["\']?(https?://[^\s"\']+)["\']?[^>]*>'
            r'(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )

        for match in anchor_pattern.finditer(body):
            actual_url  = match.group(1)
            visible_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()

            # Only check if visible text also looks like a URL
            if re.match(r'https?://', visible_text) or '.' in visible_text:
                actual_domain  = self._extract_domain(actual_url)
                visible_domain = self._extract_domain(visible_text)

                if visible_domain and actual_domain != visible_domain:
                    mismatches.append(
                        f"Disguised link: shows '{visible_domain}' "
                        f"but actually goes to '{actual_domain}'"
                    )

        return mismatches

    def _extract_domain(self, url: str) -> str:
        """Extracts the domain from a URL string."""
        match = re.search(r'https?://([^\s/?"\']+)', url)
        if match:
            return match.group(1).lower()
        # Handle plain domain text (no http://)
        parts = url.strip().split('/')
        return parts[0].lower() if parts else ''


# DETECTOR 5: Lookalike Domains
#
# Detects domains that visually impersonate legitimate brands by
# substituting characters that look identical or very similar.
#
# This is one of the most sophisticated techniques because
# the fake domain looks correct at a glance.
#
# Examples:
#  — digit '1' replacing letter 'l'
#  — 'rn' visually resembles 'm'
#  — missing letter
#  — Cyrillic 'р' replacing Latin 'p' 

class HomoglyphDetector(BaseDetector):

    # Brands and their real domains to check against
    BRAND_DOMAINS = {
        'paypal':     'paypal.com',
        'google':     'google.com',
        'amazon':     'amazon.com',
        'apple':      'apple.com',
        'microsoft':  'microsoft.com',
        'netflix':    'netflix.com',
        'facebook':   'facebook.com',
        'instagram':  'instagram.com',
        'linkedin':   'linkedin.com',
        'dropbox':    'dropbox.com',
        'docusign':   'docusign.com',
        'chase':      'chase.com',
        'wellsfargo': 'wellsfargo.com',
        'bankofamerica': 'bankofamerica.com',
    }

    # Common character substitutions used in homoglyph attacks
    # Maps each confusable character to the ASCII character it mimics
    CONFUSABLE_CHARS = {
        '0': 'o', 'o': '0',
        '1': 'l', 'l': '1', 'i': 'l',
        '3': 'e', 'e': '3',
        '4': 'a', 'a': '4',
        '5': 's', 's': '5',
        '6': 'b', 'b': '6',
        '8': 'b',
        'vv': 'w', 'w': 'vv',
        'rn': 'm', 'm': 'rn',
    }

    def analyze(self, subject, sender, reply_to, body, spf, dkim) -> DetectionResult:
        flags  = []
        passed = []
        score  = 0

        # Collect all domains to check:
        # sender domain, reply-to domain, and all domains in body URLs
        domains_to_check = set()

        sender_domain = self._extract_domain(sender)
        if sender_domain:
            domains_to_check.add(sender_domain)

        if reply_to:
            rt_domain = self._extract_domain(reply_to)
            if rt_domain:
                domains_to_check.add(rt_domain)

        body_domains = re.findall(r'https?://([^\s/>"\']+)', body)
        for d in body_domains:
            domains_to_check.add(d.lower())

        # Check each domain against every known brand
        for domain in domains_to_check:
            for brand, legit_domain in self.BRAND_DOMAINS.items():

                # Skip if it's actually the legitimate domain
                if domain == legit_domain:
                    continue

                # A domain very close to a known brand but not identical, is likely a lookalike registration
                distance = self._levenshtein(domain, legit_domain)
                if 0 < distance <= 2:
                    flags.append(
                        f"Domain '{domain}' looks very similar to "
                        f"'{legit_domain}' "
                        f"— possible lookalike domain"
                    )
                    score += 45
                    continue

                # Brand name appears in domain with extra parts
                if brand in domain and domain != legit_domain:
                    flags.append(
                        f"This sender is using a deceptive web address that mimics '{brand}' "
                        f"but is not the official"
                    )
                    score += 35
                    continue

                # Normalize the domain by replacing confusable characters and check if it then matches a known brand domain
                normalized = self._normalize_homoglyphs(domain)
                if normalized == legit_domain and domain != legit_domain:
                    flags.append(
                        f"Domain '{domain}' uses lookalike characters "
                        f"to impersonate '{legit_domain}'"
                    )
                    score += 50

        if not flags:
            passed.append("Web address looks genuine")

        return DetectionResult(
            detector_name="Homoglyph & Lookalike Domains",
            risk_score=min(score, 100),
            flags=flags,
            passed=passed,
        )

    def _levenshtein(self, s1: str, s2: str) -> int:
        """
        Computes edit distance between two strings.
        Used to catch near miss domain registrations
        """
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions  = prev_row[j + 1] + 1
                deletions   = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    def _normalize_homoglyphs(self, domain: str) -> str:
        """
        Replaces known confusable characters with their ASCII equivalents.
        Used to detect IDN homoglyph attacks and character substitution.
        """
        normalized = domain.lower()
        # Multi-char substitutions first 
        for fake, real in self.CONFUSABLE_CHARS.items():
            if len(fake) > 1:
                normalized = normalized.replace(fake, real)
        # Single-char substitutions
        result = ''
        for char in normalized:
            result += self.CONFUSABLE_CHARS.get(char, char)
        return result

    def _extract_domain(self, email_str: str) -> str:
        """Extracts domain from an email address or URL string."""
        match = re.search(r'@([\w.\-]+)', email_str)
        return match.group(1).lower() if match else ''