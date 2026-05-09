# These weights determine how much each category affects the final score.

WEIGHTS = {
    # Highest priority, malicious links are the most common way users get attacked,
    #  so they carry the most weight
    "links_urls":       0.35,


    # Urgent language is a clue, but can also be found in legitimate emails
    "content_urgency":  0.30,


     #If an email fails its technical ID check (SPF/DKIM), it is objectively untrustworthy
    "authentication":   0.15,


    # Identity spoofing is important but often overlaps with authentication failures
    "sender_identity":  0.15,


    # Lookalike domains are rare, so i keep this low to avoid over reacting to edge cases
    "homoglyph":        0.05,
}

# If an email is technically verified (SPF/DKIM pass), we multiply the 
# risk of its othe signals by this factor.
# This reduces the chance of a "False Positive" for legitimate mails
TRUST_DAMPENING_FACTOR = 0.6  

# Verdict Thresholds:
# Any score of 60 or higher is labeled as a direct threat
THRESHOLD_MALICIOUS   = 60

# Any score between 24 and 59 is labeled as a warning
THRESHOLD_SUSPICIOUS  = 24