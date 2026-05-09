/**
 * Main entry point for the Gmail Add-on 
 * Triggered whenever a user opens an email
 */
function onGmailMessage(e) {
  const accessToken = e.gmail.accessToken;
  const messageId = e.gmail.messageId;
  
  // Set permissions to read the current message
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const message = GmailApp.getMessageById(messageId);

  // Prepare the Data Payload
  const payload = {
    subject: message.getSubject(),
    sender: message.getFrom(),
    reply_to: message.getHeader("Reply-To") || "",
    spf: message.getHeader("Received-SPF") || "",
    dkim: message.getHeader("DKIM-Signature") || "",
    body: message.getPlainBody().substring(0, 3000) 
  };


  // Fetch Analysis from Backend
  const report = fetchAnalysis(payload);
  
  // Return the UI Card
  if (!report) {
    return buildErrorCard("Analysis Engine Unreachable. Ensure your backend are running.");
  }

  return buildResultCard(report);
}

/**
 * Sends the email data to the FastAPI backend
 */
function fetchAnalysis(data) {
  const BACKEND_URL = PropertiesService.getScriptProperties().getProperty("BACKEND_URL");

  const options = {
    "method": "post",
    "contentType": "application/json",
    "headers": {
      "ngrok-skip-browser-warning": "true" 
    },
    "payload": JSON.stringify(data),
    "muteHttpExceptions": true
  };

  try {
    const response = UrlFetchApp.fetch(BACKEND_URL, options);
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    }
  } catch (err) {
    console.error("Fetch error: " + err);
  }
  return null;
}

/**
 * Builds the UI Card to display the verdict and red flags.
 */
function buildResultCard(report) {
  const card = CardService.newCardBuilder();
  
  // Header with Verdict and Score
  const header = CardService.newCardHeader()
    .setTitle(verdictEmoji(report.verdict) + " " + report.verdict)
    .setSubtitle("Security Risk Score: " + report.score + "/100");
  card.setHeader(header);

  const section = CardService.newCardSection().setHeader("Detection Details");
  
  let flagsAdded = 0;

  // display order
  const DISPLAY_ORDER = [
    "content_urgency",
    "sender_identity",
    "links_urls",
    "authentication",
    "homoglyph",
  ];

  // Within content_urgency, urgency and sensitive info requests are
  // shown first, any other content flags (tech scam, language mismatch,...) follow
  const CONTENT_PRIORITY_PREFIXES = [
    "High-pressure language",
    "Urgent tone",
    "Requests personal data",
  ];

  const breakdown = report.breakdown;

  // Build the full ordered list: known categories in order, then any
  // unexpected future categories appended at the end
  const allCategories = DISPLAY_ORDER.concat(
    Object.keys(breakdown).filter(function(k) {
      return DISPLAY_ORDER.indexOf(k) === -1;
    })
  );

  allCategories.forEach(function(category) {
    const categoryData = breakdown[category];
    if (!categoryData || !categoryData.flags || categoryData.flags.length === 0) return;

    let flags = categoryData.flags.slice(); // copy to avoid mutating original

    // For the content category, bubble the two priority flags to the top
    if (category === "content_urgency") {
      const top  = flags.filter(function(f) {
        return CONTENT_PRIORITY_PREFIXES.some(function(prefix) {
          return f.indexOf(prefix) === 0;
        });
      });
      const rest = flags.filter(function(f) {
        return CONTENT_PRIORITY_PREFIXES.every(function(prefix) {
          return f.indexOf(prefix) !== 0;
        });
      });
      flags = top.concat(rest);
    }

    flags.forEach(function(flag) {
      section.addWidget(CardService.newTextParagraph().setText("✗ " + flag));
      flagsAdded++;
    });
  });

  // If no flags were found, show a success message
  if (flagsAdded === 0) {
    section.addWidget(CardService.newTextParagraph().setText("✓ No significant threats detected in this message."));
  }

  // Display Trust Dampening Info
  if (report.trust_applied) {
    section.addWidget(CardService.newTextParagraph()
      .setText("ℹ Trust Logic: This sender is authenticated."));
  }

  return card.addSection(section).build();
}

function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Connection Error"))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(message)))
    .build();
}

/**
 * Returns an emoji matching the threat level of the verdict
 */
function verdictEmoji(verdict) {
  if (verdict === "MALICIOUS") return "🚨";
  if (verdict === "SUSPICIOUS") return "⚠️";
  return "✅";
}