import { useState } from "react"; 
import "./App.css"; 
function extractUrl(text) {

  const urlPattern = /(https?:\/\/[^\s]+)/gi;

  const matches = text.match(urlPattern);

  return matches ? matches[0].replace(/[.,!?)]$/, "") : null;

}




const analyzeUrl = (url) => {
  try {
    const parsedUrl = new URL(url);

    const hostname = parsedUrl.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();

    const findings = [];
    let urlScore = 0;

    // HTTP instead of HTTPS
    if (parsedUrl.protocol !== "https:") {
      findings.push("Uses HTTP instead of HTTPS");
      urlScore += 10;
    }

    // IP address instead of domain
    const isIpAddress =
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    if (isIpAddress) {
      findings.push("Uses an IP address instead of a domain");
      urlScore += 25;
    }

    // Suspicious words
    const suspiciousWords = [
      "login",
      "verify",
      "verification",
      "kyc",
      "update",
      "secure",
      "account",
      "banking",
      "wallet",
      "password",
      "reward",
      "claim"
    ];

    const foundUrlWords = suspiciousWords.filter((word) =>
      fullUrl.includes(word)
    );

    if (foundUrlWords.length > 0) {
      findings.push(
        `Suspicious URL words: ${foundUrlWords.join(", ")}`
      );

      urlScore += Math.min(foundUrlWords.length * 5, 20);
    }

    // Very long URL
    if (url.length > 100) {
      findings.push("Unusually long URL");
      urlScore += 10;
    }

    // Multiple subdomains
    const dotCount = (hostname.match(/\./g) || []).length;

    if (dotCount >= 3) {
      findings.push("Multiple subdomains detected");
      urlScore += 10;
    }

    // @ symbol
    if (url.includes("@")) {
      findings.push("Contains @ symbol in URL");
      urlScore += 20;
    }

    // Higher-risk TLD heuristic
    const higherRiskTlds = [
      ".xyz",
      ".top",
      ".click",
      ".icu",
      ".buzz",
      ".online"
    ];

    if (
      higherRiskTlds.some((tld) =>
        hostname.endsWith(tld)
      )
    ) {
      findings.push("Higher-risk domain extension");
      urlScore += 15;
    }

    return {
      score: Math.min(urlScore, 50),
      findings
    };

  } catch (error) {

    return {
      score: 0,
      findings: []
    };

  }
};
const getIntervention = (stage) => {
  switch (stage) {
    case "not_interacted":
      return {
        title: "You're still in the safest position",
        steps: [
          "Do not click the link or reply to the sender.",
          "Do not share OTP, PIN, password or banking details.",
          "Verify the message independently through the organization's official app or website."
        ]
      };

    case "clicked":
      return {
        title: "You clicked the link — secure yourself now",
        steps: [
          "Close the suspicious website immediately.",
          "Do not enter or submit any further information.",
          "If you entered credentials, change the affected password through the official website/app."
        ]
      };

    case "shared_info":
      return {
        title: "Sensitive information may be compromised",
        steps: [
          "Contact your bank or relevant service provider immediately.",
          "Change compromised passwords or security credentials.",
          "Monitor your account for unauthorized activity."
        ]
      };

    case "transferred_money":
      return {
        title: "Possible financial loss — act immediately",
        steps: [
          "Contact your bank or payment provider immediately.",
          "Report the unauthorized transaction through the appropriate official channel.",
          "Preserve transaction IDs, screenshots, phone numbers and messages as evidence."
        ]
      };

    default:
      return null;
  }
};
function App()
 {   const [input, setInput] = useState(""); 
     const [result, setResult] = useState(null);
const [showReportForm, setShowReportForm] = useState(false);
const [reportSubmitted, setReportSubmitted] = useState(false);
const [reportError, setReportError] = useState("");
const [incidentStage, setIncidentStage] = useState("");
const getAttackPattern = (result) => {
  if (!result) return [];

  const detected = result.indicators || [];
  const stages = [];

  if (
    detected.includes("Prize") ||
    detected.includes("Banking")
  ) {
    stages.push({
      number: 1,
      title: "Trust / Fear Trigger",
      description: "The message attempts to create trust, excitement, or fear."
    });
  }

  if (detected.includes("Urgency") || detected.includes("Threat")) {
    stages.push({
      number: 2,
      title: "Psychological Pressure",
      description: "Urgency or threats are used to make the victim act quickly."
    });
  }

  if (
    detected.includes("OTP") ||
    detected.includes("Password") ||
    detected.includes("KYC")
  ) {
    stages.push({
      number: 3,
      title: "Credential Theft",
      description: "The message attempts to obtain sensitive account information."
    });
  }

  if (
    detected.includes("Payment") ||
    detected.includes("UPI")
  ) {
    stages.push({
      number: 4,
      title: "Financial Action",
      description: "The victim is pushed toward a payment or money transfer."
    });
  }

  if (detected.includes("Link")) {
    stages.push({
      number: stages.length + 1,
      title: "Potential Phishing Channel",
      description: "A link or website is used to continue the attack."
    });
  }

  return stages;
};
 const checkScam = async () => {
  if (!input.trim()) return;

setIncidentStage("");

  const originalText = input;
  const text = input.toLowerCase();

  // -----------------------------------------
  // 1. Scam indicators and their importance
  // -----------------------------------------

  const indicators = {
    OTP: ["otp", "one time password"],
    KYC: ["kyc", "verify kyc", "verification"],
    Urgency: [
      "urgent",
      "immediately",
      "hurry",
      "act now",
      "within 24 hours",
      "within 1 hour"
    ],
    Payment: [
      "payment",
      "pay",
      "transfer",
      "send money",
      "send ₹",
      "send rs"
    ],
    Banking: [
      "bank",
      "account",
      "blocked",
      "suspend",
      "suspended"
    ],
    Link: [
      "click",
      "link",
      "website",
      "http",
      "www"
    ],
    Prize: [
      "winner",
      "prize",
      "lottery",
      "reward",
      "won",
      "congratulations"
    ],
    UPI: [
      "upi",
      "upi id",
      "qr code",
      "scan qr"
    ],
    Password: [
      "password",
      "pin",
      "passcode",
      "login"
    ],
    Threat: [
      "account will be blocked",
      "account will be closed",
      "legal action",
      "police case",
      "penalty",
      "fine"
    ]
  };

  // -----------------------------------------
  // 2. Weight of each indicator
  // -----------------------------------------

  const weights = {
    OTP: 20,
    KYC: 12,
    Urgency: 15,
    Payment: 15,
    Banking: 8,
    Link: 8,
    Prize: 15,
    UPI: 15,
    Password: 18,
    Threat: 15
  };

  // -----------------------------------------
  // 3. Detect indicators
  // -----------------------------------------

  const detected = [];

  Object.entries(indicators).forEach(([name, words]) => {
    if (words.some((word) => text.includes(word))) {
      detected.push(name);
    }
  });

  // -----------------------------------------
  // 4. Calculate initial risk score
  // -----------------------------------------

  let score = detected.reduce(
    (total, indicator) => total + weights[indicator],
    0
  );

  // -----------------------------------------
  // 5. Combination signals
  // -----------------------------------------

  // OTP + urgency is much more suspicious
  if (
    detected.includes("OTP") &&
    detected.includes("Urgency")
  ) {
    score += 15;
  }

  // Payment + urgency
  if (
    detected.includes("Payment") &&
    detected.includes("Urgency")
  ) {
    score += 15;
  }

  // Banking + KYC + urgency
  if (
    detected.includes("Banking") &&
    detected.includes("KYC") &&
    detected.includes("Urgency")
  ) {
    score += 15;
  }

  // Link + urgency + credentials
  if (
    detected.includes("Link") &&
    detected.includes("Urgency") &&
    (detected.includes("OTP") ||
      detected.includes("Password") ||
      detected.includes("KYC"))
  ) {
    score += 20;
  }

  // -----------------------------------------
  // 6. Detect protective / awareness language
  // -----------------------------------------

  const protectivePhrases = [
    "never share your otp",
    "do not share your otp",
    "don't share your otp",
    "never share otp",
    "do not click",
    "don't click",
    "never click",
    "never share your password",
    "bank will never ask",
    "banks never ask",
    "beware of scams",
    "this is a scam",
    "report the scam", 
      "don't share",
      "do not share",
      "never share",
      "we don't call",
      "we do not call",
      "never ask for otp",
      "never ask you for otp",
      "don't reveal",
      "do not reveal"
    ];

const isProtectiveMessage = protectivePhrases.some(phrase =>
  text.includes(phrase)
);

  const lowerText = text.toLowerCase();

if (isProtectiveMessage) {
  score = 0;

}



  // -----------------------------------------
  // 7. Find URL
  // -----------------------------------------

  const url = extractUrl(originalText);
  const urlAnalysis = url ? analyzeUrl(url) : null;

  // -----------------------------------------
// Add URL risk score
// -----------------------------------------

if (urlAnalysis) {
  score += urlAnalysis.score;
}

// Keep score between 0 and 100
score = Math.max(0, Math.min(score, 100));

  let virusTotalStatus = null;
  let virusTotalDetails = null;

  // -----------------------------------------
  // 8. Check URL with backend / VirusTotal
  // -----------------------------------------

  if (url) {
    try {
      const response = await fetch(
        `http://localhost:3001/api/check-url?url=${encodeURIComponent(url)}`
      );

      const data = await response.json();

      virusTotalStatus = data.status;
      virusTotalDetails = data;
    } catch (error) {
      console.error("VirusTotal check failed:", error);
    }
  }

  // -----------------------------------------
  // 9. Default result
  // -----------------------------------------

  let risk = "Likely Safe";

  let action =
    "No major warning signs detected. Still verify the sender before taking action.";

  let category = "General Message";

  // -----------------------------------------
  // 10. Determine scam category
  // -----------------------------------------

  if (
    detected.includes("OTP") ||
    detected.includes("Password") ||
    detected.includes("KYC")
  ) {
    category = "Account / Identity Fraud";
  }

  if (
    detected.includes("UPI") ||
    detected.includes("Payment") ||
    detected.includes("Banking")
  ) {
    category = "Banking / Payment Fraud";
  }

  if (detected.includes("Prize")) {
    category = "Prize / Lottery Scam";
  }

  if (
    detected.includes("Link") &&
    detected.includes("Urgency")
  ) {
    category = "Phishing Scam";
  }
  if (isProtectiveMessage) {
  category = "Fraud Awareness / Safety Guidance";
}

  // -----------------------------------------
  // 11. Determine risk level
  // -----------------------------------------

  if (virusTotalStatus === "malicious") {
    risk = "High Risk";

    score = Math.max(score, 90);

    action =
      "The URL has been flagged by external security analysis. Do NOT open the link, enter credentials, share OTPs, or make payments.";
  }

  else if (virusTotalStatus === "suspicious") {
    risk = "High Risk";

    score = Math.max(score, 75);

    action =
      "The URL has suspicious security signals. Avoid opening it and verify the organization through its official website or app.";
  }

  else if (isProtectiveMessage && score < 30) {
    risk = "Likely Safe";

    action =
      "This message appears to provide fraud-awareness guidance rather than requesting sensitive information.";
  }

  else if (score >= 70) {
    risk = "High Risk";

    action =
      "Do NOT click links, share OTPs, reveal passwords, scan unknown QR codes, or send money. Verify through the official organization.";
  }

  else if (score >= 35) {
    risk = "Verify Before Trusting";

    action =
      "Some risk indicators were detected, but there is not enough evidence to confirm that the message is fraudulent. Verify the sender independently before taking action.";
  }

  // -----------------------------------------
  // 12. Store result
  // -----------------------------------------

  setResult({
  risk,
  score,
  category,
  indicators: detected,
  action,
  url,
  virusTotalStatus,
  virusTotalDetails,
  isProtectiveMessage,
  urlScore: urlAnalysis ? urlAnalysis.score : 0,
  urlFindings: urlAnalysis ? urlAnalysis.findings : [],
});
};return ( <div className="app"> <nav className="navbar"> <div className="logo"> 🛡️ ScamTrace </div> <div className="nav-links"> <a href="#home">Home</a> <a href="#check">Check Scam</a> <a href="#about">About</a> </div> </nav> <main id="home"> <section className="hero"> <div className="hero-text"> <p className="tag">CYBER FRAUD DETECTION</p> <h1> Trace the Scam. <br /> <span>Stop the Fraud.</span> </h1> <p className="description"> ScamTrace analyzes suspicious messages and identifies potential cyber-fraud indicators before you take action. </p> <a href="#check" className="start-btn"> Check a Message → </a> </div> <div className="shield"> 🛡️ </div> </section>
  <section id="check" className="checker"> <div className="section-heading"> <p className="tag">SCAM ANALYZER</p> <h2 style={{ color: "#00d9ff" }}>Check a suspicious message</h2> <p> Paste an SMS, WhatsApp message, email or payment request below. </p> </div> <textarea value={input} onChange={(e) => setInput(e.target.value)} placeholder="Example: Your bank account will be blocked. Verify your KYC immediately by clicking this link..." /> <button onClick={checkScam} className="analyze-btn"> 🔍 Analyze for Scam </button> {result && ( <div className={`result ${result.risk .replace(" ", "-") .toLowerCase()}`} > <h3>{result.risk}</h3> <div className="score"> Risk Score: <strong>{result.score}/100</strong> </div> <p> <strong>Detected Category:</strong>{" "} {result.category} </p> <div className="why-box">
  <strong>
    {result.risk === "Likely Safe"
      ? "Why does ScamTrace consider this safe?"
      : "Why is this suspicious?"}
  </strong>

  {result.indicators.length > 0 ? (
    <ul>
      {result.indicators.map((item) => (
        <li key={item}>
          {item} indicator detected
        </li>
      ))}
    </ul>
  ) : (
    <p>No major risk indicators were detected.</p>
  )}

  {result.urlFindings?.length > 0 && (
    <ul>
      {result.urlFindings.map((finding, index) => (
        <li key={index}>{finding}</li>
      ))}
    </ul>
  )}
</div><div className="indicators"> {result.indicators.length > 0 ? ( result.indicators.map((item) => ( <span key={item}>{item}</span> )) ) : ( <span>No major indicators detected</span> )} </div>
   <div className="action-box">
     <strong>Recommended Action</strong>
     <p>{result.action}</p> </div> 
     {result.risk !== "Likely Safe" && (
  <div className="attack-pattern-box">
    <strong>🧠 Detected Attack Pattern</strong>

    <p className="pattern-intro">
      ScamTrace identified the following signals in the possible attack:
    </p>

    <div className="attack-timeline">
      {getAttackPattern(result).map((stage, index) => (
        <div className="attack-stage" key={index}>
          <div className="stage-number">{stage.number}</div>

          <div>
            <strong>{stage.title}</strong>
            <p>{stage.description}</p>
          </div>
        </div>
      ))}
    </div>
  </div>
)}
  {result.risk !== "Likely Safe" && (
  <div className="intervention-box">

    <strong>🛡️ What happened after receiving this message?</strong>

    <p>
      Select the situation that best describes what happened.
      ScamTrace will provide the appropriate next steps.
    </p>

    <div className="intervention-buttons">

      <button onClick={() => setIncidentStage("not_interacted")}>
        🟢 I haven't interacted
      </button>

      <button onClick={() => setIncidentStage("clicked")}>
        🟡 I clicked the link
      </button>

      <button onClick={() => setIncidentStage("shared_info")}>
        🟠 I shared information
      </button>

      <button onClick={() => setIncidentStage("transferred_money")}>
        🔴 I transferred money
      </button>

    </div>

    {incidentStage && (
      <div className="intervention-result">

        <h4>
          {getIntervention(incidentStage).title}
        </h4>

        <ul>
          {getIntervention(incidentStage).steps.map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ul>

      </div>
    )}

  </div>
)}
     {result.url && result.virusTotalStatus && (
  <div className="url-check-box">
    <strong>🌐 External URL Check</strong>

    <p>
      <strong>VirusTotal Reputation:</strong>{" "}
      {result.virusTotalStatus === "malicious"
        ? "⚠️ Flagged"
        : result.virusTotalStatus === "suspicious"
        ? "⚠️ Suspicious"
        : result.virusTotalStatus === "clean"
        ? "✅ No major detections"
        : "❓ Unknown"}
    </p>

    {result.virusTotalDetails && (
      <p>
        Malicious: {result.virusTotalDetails.malicious ?? 0} |{" "}
        Suspicious: {result.virusTotalDetails.suspicious ?? 0} |{" "}
        Harmless: {result.virusTotalDetails.harmless ?? 0}
      </p>
    )}

    <small>
      External reputation signal provided by VirusTotal.
    </small>
  </div>
)}
     </div> )} </section> 
     <section id="about" className="features">
     <div className="section-heading">
     <p className="tag">WHY SCAMTRACE?</p> 
     <h2>Detect digital fraud before it causes damage</h2> 
     </div> 
     <div className="cards">
     <div className="card">
     <div className="card-icon">📱</div> 
     <h3>Message Analysis</h3>
     <p> Analyze suspicious SMS, WhatsApp messages and online communication. </p> </div>
    <div className="card"> 
    <div className="card-icon">💳</div> 
    <h3>Cyber Fraud Detection</h3> 
    <p> Detect OTP, KYC, UPI, banking, payment and phishing indicators. </p> </div> 
    <div className="card"> 
    <div className="card-icon">⚠️</div> 
    <h3>Actionable Warning</h3> 
    <p> Get a risk score and immediate safety recommendations instead of just a warning. </p> 
    </div> 
    </div>  
    </section>
  <section className="emergency">
  <div className="section-heading">
    <p className="tag">ALREADY SCAMMED?</p>

    <h2>Act quickly. Protect yourself.</h2>

    <p>
      If you have already shared sensitive information or lost money,
      take these steps immediately.
    </p>
  </div>

  <div className="emergency-cards">
    <div className="emergency-card">
      <span>💳</span>
      <h3>Stop Further Payments</h3>
      <p>
        Do not send any more money or approve additional payment requests.
      </p>
    </div>

    <div className="emergency-card">
      <span>🔐</span>
      <h3>Secure Your Accounts</h3>
      <p>
        Contact your bank and secure your UPI, banking and other accounts.
      </p>
    </div>

    <div className="emergency-card">
      <span>📋</span>
      <h3>Preserve Evidence</h3>
      <p>
        Save screenshots, phone numbers, messages and transaction details.
      </p>
    </div>

  <div className="emergency-card">
  <span>🚨</span>
  <h3>Report the Fraud</h3>

  <p>
    Record the important details and prepare them for reporting.
  </p>

  <button
    className="report-btn"
    onClick={() =>  {
    setShowReportForm(true);
    setTimeout(() => {
      document.getElementById("report")?.scrollIntoView({
        behavior: "smooth",
      });
    }, 100);
  }}

    >

    Report Scam
  </button>
</div>
  </div>
</section>
{showReportForm && (
<section id="report" className="report-form-section">    {!reportSubmitted ? (
      <>
        <div className="section-heading">
          <p className="tag">REPORT SCAM</p>
          <h2>Report a Cyber Fraud Incident</h2>
          <p>
            Enter the important details below to prepare your incident report.
          </p>
        </div>

        <div className="report-form">
          {reportError && (
  <p className="report-error">
    ⚠️ {reportError}
  </p>
)}
          <input  id="fraudType"
           type="text"
           placeholder="Fraud Type (e.g. UPI, OTP, KYC)"
         />
          <input
            id="contact"
            type="text"
            placeholder="Phone Number / UPI ID"
          />

          <input
            id="transactionId"
            type="text"
            placeholder="Transaction ID"
          />

          <input
            id="amount"
            type="number"
            placeholder="Amount Lost (₹)"
          />

          <textarea
            id="description"
            placeholder="Describe what happened..."
          ></textarea>

          <button
            className="analyze-btn"
            onClick={() => {
                const fraudType = document.getElementById("fraudType").value.trim();
                const contact = document.getElementById("contact").value.trim();
                const transactionId = document
                  .getElementById("transactionId")
                  .value.trim();
                const amount = document.getElementById("amount").value.trim();
                const description = document
                  .getElementById("description")
                  .value.trim();

                if (!fraudType || !contact || !transactionId || !amount || !description) {
                  setReportError(
                    "Please fill in all the required details before submitting the report."
                  );
                  return;
                }

                setReportError("");
                setReportSubmitted(true);
              }}

          >
            Submit Scam Report
          </button>
        </div>
      </>
    ) : (
      <div className="report-success">
        <div className="success-icon">✅</div>

        <p className="tag">REPORT CREATED</p>

        <h2>Scam Report Submitted Successfully</h2>

        <p>
          Your incident details have been recorded in this ScamTrace
          prototype.
        </p>

        <div className="report-id">
          <span>Report ID</span>
          <strong>ST-{Math.floor(100000 + Math.random() * 900000)}</strong>
        </div>

        <div className="report-status">
            <span>STATUS</span>
            <strong>READY FOR REVIEW</strong>
          </div>

        <div className="next-action">
          <strong>Next Step</strong>
          <p>
            Preserve screenshots, transaction details and communication
            records for further reporting.
          </p>
        </div>
        <button
              className="check-again-btn"
              onClick={() => {
                setReportSubmitted(false);
                setShowReportForm(false);
                setReportError("");
                setInput("");
                setResult(null);

                setTimeout(() => {
                  document.getElementById("check")?.scrollIntoView({
                    behavior: "smooth",
                  });
                }, 100);
              }}
            >
              🔍 Check Another Message 
            </button>
      </div>
    )}
  </section>
)}
 </main> 
<footer> <strong>ScamTrace</strong> — Cyber fraud awareness prototype. </footer> </div> ); } export default App;