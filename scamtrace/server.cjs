
require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: "10kb" }));

// 1. Backend home
app.get("/", (req, res) => {
  res.json({
    service: "ScamTrace Backend",
    status: "online"
  });
});

// 2. Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ScamTrace API"
  });
});

// 3. Convert URL to VirusTotal URL ID
function getUrlId(url) {
  return Buffer.from(url, "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// 4. Check URL reputation using VirusTotal
app.get("/api/check-url", async (req, res) => {
  const url = req.query.url;

  if (!url || typeof url !== "string") {
    return res.status(400).json({
      status: "unknown",
      error: "Please provide a URL."
    });
  }

  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    return res.status(400).json({
      status: "unknown",
      error: "Invalid URL."
    });
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return res.status(400).json({
      status: "unknown",
      error: "Only HTTP and HTTPS URLs are supported."
    });
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return res.status(503).json({
      status: "unknown",
      error: "VirusTotal API key is missing. Configure your .env file."
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${getUrlId(url)}`,
      {
        headers: {
          "x-apikey": apiKey,
          accept: "application/json"
        },
        signal: controller.signal
      }
    );

    if (response.status === 404) {
      return res.json({
        status: "unknown",
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        message: "No existing URL report was found."
      });
    }

    if (response.status === 429) {
      return res.status(429).json({
        status: "unknown",
        error: "VirusTotal rate limit reached."
      });
    }

    if (response.status === 401 || response.status === 403) {
      return res.status(502).json({
        status: "unknown",
        error: "VirusTotal API key rejected or access denied."
      });
    }

    if (!response.ok) {
      return res.status(502).json({
        status: "unknown",
        error: `VirusTotal returned HTTP ${response.status}.`
      });
    }

    const report = await response.json();

    const stats =
      report?.data?.attributes?.last_analysis_stats || {};

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);

    let status = "unknown";

    if (malicious > 0) {
      status = "malicious";
    } else if (suspicious > 0) {
      status = "suspicious";
    } else if (harmless + undetected > 0) {
      status = "clean";
    }

    return res.json({
      status,
      malicious,
      suspicious,
      harmless,
      undetected,
      source: "VirusTotal",
      message:
        status === "malicious"
          ? "Security engines flagged this URL as malicious."
          : status === "suspicious"
          ? "Security engines flagged this URL as suspicious."
          : status === "clean"
          ? "No malicious or suspicious detections were reported. This does not guarantee safety."
          : "The URL reputation is unknown."
    });
  } catch (error) {
    console.error("VirusTotal error:", error.message);

    return res.status(
      error.name === "AbortError" ? 504 : 502
    ).json({
      status: "unknown",
      error:
        error.name === "AbortError"
          ? "VirusTotal request timed out."
          : "Could not connect to VirusTotal."
    });
  } finally {
    clearTimeout(timeout);
  }
});

// 5. Demo incident-report endpoint
// This acknowledges reports but does not save them permanently.
app.post("/api/report", (req, res) => {
  const { incidentType, description } = req.body || {};

  if (
    typeof incidentType !== "string" ||
    !incidentType.trim() ||
    typeof description !== "string" ||
    !description.trim()
  ) {
    return res.status(400).json({
      success: false,
      error: "Incident type and description are required."
    });
  }

  res.status(201).json({
    success: true,
    reportId: `ST-${Date.now()}`,
    message:
      "Demo report received. It has not been saved to a database or sent to authorities."
  });
});

// 6. Start backend server
app.listen(PORT, () => {
  console.log(
    `ScamTrace backend running at http://localhost:${PORT}`
  );
  console.log(
    `Health check: http://localhost:${PORT}/api/health`
  );
});
