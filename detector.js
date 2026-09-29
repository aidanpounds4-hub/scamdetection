/*
 * PauseFirst scam detector.
 * Pure, dependency-free heuristics. Runs entirely in the browser.
 *
 * analyze(text, channel) -> {
 *   score,            // 0..100 risk score
 *   level,            // 'low' | 'caution' | 'high'
 *   signals,          // [{ id, label, detail, weight }]
 *   advice            // [strings]
 * }
 */
(function (global) {
  "use strict";

  // Each rule inspects the (lowercased) text and returns a signal or null.
  // weight roughly reflects how strongly the pattern indicates a scam.
  var RULES = [
    {
      id: "urgency",
      label: "Creates urgency or pressure",
      weight: 18,
      detail: "Scammers rush you so you act before thinking.",
      test: function (t) {
        return /\b(urgent|immediately|right now|act now|within \d+\s*(hours?|minutes?)|final notice|last warning|exptelecom|suspend(ed|ing)?|deactivat|limited time|before it'?s too late)\b/.test(t);
      }
    },
    {
      id: "credentials",
      label: "Asks for passwords, PINs, or one-time codes",
      weight: 30,
      detail: "Legitimate organizations never ask you to share these.",
      test: function (t) {
        return /\b(password|passcode|\bpin\b|one[-\s]?time (code|password)|\botp\b|verification code|security code|2fa|two[-\s]?factor|login credentials|card number|cvv|ssn|social security)\b/.test(t);
      }
    },
    {
      id: "payment",
      label: "Wants money, gift cards, or crypto",
      weight: 28,
      detail: "Requests for gift cards, wire transfers, or crypto are a classic scam signature.",
      test: function (t) {
        return /\b(gift card|itunes|google play card|steam card|wire transfer|western union|moneygram|bitcoin|btc|ethereum|crypto|usdt|zelle|cash app|venmo|pay(?:pal)? (?:me|now)|send (?:money|payment|\$?\d))\b/.test(t);
      }
    },
    {
      id: "prize",
      label: "Promises a prize, refund, or windfall",
      weight: 20,
      detail: "You didn't enter, but you 'won'? Unexpected money is bait.",
      test: function (t) {
        return /\b(you'?ve won|congratulations|claim your (prize|reward|refund)|lottery|sweepstakes|inheritance|unclaimed (funds|money)|free (gift|money|prize)|selected as (a )?winner)\b/.test(t);
      }
    },
    {
      id: "impersonation",
      label: "Claims to be a bank, agency, or big company",
      weight: 14,
      detail: "Impersonating a trusted name lowers your guard. Verify through official channels.",
      test: function (t) {
        return /\b(irs|hmrc|social security administration|ssa|medicare|amazon|apple|microsoft|paypal|netflix|fedex|ups|usps|dhl|your bank|bank of|wells fargo|chase|citibank|customs|border|police|law enforcement|court)\b/.test(t);
      }
    },
    {
      id: "threat",
      label: "Threatens arrest, fines, or legal action",
      weight: 24,
      detail: "Real agencies don't threaten immediate arrest over a text or call.",
      test: function (t) {
        return /\b(arrest(ed)?|warrant|lawsuit|legal action|court|fine|penalty|deport|prosecut|frozen account|blacklist|criminal charges)\b/.test(t);
      }
    },
    {
      id: "secrecy",
      label: "Tells you to keep it secret",
      weight: 22,
      detail: "Isolation is a tactic — talk to someone you trust.",
      test: function (t) {
        return /\b(don'?t tell|do not tell|keep (this|it) (a )?secret|between us|confidential|don'?t (call|contact|talk to) (the )?(bank|police|anyone))\b/.test(t);
      }
    },
    {
      id: "link",
      label: "Contains a link to click",
      weight: 8,
      detail: "Links can lead to fake login pages. Don't click — go to the site directly.",
      test: function (t) {
        return /(https?:\/\/|www\.)\S+/.test(t) || /\b\w+\.(com|net|org|info|xyz|top|link|click|live|shop)\b\/?\S*/.test(t);
      }
    },
    {
      id: "suspicious-link",
      label: "Link looks disguised or suspicious",
      weight: 20,
      detail: "URL shorteners, look-alike domains, and IP addresses hide where a link really goes.",
      test: function (t) {
        return /(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|ow\.ly|cutt\.ly|rb\.gy|shorturl)/.test(t) ||
               /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(t) ||
               /(secure|verify|update|account|login|signin|confirm|support)[-.]\w+\.(com|net|info|xyz|top)/.test(t) ||
               /\bxn--/.test(t);
      }
    },
    {
      id: "contact-info",
      label: "Pushes you to a specific number or reply",
      weight: 10,
      detail: "Numbers in the message may ring the scammer, not the real company.",
      test: function (t) {
        return /\b(call|text|reply|contact|dial)\b[^.?!]{0,40}\b(\+?\d[\d\s().-]{6,}\d|now|immediately|this number)\b/.test(t);
      }
    },
    {
      id: "impersonal",
      label: "Vague, impersonal greeting",
      weight: 6,
      detail: "'Dear customer' or 'Dear user' suggests a mass, untargeted message.",
      test: function (t) {
        return /\b(dear (customer|user|account holder|sir\/madam|member)|valued customer|account holder)\b/.test(t);
      }
    },
    {
      id: "grammar",
      label: "Odd spelling or formatting",
      weight: 6,
      detail: "Misspellings and strange spacing are common in scam messages.",
      test: function (t) {
        // crude signal: several ALL-CAPS words, or repeated punctuation
        var caps = (t.match(/\b[A-Z]{4,}\b/g) || []).length;
        var bangs = (t.match(/[!?]{2,}/g) || []).length;
        return caps >= 3 || bangs >= 1;
      }
    }
  ];

  // Channel-specific advice.
  var CHANNEL_ADVICE = {
    text: "For texts, never tap links. If it claims to be a company you use, open their app or type their address yourself.",
    email: "For email, check the real sender address (not just the display name) and hover links before trusting them.",
    call: "For calls, hang up and call the organization back on a number you look up independently.",
    social: "On social media, accounts can be hacked or faked. Verify with the person through another channel.",
    other: "When unsure of the source, treat requests for money or personal info as suspicious until verified."
  };

  function analyze(rawText, channel) {
    var text = String(rawText || "");
    // grammar rule needs original case; others use lowercase.
    var lower = text.toLowerCase();

    var signals = [];
    var score = 0;

    RULES.forEach(function (rule) {
      var subject = rule.id === "grammar" ? text : lower;
      var hit = false;
      try {
        hit = rule.test(subject);
      } catch (e) {
        hit = false;
      }
      if (hit) {
        signals.push({
          id: rule.id,
          label: rule.label,
          detail: rule.detail,
          weight: rule.weight
        });
        score += rule.weight;
      }
    });

    // Combination boosts: certain pairs are far more dangerous together.
    var ids = signals.map(function (s) { return s.id; });
    function has(id) { return ids.indexOf(id) !== -1; }

    if (has("urgency") && (has("credentials") || has("payment"))) score += 12;
    if (has("impersonation") && has("suspicious-link")) score += 10;
    if (has("threat") && has("payment")) score += 12;
    if (has("secrecy") && has("payment")) score += 10;

    if (score > 100) score = 100;

    var level = score >= 55 ? "high" : score >= 25 ? "caution" : "low";

    var advice = buildAdvice(level, ids, channel);

    return {
      score: score,
      level: level,
      signals: signals.sort(function (a, b) { return b.weight - a.weight; }),
      advice: advice
    };
  }

  function buildAdvice(level, ids, channel) {
    var advice = [];

    if (level === "high") {
      advice.push("This has strong signs of a scam. Do not respond, click, call, or send anything.");
    } else if (level === "caution") {
      advice.push("Some warning signs are present. Slow down and verify before you act.");
    } else {
      advice.push("No strong scam signals found — but stay alert, especially with anything about money or accounts.");
    }

    if (ids.indexOf("credentials") !== -1) {
      advice.push("Never share passwords, PINs, or one-time codes. No real company will ask for them.");
    }
    if (ids.indexOf("payment") !== -1) {
      advice.push("Do not send money, gift cards, or crypto. These payments can't be reversed.");
    }
    if (ids.indexOf("link") !== -1 || ids.indexOf("suspicious-link") !== -1) {
      advice.push("Don't use the link provided. Go to the official site or app directly instead.");
    }
    if (ids.indexOf("impersonation") !== -1 || ids.indexOf("threat") !== -1) {
      advice.push("Verify by contacting the organization on a number you look up yourself — not one from the message.");
    }
    if (ids.indexOf("secrecy") !== -1) {
      advice.push("Ignore any request for secrecy. Tell someone you trust what's happening.");
    }

    advice.push(CHANNEL_ADVICE[channel] || CHANNEL_ADVICE.other);
    return advice;
  }

  var api = { analyze: analyze, RULES: RULES };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    global.PauseFirst = api;
  }
})(typeof window !== "undefined" ? window : this);
