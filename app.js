/* PauseFirst UI glue. Wires the form to the detector and renders results. */
(function () {
  "use strict";

  var msg = document.getElementById("msg");
  var channel = document.getElementById("channel");
  var checkBtn = document.getElementById("checkBtn");
  var clearBtn = document.getElementById("clearBtn");
  var result = document.getElementById("result");
  var exampleButtons = document.getElementById("exampleButtons");

  var EXAMPLES = [
    {
      name: "Bank 'suspension' text",
      channel: "text",
      text: "URGENT: Your bank account has been suspended due to unusual activity. Verify immediately at http://secure-bank-verify.top/login or your account will be permanently closed. Confirm your password and the code we just texted you."
    },
    {
      name: "Gift card boss scam",
      channel: "email",
      text: "Hi, I'm in a meeting and can't talk. I need you to buy 5 Apple gift cards ($100 each) for a client gift right now. Keep this between us, I'll reimburse you later. Send me the codes ASAP."
    },
    {
      name: "Package redelivery",
      channel: "text",
      text: "USPS: Your package could not be delivered due to an incomplete address. Please update within 12 hours: bit.ly/usps-redeliver"
    },
    {
      name: "Normal reminder",
      channel: "email",
      text: "Hi Sam, just confirming our coffee catch-up on Thursday at 10am at the usual place. Let me know if that still works for you!"
    }
  ];

  function renderExamples() {
    EXAMPLES.forEach(function (ex) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ghost small";
      b.textContent = ex.name;
      b.addEventListener("click", function () {
        msg.value = ex.text;
        channel.value = ex.channel;
        run();
        msg.focus();
      });
      exampleButtons.appendChild(b);
    });
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  var LEVEL_META = {
    high: { title: "Stop — likely a scam", cls: "level-high", icon: "⛔" },
    caution: { title: "Pause — be careful", cls: "level-caution", icon: "⚠️" },
    low: { title: "Low risk — stay alert", cls: "level-low", icon: "✅" }
  };

  function render(report) {
    var meta = LEVEL_META[report.level];

    var html = "";
    html += '<div class="verdict ' + meta.cls + '">';
    html += '  <div class="verdict-head">';
    html += '    <span class="verdict-icon" aria-hidden="true">' + meta.icon + "</span>";
    html += '    <div>';
    html += "      <h2>" + esc(meta.title) + "</h2>";
    html += '      <p class="score">Risk score: <strong>' + report.score + "/100</strong></p>";
    html += "    </div>";
    html += "  </div>";
    html += '  <div class="meter" role="img" aria-label="Risk ' + report.score + ' out of 100">';
    html += '    <span class="meter-fill" style="width:' + report.score + '%"></span>';
    html += "  </div>";
    html += "</div>";

    if (report.signals.length) {
      html += '<div class="signals">';
      html += "<h3>What stood out</h3><ul>";
      report.signals.forEach(function (s) {
        html += "<li><strong>" + esc(s.label) + "</strong><span>" + esc(s.detail) + "</span></li>";
      });
      html += "</ul></div>";
    } else {
      html += '<div class="signals"><p>No common scam patterns were detected in the text.</p></div>';
    }

    html += '<div class="advice"><h3>What to do</h3><ul>';
    report.advice.forEach(function (a) {
      html += "<li>" + esc(a) + "</li>";
    });
    html += "</ul></div>";

    result.className = "result " + meta.cls;
    result.innerHTML = html;
    result.hidden = false;
  }

  function run() {
    var text = msg.value.trim();
    if (!text) {
      result.className = "result";
      result.innerHTML = '<p class="empty">Paste a message above, then press <strong>Check it</strong>.</p>';
      result.hidden = false;
      return;
    }
    var report = window.PauseFirst.analyze(text, channel.value);
    render(report);
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  checkBtn.addEventListener("click", run);
  clearBtn.addEventListener("click", function () {
    msg.value = "";
    result.hidden = true;
    result.innerHTML = "";
    msg.focus();
  });

  // Ctrl/Cmd+Enter to check.
  msg.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      run();
    }
  });

  renderExamples();
})();
