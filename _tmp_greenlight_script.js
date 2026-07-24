
              (function () {
                const statusEl = document.getElementById("genesys-bulk-history-status");
                const tableEl = document.getElementById("genesys-bulk-history-table");
                const refreshBtn = document.getElementById("genesys-bulk-history-refresh-btn");

                if (!statusEl || !tableEl) {
                  return;
                }

                function esc(value) {
                  return String(value || "")
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/\"/g, "&quot;")
                    .replace(/'/g, "&#39;");
                }

                async function loadHistory() {
                  statusEl.textContent = "Loading latest batch logs...";
                  tableEl.innerHTML = "";
                  try {
                    const response = await fetch("/genesys/users/batch-history?limit=20", {
                      method: "GET",
                      headers: { "Accept": "application/json" },
                    });

                    const contentType = String(response.headers.get("content-type") || "").toLowerCase();
                    const bodyText = await response.text();
                    let payload = {};
                    if (contentType.indexOf("application/json") >= 0) {
                      try {
                        payload = JSON.parse(bodyText || "{}");
                      } catch (_jsonErr) {
                        payload = { ok: false, error: "Invalid JSON from batch history endpoint." };
                      }
                    } else {
                      payload = {
                        ok: false,
                        error: bodyText && bodyText.indexOf("Authentication required") >= 0
                          ? "Session expired. Please log in again."
                          : "Non-JSON response from batch history endpoint.",
                      };
                    }

                    if (!response.ok || !payload.ok) {
                      throw new Error((payload && payload.error) || ("HTTP " + response.status));
                    }

                    const rows = Array.isArray(payload.rows) ? payload.rows : [];
                    if (!rows.length) {
                      statusEl.textContent = "No batch logs yet.";
                      return;
                    }

                    statusEl.textContent = "Showing " + rows.length + " most recent batch log(s).";
                    let html = "<table><thead><tr>";
                    html += "<th>Timestamp</th><th>Status</th><th>Requested</th><th>Processed</th><th>Failed</th><th>Duration(s)</th><th>Original Input</th><th>Failed Rerun</th>";
                    html += "</tr></thead><tbody>";

                    rows.forEach(function (row, i) {
                      const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                      const originalUrl = esc(String((row && row.original_download_url) || ""));
                      const failedUrl = esc(String((row && row.failed_download_url) || ""));
                      html += "<tr style='background:" + bg + ";'>";
                      html += "<td>" + esc(String((row && row.timestamp) || "")) + "</td>";
                      html += "<td>" + esc(String((row && row.status) || "")) + "</td>";
                      html += "<td>" + esc(String((row && row.requested) || "0")) + "</td>";
                      html += "<td>" + esc(String((row && row.success_count) || "0")) + "</td>";
                      html += "<td>" + esc(String((row && row.failure_count) || "0")) + "</td>";
                      html += "<td>" + esc(String((row && row.duration_seconds) || "0")) + "</td>";
                      html += "<td>" + (originalUrl ? ("<a href='" + originalUrl + "'>Download</a>") : "-") + "</td>";
                      html += "<td>" + (failedUrl ? ("<a href='" + failedUrl + "'>Download</a>") : "-") + "</td>";
                      html += "</tr>";
                    });

                    html += "</tbody></table>";
                    tableEl.innerHTML = html;
                  } catch (err) {
                    statusEl.textContent = "Bulk log load failed: " + ((err && err.message) || "Unknown error.");
                  }
                }

                if (refreshBtn) {
                  refreshBtn.addEventListener("click", function () {
                    loadHistory();
                  });
                }

                loadHistory();
              })();
            
