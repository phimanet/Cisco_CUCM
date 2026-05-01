from fastapi import FastAPI, Form, UploadFile, File, Query
from fastapi.responses import HTMLResponse, Response, JSONResponse
from html import escape
from uuid import uuid4

from toolkit.enduser import export_endusers_all_fields
from toolkit.directory_number import export_directory_numbers
from toolkit.add_directory_number import add_directory_numbers_from_csv
from toolkit.build_user_csf_phone import build_user_csf_phone_from_template
from toolkit.decommission_user_csf_voicemail import decommission_user_csf_voicemail
from toolkit.add_secondary_devices import (
  add_secondary_tct_device,
  add_secondary_bot_device,
  add_secondary_strike_devices,
)

app = FastAPI(title="Cisco Voice Server Automation Site - Restricted Access")
JOB_OUTPUTS = {}


def _to_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    return str(data).encode("utf-8")


def _store_job_output(csv_data: bytes, filename: str) -> str:
    job_id = str(uuid4())
    JOB_OUTPUTS[job_id] = {"data": csv_data, "filename": filename}

    # Keep an in-memory cap so older outputs naturally roll off.
    if len(JOB_OUTPUTS) > 100:
        oldest_key = next(iter(JOB_OUTPUTS))
        JOB_OUTPUTS.pop(oldest_key, None)

    return job_id


def _prepare_job_output(csv_data, filename: str) -> dict:
    csv_bytes = _to_bytes(csv_data)
    job_id = _store_job_output(csv_bytes, filename)
    return {
        "job_id": job_id,
        "filename": filename,
        "output_text": csv_bytes.decode("utf-8", errors="replace"),
    }


def _render_job_result(title: str, csv_data, filename: str) -> HTMLResponse:
    job_output = _prepare_job_output(csv_data, filename)
    job_id = job_output["job_id"]
    output_text = escape(job_output["output_text"])

    html = f"""
<html>
  <head>
    <title>{escape(title)} - Job Output</title>
  </head>
  <body style="font-family: Arial; margin:40px; background-color:#000; color:#fff;">
    <h2>{escape(title)} - Job Output</h2>
    <p><a href="/menu" style="color:#7ec8ff;">Back to Menu</a></p>
    <p>
      <a href="/download/job-output/{job_id}" style="color:#7ec8ff; font-weight:bold;">
        Download CSV Output
      </a>
    </p>
    <p>Output Preview:</p>
    <textarea readonly style="width:100%; height:420px; font-family: Consolas, monospace;">{output_text}</textarea>
  </body>
</html>
"""
    return HTMLResponse(html)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
<html>
  <head>
    <title>Cisco Voice Administration Page</title>
  </head>
  <body style="font-family: Arial; margin:40px; background-color:#000; color:#fff;">
    <h1>Cisco Voice Administration Page</h1>
    <p>
      Welcome to the Cisco Voice administration portal.
      Use this site to run common CUCM automation and reporting tasks.
    </p>
    <p>
      <a href="/menu" style="color:#7ec8ff; font-weight:bold;">Go to Menu Options</a>
    </p>
  </body>
</html>
"""


@app.get("/menu", response_class=HTMLResponse)
def menu_page():
    return """
<html>
  <head>
    <title>Cisco Voice Server Automation Site - Restricted Access</title>
    <style>
      .build-user-layout {
        display: flex;
        gap: 24px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .build-user-form {
        flex: 1 1 420px;
        min-width: 320px;
      }

      .build-user-output {
        flex: 1 1 480px;
        min-width: 320px;
        border: 1px solid #333;
        background: #0f0f0f;
        padding: 12px;
      }

      .build-user-output h4 {
        margin: 0 0 10px 0;
      }

      .build-user-output textarea {
        width: 100%;
        height: 380px;
        font-family: Consolas, monospace;
        background: #000;
        color: #fff;
        border: 1px solid #2f2f2f;
      }

      .build-user-status {
        color: #b0dfff;
        min-height: 18px;
      }

      .offboard-layout {
        display: flex;
        gap: 24px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .offboard-form {
        flex: 1 1 420px;
        min-width: 320px;
      }

      .offboard-output {
        flex: 1 1 480px;
        min-width: 320px;
        border: 1px solid #333;
        background: #0f0f0f;
        padding: 12px;
      }

      .offboard-output h4 {
        margin: 0 0 10px 0;
      }

      .offboard-output textarea {
        width: 100%;
        height: 380px;
        font-family: Consolas, monospace;
        background: #000;
        color: #fff;
        border: 1px solid #2f2f2f;
      }

      .offboard-status {
        color: #b0dfff;
        min-height: 18px;
      }

      @media (max-width: 980px) {
        .build-user-output textarea {
          height: 280px;
        }
      }
    </style>
  </head>
  <body style="font-family: Arial; margin:40px; background-color:#000; color:#fff;">
    <h2>Cisco Voice Server Automation Site - Restricted Access</h2>
    <p><a href="/" style="color:#7ec8ff;">Back to Landing Page</a></p>

    <h3>Build User CSF Phone From Template</h3>

    <div class="build-user-layout">
      <form id="build-user-form" class="target-user-form build-user-form" action="/build/user-csf-phone" method="post">
        Cisco Callmanager Envronment:<br>
        <select name="cucm_host">
          <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
          <option value="lascucmpl01.ahs.int">LAB CUCM</option>
        </select><br><br>

        Cisco Callmanager Username:<br>
        <input name="cucm_user"><br><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass"><br><br>

        User ID for person to Build Jabber for:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        DN Type:<br>
        <select name="dn_type">
          <option value="recruiter">Recruiter (469)</option>
          <option value="general" selected>General FTE (214)</option>
          <option value="strike">Strike (945)</option>
        </select><br><br>

        <button type="submit">Run Build User CSF Phone</button>
      </form>

      <section class="build-user-output" aria-live="polite">
        <h4>Build User Output Preview</h4>
        <p id="build-user-status" class="build-user-status">Run Build User to view output here.</p>
        <p>
          <a id="build-user-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="build-user-preview" readonly></textarea>
      </section>
    </div>

    <hr>

    <h3>Offboard User - Delete all Jabber (Option 10)</h3>

    <div class="offboard-layout">
      <form id="offboard-user-form" class="target-user-form offboard-form" action="/decommission/user-csf-voicemail" method="post">
        Cisco Callmanager Envronment:<br>
        <select name="cucm_host">
          <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
          <option value="lascucmpl01.ahs.int">LAB CUCM</option>
        </select><br><br>

        Cisco Callmanager Username:<br>
        <input name="cucm_user"><br><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass"><br><br>

        User ID for person to Offboard:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <button type="submit">Run Offboard User - Delete all Jabber (Option 10)</button>
      </form>

      <section class="offboard-output" aria-live="polite">
        <h4>Offboard Output Preview</h4>
        <p id="offboard-status" class="offboard-status">Run Offboard User to view output here.</p>
        <p>
          <a id="offboard-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="offboard-preview" readonly></textarea>
      </section>
    </div>

    <hr>

    <h3>Add Secondary Device - Jabber for iPhone (Option 3)</h3>

    <form class="target-user-form" action="/add/secondary-tct-device" method="post">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      User ID for person to add secondary iPhone device for:<br>
      <input name="target_user" placeholder="john.doe" required><br><br>

      <button type="submit">Run Add Secondary Device - Jabber for iPhone (Option 3)</button>
    </form>

    <hr>

    <h3>Add Secondary Device - Jabber for Android (Option 4)</h3>

    <form class="target-user-form" action="/add/secondary-bot-device" method="post">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      User ID for person to add secondary Android device for:<br>
      <input name="target_user" placeholder="john.doe" required><br><br>

      <button type="submit">Run Add Secondary Device - Jabber for Android (Option 4)</button>
    </form>

    <hr>

    <h3>STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)</h3>

    <form class="target-user-form" action="/add/secondary-strike-devices" method="post">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      User ID for person to add STRIKE MODE devices for:<br>
      <input name="target_user" placeholder="john.doe" required><br><br>

      <button type="submit">Run STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)</button>
    </form>

    <hr>

    <h3>Add Directory Numbers (Upload CSV)</h3>

    <form action="/add/directorynumbers" method="post" enctype="multipart/form-data">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      CSV File:<br>
      <input type="file" name="csv_file" required><br><br>

      <a href="/download/add-directorynumbers-template">Download CSV Template</a><br><br>

      <button type="submit">Run Add Directory Numbers</button>
    </form>

    <hr>

    <h3>Export Directory Numbers</h3>

    <form action="/export/directorynumbers" method="post">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      DN Pattern (supports %):<br>
      <input name="dn_contains"><br><br>

      Route Partition (optional):<br>
      <input name="route_partition"><br><br>

      <button type="submit">Export Directory Numbers</button>
    </form>

    <hr>

    <h3>Export End Users</h3>

    <form action="/export/endusers" method="post">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      Last Name:<br>
      <input name="lastname"><br><br>

      <button type="submit">Export End Users</button>
    </form>

    <script>
      const fieldRules = {
        cucm_user: {
          required: true,
          requiredMessage: "Cisco Callmanager Username is required.",
        },
        cucm_pass: {
          required: true,
          requiredMessage: "Cisco Callmanager Password is required.",
        },
        target_user: {
          required: true,
          requiredMessage: "User ID is required.",
          pattern: /^[A-Za-z0-9._-]+$/,
          patternMessage: "User ID can only contain letters, numbers, dot, underscore, or hyphen.",
        },
        dn_contains: {
          required: true,
          requiredMessage: "DN Pattern is required.",
        },
        lastname: {
          required: true,
          requiredMessage: "Last Name is required.",
        },
      };

      function clearFieldError(field) {
        const errorEl = field.nextElementSibling;
        if (errorEl && errorEl.classList.contains("field-error")) {
          errorEl.remove();
        }
        field.style.borderColor = "";
      }

      function addFieldError(field, message) {
        clearFieldError(field);
        const errorEl = document.createElement("div");
        errorEl.className = "field-error";
        errorEl.style.color = "#ff8a8a";
        errorEl.style.fontSize = "12px";
        errorEl.style.marginTop = "4px";
        errorEl.textContent = message;
        field.style.borderColor = "#ff6b6b";
        field.insertAdjacentElement("afterend", errorEl);
      }

      function validateForm(form) {
        let firstInvalid = null;
        let hasErrors = false;

        Object.entries(fieldRules).forEach(([fieldName, rule]) => {
          const field = form.querySelector(`[name="${fieldName}"]`);
          if (!field) {
            return;
          }

          const value = (field.value || "").trim();
          clearFieldError(field);

          if (rule.required && !value) {
            addFieldError(field, rule.requiredMessage);
            hasErrors = true;
            if (!firstInvalid) {
              firstInvalid = field;
            }
            return;
          }

          if (rule.pattern && value && !rule.pattern.test(value)) {
            addFieldError(field, rule.patternMessage);
            hasErrors = true;
            if (!firstInvalid) {
              firstInvalid = field;
            }
          }
        });

        if (firstInvalid) {
          firstInvalid.focus();
        }

        return !hasErrors;
      }

      async function submitBuildUserInline(form) {
        const statusEl = document.getElementById("build-user-status");
        const outputEl = document.getElementById("build-user-preview");
        const downloadEl = document.getElementById("build-user-download");

        statusEl.textContent = "Running Build User...";
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || "build_user_output.csv"}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          const targetUserInput = form.querySelector('input[name="target_user"]');
          if (targetUserInput) {
            targetUserInput.value = "";
          }
        } catch (error) {
          statusEl.textContent = "Build User failed. Review output and retry.";
          outputEl.value = error.message || "Unknown error.";
        }
      }

      async function submitOffboardInline(form) {
        const statusEl = document.getElementById("offboard-status");
        const outputEl = document.getElementById("offboard-preview");
        const downloadEl = document.getElementById("offboard-download");

        statusEl.textContent = "Running Offboard User...";
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || "offboard_output.csv"}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          const targetUserInput = form.querySelector('input[name="target_user"]');
          if (targetUserInput) {
            targetUserInput.value = "";
          }
        } catch (error) {
          statusEl.textContent = "Offboard User failed. Review output and retry.";
          outputEl.value = error.message || "Unknown error.";
        }
      }

      document.querySelectorAll("form").forEach((form) => {
        form.querySelectorAll("input").forEach((field) => {
          field.addEventListener("input", () => clearFieldError(field));
        });

        form.addEventListener("submit", (event) => {
          if (!validateForm(form)) {
            event.preventDefault();
            return;
          }

          if (form.id === "build-user-form") {
            event.preventDefault();
            submitBuildUserInline(form);
            return;
          }

          if (form.id === "offboard-user-form") {
            event.preventDefault();
            submitOffboardInline(form);
            return;
          }

          const targetUserInput = form.querySelector('input[name="target_user"]');
          if (targetUserInput) {
            setTimeout(() => {
              targetUserInput.value = "";
            }, 0);
          }
        });
      });
    </script>
  </body>
</html>
"""


@app.get("/download/add-directorynumbers-template")
def download_add_directorynumbers_template():
  template_csv = "pattern\n5551001\n5551002\n"
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="add_directory_numbers_template.csv"'}
  )


@app.get("/download/job-output/{job_id}")
def download_job_output(job_id: str):
  job_output = JOB_OUTPUTS.get(job_id)
  if not job_output:
    return Response("Job output not found.", media_type="text/plain", status_code=404)

  return Response(
    job_output["data"],
    media_type="text/csv",
    headers={"Content-Disposition": f'attachment; filename="{job_output["filename"]}"'}
  )
    

@app.post("/add/directorynumbers")
async def add_directorynumbers(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    csv_file: UploadFile = File(...)
):
    csv_bytes = await csv_file.read()
    log_csv, filename = add_directory_numbers_from_csv(
        cucm_host, cucm_user, cucm_pass, csv_bytes, {}
    )
    return _render_job_result("Add Directory Numbers", log_csv, filename)


@app.post("/export/directorynumbers")
def export_directorynumbers(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    dn_contains: str = Form(...),
    route_partition: str = Form("")
):
    data, filename = export_directory_numbers(
        cucm_host, cucm_user, cucm_pass, dn_contains, route_partition
    )
    return _render_job_result("Export Directory Numbers", data, filename)


@app.post("/export/endusers")
def export_endusers(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    lastname: str = Form(...)
):
    data, filename = export_endusers_all_fields(
        cucm_host, cucm_user, cucm_pass, lastname
    )
    return _render_job_result("Export End Users", data, filename)


@app.post("/build/user-csf-phone")
async def build_user_csf_phone(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    target_user: str = Form(...),
    dn_type: str = Form("general"),
    inline: bool = Query(False),
):
    data, filename = build_user_csf_phone_from_template(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
        dn_type=dn_type,
    )

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("Build User CSF Phone", data, filename)


@app.post("/decommission/user-csf-voicemail")
def decommission_user_csf_voicemail_route(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    target_user: str = Form(...),
    inline: bool = Query(False),
):
    data, filename = decommission_user_csf_voicemail(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("Offboard User - Delete all Jabber (Option 10)", data, filename)


@app.post("/add/secondary-tct-device")
def add_secondary_tct_device_route(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    target_user: str = Form(...),
):
    data, filename = add_secondary_tct_device(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    return _render_job_result("Add Secondary Device - Jabber for iPhone (Option 3)", data, filename)


@app.post("/add/secondary-bot-device")
def add_secondary_bot_device_route(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    target_user: str = Form(...),
):
    data, filename = add_secondary_bot_device(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    return _render_job_result("Add Secondary Device - Jabber for Android (Option 4)", data, filename)


@app.post("/add/secondary-strike-devices")
def add_secondary_strike_devices_route(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    target_user: str = Form(...),
):
    data, filename = add_secondary_strike_devices(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    return _render_job_result("STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)", data, filename)
