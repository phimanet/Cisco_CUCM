from fastapi import FastAPI, Form, UploadFile, File
from fastapi.responses import HTMLResponse, Response

from toolkit.enduser import export_endusers_all_fields
from toolkit.directory_number import export_directory_numbers
from toolkit.add_directory_number import add_directory_numbers_from_csv
from toolkit.build_user_csf_phone import build_user_csf_phone_from_template

app = FastAPI(title="Cisco Voice Server Automation Site - Restricted Access")


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
      This site is the centralized portal for Cisco Voice administration tasks,
      including user CSF build automation, directory number exports, end-user exports,
      and bulk directory number creation.
    </p>
    <p>
      Use the administration tools page to run CUCM automation workflows.
    </p>
    <p>
      <a href="/admin" style="color:#7ec8ff; font-weight:bold;">Open Administration Tools</a>
    </p>
    <p>
      <a href="/pre-landing" style="color:#ffd27e; font-weight:bold;">Open Pre-Landing Page (Legacy)</a>
    </p>
  </body>
</html>
"""


@app.get("/pre-landing", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return """
<html>
  <head>
    <title>Pre-Landing Page - Cisco Voice Administration Tools</title>
  </head>
  <body style="font-family: Arial; margin:40px; background-color:#000; color:#fff;">
    <h2>Pre-Landing Page - Cisco Voice Administration Tools</h2>
    <p><a href="/" style="color:#7ec8ff;">Back to Landing Page</a></p>

    <h3>Shared CUCM Authentication</h3>

    <label for="shared_cucm_host">Cisco Callmanager Environment:</label><br>
    <select id="shared_cucm_host">
      <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
      <option value="lascucmpl01.ahs.int">LAB CUCM</option>
    </select><br><br>

    <label for="shared_cucm_user">Cisco Callmanager Username:</label><br>
    <input id="shared_cucm_user" autocomplete="username"><br><br>

    <label for="shared_cucm_pass">Cisco Callmanager Password:</label><br>
    <input id="shared_cucm_pass" type="password" autocomplete="current-password"><br><br>

    <hr>

    <h3>Build User CSF Phone From Template</h3>

    <form action="/build/user-csf-phone" method="post" class="cucm-action-form">
      <input type="hidden" name="cucm_host" class="shared-cucm-host">
      <input type="hidden" name="cucm_user" class="shared-cucm-user">
      <input type="hidden" name="cucm_pass" class="shared-cucm-pass">

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

    <hr>

    <h3>Add Directory Numbers (Upload CSV)</h3>

    <form action="/add/directorynumbers" method="post" enctype="multipart/form-data" class="cucm-action-form">
      <input type="hidden" name="cucm_host" class="shared-cucm-host">
      <input type="hidden" name="cucm_user" class="shared-cucm-user">
      <input type="hidden" name="cucm_pass" class="shared-cucm-pass">

      CSV File:<br>
      <input type="file" name="csv_file" required><br><br>

      <a href="/download/add-directorynumbers-template">Download CSV Template</a><br><br>

      <button type="submit">Run Add Directory Numbers</button>
    </form>

    <hr>

    <h3>Export Directory Numbers</h3>

    <form action="/export/directorynumbers" method="post" class="cucm-action-form">
      <input type="hidden" name="cucm_host" class="shared-cucm-host">
      <input type="hidden" name="cucm_user" class="shared-cucm-user">
      <input type="hidden" name="cucm_pass" class="shared-cucm-pass">

      DN Pattern (supports %):<br>
      <input name="dn_contains"><br><br>

      Route Partition (optional):<br>
      <input name="route_partition"><br><br>

      <button type="submit">Export Directory Numbers</button>
    </form>

    <hr>

    <h3>Export End Users</h3>

    <form action="/export/endusers" method="post" class="cucm-action-form">
      <input type="hidden" name="cucm_host" class="shared-cucm-host">
      <input type="hidden" name="cucm_user" class="shared-cucm-user">
      <input type="hidden" name="cucm_pass" class="shared-cucm-pass">

      Last Name:<br>
      <input name="lastname"><br><br>

      <button type="submit">Export End Users</button>
    </form>

    <script>
      const sharedHost = document.getElementById("shared_cucm_host");
      const sharedUser = document.getElementById("shared_cucm_user");
      const sharedPass = document.getElementById("shared_cucm_pass");

      document.querySelectorAll(".cucm-action-form").forEach((form) => {
        form.addEventListener("submit", (event) => {
          if (!sharedUser.value || !sharedPass.value) {
            event.preventDefault();
            alert("Enter shared Cisco Callmanager username and password first.");
            return;
          }

          form.querySelector(".shared-cucm-host").value = sharedHost.value;
          form.querySelector(".shared-cucm-user").value = sharedUser.value;
          form.querySelector(".shared-cucm-pass").value = sharedPass.value;
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
    return Response(
        log_csv,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


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
    return Response(
        data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


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
    return Response(
        data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.post("/build/user-csf-phone")
async def build_user_csf_phone(
    cucm_host: str = Form(...),
    cucm_user: str = Form(...),
    cucm_pass: str = Form(...),
    target_user: str = Form(...),
  dn_type: str = Form("general")
):
    data, filename = build_user_csf_phone_from_template(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
        dn_type=dn_type,
    )
    return Response(
        data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
