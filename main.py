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
    <title>Cisco Voice Server Automation Site - Restricted Access</title>
  </head>
  <body style="font-family: Arial; margin:40px; background-color:#000; color:#fff;">
    <h2>Cisco Voice Server Automation Site - Restricted Access</h2>

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

    <hr>

    <h3>Build User CSF Phone From Template</h3>

    <form action="/build/user-csf-phone" method="post">
      Cisco Callmanager Envronment:<br>
      <select name="cucm_host">
        <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
        <option value="lascucmpl01.ahs.int">LAB CUCM</option>
      </select><br><br>

      Cisco Callmanager Username:<br>
      <input name="cucm_user"><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      Target User ID:<br>
      <input name="target_user" placeholder="john.doe" required><br><br>

      DN Type:<br>
      <select name="dn_type">
        <option value="recruiter">Recruiter (469)</option>
        <option value="general" selected>General FTE (214)</option>
        <option value="strike">Strike (945)</option>
      </select><br><br>

      Template:<br>
      <input value="phone_device_template_lab_csf.json (server default)" readonly><br><br>

      <button type="submit">Run Build User CSF Phone</button>
    </form>

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
