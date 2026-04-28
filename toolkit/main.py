from fastapi import FastAPI, Form, UploadFile, File
from fastapi.responses import HTMLResponse, Response

from toolkit.enduser import export_endusers_all_fields
from toolkit.directory_number import export_directory_numbers
from toolkit.add_directory_number import add_directory_numbers_from_csv

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
      <input name="cucm_host" value="lascucmpp01.ahs.int"><br><br>

      CUCM Username:<br>
      <input name="cucm_user"><br><br>

      CUCM Password:<br>
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
      <input name="cucm_host" value="lascucmpp01.ahs.int"><br><br>

      CUCM Username:<br>
      <input name="cucm_user"><br><br>

      CUCM Password:<br>
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
      <input name="cucm_host" value="lascucmpp01.ahs.int"><br><br>

      CUCM Username:<br>
      <input name="cucm_user"><br><br>

      CUCM Password:<br>
      <input type="password" name="cucm_pass"><br><br>

      Last Name:<br>
      <input name="lastname"><br><br>

      <button type="submit">Export End Users</button>
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
