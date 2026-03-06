from flask import Flask, render_template, send_file
import psutil
import datetime
import pandas as pd

app = Flask(__name__)

# -----------------------------
# Get Running Processes
# -----------------------------
def get_processes():

    processes = []
    suspicious_processes = []
    suspicious_count = 0

    for proc in psutil.process_iter(['pid','name','cpu_percent','memory_percent']):

        try:
            info = proc.info

            suspicious = False

            if info['cpu_percent'] > 50 or info['memory_percent'] > 10:
                suspicious = True
                suspicious_count += 1

            process_data = {
                "pid": info['pid'],
                "name": info['name'],
                "cpu": info['cpu_percent'],
                "memory": round(info['memory_percent'],2),
                "suspicious": suspicious
            }

            processes.append(process_data)

            if suspicious:
                suspicious_processes.append(process_data)

        except:
            pass

    return processes, suspicious_processes, suspicious_count


# -----------------------------
# Active Network Connections
# -----------------------------
def get_connections():

    connections = []

    for conn in psutil.net_connections():

        try:
            if conn.laddr:

                connections.append({
                    "pid": conn.pid,
                    "local": str(conn.laddr),
                    "remote": str(conn.raddr) if conn.raddr else "N/A",
                    "status": conn.status
                })

        except:
            pass

    return connections


# -----------------------------
# Logged in Users
# -----------------------------
def get_users():

    users = []

    for user in psutil.users():

        users.append({
            "name": user.name,
            "terminal": user.terminal,
            "host": user.host,
            "started": datetime.datetime.fromtimestamp(user.started).strftime("%Y-%m-%d %H:%M:%S")
        })

    return users


# -----------------------------
# Download Report
# -----------------------------
@app.route("/download")
def download_report():

    processes, _, _ = get_processes()

    df = pd.DataFrame(processes)

    file = "forensics_report.csv"

    df.to_csv(file,index=False)

    return send_file(file,as_attachment=True)


# -----------------------------
# Dashboard
# -----------------------------
@app.route("/")
def home():

    processes, suspicious_processes, suspicious_count = get_processes()
    connections = get_connections()
    users = get_users()

    return render_template(
        "dashboard.html",
        processes=processes,
        suspicious_processes=suspicious_processes,
        suspicious_count=suspicious_count,
        connections=connections,
        users=users
    )


if __name__ == "__main__":
    app.run(debug=True)