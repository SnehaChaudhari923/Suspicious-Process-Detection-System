import psutil
import datetime


# suspicious keywords often used in malware
suspicious_keywords = [
    "crypto",
    "miner",
    "hack",
    "trojan",
    "malware",
    "rat",
    "keylog"
]


def calculate_risk(name, cpu, memory):

    risk = 0

    if cpu > 50:
        risk += 40

    if memory > 10:
        risk += 30

    for word in suspicious_keywords:
        if word in name.lower():
            risk += 30
            break

    return risk


def get_processes():

    processes = []

    for proc in psutil.process_iter(['pid','name','cpu_percent','memory_percent']):
        try:

            info = proc.info

            name = info['name']
            cpu = info['cpu_percent']
            memory = round(info['memory_percent'],2)

            risk = calculate_risk(name, cpu, memory)

            suspicious = False

            if risk >= 50:
                suspicious = True

            processes.append({
                "pid": info['pid'],
                "name": name,
                "cpu": cpu,
                "memory": memory,
                "risk": risk,
                "suspicious": suspicious
            })

        except:
            pass

    return processes


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