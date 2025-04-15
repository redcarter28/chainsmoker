import dash
from dash import dcc, html
import plotly.express as px
import pandas as pd

# Sample data
data = [
    {
        "date_time_local": "07/25/2024, 0721",
        "mitre_tactic": "C2",
        "source_ip": "172.25.200.132",
        "target_ip": "172.25.17.146",
        "details": "User packer created a schtask that references firefox install.ps1 that beacons out to 172.25.17.146",
        "notes": "PSEXEC file name is ADMIN$\\198c70.exe",
        "operator": "davidson",
        "attack_chain": 1
    },
    {
        "date_time_local": "08/09/2024, 0723",
        "mitre_tactic": "Execution",
        "source_ip": "n/a",
        "target_ip": "W10A.ansible.ctf",
        "details": "User /not 092pct7 ran a powershell command that was Mozillainstall.ps1",
        "notes": "",
        "operator": "davidson",
        "attack_chain": 2
    },
    {
        "date_time_local": "08/12/2024, 1439",
        "mitre_tactic": "C2",
        "source_ip": "n/a",
        "target_ip": "W10E.ansible.ctf",
        "details": "A named pipe appears to be cobalt strike on W10E.ansible.ctf",
        "notes": "",
        "operator": "feng",
        "attack_chain": 2
    },
    {
        "date_time_local": "07/23/2024, 1404",
        "mitre_tactic": "Execution",
        "source_ip": "W10A.ansible.ctf",
        "target_ip": "172.25.17.146",
        "details": "W10A.ansible.ctf reaches out to 172.25.17.146 to download Mozillainstall.ps1",
        "notes": "",
        "operator": "molina",
        "attack_chain": 1
    },
    {
        "date_time_local": "07/23/2024, 1541",
        "mitre_tactic": "Execution",
        "source_ip": "W10C.ansible.ctf",
        "target_ip": "172.25.17.146",
        "details": "W10C.ansible.ctf reaches out to 172.25.17.146 to download FirefoxInstall.ps1 and Taskings.ps1",
        "notes": "",
        "operator": "molina",
        "attack_chain": 1
    },
    {
        "date_time_local": "08/09/2024, 0721",
        "mitre_tactic": "Execution",
        "source_ip": "W10A.ansible.ctf",
        "target_ip": "172.25.17.146",
        "details": "W10A.ansible.ctf reaches out to 172.25.17.146 to download Cobalt Strike beacon",
        "notes": "",
        "operator": "molina",
        "attack_chain": 2
    },
    {
        "date_time_local": "08/12/2024, 1428",
        "mitre_tactic": "Lateral Movement",
        "source_ip": "W10A.ansible.ctf",
        "target_ip": "W10C.ansible.ctf",
        "details": "W10A.ansible.ctf laterally moves via PSEXEC to W10C.ansible.ctf",
        "notes": "PSEXEC file name is ADMIN$\\1696191.exe, PipeName: MSSE-4688-server",
        "operator": "marshall",
        "attack_chain": 2
    },
    {
        "date_time_local": "08/12/2024, 1428",
        "mitre_tactic": "Lateral Movement",
        "source_ip": "W10C.ansible.ctf",
        "target_ip": "W10A.ansible.ctf",
        "details": "W10C.ansible.ctf laterally moves via PSEXEC to W10A.ansible.ctf",
        "notes": "PSEXEC file name is ADMIN$\\198c70.exe",
        "operator": "marshall",
        "attack_chain": 1
    },
    {
        "date_time_local": "08/13/2024, 1055",
        "mitre_tactic": "Collection",
        "source_ip": "172.25.17.36",
        "target_ip": "172.25.17.151",
        "details": "user packer creds being send over cleartext from 172.25.200.131 (W10A.ansible.ctf) to 172.25.17.151",
        "notes": "authentication_token=lgPXD6T5yldF54q3jbxoopfVSh-Lk4yXjQl-T-bwhYvXgttTXpL_7peanLjFJ9_mUvnVbsufN1o-MVX73wOg&user%5Blogin%5D=packer&user%5Bpassword%5D=packer&user%5Bremember_me%5D=0",
        "operator": "molina",
        "attack_chain": 3
    },
    {
        "date_time_local": "08/12/2024, 1404",
        "mitre_tactic": "Discovery",
        "source_ip": "W10D.ansible.ctf",
        "target_ip": "172.25.17.36",
        "details": "W10D.ansible.ctf's file system is enumerated by 172.25.17.36",
        "notes": "Accessed C$ share",
        "operator": "molina",
        "attack_chain": 3
    }
]

# Convert to DataFrame
df = pd.DataFrame(data)

# Create a timeline figure
fig = px.timeline(
    df,
    x_start="date_time_local",
    x_end="date_time_local",
    y="mitre_tactic",
    hover_data=["details", "notes", "source_ip", "target_ip"],
    color="attack_chain",
    title="Attack Chain Timeline"
)

# Customize layout
fig.update_layout(
    xaxis_title="Time",
    yaxis_title="MITRE Tactic",
    template="plotly_dark"
)

# Initialize Dash app
app = dash.Dash(__name__)

# Define layout
app.layout = html.Div([
    dcc.Graph(figure=fig)
])

# Run app
if __name__ == '__main__':
    app.run(debug=True)