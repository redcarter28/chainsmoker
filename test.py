import plotly.express as px
import pandas as pd
import numpy as np

# Sample events data
events = [
    {"IP Address": "192.168.1.1", "Action": "Initial Access", "Start": "2024-07-01 00:05:00", "End": "2024-07-01 00:05:01"},
    {"IP Address": "192.168.1.1", "Action": "Execution", "Start": "2024-07-01 01:15:00", "End": "2024-07-01 01:15:01"},
    {"IP Address": "192.168.1.2", "Action": "Persistence", "Start": "2024-07-01 02:30:00", "End": "2024-07-01 02:35:00"},
    {"IP Address": "192.168.1.3", "Action": "Privilege Escalation", "Start": "2024-07-01 03:45:00", "End": "2024-07-01 03:45:01"},
    {"IP Address": "192.168.1.1", "Action": "Credential Access", "Start": "2024-07-01 04:00:00", "End": "2024-07-01 04:00:01"},
    {"IP Address": "192.168.1.2", "Action": "Discovery", "Start": "2024-07-01 05:30:00", "End": "2024-07-01 05:30:01"}
]

# Convert to DataFrame
df = pd.DataFrame(events)
df['Start'] = pd.to_datetime(df['Start'])
df['End'] = pd.to_datetime(df['End'])

# Calculate duration of each event
df['Duration'] = (df['End'] - df['Start']).dt.total_seconds()

# Set a minimum bar width and scale duration
min_barwidth = 180  # Minimum bar width for a short event (pixels)
max_barwidth = 960  # Maximum bar width for long events (pixels)

# Scale the duration to barwidth within limits
df['BarWidth'] = np.clip(df['Duration'] * 10, min_barwidth, max_barwidth)

# Create the Gantt chart using Plotly
fig = px.timeline(df, x_start="Start", x_end="End", y="IP Address", color="Action", 
                  labels={"IP Address": "Computer", "Action": "Action"}, 
                  title="Event Timeline")

# Update the layout to make sure the bar width is applied correctly
fig.update_traces(marker=dict(line=dict(width=0)))

# Adjust the bar width based on the calculated BarWidth
for i, event in df.iterrows():
    fig.data[0].marker.line.width = event['BarWidth']

fig.update_layout(bargap=0.2)

fig.show()
