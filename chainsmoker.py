import dash
from dash import dcc, html, callback, Input, Output, State, dash_table
import json
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
from itertools import product
import hashlib
import os 

#html bootstrap
styles = {
    'pre': {
        'border': 'thin lightgrey solid',
        'overflowX': 'scroll'
    }
}



# Read data from Excel file using openpyxl
df = pd.read_excel('data/data2.xlsx', engine='openpyxl')

# Define a custom date parsing function to handle the specific format
def custom_date_parser(date_str):
    return pd.to_datetime(date_str, format='%m/%d/%Y, %H%M')


def expand_rows(row):
    sources = row['Source Hostname/IP'.split(',')]
    targets = row['Target Hostname/IP'.split(',')]
    return pd.DataFrame(list(product(sources,targets)), columns=['Source Hostname/IP', 'Target Hostname/IP'])

df_expanded = df.apply(expand_rows, axis=1).reset_index(drop=True)
df = df.sort_values(by='Date/Time local', ascending=False)

df['Date/Time MPNET'] = df['Date/Time MPNET'].apply(custom_date_parser)

df = df.sort_values(by='Date/Time MPNET', ascending=False)

df['Date/Time MPNET'] = df['Date/Time MPNET'].fillna('No Data')

#remove weird unnamed bug
df = df.loc[:, ~df.columns.str.contains('^Unnamed')]



#load json DB
if os.path.exists('db/node_data.json'):
    with open('db/node_data.json', 'r') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = {}
else:
    data = {}



app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

fig = go.Figure()

# Add Gantt chart style bars
""" for index, row in df.iterrows():
    fig.add_trace(go.Bar(
        x=[row['Date/Time MPNET'], row['Date/Time MPNET']],
        #y=[f"{row['Source Hostname/IP']} -> {row['Target Hostname/IP']}"],
        y=df['MITRE Tactic'],
        orientation='h',
        name=row['Source Hostname/IP'],
        hovertext=row['Details'],
        marker=dict(color='rgba(0, 0, 0, 0)')  # Transparent bar for Gantt effect
    )) """


""" # Add scatter points for each event
fig.add_trace(go.Scatter(
    x=df['Date/Time MPNET'].tolist() + [None],
    #y=[f"{source} -> {target}" for source, target in zip(df['Source Hostname/IP'], df['Target Hostname/IP'])],
    y=df['MITRE Tactic'].tolist() + [None],
    
    mode='lines+markers',
    marker=dict(
        size=12,
        color=list(range(10)), colorscale='sunset',
        line=dict(width=1, color='DarkSlateGrey')
    ),
    line=dict(color='grey', width=2),
    text=df['Details'],
    hoverinfo='text'
)) """

#draw lines 
for chain_id in df['Attack Chain'].dropna().unique():

    chain_df = df[df['Attack Chain'] == chain_id]

    fig.add_trace(go.Scatter(
        x=chain_df['Date/Time MPNET'].tolist() + [None],
        #y=[f"{source} -> {target}" for source, target in zip(df['Source Hostname/IP'], df['Target Hostname/IP'])],
        y=chain_df['MITRE Tactic'].tolist() + [None],
        
        mode='lines+markers',
        marker=dict(
            size=12,
            color=list(range(6)), colorscale='sunset',
            line=dict(width=1, color='DarkSlateGrey')
        ),
        line=dict(color='grey', width=2),
        text=chain_df['Details'],
        hoverinfo='text',
        showlegend=False
    ))


# Update layout for better display
fig.update_layout(
    title='Attack Chain Visualization',
    xaxis_title='Date/Time MPNET',
    yaxis_title='MITRE Tactic',
    barmode='overlay',
    xaxis=dict(type='date', gridcolor='rgba(255, 255, 255, 0.2)'),  # Light gridlines
    yaxis=dict(gridcolor='rgba(255, 255, 255, 0.2)'),
    plot_bgcolor='rgba(35, 35, 35, 1)',  # Dark background
    paper_bgcolor='rgba(35, 35, 35, 1)',  # Dark background
    font=dict(color='white'),  # White font for readability
    title_font=dict(color='white'),
    margin=dict(l=50, r=50, t=50, b=50),  # Add some padding around the chart
    hovermode='closest'
)

name_field = html.Div(
    [   
        dbc.Input(id='name-input', placeholder='Operator', style={'width': '100%'}),
    ],
    className='InputField',  # Use a consistent class name for styling
    style={'width': '20%'}  # Consistent styling for width and margin
)

mitre_drop = html.Div(
    dcc.Dropdown(
        options=[
            {'label': 'Initial Access', 'value': 'Initial Access'},
            {'label': 'Execution', 'value': 'Execution'},
            {'label': 'Persistence', 'value': 'Persistence'},
            {'label': 'Privilege Escalation', 'value': 'Privilege Escalation'},
            {'label': 'Defense Evasion', 'value': 'Defense Evasion'},
            {'label': 'Credential Access', 'value': 'Credential Access'},
            {'label': 'Discovery', 'value': 'Discovery'},
            {'label': 'Lateral Movement', 'value': 'Lateral Movement'},
            {'label': 'Collection', 'value': 'Collection'},
            {'label': 'C2', 'value': 'C2'},
            {'label': 'Exfiltration', 'value': 'Exfiltration'}
        ],
        placeholder="Select MITRE Tactic",
        clearable=False,
        style={'width': '100%', 'color': 'black'},
        id='mitre-dropdown'
    ),
    className='InputField',  # Use a consistent class name for styling
    style={'width': '19.95%'}  # Consistent styling for width and margin
)

mpnet_date_field = html.Div(
    [
        dbc.Input(id='mpnet-date', placeholder='Date Occurred on MPNET', style={'width': '100%'}),
        dbc.FormText(
            'Date must be in MM-DD-YYYY, XXXX format\nex. 07-25-2024, 0721',
            color='gray'
        )
    ],
    className='InputField',  # Use a consistent class name for styling
    style={'width': '20%'}  # Consistent styling for width and margin
)

form = html.Div([
    dbc.Form([name_field, mitre_drop, mpnet_date_field], style={'padding': '4px'}),
])

# Layout of the Dash app
app.layout = html.Div(children=[

    # Header section with the logo and title
    html.Div([
        html.H1(children=[
            html.Img(src='assets/logo.png', style={'display':'inline', 'width':'96px', 'height':'96px', 'padding':'12px'}),
            'Chainsmoker'
        ], className='page-title')
    ], style={'text-align': 'left', 'margin-bottom': '20px'}),

    # Graph section
    dcc.Graph(
        id='attack-chain-graph',
        figure=fig,
        className='fig',
        style={'margin': '12px'}
    ),
    html.Div(id='hover-data', style={'margin-left': '0px'}),
    # Node data and note input section
    html.Div([
        
        dcc.Markdown("** Node Data:** "),
        html.Pre(id='click-data', style={'margin-left': '0px'}),
        form,
        dcc.Textarea(
            id='note-input',
            style={'width': '85%', 'height': 100, 'margin-top': '10px'},
            placeholder='Enter your notes here...',
            className='text-box'
        ),
        html.Button('Submit', id='save-button', n_clicks=0, style={'padding': '6px', 'margin-top': '10px'}),
        
        html.Pre(id='save-fdbk', style={'margin-top': '10px'})
    ], className='three columns', style={'margin-left': '12px'})
])




def hash_node(clickData):
    if clickData and 'points' in clickData and clickData['points'][0]:
        # Combine relevant node contents into a single string
        point = clickData['points'][0]
        node_content = f"{point.get('x', '')}{point.get('y', '')}{point.get('text', '')}"
    else:
        return None

    return hashlib.sha1(node_content.encode()).hexdigest()

def hash_record():
    pass

@callback(
    Output('click-data', 'children'),
    Input('attack-chain-graph', 'clickData'))
def display_click_data(clickData):
    #return json.dumps(clickData, indent=2)
    node_id = hash_node(clickData)

    title = clickData['points'][0].get('text', '')

    if(os.path.exists('db/node_data.json')):
        if(node_id in data):
            notes = data[node_id]['notes']
            table = dash_table.DataTable(
                notes, 
                [{"name": key, "id": key} for key in notes[0].keys()], id='notes-table',
                style_header={
                    'backgroundColor': 'rgb(30, 30, 30)',
                    'color': 'white'
                },
                style_data={
                    'backgroundColor': 'rgb(50, 50, 50)',
                    'color': 'white'
                },
                style_cell={
                    'textAlign': 'left',
                    'minWidth': '60px', 'width': '180px', 'maxWidth': '960px',
                }
            )
            return table
            
        else:
            return f'{title}\n\nNotes are empty. Consider hunting harder.'
    else:
    
        return f'{title}\n\nNotes are empty. Consider hunting harder.'

@callback(
    Output('save-fdbk', 'children'),
    Input('save-button', 'n_clicks'),
    State('mitre-dropdown', 'value'),
    State('mpnet-date', 'value'),
    State('name-input', 'value'),
    State('note-input', 'value'),
    State('attack-chain-graph', 'clickData'),
    prevent_initial_call=True)
def save_json(n_clicks, tactic, date, name, note_input, clickData):
    if (n_clicks > 0):
        print(note_input)
        node_id = hash_node(clickData)

        if not node_id:
            return "Error: Unable to determine node ID."
        
        if node_id not in data:
            data[node_id] = {'notes': []}

        data[node_id]['notes'].append({"operator":name,"tactic":tactic,"date":date,"note":note_input})

        # Write back to the JSON file
        with open('db/node_data.json', 'w') as file:
            json.dump(data, file, indent=2)

        return "Notes saved."
    
    return dash.no_update

""" @callback(
    Output('hover-data', 'children'),
    Input('attack-chain-graph', 'hoverData')
)
def hoverColor(hoverData):
    point_index = hoverData['points'][0]['pointIndex']
    curve_number = hoverData['points'][0]['curveNumber']
    new_fig = fig

    for trace in new_fig.data:
        trace.marker.color = list(range(6))
        trace.market.colorscale='sunset' """


if __name__ == '__main__':
    app.run_server(port=8080, host = '0.0.0.0')

