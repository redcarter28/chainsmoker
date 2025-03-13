import dash
from dash import dcc, html, callback, Input, Output, State, dash_table
import json
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
from itertools import product
import hashlib
import os 
import re

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



app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY], suppress_callback_exceptions=True)

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

    # Create a list of formatted strings combining 'Details' and 'Notes' for each point
    hover_text = [f"<b>Details:</b> {details} <br><b>Notes:</b> {notes}<br><b>Found By:</b> {operator} <br><b>Attack Chain:</b> {att}" for details, notes, operator, att in zip(chain_df['Details'], chain_df['Notes'], chain_df['Operator'], chain_df['Attack Chain'])]

    fig.add_trace(go.Scatter(
        x=chain_df['Date/Time MPNET'].tolist() + [None],
        y=chain_df['MITRE Tactic'].tolist() + [None],
        mode='lines+markers',
        marker=dict(
            size=12,
            opacity=0.8,
            color=list(range(len(chain_df))),  # Adjusting color range to match the length of chain_df
            colorscale='sunset',
            line=dict(width=1, color='DarkSlateGrey')
        ),
        line=dict(color='grey', width=2),
        text=hover_text,  # Use the formatted hover text
        hoverinfo='text',
        showlegend=False,
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
    
)

mpnet_date_field = html.Div(
    [
        dbc.Input(id='mpnet-date', placeholder='Date/Time MPNET (MM/DD/YYYY, XXXX)', style={'width': '100%'}),
    ],
    className='InputField',  # Use a consistent class name for styling
    
)

form = html.Div([
    dbc.Form([name_field, mitre_drop, mpnet_date_field], style={'padding': '4px'}),
])

node_form = html.Div(
    dbc.Form(
        [
            html.Div(
                [   
                    dbc.Input(id='mpnet-date-input-node', placeholder='Date/Time MPNET (MM/DD/YY, XXXX)', style={'width': '100%'}),
                ],
                className='InputField',  
                #style={'width': '20%'}  
            ), 
            html.Div(
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
                    id='mitre-dropdown-node'
                ),
                className='InputField',  # Using a consistent class name for styling
            ),
            html.Div(
                [   
                    dbc.Input(id='src-ip-node', placeholder='Source Hostname/IP', style={'width': '100%'}),
                ],
                className='InputField',  
            ),
            html.Div(
                [   
                    dbc.Input(id='dst-ip-node', placeholder='Destination Hostname/IP', style={'width': '100%'}),
                ],
                className='InputField',  
            ),
            html.Div(
                [   
                    dbc.Input(id='details-input-node', placeholder='Details', style={'width': '100%'}),
                ],
                className='InputField',  
            ),
            html.Div(
                [   
                    dbc.Input(id='notes-input-node', placeholder='Notes', style={'width': '100%'}),
                ],
                className='InputField',  
            ),
            html.Div(
                [   
                    dbc.Input(id='name-input-node', placeholder='Operator', style={'width': '100%'}),
                ],
                className='InputField',  
            ),
            html.Div(
                [   
                    dbc.Input(id='atk-chn-input-node', placeholder='Attack Chain', style={'width': '100%'}),
                ],
                className='InputField',  
            )
        ], 
        style={'padding': '4px'})
)

add_note_btn = html.Div([
                    html.Button('Add Note', id='show-notes-btn-1', n_clicks=0, style={'padding': '6px', 'margin-top': '2px'}, className='fancy-button'),
                    html.Pre(id='notes-btn-fdbk-1', style={'margin-top': '4px'})
                ], style={'text-align':'left', 'padding-right':'20px', 'padding-top':'10px'})

save_note_btn = html.Div([
                html.Button('Submit', id='save-button', n_clicks=0, style={'padding': '6px', 'margin-top': '2px'}, className='fancy-button'),
                html.Pre(id='save-fdbk', style={'margin-top': '4px'})
            ], style={'text-align':'left', 'display': 'block'})

# Layout of the Dash app
app.layout = html.Div(children=[

    dcc.Location(id='url', refresh=True),
    dcc.Store(id='plot-data', data=fig.to_plotly_json()),

    # Header section with the logo and title
    html.Div([
        html.H1(children=[
            html.Img(src='assets/logo.png', style={'display':'inline', 'width':'96px', 'height':'96px', 'padding':'12px'}),
            'Chainsmoker'
        ], className='page-title')
    ], style={'text-align': 'left', 'margin-bottom': '20px'}),
    html.Div([]),
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
        html.Div([  
            form,
            dcc.Textarea(
                id='note-input',
                style={'width': '85%', 'height': 100, 'margin-top': '10px'},
                placeholder='Enter your notes here...',
                className='text-box'
            ),
            save_note_btn,
        ], id='notes-hide', style={'display': 'block'}),
        
        html.Div([
            node_form,
            html.Button('Submit', id='save-button-node', n_clicks=0, style={'padding': '6px', 'margin-top': '2px'}, className='fancy-button'),
            html.Pre(id='save-fdbk-node', style={'margin-top': '4px'})
        ], id='node-hide',style={'text-align':'left', 'visible': 'block'}),
    ], className='three columns', style={'margin-left': '12px'})
    

])


# general config
app.title = 'Chainsmoker'



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
    [Output('save-fdbk', 'children'),
     Output('click-data', 'children')],
    [Input('save-button', 'n_clicks'),
     Input('attack-chain-graph', 'clickData'),
     Input('attack-chain-graph', 'hoverData')],
    [State('mitre-dropdown', 'value'),
     State('mpnet-date', 'value'),
     State('name-input', 'value'),
     State('note-input', 'value')],
    prevent_initial_call=True
)
def update_webpage_callback(n_clicks, clickData, hoverData, tactic, date, name, note_input):
    ctx = dash.callback_context
    if not ctx.triggered:
        triggered_id = None
    else:
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]

    # Check if node data is present
    if not clickData:
        return "Error: No node selected.", dash.no_update

    node_id = hash_node(clickData)
    if not node_id:
        return "Error: Unable to determine node ID.", dash.no_update
    
    # Ensure node exists in data
    if node_id not in data:
        data[node_id] = {'notes': []}

    # Only add a new note if the save button triggered the callback
    if triggered_id == 'save-button' and note_input:
        new_entry = {"operator": name, "tactic": tactic, "date": date, "note": note_input}
        data[node_id]['notes'].append(new_entry)

        # Save updated data
        with open('db/node_data.json', 'w') as file:
            json.dump(data, file, indent=2)
        
        feedback = 'Notes Saved!'
    else:
        feedback = ''  # No update to feedback if the node was clicked

    hoverdata = re.sub(r'<.*?>', '', clickData['points'][0].get('text', '')).replace('Notes:', '\nNotes:').replace('Found By:', '\nFound By:').replace('Attack Chain:', '\nAttack Chain:') #4 replaces chained because i cannot be fucked to find a better solution rn tbh

    # Build the table from current notes
    notes = data[node_id]['notes']
    if notes:
        table = dash_table.DataTable(
            data=notes, 
            columns=[{"name": key, "id": key} for key in notes[0].keys()],
            id='notes-table',
            style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
            style_data={'backgroundColor': 'rgb(50, 50, 50)', 'color': 'white'},
            style_cell={'textAlign': 'left', 'minWidth': '60px', 'width': '180px', 'maxWidth': '960px'}
        )
        table_div = html.Div([hoverdata, html.H6("Comments:"), table])
    else:
        table_div = html.Div([hoverdata, "\n\nComments are empty. Consider hunting harder."])

    return feedback, [table_div, add_note_btn]

@callback(
    Output('notes-hide', 'style'),
    Input('show-notes-btn-1', 'n_clicks')
)
def notes_hide(n_clicks):
    if n_clicks % 2 == 1:
        return {'display': 'block'}
    else:
        return {'display': 'none'}


if __name__ == '__main__':
    app.run_server(port=8080, host = '0.0.0.0')