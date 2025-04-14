import dash
import flask
import openpyxl
from openpyxl import load_workbook
from dash import dcc, html, callback, Input, Output, State, dash_table
import json
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
from itertools import product
import hashlib
import os 
import re

# Centralized layout configuration for figures
# Optimization: Reduces redundancy in layout definitions
def get_base_layout():
    return dict(
        title='Attack Chain Visualization',
        xaxis_title='Date/Time MPNET',
        yaxis_title='MITRE Tactic',
        barmode='overlay',
        xaxis=dict(type='date', gridcolor='rgba(255, 255, 255, 0.2)'),
        yaxis=dict(gridcolor='rgba(255, 255, 255, 0.2)'),
        plot_bgcolor='rgba(35, 35, 35, 1)',
        paper_bgcolor='rgba(35, 35, 35, 1)',
        font=dict(color='white'),
        title_font=dict(color='white'),
        margin=dict(l=50, r=50, t=50, b=50),
        hovermode='closest',
        legend_title_text='Attack Chain',
        legend={'itemsizing': 'constant', 'itemwidth':30}
    )

styles = {
    'pre': {
        'border': 'thin lightgrey solid',
        'overflowX': 'scroll'
    }
}

# Read data from Excel file using openpyxl
df = pd.read_excel('data/data2.xlsx', engine='openpyxl')

def custom_date_parser(date_str):
    return pd.to_datetime(date_str, format='%m/%d/%Y, %H%M')

def expand_rows(row):
    sources = row['Source Hostname/IP'.split(',')]
    targets = row['Target Hostname/IP'.split(',')]
    return pd.DataFrame(list(product(sources,targets)), columns=['Source Hostname/IP', 'Target Hostname/IP'])

# Initial data processing
df_expanded = df.apply(expand_rows, axis=1).reset_index(drop=True)
df = df.sort_values(by='Date/Time local', ascending=False)
df['Date/Time MPNET'] = df['Date/Time MPNET'].apply(custom_date_parser)
df = df.sort_values(by='Date/Time MPNET', ascending=False)
df['Date/Time MPNET'] = df['Date/Time MPNET'].fillna('No Data')
df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

# Load JSON DB
if os.path.exists('db/node_data.json'):
    with open('db/node_data.json', 'r') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = {}
else:
    data = {}

# Initialize Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY], suppress_callback_exceptions=True)

# Global variables
fig = go.Figure()
fig_list_all = None
all_tactics = None
visible_tactics = None
missing_tactics = None
selected_fig = None

# Optimization: Centralized MITRE tactics list
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "C2", "Exfiltration"
]

# Optimization: Centralized trace creation function
def create_chain_trace(chain_df, chain_id):
    hover_text = [
        f"<b>Details:</b> {details} <br><b>Notes:</b> {notes}<br><b>Found By:</b> {operator} <br><b>Attack Chain:</b> {att}" 
        for details, notes, operator, att in zip(
            chain_df['Details'], 
            chain_df['Notes'], 
            chain_df['Operator'], 
            chain_df['Attack Chain']
        )
    ]

    return go.Scatter(
        x=chain_df['Date/Time MPNET'].tolist() + [None],
        y=chain_df['MITRE Tactic'].tolist() + [None],
        mode='lines+markers',
        marker=dict(
            size=12,
            opacity=0.8,
            color=list(range(len(chain_df))),
            colorscale='sunset',
            line=dict(width=1, color='DarkSlateGrey')
        ),
        line=dict(color='grey', width=2),
        text=hover_text,
        hoverinfo='text',
        showlegend=True,
        name=str(chain_id)
    )

# main chainsmoker algo 
def chainsmoker():

    df['Date/Time MPNET'] = df['Date/Time MPNET'].apply(custom_date_parser)

    global fig
    fig = go.Figure()  # Clear existing figure
    

    # Process each attack chain
    for chain_id in df['Attack Chain'].dropna().unique():
        chain_df = df[df['Attack Chain'] == chain_id]
        fig.add_trace(create_chain_trace(chain_df, chain_id))

    # Apply base layout
    fig.update_layout(**get_base_layout())

    # Create fig_list_all with all tactics
    all_tactics = MITRE_TACTICS.copy()
    all_tactics.reverse()
    
    visible_tactics = [t for t in all_tactics if t in set(df['MITRE Tactic'].dropna().unique())]

    # Create fig_list_all as a copy of the main figure
    fig_list_all = go.Figure(fig.to_plotly_json())
    
    # Add missing tactics visualization
    
    x0 = df['Date/Time MPNET'].min()
    missing_tactics = [t for t in all_tactics if t not in visible_tactics]
    
    # Add dummy trace for all tactics visibility
    dummy_trace = go.Scatter(
        x=[x0] * len(all_tactics),
        y=all_tactics,
        mode='lines+markers',
        marker=dict(color='rgba(0,0,0,0)', size=1),
        line=dict(color='rgba(0,0,0,0)', width=1),
        hoverinfo='none',
        showlegend=False,
        name="Attack Chain 0"
    )
    
    fig_list_all.add_trace(dummy_trace)
    
    # Add missing tactics highlighting
    for t in missing_tactics:
        fig_list_all.add_hline(y=t, line_color="indianred", line_width=25, opacity=0.2)

    # Update layouts with appropriate category arrays
    fig.update_layout(yaxis={'categoryorder': 'array', 'categoryarray': visible_tactics})
    fig_list_all.update_layout(yaxis={'categoryorder': 'array', 'categoryarray': all_tactics})

    return fig, fig_list_all, missing_tactics
fig, fig_list_all, missing_tactics = chainsmoker()  # initial call

# HTML element definitions
# Optimization: Centralized dropdown options
mitre_dropdown_options = [{'label': tactic, 'value': tactic} for tactic in MITRE_TACTICS]

name_field = html.Div(
    [   
        dbc.Input(id='name-input', placeholder='Operator', style={'width': '100%'}),
    ],
    className='InputField',
)

mitre_drop = html.Div(
    dcc.Dropdown(
        options=mitre_dropdown_options,
        placeholder="Select MITRE Tactic",
        clearable=False,
        style={'width': '100%', 'color': 'black'},
        id='mitre-dropdown'
    ),
    className='InputField',
)

mpnet_date_field = html.Div(
    [
        dbc.Input(id='mpnet-date', placeholder='Date/Time MPNET (MM/DD/YYYY, XXXX)', style={'width': '100%'}),
    ],
    className='InputField',
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
            ), 
            html.Div(
                dcc.Dropdown(
                    options=mitre_dropdown_options,
                    placeholder="Select MITRE Tactic",
                    clearable=False,
                    style={'width': '100%', 'color': 'black'},
                    id='mitre-dropdown-node'
                ),
                className='InputField',
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
        style={'padding': '4px'},
        id='node-form')
)

# Button and UI element definitions
add_note_btn = html.Div([
    html.Button('Add Note', id='show-notes-btn-1', n_clicks=0, 
                style={'padding': '6px', 'margin-top': '2px'}, 
                className='fancy-button'),
    html.Pre(id='notes-btn-fdbk-1', style={'margin-top': '4px'})
], style={'text-align':'left', 'padding-right':'20px', 'padding-top':'10px'})

save_note_btn = html.Div([
    html.Button('Submit', id='save-button', n_clicks=0, 
                style={'padding': '6px', 'margin-top': '2px'}, 
                className='fancy-button'),
    html.Pre(id='save-fdbk', style={'margin-top': '4px'})
], style={'text-align':'left', 'display': 'block'})

toggle_list_all_btn = html.Div([
    html.Button('Hide Missing Tactics', id='toggle-list-all-btn', n_clicks=2, 
                style={'padding': '6px', 'margin-top': '2px'}, 
                className='fancy-button')
], style={'text-align':'right', 'display': 'block', 'max-width': '170px'})

# Attack chain checklist
attack_chain_unique = list(set(df['Attack Chain'].tolist()))
chain_checklist = dcc.Checklist(
    options=[{"label": chain, "value": chain} for chain in attack_chain_unique],
    value=attack_chain_unique,
    inline=True,
    id='chain-checklist',
    style={'text-align':'right'},
    labelStyle={'margin-right': '10px'}
)

# Optimization: Main layout structure
app.layout = html.Div(children=[
    # Store components
    dcc.Location(id='url', refresh=True),
    dcc.Store(id='fig-store', data=fig.to_dict()),
    dcc.Store(id='zoom-state', storage_type='memory'),

    # Header section
    html.Div([
        html.H1(children=[
            html.Img(src='assets/logo.png', 
                    style={'display':'inline', 'width':'96px', 'height':'96px', 'padding':'12px'}),
            'Chainsmoker'
        ], className='page-title')
    ], style={'text-align': 'left', 'margin-bottom': '2px'}),

    # Controls section
    html.Div([
        html.Div([
            html.Span('Select Attack Chain: ', 
                     style={'font-size':'medium','margin-left':'5px', 'margin-right':'5px'}), 
            chain_checklist
        ], className='fancy-border', style={'display':'none'}), 
        toggle_list_all_btn
    ], style={'display': 'flex', 'align-items': 'stretch', 'gap': '10px', 
              'justify-content': 'flex-end', 'padding-right': '20px'}),
    
    # Graph section 
   dcc.Graph(
    id='attack-chain-graph',
    figure=fig,
    className='fig',
    style={'margin': '12px'},
    config={
        'scrollZoom': True,  # Enable scroll zoom for timeline navigation
        'displaylogo': False,  # Remove the plotly logo
        'modeBarButtonsToRemove': ['autoScale2d', 'select2d', 'lasso2d'],  # Remove unnecessary buttons
        'displayModeBar': 'hover',  # Only show mode bar on hover
        'doubleClick': 'reset+autosize',  # Double click resets view
        'showAxisDragHandles': True,  # Keep drag handles for easy navigation
        'showAxisRangeEntryBoxes': True,  # Allow manual range entry
        'showTips': True,  # Show interaction tips
        'responsive': False,  # Make the graph responsive to window size
        'editable': False,  # Prevent accidental edits
        'autosizable': True,  # Allow auto-sizing
        'doubleClickDelay': 0,  # Standard double-click delay
        'toImageButtonOptions': {  # Configure image export
            'format': 'png',
            'filename': 'attack_chain',
            'height': None,
            'width': None,
            'scale': 2
        }
    }

),
    html.Div(id='hover-data', style={'margin-left': '0px'}),

    # Node data and input section
    html.Div([
        dcc.Markdown("** Node Data:** "),
        html.Pre('Click on a node to retrieve data',
                id='click-data', 
                style={'margin-left': '0px'}, 
                className='fancy-border'),
        
        # Notes section
        html.Div([  
            form,
            dcc.Textarea(
                id='note-input',
                style={'width': '85%', 'height': 100, 'margin-top': '10px'},
                placeholder='Enter your notes here...',
                className='text-box'
            ),
            save_note_btn,
        ], id='notes-hide', style={'display': 'none'}),
        
        # Node input section
        html.Div([
            node_form,
            html.Button('Submit', 
                       id='save-button-node', 
                       n_clicks=0, 
                       style={'padding': '6px', 'margin-top': '2px'}, 
                       className='fancy-button'),
            html.Pre(id='save-fdbk-node', style={'margin-top': '4px'})
        ], id='node-hide', style={'text-align':'left', 'visible': 'block'}),
    ], className='three columns', style={'margin-left': '12px'})
])

# General config
app.title = 'Chainsmoker'

# Utility functions
def hash_node(clickData):
    if clickData and 'points' in clickData and clickData['points'][0]:
        point = clickData['points'][0]
        node_content = f"{point.get('x', '')}{point.get('y', '')}{point.get('text', '')}"
        return hashlib.sha1(node_content.encode()).hexdigest()
    return None

def get_excel_writer(file_path):
    return pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='overlay')

# APP CALLBACKS 
@callback(
    [Output('save-fdbk', 'children'),
     Output('click-data', 'children')],
    [Input('save-button', 'n_clicks'),
     Input('attack-chain-graph', 'clickData')],
    [State('mitre-dropdown', 'value'),
     State('mpnet-date', 'value'),
     State('name-input', 'value'),
     State('note-input', 'value')],
    prevent_initial_call=True
)
def notes_clickdata(n_clicks, clickData, tactic, date, name, note_input):
    ctx = dash.callback_context
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None

    if not clickData:
        return "Error: No node selected.", dash.no_update

    node_id = hash_node(clickData)
    if not node_id:
        return "Error: Unable to determine node ID.", dash.no_update
    
    # Ensure node exists in data
    if node_id not in data:
        data[node_id] = {'notes': []}

    # Handle note saving
    if triggered_id == 'save-button' and note_input:
        new_entry = {"operator": name, "tactic": tactic, "date": date, "note": note_input}
        data[node_id]['notes'].append(new_entry)
        
        with open('db/node_data.json', 'w') as file:
            json.dump(data, file, indent=2)
        
        feedback = 'Notes Saved!'
    else:
        feedback = ''

    # Process hover data
    hoverdata = re.sub(r'<.*?>', '', clickData['points'][0].get('text', '')).replace(
        'Notes:', '\nNotes:').replace('Found By:', '\nFound By:').replace('Attack Chain:', '\nAttack Chain:')

    # Build notes table
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
    return {'display': 'block' if n_clicks % 2 == 1 else 'none'}

# Optimization: Combined node saving and figure updating
@callback(
    [Output('save-fdbk-node', 'children'),
     Output('fig-store', 'data')],
    Input('save-button-node', 'n_clicks'),
    [State('mpnet-date-input-node', 'value'),
     State('mitre-dropdown-node', 'value'),
     State('src-ip-node', 'value'),
     State('dst-ip-node', 'value'),
     State('details-input-node', 'value'),
     State('notes-input-node', 'value'),
     State('name-input-node', 'value'),
     State('atk-chn-input-node', 'value'),
     State('fig-store', 'data')],
    prevent_initial_call=True
)
def save_node(n_clicks, date, tactic, src, dst, details, notes, name, chain, existing_fig_data):
    
    if not n_clicks:
        return dash.no_update, dash.no_update

    # Validate inputs
    if not date:
        return [html.Pre('Error: Please fill out all fields', 
                        style={'font-size': 'medium', 'color':'indianred'})], dash.no_update
    
    if not re.match(r"\d{2}/\d{2}/\d{4}, \d{4}$", date):
        return [html.Pre('Error: Incorrect time/date format', 
                        style={'font-size': 'medium', 'color':'indianred'})], dash.no_update

    # Update DataFrame
    new_data = pd.DataFrame([{
        'Date/Time MPNET': date,
        'MITRE Tactic': tactic,
        'Source Hostname/IP': src,
        'Target Hostname/IP': dst,
        'Details': details,
        'Notes': notes,
        'Operator': name,
        'Attack Chain': chain
    }])
    
    global df
    print(df)
    df['Date/Time MPNET'] = df['Date/Time MPNET'].apply(custom_date_parser)
    df = pd.concat([df, new_data], ignore_index=True)

    print(df)
    
    # Save to Excel
    df['Date/Time MPNET'] = pd.to_datetime(df['Date/Time MPNET'], format='%m/%d/%Y, %H%M', errors='coerce')
    df['Date/Time MPNET'] = df['Date/Time MPNET'].dt.strftime('%m/%d/%Y, %H%M')
    with get_excel_writer('data/data2.xlsx') as writer:
        df.to_excel(writer, index=False, header=True, sheet_name='Sheet1')

    print(pd.read_excel('data/data2.xlsx', engine='openpyxl'))

    # Update figures
    global fig, fig_list_all, missing_tactics
    fig, fig_list_all, missing_tactics = chainsmoker()

    return [html.Pre('Node Saved!', style={'font-size': 'medium'})], fig.to_dict()

@callback(
    Output('zoom-state', 'data'),
    Input('attack-chain-graph', 'relayoutData'),
    prevent_initial_call=True
)
def store_zoom_state(relayoutData):
    if not relayoutData or 'xaxis.autorange' in relayoutData or 'yaxis.autorange' in relayoutData:
        return None

    zoom_data = {}
    for axis in ['xaxis', 'yaxis']:
        if f'{axis}.range[0]' in relayoutData:
            zoom_data[f'{axis}.range[0]'] = relayoutData[f'{axis}.range[0]']
            zoom_data[f'{axis}.range[1]'] = relayoutData[f'{axis}.range[1]']
    
    return zoom_data if zoom_data else None 

@callback(
    Output('attack-chain-graph', 'figure'),
    Input('fig-store', 'data'),
    prevent_initial_call=True
)
def update_graph(fig_data):
    if fig_data is None:
        raise dash.exceptions.PreventUpdate
    return go.Figure(fig_data)

@callback(
    [Output('fig-store', 'data', allow_duplicate=True),
     Output('toggle-list-all-btn', 'children')],
    [Input('toggle-list-all-btn', 'n_clicks'),
     Input('zoom-state', 'data')],
    prevent_initial_call=True
)
def toggle_graph_view(n_clicks, zoom_state):
    print(n_clicks)
    n_clicks = 0 if n_clicks is None else n_clicks  # Convert None to 0
    if not n_clicks:
        return dash.no_update, dash.no_update

    zoom_xaxis = [None, None]
    zoom_yaxis = [None, None]

    if zoom_state:
        zoom_xaxis = [zoom_state.get('xaxis.range[0]'), zoom_state.get('xaxis.range[1]')]
        zoom_yaxis = [zoom_state.get('yaxis.range[0]'), zoom_state.get('yaxis.range[1]')]

    global selected_fig
    if n_clicks % 2 == 1:
        selected_fig = go.Figure(fig)
        if zoom_state:
            #zoom_yaxis[1] = zoom_yaxis[1] - len(missing_tactics)  #removed this shit lol
            pass
        
        button_label = 'Show Missing Tactics'
    else:
        if zoom_state:
            #zoom_yaxis[1] = zoom_yaxis[1] + len(missing_tactics)
            pass
        selected_fig = go.Figure(fig_list_all)
        button_label = 'Hide Missing Tactics'

    if all(x is not None for x in zoom_xaxis + zoom_yaxis):
        selected_fig.update_layout(
            xaxis=dict(range=zoom_xaxis),
            yaxis=dict(range=zoom_yaxis)
        )

    return selected_fig.to_dict(), button_label
 
if __name__ == '__main__':
    app.run_server(port=8080, host='0.0.0.0')