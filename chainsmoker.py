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

styles = {
    'pre': {
        'border': 'thin lightgrey solid',
        'overflowX': 'scroll'
    }
}

# Read data from Excel file using openpyxl
df = pd.read_excel('data/data2.xlsx', engine='openpyxl')

""" book = load_workbook('data/target.xlsx')
writer = pd.ExcelWriter('data/target.xlsx', engine='openpyxl', mode='a', if_sheet_exists='overlay')
writer.book = book
writer.sheets = {ws.title: ws for ws in book.worksheets} """

# handle dates
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
fig_list_all = None
all_tactics = None
visible_tactics = None
missing_tactics = None
selected_fig = None

# main chainsmoker algo 
def chainsmoker():
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
            showlegend=True,
            name= str(chain_id)
        ))


    # update layout for better display
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
        hovermode='closest',
        legend_title_text='Attack Chain',
        legend= {'itemsizing': 'constant', 'itemwidth':30}
    )

    # copy fig to fig_list_all and add dummy traces to show all relevant, possible tactics
    fig_list_all = go.Figure(fig.to_plotly_json())
    all_tactics = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "C2", "Exfiltration"
    ] 
    visible_tactics = [t for t in all_tactics if t in set(df['MITRE Tactic'].dropna().unique())]

    # reverse these two because I want it top -> bottom
    visible_tactics.reverse() 
    all_tactics.reverse() 

    x0 = df['Date/Time MPNET'].min()
    dummy_trace = go.Scatter(
        x=[x0] * len(all_tactics),
        y=all_tactics,
        mode='lines+markers',
        marker=dict(color='rgba(0,0,0,0)', size=1),  # fully transparent markers
        line=dict(color='rgba(0,0,0,0)', width=1),    # fully transparent line
        hoverinfo='none',
        showlegend=False,
        name="Attack Chain 0"  # Invisible trace to view all mitre tactics
    )
    missing_tactics = [t for t in all_tactics if t not in visible_tactics]

    for t in missing_tactics:
        fig_list_all.add_hline(y=t, line_color="indianred", line_width=25, opacity=0.2)

    fig_list_all.add_trace(dummy_trace)

    # update category order to match the MITRE matrix, the copy doesn't preserve order it seems
    fig.update_layout(yaxis={'categoryorder': 'array', 'categoryarray': visible_tactics})
    fig_list_all.update_layout(yaxis={'categoryorder': 'array', 'categoryarray': all_tactics})

    return fig, fig_list_all, missing_tactics

# html element definitions

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
        style={'padding': '4px'},
        id='node-form')
)

add_note_btn = html.Div([
                    html.Button('Add Note', id='show-notes-btn-1', n_clicks=0, style={'padding': '6px', 'margin-top': '2px'}, className='fancy-button'),
                    html.Pre(id='notes-btn-fdbk-1', style={'margin-top': '4px'})
                ], style={'text-align':'left', 'padding-right':'20px', 'padding-top':'10px'})

save_note_btn = html.Div([
                html.Button('Submit', id='save-button', n_clicks=0, style={'padding': '6px', 'margin-top': '2px'}, className='fancy-button'),
                html.Pre(id='save-fdbk', style={'margin-top': '4px'})
            ], style={'text-align':'left', 'display': 'block'})

toggle_list_all_btn = html.Div([
                html.Button('Hide Missing Tactics', id='toggle-list-all-btn', n_clicks=0, style={'padding': '6px', 'margin-top': '2px'}, className='fancy-button')
            ], style={'text-align':'right', 'display': 'block', 'max-width': '170px'})

attack_chain_unique = list(set(df['Attack Chain'].tolist()))
chain_checklist = dcc.Checklist(
                options=[{"label": chain, "value": chain} for chain in attack_chain_unique],
                value=attack_chain_unique,  # Default: all selected
                inline=True,
                id='chain-checklist',
                style={'text-align':'right'},
                labelStyle={'margin-right': '10px'}
            )

# Layout of the Dash app
app.layout = html.Div(children=[

    dcc.Location(id='url', refresh=True),
    dcc.Store(id='fig-store'),
    dcc.Store(id='zoom-state', storage_type='memory'),

    # Header section with the logo and title
    html.Div([
        html.H1(children=[
            html.Img(src='assets/logo.png', style={'display':'inline', 'width':'96px', 'height':'96px', 'padding':'12px'}),
            'Chainsmoker'
        ], className='page-title')
    ], style={'text-align': 'left', 'margin-bottom': '20px'}),
    html.Div([html.Div([html.Span('Select Attack Chain: ', style={'font-size':'medium','margin-left':'5px', 'margin-right':'5px'}), chain_checklist], className='fancy-border', style={'display':'none'}), toggle_list_all_btn], style={'display': 'flex', 'align-items': 'stretch', 'gap': '10px', 'justify-content': 'flex-end', 'padding-right': '20px'}),
    
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
        html.Pre('Click on a node to retrieve data',id='click-data', style={'margin-left': '0px'}, className='fancy-border'),
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
     State('atk-chn-input-node', 'value')],
    prevent_initial_call=True,
    allow_duplicate=True
)
def save_node(n_clicks, date, tactic, src, dst, details, notes, name, chain):
    if n_clicks > 0:

        if(date is None):
            return [html.Pre('Error: Please fill out all fields', style={'font-size': 'medium', 'color':'indianred'})], dash.no_update
        
        # logic to regex enforce time/date format
        if(not re.match(r"\d{2}/\d{2}/\d{4}, \d{4}$", date)):
            return [html.Pre('Error: Incorrect time/date format', style={'font-size': 'medium', 'color':'indianred'})], dash.no_update

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
    
        try:
            df['Date/Time MPNET'] = pd.to_datetime(df['Date/Time MPNET'], format='%m/%d/%Y, %H%M', errors='coerce')
        except Exception as e:
            print(f"Date conversion error: {e}")
        
        df['Date/Time MPNET'] = df['Date/Time MPNET'].apply(lambda x: x.strftime('%m/%d/%Y, %H%M') if not pd.isnull(x) else '')

        df = pd.concat([df, new_data], ignore_index=True)
        
        with get_excel_writer('data/data2.xlsx') as writer:
            df.to_excel(writer, index=False, header=True, sheet_name='Sheet1')

        global fig, fig_list_all, missing_tactics 
        fig, fig_list_all, missing_tactics = chainsmoker() # regen the dfs for plotly

        
        return [html.Pre('Node Saved!', style={'font-size': 'medium'})], fig.to_dict()


    return dash.no_update, dash.no_update

@callback(
    Output('zoom-state', 'data'),
    Input('attack-chain-graph', 'relayoutData'),
    prevent_initial_call=True
)
def store_zoom_state(relayoutData):
    # Check if the relayoutData indicates a reset (autorange)
    if relayoutData is None or 'xaxis.autorange' in relayoutData or 'yaxis.autorange' in relayoutData:
        return None  # Clear the zoom state

    # Only store zoom-related data
    zoom_data = {}
    if 'xaxis.range[0]' in relayoutData:
        zoom_data['xaxis.range[0]'] = relayoutData['xaxis.range[0]']
        zoom_data['xaxis.range[1]'] = relayoutData['xaxis.range[1]']
    if 'yaxis.range[0]' in relayoutData:
        zoom_data['yaxis.range[0]'] = relayoutData['yaxis.range[0]']
        zoom_data['yaxis.range[1]'] = relayoutData['yaxis.range[1]']
    
    return zoom_data if zoom_data else None

@callback(
    Output('attack-chain-graph', 'figure'),
    Input('fig-store', 'data'),
    prevent_initial_call=True
)
def update_graph(fig_data):
    if fig_data is None:
        raise dash.exceptions.PreventUpdate

    fig = go.Figure(fig_data)

    return fig

"""global fig, fig_list_all, missing_tactics
fig, fig_list_all, missing_tactics = chainsmoker()"""


@callback(
    [Output('fig-store', 'data', allow_duplicate=True),
     Output('toggle-list-all-btn', 'children')],
    [Input('toggle-list-all-btn', 'n_clicks'),
     Input('zoom-state', 'data')],
    prevent_initial_call=True
)
def toggle_graph_view(n_clicks, zoom_state):
    zoom_xaxis = [None, None]
    zoom_yaxis = [None, None]

    if zoom_state:
        zoom_xaxis = [
            zoom_state.get('xaxis.range[0]'), 
            zoom_state.get('xaxis.range[1]')
        ]
        zoom_yaxis = [
            zoom_state.get('yaxis.range[0]'), 
            zoom_state.get('yaxis.range[1]')
        ]

    if n_clicks % 2 == 1:
        if zoom_state:
            zoom_yaxis[1] = zoom_yaxis[1] - len(missing_tactics)

        global selected_fig
        selected_fig = go.Figure(fig)  
        button_label = 'Show Missing Tactics'
    else:
        selected_fig = go.Figure(fig_list_all) 
        button_label = 'Hide Missing Tactics'

    if zoom_xaxis[0] is not None and zoom_xaxis[1] is not None and \
       zoom_yaxis[0] is not None and zoom_yaxis[1] is not None:
        selected_fig.update_layout(
            xaxis=dict(range=zoom_xaxis),
            yaxis=dict(range=zoom_yaxis)
        )

    # Return the figure data to the store
    return selected_fig.to_dict(), button_label

# utility methods

def map_value(value, in_min, in_max, out_min, out_max): # UNUSED
    """
    Maps a value from one range to another.
    Args:
        value: The input value to be mapped.
        in_min: The minimum value of the input range.
        in_max: The maximum value of the input range.
        out_min: The minimum value of the output range.
        out_max: The maximum value of the output range.

    Returns:
        The mapped value within the output range.
    """
    return (value - in_min) * (out_max - out_min) / (in_max - in_min) + out_min

def get_excel_writer(file_path):

    return pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='overlay')

if __name__ == '__main__':
    fig, fig_list_all, missing_tactics = chainsmoker() # initial call
    app.run_server(port=8080, host = '0.0.0.0')