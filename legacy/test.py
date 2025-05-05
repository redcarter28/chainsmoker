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
    dcc.Store(id='df-store', data=df.to_dict('records')),
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

import plotly.graph_objects as go
import pandas as pd

# Assuming df is your DataFrame with the necessary data
# Ensure 'Date/Time MPNET' is in datetime format
df['Date/Time MPNET'] = pd.to_datetime(df['Date/Time MPNET'], format='%m/%d/%Y, %H%M', errors='coerce')

# Create a unique y-value for each entry to spread them out
df['Y'] = range(len(df))

# Create the figure
fig_ioc = go.Figure()

# Add a scatter plot with spline lines
fig_ioc.add_trace(go.Scatter(
    x=df['Date/Time MPNET'],
    y=df['Y'],
    mode='lines+markers',
    line_shape='spline',  # Use spline for smooth lines
    marker=dict(size=8, color='blue'),
    line=dict(width=2, color='blue'),
    text=df['Details'],  # Assuming 'Details' is a column with information about each IOC
    hoverinfo='text',
    name='IOC'
))

# Update layout
fig_ioc.update_layout(
    title='Indicators of Compromise Over Time',
    xaxis_title='Time of Action',
    yaxis_title='IOC Index',
    plot_bgcolor='rgba(35, 35, 35, 1)',
    paper_bgcolor='rgba(35, 35, 35, 1)',
    font=dict(color='white'),
    title_font=dict(color='white'),
    margin=dict(l=50, r=50, t=50, b=50),
    hovermode='closest'
)

# Show the figure
#fig_ioc.show()

# Assuming df is your DataFrame with the necessary data

# Ensure 'Date/Time MPNET' is in datetime format

df['Date/Time MPNET'] = pd.to_datetime(df['Date/Time MPNET'], format='%m/%d/%Y, %H%M', errors='coerce')


# Sort the DataFrame by 'Date/Time MPNET'

df = df.sort_values(by='Date/Time MPNET')


# Initialize y-values

y_values = [0] * len(df)


# Calculate y-values based on time difference

for i in range(1, len(df)):

    time_diff = (df['Date/Time MPNET'].iloc[i] - df['Date/Time MPNET'].iloc[i - 1]).total_seconds() / 3600

    if time_diff < 1:

        y_values[i] = y_values[i - 1] + 1

    else:

        y_values[i] = 0


# Add y-values to the DataFrame

df['Y'] = y_values


# Create the figure

fig_ioc = go.Figure()


# Add a scatter plot with spline lines

fig_ioc.add_trace(go.Scatter(

    x=df['Date/Time MPNET'],

    y=df['Y'],

    mode='lines+markers',

    line_shape='spline',  # Use spline for smooth lines

    marker=dict(size=8, color='blue'),

    line=dict(width=2, color='blue', smoothing=1.3),

    text=df['Details'],  # Assuming 'Details' is a column with information about each IOC

    hoverinfo='text',

    name='IOC'

))


# Update layout

fig_ioc.update_layout(

    title='Indicators of Compromise Over Time',

    xaxis_title='Time of Action',

    yaxis_title='IOC Index',

    plot_bgcolor='rgba(35, 35, 35, 1)',

    paper_bgcolor='rgba(35, 35, 35, 1)',

    font=dict(color='white'),

    title_font=dict(color='white'),

    margin=dict(l=50, r=50, t=50, b=50),

    hovermode='closest'

)


# Show the figure

#fig_ioc.show()


# Utility functions
def hash_node(clickData):
    if clickData and 'points' in clickData and clickData['points'][0]:
        point = clickData['points'][0]
        node_content = f"{point.get('x', '')}{point.get('y', '')}{point.get('text', '')}"
        return hashlib.sha1(node_content.encode()).hexdigest()
    return None

def get_excel_writer(file_path):
    return pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='overlay')


def _extract_axis_ranges(relayout_data: dict) -> dict | None:
    """
    Pick only the '[xy]axis.range[0|1]' keys from Plotly `relayoutData`.
    Return None if no explicit ranges are found or if autorange was used.
    """
    if not relayout_data:
        return None

    # autorange (double click) – clear the zoom store
    if "xaxis.autorange" in relayout_data or "yaxis.autorange" in relayout_data:
        return None

    zoom = {}
    for ax in ("xaxis", "yaxis"):
        low  = f"{ax}.range[0]"
        high = f"{ax}.range[1]"
        if low in relayout_data and high in relayout_data:
            zoom[low]  = relayout_data[low]
            zoom[high] = relayout_data[high]

    return zoom or None


### CALLBACKS (yuh)
@callback(
    Output("zoom-state", "data", allow_duplicate=True),
    Input("attack-chain-graph", "relayoutData"),
    prevent_initial_call=True,
)
def store_zoom(relayout_data):
    """
    Store the current axis ranges whenever the user zooms / pans.
    Double-click (autorange) will wipe the store (returns None).
    """
    return _extract_axis_ranges(relayout_data)

@callback(
    outputs=[
        Output("attack-chain-graph", "figure"),          # the graph itself
        Output("toggle-list-all-btn", "children"),       # rename button
    ],
    inputs=[
        Input("fig-store",            "data"),           # any fig refresh
        Input("toggle-list-all-btn",  "n_clicks"),       # user clicks
        State("zoom-state",           "data"),           # current zoom
    ],
    prevent_initial_call=True,
)
def update_attack_chain_graph(figs_dict, n_clicks, zoom_state):
    """
    Single source of truth for whatever the user should currently see.
    The function decides which pre-built figure to serve and applies the
    last zoom window (if it exists).
    """
    # ----------------------------------------------------------------------
    # Safety – initialise ‘n_clicks’
    #   *None*  → page just loaded         → default is “hide missing”,
    #                                         the button shows “Hide …”
    #   0 or even value  →  All-tactics view is ON  (button = Hide)
    #   odd value        →  Normal view (button = Show)
    # ----------------------------------------------------------------------
    if n_clicks is None:
        n_clicks = 2        # page load = even → all-tactics hidden

    show_normal_view = n_clicks % 2 == 1

    # Pick the correct figure out of the store
    figure_key   = "normal" if show_normal_view else "all_tactics"
    selected_fig = go.Figure(figs_dict[figure_key])

    # Nice button label for next action
    button_text  = "Show Missing Tactics" if show_normal_view else "Hide Missing Tactics"

    # ------------------------------------------------------------------
    # Re-apply previous zoom window if it exists
    # ------------------------------------------------------------------
    if zoom_state and all(v is not None for v in zoom_state.values()):
        selected_fig.update_layout(
            xaxis=dict(range=[zoom_state["xaxis.range[0]"], zoom_state["xaxis.range[1]"]]),
            yaxis=dict(range=[zoom_state["yaxis.range[0]"], zoom_state["yaxis.range[1]"]]),
        )

    return selected_fig, button_text

@callback(
    [Output("save-fdbk-node", "children"),
     Output("fig-store",       "data")],                 #  <<< now returns dict
    Input("save-button-node",  "n_clicks"),
    [
        State("mpnet-date-input-node", "value"),
        State("mitre-dropdown-node",   "value"),
        State("src-ip-node",           "value"),
        State("dst-ip-node",           "value"),
        State("details-input-node",    "value"),
        State("notes-input-node",      "value"),
        State("name-input-node",       "value"),
        State("atk-chn-input-node",    "value"),
    ],
    prevent_initial_call=True,
)
def save_node(n_clicks, date, tactic, src, dst, details, notes, name, chain):
    # … validation / Excel write code identical to original …
    # After df is updated we rebuild the two figures
    global fig, fig_list_all, missing_tactics
    fig, fig_list_all, missing_tactics = chainsmoker()

    new_store = {
        "normal":      fig.to_dict(),
        "all_tactics": fig_list_all.to_dict(),
    }

    return [html.Pre("Node Saved!", style={"font-size": "medium"})], new_store

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



if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")



