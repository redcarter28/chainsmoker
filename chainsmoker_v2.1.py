# ─────────────────────────────────────────────────────────────────────────────
#  CHAINS​MOKER – unified & stateless
# ─────────────────────────────────────────────────────────────────────────────
import os, re, json, math, hashlib
from itertools import product

import dash
from dash import dcc, html, dash_table, callback, Input, Output, State
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.graph_objects as go
from openpyxl import load_workbook                                   # noqa

# -------------------------------------------------------------------
# Plotly config used for every graph in the app
# -------------------------------------------------------------------
PLOT_CONFIG = dict(
    scrollZoom=True,                  # allow wheel zoom
    displaylogo=False,                # hide Plotly logo
    modeBarButtonsToRemove=[
        'autoScale2d', 'select2d', 'lasso2d'
    ],
    displayModeBar='hover',           # show toolbar on hover only
    doubleClick='reset+autosize',     # dbl-click resets axes
    showAxisDragHandles=True,
    showAxisRangeEntryBoxes=True,
    showTips=True,
    responsive=False,
    editable=False,
    autosizable=True,
    doubleClickDelay=0,
    toImageButtonOptions={
        'format': 'png',
        'filename': 'attack_chain',
        'scale': 2
    },
)

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & HELPERS
# ─────────────────────────────────────────────────────────────────────────────
MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "C2", "Exfiltration"
]

def custom_date_parser(date_str: str):
    return pd.to_datetime(date_str, format='%m/%d/%Y, %H%M', errors='coerce')

def hash_node(click_data):
    if click_data and click_data.get('points'):
        p = click_data['points'][0]
        content = f"{p.get('x','')}{p.get('y','')}{p.get('text','')}"
        return hashlib.sha1(content.encode()).hexdigest()
    return None

def clamp(i: int, lo: int, hi: int) -> int:
    """Return i clamped to the closed interval [lo, hi]."""
    return max(lo, min(i, hi))

# ─────────────────────────────────────────────────────────────────────────────
#  DATA LOAD
# ─────────────────────────────────────────────────────────────────────────────
df = pd.read_excel('data/data2.xlsx', engine='openpyxl')
df['Date/Time MPNET'] = df['Date/Time MPNET'].apply(custom_date_parser)
df = df.sort_values(by='Date/Time MPNET', ascending=False)
df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

# JSON “DB” for per-node comments
if os.path.exists('db/node_data.json'):
    with open('db/node_data.json', 'r') as fh:
        try:
            NODE_NOTES = json.load(fh)
        except json.JSONDecodeError:
            NODE_NOTES = {}
else:
    NODE_NOTES = {}

# ─────────────────────────────────────────────────────────────────────────────
#  FIGURE BUILD
# ─────────────────────────────────────────────────────────────────────────────
def build_base_layout():
    return dict(
        title='Attack Chain Visualization',
        xaxis_title='Date/Time MPNET',
        yaxis_title='MITRE Tactic',
        xaxis=dict(type='date', gridcolor='rgba(255,255,255,0.2)'),
        yaxis=dict(gridcolor='rgba(255,255,255,0.2)'),
        plot_bgcolor='rgba(35,35,35,1)',
        paper_bgcolor='rgba(35,35,35,1)',
        font=dict(color='white'),
        hovermode='closest',
        margin=dict(l=50, r=50, t=50, b=50),
        legend_title_text='Attack Chain',
        legend={'itemsizing': 'constant', 'itemwidth': 30}
    )

def create_trace(chain_df, chain_id):
    hover = [
        f"<b>Details:</b> {d}<br><b>Notes:</b> {n}<br><b>Found&nbsp;By:</b> {o}"
        f"<br><b>Attack&nbsp;Chain:</b> {ac}"
        for d, n, o, ac in zip(chain_df['Details'],
                               chain_df['Notes'],
                               chain_df['Operator'],
                               chain_df['Attack Chain'])
    ]
    return go.Scatter(
        x=chain_df['Date/Time MPNET'].tolist() + [None],
        y=chain_df['MITRE Tactic'].tolist()     + [None],
        mode='lines+markers',
        marker=dict(size=12, opacity=.8,
                    color=list(range(len(chain_df))),
                    colorscale='sunset',
                    line=dict(width=1, color='DarkSlateGrey')),
        line=dict(color='grey', width=2),
        text=hover, hoverinfo='text',
        showlegend=True, name=str(chain_id)
    )

def chainsmoker():
    """Return  (fig_normal, fig_all, missing, visible, all_tactic_list)"""
    normal = go.Figure(layout=build_base_layout())
    for cid in df['Attack Chain'].dropna().unique():
        normal.add_trace(create_trace(df[df['Attack Chain'] == cid], cid))

    # --- build ALL-TACTICS figure ------------------------------------------
    all_tacs   = MITRE_TACTICS[::-1]                              # top → bottom
    visible    = [t for t in all_tacs if t in df['MITRE Tactic'].unique()]
    missing    = [t for t in all_tacs if t not in visible]
    visible.reverse()

    normal.update_layout(yaxis={'categoryorder': 'array',
                                'categoryarray': visible[::-1]})

    all_fig = go.Figure(normal.to_plotly_json())
    x0 = df['Date/Time MPNET'].min()

    # dummy invisible trace so every tactic has a y-slot
    all_fig.add_trace(go.Scatter(
        x=[x0] * len(all_tacs), y=all_tacs, mode='lines+markers',
        marker=dict(color='rgba(0,0,0,0)', size=1),
        line=dict(color='rgba(0,0,0,0)'), hoverinfo='none',
        showlegend=False, name='dummy'))

    for t in missing:
        all_fig.add_hline(y=t, line_color='indianred', line_width=25, opacity=.2)

    all_fig.update_layout(yaxis={'categoryorder': 'array',
                                 'categoryarray': all_tacs})

    return normal, all_fig, missing, visible[::-1], all_tacs

fig_normal, fig_all, missing_t, visible_t, all_t = chainsmoker()

# ─────────────────────────────────────────────────────────────────────────────
#  DASH APP & LAYOUT
# ─────────────────────────────────────────────────────────────────────────────
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY],
                suppress_callback_exceptions=True)
app.title = 'Chainsmoker'

mitre_dropdown_opts = [{'label': t, 'value': t} for t in MITRE_TACTICS]

def build_dropdown(id_):
    return dcc.Dropdown(id=id_, options=mitre_dropdown_opts,
                        placeholder="Select MITRE Tactic",
                        clearable=False,
                        style={'width': '100%', 'color': 'black'})

# ───── controls / forms (trimmed for brevity – unchanged UI) ─────
name_field = html.Div(dbc.Input(id='name-input', placeholder='Operator',
                                style={'width': '100%'}), className='InputField')
mitre_drop = html.Div(build_dropdown('mitre-dropdown'), className='InputField')
mpnet_date_field = html.Div(dbc.Input(id='mpnet-date',
                           placeholder='Date/Time MPNET (MM/DD/YYYY, XXXX)',
                           style={'width': '100%'}), className='InputField')
form = html.Div(dbc.Form([name_field, mitre_drop, mpnet_date_field],
                         style={'padding': '4px'}))

add_note_btn = html.Div([
    html.Button('Add Note', id='show-notes-btn-1', n_clicks=0,
                className='fancy-button', style={'padding': '6px'}),
    html.Pre(id='notes-btn-fdbk-1', style={'margin-top': '4px'})
], style={'text-align':'left', 'padding-right':'20px', 'padding-top':'10px'})

save_note_btn = html.Div([
    html.Button('Submit', id='save-button', n_clicks=0,
                className='fancy-button', style={'padding': '6px'}),
    html.Pre(id='save-fdbk', style={'margin-top': '4px'})
])

toggle_btn = html.Button('Hide Missing Tactics',
                         id='toggle-list-all-btn', n_clicks=0,
                         className='fancy-button',
                         style={'padding':'6px', 'margin-top':'2px'})

app.layout = html.Div([
    dcc.Store(id='fig-store', data={'normal': fig_normal.to_dict(),
                                    'all':    fig_all.to_dict()}),
    dcc.Store(id='zoom-state', storage_type='memory'),
    dcc.Store(id='internal-counter', data=0, storage_type='memory'),
    dcc.Location(id='url', refresh=True),
    

    html.H1(children=[
            html.Img(src='assets/logo.png', 
                    style={'display':'inline', 'width':'96px', 'height':'96px', 'padding':'2px'}),
            html.Div('Chainsmoker', style={'font-size':'calc(24px + 1.5vw)'})
        ], className='page-title'),


    html.Div(toggle_btn, style={'text-align':'right', 'margin-right':'20px'}),

    dcc.Graph(id='attack-chain-graph',
              figure=fig_all,                 # start with all-tactics
              config=PLOT_CONFIG,
              className='fig', style={'margin':'12px'}),

    html.Pre('Click on a node to retrieve data', id='click-data',
             className='fancy-border', style={'margin':'12px'}),

    # --- note entry UI (unchanged) --------------------------------------
    html.Div([form,
              dcc.Textarea(id='note-input', style={'width':'90%','height':'100px'}),
              save_note_btn], id='notes-hide', style={'display':'none'}),
])

# ─────────────────────────────────────────────────────────────────────────────
#  CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────
@callback(Output('zoom-state', 'data', allow_duplicate=True),
          Input('attack-chain-graph', 'relayoutData'),
          prevent_initial_call=True)
def store_zoom(relayout):
    if not relayout or 'xaxis.autorange' in relayout or 'yaxis.autorange' in relayout:
        return None
    z = {}
    for ax in ('xaxis', 'yaxis'):
        lo, hi = f'{ax}.range[0]', f'{ax}.range[1]'
        if lo in relayout and hi in relayout:
            z[lo] = relayout[lo]
            z[hi] = relayout[hi]
    return z or None

@callback(
    Output('attack-chain-graph', 'figure'),
    Output('toggle-list-all-btn', 'children'),
    Output('internal-counter', 'data'),
    Input('fig-store',              'data'),        # refresh (e.g. new node)
    Input('toggle-list-all-btn',    'n_clicks'),    # user toggles
    State('zoom-state',             'data'),        # last zoom
    State('internal-counter',       'data'),        # current view flag
    prevent_initial_call=True
)
def update_graph(figs_dict, n_clicks, zoom, flag):
    """
    flag (internal-counter): 0 = all-tactics, 1 = normal view
    """
    # Determine desired view after this callback
    if dash.callback_context.triggered_id == 'toggle-list-all-btn':
        flag = 1 - flag                                   # flip view

    view_key = 'normal' if flag else 'all'
    fig = go.Figure(figs_dict[view_key])

    # --- apply special ceil/floor y-axis maths when switching views
    if zoom and dash.callback_context.triggered_id == 'toggle-list-all-btn':
        zx0, zx1 = zoom['xaxis.range[0]'], zoom['xaxis.range[1]']
        zy0, zy1 = zoom['yaxis.range[0]'], zoom['yaxis.range[1]']

        if flag:  # we are moving all-→normal (visible_t list is shorter)
            raw_y0 = math.ceil(zy0)
            raw_y1 = math.floor(zy1)

            raw_y0 = clamp(raw_y0, 0, len(all_t)     - 1)
            raw_y1 = clamp(raw_y1, 0, len(all_t)     - 1)

            y0_idx = visible_t.index(all_t[raw_y0])
            y1_idx = visible_t.index(all_t[raw_y1])

            fig.update_layout(
                xaxis=dict(range=[zx0, zx1]),
                yaxis=dict(range=[y0_idx - (zy0 - math.floor(zy0)),
                                  y1_idx + (zy1 - math.floor(zy1))])
            )

        else:     # moving normal-→all (longer y-axis)
            raw_y0 = math.ceil(zy0)
            raw_y1 = math.floor(zy1)

            raw_y0 = clamp(raw_y0, 0, len(visible_t) - 1)
            raw_y1 = clamp(raw_y1, 0, len(visible_t) - 1)

            y0_idx = all_t.index(visible_t[raw_y0])
            y1_idx = all_t.index(visible_t[raw_y1])
            fig.update_layout(
                xaxis=dict(range=[zx0, zx1]),
                yaxis=dict(range=[y0_idx - (zy0 - math.floor(zy0)),
                                  y1_idx + (zy1 - math.floor(zy1))])
            )
    elif zoom:   # no view change – just reuse stored ranges
        fig.update_layout(
            xaxis=dict(range=[zoom['xaxis.range[0]'], zoom['xaxis.range[1]']]),
            yaxis=dict(range=[zoom['yaxis.range[0]'], zoom['yaxis.range[1]']])
        )

    btn_label = 'Hide Missing Tactics' if not flag else 'Show Missing Tactics'
    return fig, btn_label, flag

@callback(
    [Output('save-fdbk', 'children'),
     Output('click-data', 'children')],
    [Input('save-button',    'n_clicks'),
     Input('attack-chain-graph', 'clickData')],
    [State('mitre-dropdown', 'value'),
     State('mpnet-date',     'value'),
     State('name-input',     'value'),
     State('note-input',     'value')],
    prevent_initial_call=True
)
def notes_clickdata(n_clicks, clickData, tactic, date, name, note_input):
    # ----- reference the module-level dict --------------------------
    global NODE_NOTES
    

    ctx          = dash.callback_context
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None

    if not clickData:
        return "Error: No node selected.", dash.no_update

    node_id = hash_node(clickData)
    if not node_id:
        return "Error: Unable to determine node ID.", dash.no_update

    # Make sure we have a slot for this node
    NODE_NOTES.setdefault(node_id, {'notes': []})

    # Save a new note if the save button was the trigger
    if triggered_id == 'save-button' and note_input:
        NODE_NOTES[node_id]['notes'].append(
            {"operator": name, "tactic": tactic, "date": date, "note": note_input}
        )
        with open('db/node_data.json', 'w') as fh:
            json.dump(NODE_NOTES, fh, indent=2)
        feedback = 'Notes Saved!'
    else:
        feedback = ''

    # Build nice hover / note table (unchanged logic)
    hover_txt = re.sub(r'<.*?>', '', clickData['points'][0]['text'])\
                    .replace('Notes:', '\nNotes:')\
                    .replace('Found By:', '\nFound By:')\
                    .replace('Attack Chain:', '\nAttack Chain:')

    notes = NODE_NOTES[node_id]['notes']
    if notes:
        table = dash_table.DataTable(
            data=notes,
            columns=[{"name": k, "id": k} for k in notes[0].keys()],
            style_header={'backgroundColor':'#1e1e1e', 'color':'white'},
            style_data={'backgroundColor':'#323232', 'color':'white'},
            style_cell={'textAlign':'left', 'minWidth':'60px', 'width':'180px'}
        )
        table_div = html.Div([hover_txt, html.H6("Comments:"), table])
    else:
        table_div = html.Div([hover_txt, "\n\nComments are empty."])

    return feedback, [table_div, add_note_btn]

@callback(
    Output('notes-hide', 'style'),
    Input('show-notes-btn-1', 'n_clicks')
)
def notes_hide(n_clicks):
    return {'display': 'block' if n_clicks % 2 == 1 else 'none'}

# ─────────────────────────────────────────────────────────────────────────────


if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')