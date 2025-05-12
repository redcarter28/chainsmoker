# ─────────────────────────────────────────────────────────────────────────────
#  CHAINS​MOKER – unified & stateless & uhhhh uhhh uh um
# ─────────────────────────────────────────────────────────────────────────────
import os, re, json, math, hashlib
from itertools import product
import dash
from dash import dcc, html, dash_table, callback, Input, Output, State
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.graph_objects as go
from openpyxl import load_workbook                                   # noqa
from sqlalchemy import create_engine
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, session, redirect, url_for, request
from authlib.integrations.flask_client import OAuth
import ssl
import hashlib
import socket
from urllib.parse import urlparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from authlib.integrations.requests_client import OAuth2Session
import certifi
import secrets
import jwt
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from integrations.seconion import OnionHandler

context = ssl.create_default_context(cafile=certifi.where())
http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs='/usr/local/share/ca-certificates/keycloak.crt'
)
#os.environ['NO_PROXY'] = os.environ.get('NO_PROXY', '') + ',controller.lan'

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

# The certificate fingerprint you got from the openssl command
EXPECTED_FINGERPRINT = "CB:12:CC:A5:55:F9:4A:97:97:FE:32:76:E3:89:53:36:76:EF:A3:07"  # Replace with your actual fingerprint

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

def hash_node(clickData):
    """Return the stable row_id that was stored in customdata."""
    if clickData and clickData.get('points'):
        return str(clickData['points'][0].get('customdata'))
    return None

def clamp(i: int, lo: int, hi: int) -> int:
    """Return i clamped to the closed interval [lo, hi]."""
    return max(lo, min(i, hi))

def memes(i, value):
    match i:
        case 'name':
            if 'Blake Davidson' in value:
                return 'Blakonater (w/ cheese)'
            if 'Abraham Molina' in value:
                return 'chainsmonker'
            if 'Cracraft' in value:
                return 'The Venerable (Honorable) Distinguished Chief Warrant Officer 2 (II, two) Mr. Sir Dennis Cracraft'
    return value

# ─────────────────────────────────────────────────────────────────────────────
#  DATA LOAD
# ─────────────────────────────────────────────────────────────────────────────
df = pd.read_excel('app/data/data2.xlsx', engine='openpyxl')
df.reset_index(inplace=True)          # gives an 'index' column 0..N-1
df.rename(columns={'index': 'row_id'}, inplace=True)


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

# ─── FLASK & SESSION SETUP ────────────────────────────────────────────────
server = Flask(__name__)
server.config.update({
    "SECRET_KEY":               os.environ.get("SECRET_KEY", "dev_secret"),
    "SQLALCHEMY_DATABASE_URI":  os.environ["DATABASE_URL"],

    # Tell Flask-Session to store sessions in SQLAlchemy…
    "SESSION_TYPE":             "sqlalchemy",
    "SESSION_SQLALCHEMY":       None,               # <-- placeholder
    "SESSION_SQLALCHEMY_TABLE": "flask_sessions",
    "SESSION_PERMANENT":        False,
    "SESSION_COOKIE_SECURE":    False,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    "SESSION_COOKIE_SAMESITE":  "Lax",
    'DEBUG': True,
    
})

# create your single SQLAlchemy() instance
db = SQLAlchemy(server)

# now point Flask-Session at it
server.config["SESSION_SQLALCHEMY"] = db

# initialize Flask-Session, it will pick up your `db`
Session(server)

# create both `flask_sessions` + your app tables if missing
with server.app_context():
    db.create_all()

# ─── COMMENT MODEL ────────────────────────────────────────────────
class NodeComment(db.Model):
    __tablename__ = "node_comments"
    id        = db.Column(db.Integer, primary_key=True)
    node_id   = db.Column(db.String, nullable=False, index=True)
    operator  = db.Column(db.String, nullable=False)
    tactic    = db.Column(db.String, nullable=True)
    date      = db.Column(db.String, nullable=True)
    note      = db.Column(db.Text,   nullable=False)

    def to_dict(self):
        return {
            "operator": self.operator,
            "tactic":   self.tactic,
            "date":     self.date,
            "note":     self.note
        }

# ─── OAuth Setup ─────────────────────────────────────────────────────────
oauth = OAuth(server)
oauth.register(
    name='keycloak',
    client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    server_metadata_url=f"{os.environ['OIDC_ISSUER']}/.well-known/openid-configuration",
    client_kwargs={
        'scope': 'openid email profile',
    }
)

# Now register Keycloak with Authlib, telling it to use our session_class
oauth = OAuth(server)
OIDC_ISSUER = os.environ["OIDC_ISSUER"]
oauth.register(
    name="keycloak",
    client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid common_attributes_openid",
        "verify": "/usr/local/share/ca-certificates/keycloak.crt",
    },
)
# ─── Auth Check Function ─────────────────────────────────────────────────────────
def auth_required(func):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# ─── Auth Routes ─────────────────────────────────────────────────────────
@server.route("/login")
def login():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    return oauth.keycloak.authorize_redirect(
        redirect_uri=os.environ["OAUTH_REDIRECT_URI"],
        nonce=nonce,
    )

@server.route("/oidc/callback")
def auth_cb():
    token = oauth.keycloak.authorize_access_token()
    if 'id_token' not in token:
        return "No id_token!", 400

    # decode just to pull out sub/email/name (you can skip signature‐verify for demo)
    decoded = jwt.decode(token['id_token'], options={"verify_signature": False})
    session["user"]     = {
      "sub":   decoded.get("sub"),
      "email": decoded.get("email", decoded.get("preferred_username")),
      "name":  decoded.get("name", decoded.get("preferred_username")),
    }
    # <-- store the raw id_token so we can hint Keycloak on logout
    session["id_token"] = token["id_token"]

    return redirect("/")

from urllib.parse import urlencode

@server.route("/logout")
def logout():
    # Grab the raw id_token_hint we saved
    id_token = session.get("id_token")

    # Wipe out our Flask session first
    session.clear()

    # Pull Keycloak’s metadata yourself
    metadata = oauth.keycloak.load_server_metadata()
    end_session = metadata.get(
        "end_session_endpoint",
        # fallback if metadata is missing
        os.environ["OIDC_ISSUER"].rstrip("/") 
        + "/protocol/openid-connect/logout"
    )

    # Where to send them back once Keycloak logs you out
    post_logout = url_for("login", _external=True)

    # Build the query string
    params = {
        "post_logout_redirect_uri": post_logout
    }
    if id_token:
        params["id_token_hint"] = id_token

    return redirect(f"{end_session}?{urlencode(params)}")

# ─── Public Routes Middleware ─────────────────────────────────────────────────────────
@server.before_request
def check_auth():
    public_paths = ["/login", "/oidc", "/_dash-", "/assets", "/favicon.ico"]
    if not session.get("user") and not any(request.path.startswith(p) for p in public_paths):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # For AJAX requests, return a 401 status code
            return "Unauthorized", 401
        return redirect("/login")


# ─── DASH APP ─────────────────────────────────────────────────────────────
app = dash.Dash(
    __name__,
    server=server,
    external_stylesheets=[dbc.themes.DARKLY],
    suppress_callback_exceptions=True,
    routes_pathname_prefix='/'
)

# ─────────────────────────────────────────────────────────────────────────────
#  FIGURE LAYOUT BUILD
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

# ─── Auth Middleware ─────────────────────────────────────────────────────────
# Create middleware that will handle auth checks for Dash
class AuthMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Get the Flask request object
        with server.request_context(environ):
            # Check if user is authenticated
            if not session.get("user"):
                # Check if this is a path that should be public
                path = environ.get('PATH_INFO', '')
                public_paths = ["/login", "/oidc", "/_dash-", "/assets", "/favicon.ico"]
                
                if not any(path.startswith(p) for p in public_paths):
                    # Redirect to login for protected routes
                    redirect_response = redirect("/login")
                    return redirect_response(environ, start_response)
            
            # Continue with the request if authenticated or public path
            return self.app(environ, start_response)


server.wsgi_app = AuthMiddleware(server.wsgi_app)

# ─────────────────────────────────────────────────────────────────────────────
#  FIGURE BUILD
# ─────────────────────────────────────────────────────────────────────────────

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
        customdata=chain_df['row_id'].tolist(),
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

mitre_dropdown_opts = [{'label': t, 'value': t} for t in MITRE_TACTICS]

def build_dropdown(id_):
    return dcc.Dropdown(id=id_, options=mitre_dropdown_opts,
                        placeholder="Select MITRE Tactic",
                        clearable=False,
                        style={'width': '100%', 'color': 'black'},
                        className='InputField')

# ───── controls / forms (trimmed for brevity – unchanged UI) ─────
name_field = html.Div(dbc.Input(id='name-input', placeholder='Operator',
                                style={'width': '100%'}), className='InputField')
mitre_drop = build_dropdown('mitre-dropdown')
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

csrf_btn = html.Button('Test CSRF',
                         id='csrf-btn', n_clicks=0,
                         className='fancy-button',
                         style={'padding':'6px', 'margin-top':'2px'})

node_form = html.Div(
    dbc.Form(
        [
            html.Div(
                [   
                    dbc.Input(id='mpnet-date-input-node', placeholder='Date/Time MPNET (MM/DD/YY, XXXX)', style={'width': '100%'}),
                ],
                className='InputField',
            ), 
            dcc.Dropdown(
                    options=mitre_dropdown_opts,
                    placeholder="Select MITRE Tactic",
                    clearable=False,
                    style={'width': '99.9%', 'color': 'black'},
                    id='mitre-dropdown-node',
                    className='InputField'
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



# ─────────────────────────────────────────────────────────────────────────────
#  LAYOUT + HANDLING
# ─────────────────────────────────────────────────────────────────────────────

def serve_layout():
    layout = html.Div([
        dcc.Store(id='fig-store', data={'normal': fig_normal.to_dict(),
                                        'all':    fig_all.to_dict()}),
        dcc.Store(id='zoom-state', storage_type='memory'),
        dcc.Store(id='internal-counter', data=0, storage_type='memory'),
        dcc.Location(id='url', refresh=True),
        

        html.H1(children=[
                html.Img(src='assets/logo.png', 
                        style={'display':'inline', 'width':'96px', 'height':'96px', 'padding':'2px'}),
                html.Div('Chainsmoker', style={'font-size':'calc(24px + .75vw)'})
            ], className='page-title'),


        html.Div(children=[
            html.Div([
                html.Div([
                    html.Div([
                        html.Div(f"Welcome, {memes('name', str(session.get('user', {}).get('name', 'User')))}"),
                        html.A("Logout", href="/logout", className="fancy-button"),
                    ], className="top-bar-user"),
                    
                    html.Div(toggle_btn, className="top-bar-toggle"),  # toggle button container
                    html.Div(csrf_btn, className="top-bar-toggle"),  # toggle button container
                ], className='top-bar', id='top-bar')
            ]),
        ]),

        html.Pre(id='csrf-btn-fdbk', style={'font-size': 'medium'}),

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

        # --- note input -----------------------------------------------------
        
        html.Div([
                node_form,
                html.Button('Submit', 
                        id='save-button-node', 
                        n_clicks=0, 
                        style={'padding': '6px', 'margin-top': '2px'}, 
                        className='fancy-button'),
                html.Pre(id='save-fdbk-node', style={'margin-top': '4px'})
            ], id='node-hide', style={'text-align':'left', 'visible': 'block', 'padding-left':'8px'}),


    ])
    return layout

app.layout = serve_layout


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
        comment = NodeComment(
            node_id=str(node_id),
            operator=name or "unknown",
            tactic=tactic,
            date=date,
            note=note_input
        )
        db.session.add(comment)
        db.session.commit()

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

@callback(
    Output('save-fdbk-node', 'children'),
    Output('fig-store', 'data'),
    Input('save-button-node', 'n_clicks'),
    State('mpnet-date-input-node', 'value'),
    State('mitre-dropdown-node', 'value'),
    State('src-ip-node', 'value'),
    State('dst-ip-node', 'value'),
    State('details-input-node', 'value'),
    State('notes-input-node', 'value'),
    State('name-input-node', 'value'),
    State('atk-chn-input-node', 'value'),
    prevent_initial_call=True
)
def save_node(
    n_clicks, date, tactic, src, dst, details, notes, name, chain
):
    if not n_clicks:
        return dash.no_update, dash.no_update
    # Validate required fields
    if not (date and tactic and src and dst and chain):
        return html.Pre('Error: please fill out all required fields.', style={'color': 'indianred'}), dash.no_update
    
    # DATE VALIDATION
    import re
    if not re.match(r"\d{2}/\d{2}/\d{4}, \d{4}$", date):
        return html.Pre('Error: Incorrect date/time format.', style={'color': 'indianred'}), dash.no_update
    
    # Reload the dataframe fresh
    df = pd.read_excel('data/data2.xlsx', engine='openpyxl')
    if 'row_id' not in df.columns:
        df.reset_index(inplace=True)
        df.rename(columns={'index': 'row_id'}, inplace=True)
    
    # Add new row
    new_row_id = int(df['row_id'].max()) + 1 if len(df) else 0
    new_row = {
        'row_id': new_row_id,
        'Date/Time MPNET': date,
        'MITRE Tactic': tactic,
        'Source Hostname/IP': src,
        'Target Hostname/IP': dst,
        'Details': details,
        'Notes': notes,
        'Operator': name,
        'Attack Chain': chain
    }
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    # Persist to Excel
    df.to_excel('data/data2.xlsx', index=False)
    
    # Rebuild figures… assuming stateless `chainsmoker()` exists (see previous context)

    fig_normal, fig_all, missing_t, visible_t, all_t = chainsmoker()  # no globals!
    fig_store = {'normal': fig_normal.to_dict(), 'all': fig_all.to_dict()}

    return html.Pre('Node Saved!', style={'color': 'limegreen'}), fig_store

@callback(
    Output('csrf-btn-fdbk', 'children'),
    Input('csrf-btn', 'n_clicks')
)
def csrf_fdbk(n_clicks):
    if n_clicks:
        handler = OnionHandler(base_url="172.25.7.201")

        return handler.get_csrf_token()

# ─────────────────────────────────────────────────────────────────────────────


if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')

