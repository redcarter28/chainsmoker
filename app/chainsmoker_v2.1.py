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
from utility.seconion import OnionHandler
from utility.kb import KibanaHandler
import utility.crypto as crypto
from sqlalchemy import text
from datetime import datetime
import html as h
import json 
from sqlalchemy.exc import IntegrityError
#gay

context = ssl.create_default_context(cafile=certifi.where())
http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs='/usr/local/share/ca-certificates/keycloak.crt'
)
#os.environ['NO_PROXY'] = os.environ.get('NO_PROXY', '') + ',controller.lan'

requireAuth = False # enable or disable OIDC

def auth_required(func):
    if not requireAuth:
        return func  # No-op decorator
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


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


EXPECTED_FINGERPRINT = "CB:12:CC:A5:55:F9:4A:97:97:FE:32:76:E3:89:53:36:76:EF:A3:07" 

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
# 1) Load your config
server.config.update({
    "SECRET_KEY":              os.environ.get("SECRET_KEY", "dev_secret"),
    "SQLALCHEMY_DATABASE_URI": os.environ["DATABASE_URL"],

    # Tell Flask-Session to store sessions in SQLAlchemy…
    "SESSION_TYPE":             "sqlalchemy",
    "SESSION_SQLALCHEMY_TABLE": "flask_sessions",
    "SESSION_PERMANENT":        False,
    "SESSION_COOKIE_SECURE":    False,
    "SESSION_COOKIE_SAMESITE":  "Lax",
    "DEBUG":                    True,
})



# create your single SQLAlchemy() instance
db = SQLAlchemy(server)

# now point Flask-Session at it
server.config["SESSION_SQLALCHEMY"] = db

# initialize Flask-Session, it will pick up your `db`
Session(server)

# ─── SQL TABLE MODEL ────────────────────────────────────────────────
# ─── SQL TABLE MODEL ────────────────────────────────────────────────
class NodeComment(db.Model):
    __tablename__ = "node_comments"

    id       = db.Column(db.Integer, primary_key=True)
    # Changed node_id to Integer FK so it matches attack_chain.row_id
    node_id  = db.Column(
        db.Integer,
        db.ForeignKey("attack_chain.row_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    operator = db.Column(db.String, nullable=False)
    tactic   = db.Column(db.String, nullable=True)
    date     = db.Column(db.String, nullable=True)
    note     = db.Column(db.Text,   nullable=False)
    created  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # back‐reference to the parent chain
    chain    = db.relationship(
        "AttackChain",
        back_populates="comments"
    )

    def to_dict(self):
        return {
            "operator": self.operator,
            "tactic":   self.tactic,
            "date":     self.date,
            "note":     self.note
        }


class AttackChain(db.Model):
    __tablename__ = "attack_chain"

    row_id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date_time_mpnet   = db.Column(db.String,  nullable=False)
    mitre_tactic      = db.Column(db.String,  nullable=False)
    src_ip            = db.Column(db.String,  nullable=False)
    dst_ip            = db.Column(db.String,  nullable=False)
    details           = db.Column(db.Text,    nullable=True)
    notes             = db.Column(db.Text,    nullable=True)
    operator          = db.Column(db.String,  nullable=True)
    attack_chain_name = db.Column(db.String,  nullable=False)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)

    # one‐to‐many to NodeComment, auto‐deleting orphans
    comments = db.relationship(
        "NodeComment",
        back_populates="chain",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

# create both `flask_sessions` + your app tables if missing
with server.app_context():
    db.create_all()

# ─── OAuth Setup ─────────────────────────────────────────────────────────
if requireAuth:
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

# ─── Server Routes ─────────────────────────────────────────────────────────
if requireAuth:
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

        decoded = jwt.decode(token['id_token'], options={"verify_signature": False})
        session["user"] = {
            "sub":   decoded.get("sub"),
            "email": decoded.get("email", decoded.get("preferred_username")),
            "name":  decoded.get("name", decoded.get("preferred_username")),
        }
        session["id_token"] = token["id_token"]
        return redirect("/")

    @server.route("/logout")
    def logout():
        id_token = session.get("id_token")
        session.clear()

        metadata = oauth.keycloak.load_server_metadata()
        end_session = metadata.get(
            "end_session_endpoint",
            os.environ["OIDC_ISSUER"].rstrip("/") + "/protocol/openid-connect/logout"
        )

        post_logout = url_for("login", _external=True)

        # Manual string concatenation (no urlencode)
        url = f"{end_session}?post_logout_redirect_uri={post_logout}"
        if id_token:
            url += f"&id_token_hint={id_token}"

        return redirect(url)

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
    external_stylesheets=[dbc.themes.DARKLY, dbc.icons.BOOTSTRAP],
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
        for d, n, o, ac in zip(chain_df['details'],
                               chain_df['notes'],
                               chain_df['operator'],
                               chain_df['Attack Chain'])
    ]
    return go.Scatter(
        x=chain_df['Date/Time MPNET'].tolist() + [None],
        y=chain_df['MITRE Tactic'].tolist()     + [None],
        customdata=chain_df['row_id'].tolist() if 'row_id' in chain_df.columns else None,
        mode='lines+markers',
        marker=dict(size=12, opacity=.8,
                    color=list(range(len(chain_df))),
                    colorscale='sunset',
                    line=dict(width=1, color='DarkSlateGrey')),
        line=dict(color='grey', width=2),
        text=hover, hoverinfo='text',
        showlegend=True, name=str(chain_id)
    )
    

def chainsmoker(df_local):
    """Return (fig_normal, fig_all, missing, visible, all_tactic_list) from given dataframe."""
    normal = go.Figure(layout=build_base_layout())
    for cid in df_local['Attack Chain'].dropna().unique():
        normal.add_trace(create_trace(df_local[df_local['Attack Chain'] == cid], cid))

    all_tacs = MITRE_TACTICS[::-1]  # top → bottom
    visible = [t for t in all_tacs if t in df_local['MITRE Tactic'].unique()]
    missing = [t for t in all_tacs if t not in visible]
    visible.reverse()

    normal.update_layout(yaxis={'categoryorder': 'array',
                                'categoryarray': visible[::-1]})

    all_fig = go.Figure(normal.to_plotly_json())
    x0 = df_local['Date/Time MPNET'].min()

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

def chainsmoker_db():
    with server.app_context():
        # Read from PostgreSQL table "attack_chain"
        df_db = pd.read_sql_table("attack_chain", con=db.engine)

        # Make sure column names match your expected df columns or rename accordingly
        # For example, if your DB columns don't match original df columns exactly, rename here:
        df_db.rename(columns={
            'date_time_mpnet': 'Date/Time MPNET',
            'mitre_tactic': 'MITRE Tactic',
            'attack_chain_name': 'Attack Chain',
            # add other renames if needed to align with original df
        }, inplace=True)

        # Convert date string column to datetime if necessary, matching original parsing
        df_db['Date/Time MPNET'] = pd.to_datetime(df_db['Date/Time MPNET'], errors='coerce')

        # Sort descending as original
        df_db = df_db.sort_values(by='Date/Time MPNET', ascending=False)

        return chainsmoker(df_db)


fig_normal, fig_all, missing_t, visible_t, all_t = chainsmoker_db()





mitre_dropdown_opts = [{'label': t, 'value': t} for t in MITRE_TACTICS]

def build_dropdown(id_):
    return dcc.Dropdown(id=id_, options=mitre_dropdown_opts,
                        placeholder="Select MITRE Tactic",
                        clearable=False,
                        style={'width': '100%', 'color': '#1a1a1a'},
                        className='InputField dark-dropdown dark-node-dropdown',
                        searchable=True)

# ───── controls / forms (trimmed for brevity – unchanged UI) ─────
name_field = html.Div(dbc.Input(id='name-input', placeholder='Operator',
                                style={'width': '100%'}), className='InputField',style={'width': '100%'})
mitre_drop = build_dropdown('mitre-dropdown')
mpnet_date_field = html.Div(dbc.Input(id='mpnet-date',
                           placeholder='Date/Time MPNET (MM/DD/YYYY, XXXX)',
                           style={'width': '100%', 'height': '%85'}), className='InputField')

save_note_btn = html.Div([
    html.Button('Submit', id='save-button', n_clicks=0,
                className='fancy-button'),
    html.Pre(id='save-fdbk', style={'margin-top': '4px'})
])

form = html.Div(dbc.Form([
    name_field, 
    mitre_drop, 
    mpnet_date_field,
    dcc.Textarea(id='note-input',
                             style={'width':'100%','height':'100px'}),
    save_note_btn
    ],
    style={'padding': '4px', 'margin': '12px'}))

add_note_btn = html.Div([
    html.Button('Add Note', id='show-notes-btn-1', n_clicks=0,
                className='fancy-button', style={'padding': '6px'}),
    html.Pre(id='notes-btn-fdbk-1', style={'margin-top': '4px'})
], style={'text-align':'left', 'padding-right':'20px', 'padding-top':'10px'})



toggle_btn = html.Button('Hide Missing Tactics',
                         id='toggle-list-all-btn', n_clicks=0,
                         className='fancy-button',
                         style={'padding':'6px', 'margin':'12px 12px 4px'})

# a little helper to DRY up our styles
dark_input_style = {
    "width": "100%",
    "backgroundColor": "#2b2b2b",  # your --color-bg-light
    "color":           "#f0f0f0",  # your --color-text
    "border":          "1px solid #555",
}

dark_dropdown_style = {
    "width":           "100%",
    "color":           "#f0f0f0",
}

node_form = html.Div(
    dbc.Form(
        [
            html.Div(
                dbc.Input(
                    id='mpnet-date-input-node',
                    placeholder='Date/Time MPNET (MM/DD/YY, XXXX)',
                    style=dark_input_style
                ),
                className='InputField',
            ), 
            
            # MITRE tactic dropdown
            
                dcc.Dropdown(
                    id='mitre-dropdown-node',
                    options=mitre_dropdown_opts,
                    placeholder="Select MITRE Tactic",
                    clearable=False,
                    style=dark_dropdown_style,
                    className='InputField dark-node-dropdown', 
                    searchable=True
                ),
                
            
            
            html.Div(
                dbc.Input(
                    id='src-ip-node',
                    placeholder='Source Hostname/IP',
                    style=dark_input_style
                ),
                className='InputField',
            ),
            
            html.Div(
                dbc.Input(
                    id='dst-ip-node',
                    placeholder='Destination Hostname/IP',
                    style=dark_input_style
                ),
                className='InputField',
            ),
            
            html.Div(
                dbc.Textarea(
                    id='details-input-node',
                    placeholder='Details',
                    style=dark_input_style
                ),
                className='InputField',
            ),
            
            html.Div(
                dbc.Textarea(
                    id='notes-input-node',
                    placeholder='Notes',
                    style=dark_input_style
                ),
                className='InputField',
            ),
            
            html.Div(
                dbc.Input(
                    id='name-input-node',
                    placeholder='Operator',
                    style=dark_input_style
                ),
                className='InputField',
            ),
            
            html.Div(
                dbc.Input(
                    id='atk-chn-input-node',
                    placeholder='Attack Chain',
                    style=dark_input_style
                ),
                className='InputField',
            ),

            html.Button(
                    'Submit',
                    id='save-button-node',
                    n_clicks=0,
                    className='fancy-button'
            ),
        ], 
        id='node-form',
        style={'padding': '4px', 'margin': '12px'}
    )
)

'''
        html.Div(children=[
            html.Div([
                html.Div([
                    html.Div([
                        html.Div(
                            html.I(className="bi bi-person-fill", style={'color': 'white'}),
                            f"Welcome, {memes('name', str(session.get('user', {}).get('name', 'User')))}"
                            ),
                        html.A("Logout", href="/logout", className="fancy-button"),
                    ], className="top-bar-user"),
                    
                    html.Div(toggle_btn, className="top-bar-toggle"),  # toggle button container
                    html.Div(api_btn, className="top-bar-toggle"),  # toggle button container
                ], className='top-bar', id='top-bar')
            ]),
        ]),
'''



# ─────────────────────────────────────────────────────────────────────────────
#  LAYOUT + HANDLING
# ─────────────────────────────────────────────────────────────────────────────

def serve_layout():
    fig_normal, fig_all, missing_t, visible_t, all_t = chainsmoker_db()
    layout = html.Div([
        dcc.Store(id='fig-store', data={'normal': fig_normal.to_dict(),
                                        'all':    fig_all.to_dict()}),
        dcc.Store(id='zoom-state', storage_type='memory'),
        dcc.Store(id='internal-counter', data=0, storage_type='memory'),
        dcc.Location(id='url', refresh=True),
        

        html.Header(
            children=[
                    # LEFT: logo + title
                    html.Div([
                        html.Img(
                            src="assets/logo.png",
                            style={
                                "display": "inline",
                                "width": "96px",
                                "height": "96px",
                                "padding": "2px"
                            }
                        ),
                        html.Div(
                            "Chainsmoker",
                            style={
                                "display": "inline",
                                "font-size": "calc(24px + .75vw)"
                            }
                        ),
                    ], className="page-title"),
                    
                    # RIGHT: nav
                    dbc.Nav([
                        dbc.NavItem(dbc.NavLink("Home", href="/"), style={'border-radius':'4px', 'border': '1px solid #555;'}),
                        dbc.NavItem(
                            html.Div(
                                dbc.DropdownMenu(
                                    nav=True,          # Render as a nav‐item
                                    in_navbar=True,    # Bootstrap navbar styling
                                    caret=True,        # keep the little ▼
                                    label=html.Span(
                                        [
                                            html.I(className="bi bi-person-fill me-1"),
                                            " Welcome, User"
                                        ],
                                        style={"whiteSpace": "nowrap"}  # no wrapping
                                    ),
                                    children=[
                                        dbc.DropdownMenuItem("Settings", href="/settings"),
                                    ],
                                )
                            )
                        ),
                    ], className="header-nav", navbar=True, style={'margin-right': '12px'}),
                ],
                style={
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "space-between",
                    "padding-top": "0.25rem",
                    "border-bottom": "1px solid #5d696c"
                }
            ),

        html.Div(id="page-content"),

        html.Footer('chainsmoker v0.2beta (CKF25-1 Build)', style={
            'fontSize': '12px',
            'textAlign': 'center',
            'padding': '8px',
            'backgroundColor': '#222',
            'color': '#ccc',
        }),
    ],
    style={
        'display': 'flex',
        'flexDirection': 'column',
        'minHeight': '100vh',
    })
    return layout

app.layout = serve_layout
app.title = 'Chainsmoker'

graph_view = [
    toggle_btn,
    dcc.Graph(
        id='attack-chain-graph',
        figure=fig_all,
        config=PLOT_CONFIG,
        className='fig',
        style={'margin':'12px'}
    ),

    html.Div(
        [
            dbc.Button("📝 Add Note", id="btn-toggle-notes", n_clicks=0,
                       className="fancy-button"),
            dbc.Button("➕ Add Node", id="btn-toggle-node", n_clicks=0,
                       className="fancy-button", style={'marginLeft':'8px'}),
            dbc.Button("🗑️ Delete Node", id="btn-delete-node", n_clicks=0,
                       className="fancy-button",
                       style={'marginLeft':'8px'},
                       disabled=True),
        ], style={'margin':'12px 12px 4px'}
    ),

    html.Div(id="note-alert", style={'margin':'12px'}),  
    html.Div(id="delete-fdbk", style={'margin':'12px'}),

    html.Pre('Click on a node to view comments', id='click-data',
        className='fancy-border', style={'margin':'12px'}),

    

    # collapse for notes
    dbc.Collapse(
        html.Div(
            [
                form,
            ],
            className='three columns'
        ),
        id='collapse-notes',
        is_open=False
    ),

    # collapse for node form
    dbc.Collapse(
        html.Div(
            [
                node_form,
                html.Pre(id='save-fdbk-node', style={'marginTop':'4px'})
            ],
            className='three columns'
        ),
        id='collapse-node',
        is_open=False
    )
]

settings_view = dbc.Container([
    html.H2("⚙️ Settings"),
    dbc.Tabs(id="settings-tabs", active_tab="tab-api", children=[
        dbc.Tab(label="API Configuration", tab_id="tab-api"),
        dbc.Tab(label="Other Stuff",     tab_id="tab-other"),
    ]),
    html.Div(id="tabs-content"),
], className="p-4")

# ─────────────────────────────────────────────────────────────────────────────
#  CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────
@callback(
    Output('page-content', 'children'),
    Input('url', 'pathname')
)
def display_page(pathname):
    match pathname:
        case "/settings":
            return settings_view
    
    return graph_view

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
    Output('attack-chain-graph', 'figure', allow_duplicate=True),
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
    [Output('save-fdbk',    'children'),
     Output('click-data',   'children')],
    [Input('save-button',    'n_clicks'),
     Input('attack-chain-graph', 'clickData')],
    [State('mitre-dropdown', 'value'),
     State('mpnet-date',     'value'),
     State('name-input',     'value'),
     State('note-input',     'value')],
    prevent_initial_call=True
)
def notes_clickdata(n_clicks, clickData, tactic, date, name, note_input):
    if not clickData:
        return "Error: No node selected.", dash.no_update

    node_id = hash_node(clickData)
    if not node_id:
        return "Error: Unable to determine node ID.", dash.no_update

    feedback = ""
    # If they clicked Save, insert a new row in node_comment
    ctx_id = dash.callback_context.triggered[0]["prop_id"].split(".")[0]
    if ctx_id == "save-button" and note_input:
        comment = NodeComment(
            node_id=node_id,
            operator=name or "unknown",
            tactic=tactic,
            date=date,
            note=note_input,
        )
        db.session.add(comment)
        db.session.commit()
        feedback = "Notes Saved!"

    # Now always re-query all comments for this node_id
    comments = NodeComment.query.filter_by(node_id=node_id).order_by(NodeComment.created).all()
    notes = [
        {
          "operator": c.operator,
          "tactic":   c.tactic,
          "date":     c.date,
          "note":     c.note
        }
        for c in comments
    ]

    # Build your hover text + table as before
    raw_text = clickData["points"][0]["text"]
    hover_txt = (h.unescape(
                    re.sub(r"<.*?>", "", re.sub(r"(<br\s*/?>)+", "\n", raw_text))
                )
                .replace("Found By:", "\nOperator:")
                .replace("Attack Chain:", "\nAttack Chain:"))

    if notes:
        table = dash_table.DataTable(
            data=notes,
            columns=[{"name": k, "id": k} for k in notes[0].keys()],
            style_header={'backgroundColor':'#1e1e1e','color':'white'},
            style_data={'backgroundColor':'#323232','color':'white'},
            style_cell={'textAlign':'left','minWidth':'60px','width':'180px'}
        )
        table_div = html.Div([hover_txt, html.H6("Comments:"), table])
    else:
        table_div = html.Div([hover_txt, "\n\nComments are empty. Consider hunting harder."])

    return feedback, [table_div]

@callback(
    Output('notes-hide', 'style'),
    Input('show-notes-btn-1', 'n_clicks')
)
def notes_hide(n_clicks):
    return {'display': 'block' if n_clicks % 2 == 1 else 'none'}

@callback(
    Output('save-fdbk-node',    'children'),
    Output('attack-chain-graph', 'figure'),
    Output('fig-store',          'data', allow_duplicate=True),
    Input('save-button-node',    'n_clicks'),
    State('mpnet-date-input-node','value'),
    State('mitre-dropdown-node', 'value'),
    State('src-ip-node',         'value'),
    State('dst-ip-node',         'value'),
    State('details-input-node',  'value'),
    State('notes-input-node',    'value'),
    State('name-input-node',     'value'),
    State('atk-chn-input-node',  'value'),
    prevent_initial_call=True
)
def save_node(n_clicks, date, tactic, src, dst, details, notes, name, chain):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    # 1) Write to DB
    new_chain = AttackChain(
        date_time_mpnet   = date,
        mitre_tactic      = tactic,
        src_ip            = src,
        dst_ip            = dst,
        details           = details,
        notes             = notes,
        operator          = name,
        attack_chain_name = chain
    )
    db.session.add(new_chain)
    db.session.commit()

    # 2) Rebuild both figures and the store
    fig_normal, fig_all, *_ = chainsmoker_db()
    fig_store = {
        'normal': fig_normal.to_dict(),
        'all':    fig_all.to_dict()
    }

    feedback = dbc.Alert('✅ Node Saved!', style={'color': 'success'}, duration=3000)

    return feedback, fig_normal, fig_store


@app.callback(
    Output("api-url-label", "children"),
    Input("api-type", "value")
)
def update_label(api_type):
    if api_type == "kb":
        return "Kibana API Endpoint"
    return "Base URL"

@callback(Output("tabs-content", "children"),
          Input("settings-tabs", "active_tab"))
def render_settings_tab(active_tab):
    url_desc = ""
    if active_tab == "tab-api":
        return html.Div([
            # API SECTION
            html.Div([
                html.H3("🔌 API Configuration", className="section-title"),
                dbc.Label("Which Case API?", html_for="api-type"),
                dbc.Select(
                    id="api-type",
                    options=[
                      {"label": "Security Onion (Kibana)", "value": "so"},
                      {"label": "Regular Kibana",       "value": "kb"},
                    ],
                    value=session.get("api_type", "so"),
                    className="text-dark"
                ),
                            # ———————————————————————————————————————————
            # Base URL
            # ———————————————————————————————————————————
            html.Div([
                dbc.Label(url_desc, html_for="api-url"),
                dbc.Input(
                    id="api-url",
                    type="url",
                    placeholder="https://x.x.x.x",
                    value=session.get("api_url", ""),
                ),
            ], className="mb-3"),
            
            # ———————————————————————————————————————————
            # Username
            # ———————————————————————————————————————————
            html.Div([
                dbc.Label("Username", html_for="api-username"),
                dbc.Input(
                    id="api-username",
                    type="text",
                    placeholder="onion@fake.local",
                    value=session.get("api_username", ""),
                    # if you wanted to control the HTML size attribute:
                    # html_size=30,
                ),
            ], className="mb-3"),

            # ———————————————————————————————————————————
            # Password
            # ———————————————————————————————————————————
            html.Div([
                dbc.Label("Password", html_for="api-password"),
                dbc.Input(
                    id="api-password",
                    type="password",
                    placeholder="••••••••",
                    value=session.get("api_password", ""),
                ),
            ], className="mb-3"),

            # ———————————————————————————————————————————
            # API Key
            # ———————————————————————————————————————————
            html.Div([
                dbc.Label("API Key", html_for="api-key"),
                dbc.Input(
                    id="api-key",
                    type="text",
                    placeholder="Base64 Format (or leave blank if not using)",
                    value=session.get("api_key", ""),
                ),
            ], className="mb-3"),
                html.Div([
                    # Change to fancy-button
                    html.Button("Save API Settings",
                               id="btn-save-api",
                               className="fancy-button"),
                    html.Button("Pull Cases",
                               id="api-btn",
                               className="fancy-button",
                               style={"marginLeft": "12px"}),
                ], className="button-row"),
                
                html.Span(id="save-api-feedback", className="ms-3"),
                html.Span(id="api-btn-fdbk", className="ms-3")
    
            ], className="setting-section api-section"),

        ])

    elif active_tab == "tab-other":
        return dbc.CardBody([
            html.P("hello")
        ])

    return "No tab selected"


@callback(
    Output("save-api-feedback", "children"),
    Input("btn-save-api",   "n_clicks"),
    State("api-type",       "value"),
    State("api-url",        "value"),
    State("api-username",   "value"),
    State("api-password",   "value"),
    State("api-key",        "value"),
    prevent_initial_call=True
)
def save_api_settings(n, api_type, url, user, pwd, key):
    # encrypt the secrets
    session["api_type"]     = api_type
    session["api_url"]      = url
    session["api_username"] = user
    session["api_password"] = crypto.encrypt_secret(pwd)
    if key:
        session["api_key"] = crypto.encrypt_secret(key)
    else:
        session.pop("api_key", None)
    return dbc.Alert("✅ Saved!", color="success", duration=2000)

@callback(
    Output("api-btn-fdbk",    "children"),
    Output("fig-store",       "data", allow_duplicate=True),
    Input("api-btn",          "n_clicks"),
    prevent_initial_call=True
)
def pull_cases(n_clicks):

    if not n_clicks:
        return dash.no_update, dash.no_update

    # (optional) also check that the trigger *was* the button
    if dash.callback_context.triggered_id != "api-btn":
        return dash.no_update, dash.no_update

    api_type = session.get("api_type")
    base_url = session.get("api_url")
    user     = session.get("api_username")
    pwd_enc  = session.get("api_password", "")
    key_enc  = session.get("api_key", "")

    pwd = crypto.decrypt_secret(pwd_enc) if pwd_enc else None
    key = crypto.decrypt_secret(key_enc) if key_enc else None

    if api_type == "so":
        handler = OnionHandler(base_url=base_url,
                               username=user,
                               password=pwd,
                               api_key=key)
        
    if api_type == "kb":
        handler = KibanaHandler(base_url=base_url,
                               username=user,
                               password=pwd,
                               api_key=key)


    raw_json = handler.login_and_cases()
    cases_obj = json.loads(raw_json)["cases"]

    cases_obj = [c for c in cases_obj if "chainsmoker" in c.get("tags", [])]

    handler.cases_to_dataframe(cases_obj)
    df_new = handler.cases  # pandas.DataFrame

    for _, row in df_new.iterrows():
        ac = AttackChain(
            date_time_mpnet     = row["Date/Time MPNET"],
            mitre_tactic        = row["MITRE Tactic"],
            src_ip              = row["Source Hostname/IP"],
            dst_ip              = row["Target Hostname/IP"],
            details             = row["Details"],
            notes               = row["Notes"],
            operator            = row["Operator"],
            attack_chain_name   = row["Attack Chain"],
        )
        db.session.add(ac)

    db.session.commit()

    fig_normal, fig_all, missing_t, visible_t, all_t = chainsmoker_db()
    fig_store = {
        "normal": fig_normal.to_dict(),
        "all":    fig_all.to_dict()
    }

    return dbc.Alert(
            f"✅ Retrieved {len(df_new)} case(s)",
            color="success",
            dismissable=True,
            fade=False
        ), fig_store

@callback(
    Output("collapse-notes", "is_open"),
    Output("collapse-node",  "is_open"),
    Output("note-alert",     "children"),
    Input("btn-toggle-notes", "n_clicks"),
    Input("btn-toggle-node",  "n_clicks"),
    State("collapse-notes",  "is_open"),
    State("collapse-node",   "is_open"),
    State("attack-chain-graph", "clickData")
)
def toggle_forms(n_notes, n_node, open_notes, open_node, clickData):
    ctx = dash.callback_context.triggered_id

    # If the user clicked “Add Note”
    if ctx == "btn-toggle-notes":
        # If no node is selected in the graph, show an alert and keep both collapsed
        if not clickData or not clickData.get("points"):
            alert = dbc.Alert(
              "You must click a node first",
              color="indianred",
              duration=4000,
              is_open=True,
              dismissable=True
            )
            return False, False, alert

        # Otherwise, clear any alert and toggle the notes panel
        return (not open_notes), False, dash.no_update

    # If the user clicked “Add Node” – just close notes, clear any alert, and toggle node panel
    if ctx == "btn-toggle-node":
        return False, (not open_node), dash.no_update

    # on initial load or anything else – hide both panels + clear alert
    return False, False, dash.no_update

@callback(
    Output("btn-delete-node", "disabled"),
    Input("attack-chain-graph", "clickData"),
)
def toggle_delete_button(clickData):
    # Enable delete once you have valid clickData / row_id
    if clickData and hash_node(clickData):
        return False
    return True

@callback(
    Output("delete-fdbk", "children"),
    Output("fig-store",  "data", allow_duplicate=True),
    Input("btn-delete-node",  "n_clicks"),
    State("attack-chain-graph", "clickData"),
    prevent_initial_call=True
)
def delete_selected_node(n_clicks, clickData):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    node_id = hash_node(clickData)
    if not node_id:
        return "Error: no node selected.", dash.no_update

    # delete from DB
    chain = AttackChain.query.filter_by(row_id=int(node_id)).first()
    if not chain:
        return f"Node {node_id} not found in database.", dash.no_update

    db.session.delete(chain)
    db.session.commit()

    # rebuild figures
    fig_normal, fig_all, *_ = chainsmoker_db()
    fig_store = {
        'normal': fig_normal.to_dict(),
        'all':    fig_all.to_dict()
    }

    return dbc.Alert("Deleted Node Successfully", color="warning", duration=4000), fig_store
# ─────────────────────────────────────────────────────────────────────────────


if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')

