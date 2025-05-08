import dash, dash_bootstrap_components as dbc

if __name__ == '__main__':
    app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
    app.run_server(port=8080, host = '0.0.0.0')