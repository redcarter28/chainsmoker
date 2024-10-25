# chainsmoker

chainsmoker is a streamlined visualization tool for analyzing network "attack chains" by mapping connections between source IP addresses (with associated port/protocol data) and destination IP addresses. 

## Features
- **Visualize Attack Chains**: Render clear, interactive graphs for identifying connections between IP addresses and protocols involved in attack paths.
- **Automated Reconstruction** Generate Attack Chain reconstructions from a premade excel spreadsheet that operators/analysts can fill out while on desk/duty/mission/etc.
- **Data Management with pandas**: Efficiently manage and manipulate network data for streamlined analysis.
- **Interactive Visualization with pyvis**: Explore network structures interactively to identify key connection points.
- **Storage of Annotated Notes** Dumps additional notes made by operators into a JSON file for easy export

## Requirements

- `pandas`: for data handling and manipulation
- `dash`: To generate frontend in python
- `dash_bootstrap_components`: additional add-on for dash
- `plotly`: allows for visualizations of attack chain data

To install dependencies, use:
```bash
pip install -r req