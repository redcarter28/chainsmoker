# Chainsmoker

Chainsmoker is a streamlined visualization tool for analyzing network attack chains. It reconstructs attack sequences from a premade Excel spreadsheet and displays interactive diagrams via a local Dash web app. The app is accessible on both localhost and your local network (e.g., Rooknet), allowing for easy collaboration and real-time annotations.

## Features

- **Interactive Attack Chain Visualization**:  
  Render clear, time-based diagrams that display attack chain events categorized by MITRE Tactic. Lines connect related events to illustrate the progression of an attack.

- **Automated Reconstruction**:  
  Generate attack chain reconstructions automatically from an Excel spreadsheet populated by operators/analysts.

- **Dynamic Notes Annotation**:  
  Click on individual nodes to view detailed event data and annotate them. Submitted notes are stored in a JSON file for easy export and collaboration.

- **Data Processing with pandas**:  
  Efficiently manage and manipulate network event data for accurate visual representation.

- **Web-Based Dashboard**:  
  The interactive dashboard is served via Dash locally and can be accessed on both localhost and your local network.

## Requirements

- **Python 3.x**
- `pandas` – for data handling and manipulation  
- `dash` – for generating the web frontend  
- `dash_bootstrap_components` – for additional styling  
- `plotly` – for visualizing attack chain data  

## Installation

### Download via Git or ZIP

- **Git Users**:  
  Clone the repository with:
  ```bash
  git clone https://github.com/your_username/chainsmoker.git
  cd chainsmoker
  ```
- **No Git?**  
  Download the project as a ZIP file by clicking **Code > Download ZIP** on GitHub, then extract it.

Next, install the required dependencies:
```bash
pip install -r req.txt
```

## Usage

1. **Prepare Your Data**  
   Populate the premade Excel spreadsheet (`data/data2.xlsx`) with the network event and attack chain data.

2. **Configure the Application (Optional)**  
   Modify settings in the code (such as port numbers, driver paths, or network configuration) if you wish to serve the app on your local network.

3. **Run the Application**  
   Start the Dash server by running:
   ```bash
   python chainsmoker.py
   ```
   The app will be served on **localhost** (e.g., [http://127.0.0.1:8080/](http://127.0.0.1:8080/)) and can also be accessed from any device on your local network (via your Rooknet IP address).

4. **Interact with the App**  
   - Click on nodes in the visualization to view detailed event data and previously submitted notes.
   - Use the input fields to add or modify notes; changes are stored in a JSON file for later export.

## License

maybe someday

## Acknowledgements

yes
