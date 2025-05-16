# Chainsmoker 
<p align="center">
  <img src="app/assets/logo.png" alt="App Logo" width="200" />
</p>


A Chainsmoker is a dockerized Dash-based web application for viewing, annotating, and managing MITRE-style attack chains.  


---

## Table of Contents

1. [Features](#features)  
2. [Requirements](#requirements)  
3. [Installation](#installation)  
4. [Database Setup](#database-setup)  
5. [Running the App](#running-the-app)  
6. [Deleting & Recreating All Tables](#deleting--recreating-all-tables)  
7. [Contributing](#contributing)  
8. [License](#license)  

---

## Features

- Interactive attack-chain graph
- Add/Edit/Delete nodes & comments  
- Persistent storage in PostgreSQL (via Docker)  
- Automatic cascade delete of comments when a node is removed  
- Supports pulling of case data from Kibana

---

## Requirements

- Docker  
- Docker Compose  
- See `req.txt` for any additional service definitions  

---

## Installation

1. Clone the repo  
   ```bash
   git clone https://github.com/redcarter28/chainsmoker
   cd chainsmoker
   ```
2. Fill out the `sample.env` file and rename to `.env`

3. Build and start all services via Docker Compose  
   ```bash
   docker-compose up --build
   ```

4. The Dash app will be running at  
   ```
   http://localhost:8080
   ```

---

## Database Setup

The Postgres container is defined in `docker-compose.yml`. On first startup it will create the database schema automatically via Flask-Migrate/`db.create_all()`.  

If you ever need a fresh start, see **Deleting & Recreating All Tables** below.

---

## Running the App

With Docker Compose up, your services are:

- **web**: Dash/Flask application on port 8080  
- **db**: PostgreSQL on port 5432  (must expose in dockerfile)

## Deleting & Recreating All Tables

To **drop every table** in your public schema and start fresh, run the following while exec'd inside of postgres: 

`psq -U chainsmoker -W chainsmoker` 


SQL Commands:

```sql
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
```

Then restart the master container to re-build the schema.

---

## Contributing

idk 

---

## License

[MIT License](LICENSE)  