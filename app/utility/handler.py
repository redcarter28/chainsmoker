from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import requests
import pandas as pd

sample_cases = {
  "page": 1,
  "cases": [
    {
      "id": "case-001",
      "tags": ["chainsmoker"],
      "owner": "analyst1",
      "title": "Initial Access Detected",
      "status": "open",
      "created_at": "2025-04-01T08:30:00Z",
      "updated_at": "2025-04-01T09:00:00Z",
      "description": "Suspicious login from unknown IP.",
      "totalAlerts": 3,
      "totalComment": 2,
      "customFields": [
        {
          "key": "date_time_mpnet",
          "type": "text",
          "value": "04/01/2025, 0830"
        },
        {
          "key": "mitre_tactic",
          "type": "text",
          "value": "Initial Access"
        },
        {
          "key": "src_ip",
          "type": "text",
          "value": "192.168.1.5"
        },
        {
          "key": "dst_ip",
          "type": "text",
          "value": "10.0.0.15"
        },
        {
          "key": "details",
          "type": "text",
          "value": "Detected brute force on SSH."
        },
        {
          "key": "notes",
          "type": "text",
          "value": "Urgent follow-up needed."
        },
        {
          "key": "operator",
          "type": "text",
          "value": "Alice Smith"
        },
        {
          "key": "attack_chain_name",
          "type": "text",
          "value": "Early Compromise"
        }
      ]
    },
    {
      "id": "case-002",
      "tags": ["chainsmoker"],
      "owner": "analyst2",
      "title": "Persistence Mechanism Found",
      "status": "open",
      "created_at": "2025-04-02T11:15:00Z",
      "updated_at": "2025-04-02T11:45:00Z",
      "description": "Malware installed scheduled task.",
      "totalAlerts": 5,
      "totalComment": 1,
      "customFields": [
        {
          "key": "date_time_mpnet",
          "type": "text",
          "value": "04/02/2025, 1115"
        },
        {
          "key": "mitre_tactic",
          "type": "text",
          "value": "Persistence"
        },
        {
          "key": "src_ip",
          "type": "text",
          "value": "10.0.0.5"
        },
        {
          "key": "dst_ip",
          "type": "text",
          "value": "10.0.0.50"
        },
        {
          "key": "details",
          "type": "text",
          "value": "Scheduled task created for malware startup."
        },
        {
          "key": "notes",
          "type": "text",
          "value": "Confirmed by endpoint team."
        },
        {
          "key": "operator",
          "type": "text",
          "value": "Bob Jones"
        },
        {
          "key": "attack_chain_name",
          "type": "text",
          "value": "Persistence Attack"
        }
      ]
    },
    {
      "id": "case-003",
      "tags": ["chainsmoker"],
      "owner": "analyst3",
      "title": "Lateral Movement Activity",
      "status": "open",
      "created_at": "2025-04-03T14:00:00Z",
      "updated_at": "2025-04-03T14:30:00Z",
      "description": "Unusual SMB traffic observed.",
      "totalAlerts": 7,
      "totalComment": 3,
      "customFields": [
        {
          "key": "date_time_mpnet",
          "type": "text",
          "value": "04/03/2025, 1400"
        },
        {
          "key": "mitre_tactic",
          "type": "text",
          "value": "Lateral Movement"
        },
        {
          "key": "src_ip",
          "type": "text",
          "value": "10.0.0.50"
        },
        {
          "key": "dst_ip",
          "type": "text",
          "value": "10.0.0.75"
        },
        {
          "key": "details",
          "type": "text",
          "value": "Suspicious SMB share access."
        },
        {
          "key": "notes",
          "type": "text",
          "value": "Further investigation required."
        },
        {
          "key": "operator",
          "type": "text",
          "value": "Carol Lee"
        },
        {
          "key": "attack_chain_name",
          "type": "text",
          "value": "Movement Phase"
        }
      ]
    },
    {
      "id": "case-004",
      "tags": ["chainsmoker"],
      "owner": "analyst4",
      "title": "Data Exfiltration Attempt",
      "status": "open",
      "created_at": "2025-04-04T16:45:00Z",
      "updated_at": "2025-04-04T17:00:00Z",
      "description": "Large data transfer detected to external IP.",
      "totalAlerts": 2,
      "totalComment": 2,
      "customFields": [
        {
          "key": "date_time_mpnet",
          "type": "text",
          "value": "04/04/2025, 1645"
        },
        {
          "key": "mitre_tactic",
          "type": "text",
          "value": "Exfiltration"
        },
        {
          "key": "src_ip",
          "type": "text",
          "value": "10.0.0.75"
        },
        {
          "key": "dst_ip",
          "type": "text",
          "value": "203.0.113.10"
        },
        {
          "key": "details",
          "type": "text",
          "value": "Data transfer exceeding threshold."
        },
        {
          "key": "notes",
          "type": "text",
          "value": "Blocked by firewall."
        },
        {
          "key": "operator",
          "type": "text",
          "value": "Dana White"
        },
        {
          "key": "attack_chain_name",
          "type": "text",
          "value": "Exfiltration Phase"
        }
      ]
    },
    {
      "id": "case-005",
      "tags": ["random"],
      "owner": "analyst5",
      "title": "Unrelated Case Example",
      "status": "closed",
      "created_at": "2025-04-05T10:00:00Z",
      "updated_at": "2025-04-05T11:00:00Z",
      "description": "No connection to chainsmoker.",
      "totalAlerts": 0,
      "totalComment": 0,
      "customFields": [
        {
          "key": "date_time_mpnet",
          "type": "text",
          "value": "04/05/2025, 1000"
        },
        {
          "key": "mitre_tactic",
          "type": "text",
          "value": "Discovery"
        },
        {
          "key": "src_ip",
          "type": "text",
          "value": "198.51.100.1"
        },
        {
          "key": "dst_ip",
          "type": "text",
          "value": "198.51.100.2"
        },
        {
          "key": "details",
          "type": "text",
          "value": "Routine network scan."
        },
        {
          "key": "notes",
          "type": "text",
          "value": "No action required."
        },
        {
          "key": "operator",
          "type": "text",
          "value": "Eve Johnson"
        },
        {
          "key": "attack_chain_name",
          "type": "text",
          "value": "Random Example Chain"
        }
      ]
    }
  ],
  "total": 5,
  "per_page": 5
}

class OnionHandler:
    def __init__(self, base_url="https://security-onion.local", username="soadmin", password="yourpassword", api_key = 'No API Key Found', cases = pd.DataFrame()):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.cookies = {}
        self.api_key = api_key
        self.cases=cases

    def login_and_cases(self):
        options = Options()
        options.headless = True

        driver = webdriver.Remote(
            command_executor="http://selenium:4444/wd/hub",
            options=options
        )

        login_url = f"{self.base_url}/kibana/wiwi"
        driver.get(login_url)

        # Wait for CSRF field and form elements
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "csrf_token")))
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "identifier")))

        csrf_token = driver.find_element(By.NAME, "csrf_token").get_attribute("value")
        driver.find_element(By.NAME, "identifier").send_keys(self.username)
        driver.find_element(By.NAME, "password").send_keys(self.password)
        driver.find_element(By.NAME, "csrf_token").submit()


        # ✅ Get cookies
        # raw_cookies = driver.get_cookies()
        # self.cookies = {c['name']: c['value'] for c in raw_cookies}

        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "username")))
        driver.find_element(By.NAME, "username").send_keys(self.username)
        driver.find_element(By.NAME, "password").send_keys(self.password)

        driver.find_element(By.CSS_SELECTOR, 'button[data-test-subj="loginSubmit"]').click()

        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Not Found')]"))
        )   

        login_url = f"{self.base_url}/kibana/api/cases/_find"
        driver.get(login_url)

        driver.find_element(By.ID, "rawdata-tab").click()


        pre = WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.TAG_NAME, "pre"))
        )
        raw_json = pre.text
        
        driver.quit()

        return raw_json




        #driver.quit()

    def query_kibana_cases(self):

        if not self.cookies:
            self.login()

        url = f"{self.base_url}:9200/api/cases/_find"
        headers = {
            "Authorization": f"ApiKey {self.api_key}"
        }

        response = requests.get(
            url,
            headers=headers,
            cookies=self.cookies,  # Pass cookies from login() directly
            verify=False  # Disable SSL verification (use cautiously in production)
        )

        response.raise_for_status()
        return response.json()

    def cases_to_dataframe(self, cases):
        # Define field order as they appear in customFields list:
        field_order = [
            "Attack Chain",
            "Date/Time MPNET",
            "Details",
            "MITRE Tactic",
            "Notes",
            "Operator",
            "Source Hostname/IP",
            "Target Hostname/IP"
        ]

        flat_cases = []
        for case in cases:
            flat_case = {
                "id": case.get("id"),
                "title": case.get("title"),
                "status": case.get("status"),
                "severity": case.get("severity"),
                "owner": case.get("owner"),
                "description": case.get("description"),
                "totalAlerts": case.get("totalAlerts"),
                "created_at": case.get("created_at"),
            }
            
            custom_fields = case.get("customFields", [])
            # Initialize fields as None
            for col in field_order:
                flat_case[col] = None
            
            for i, field in enumerate(custom_fields):
                if i < len(field_order):
                    flat_case[field_order[i]] = field.get("value")
                else:
                    # Extra unexpected fields
                    pass
            
            flat_cases.append(flat_case)
        
        self.cases = pd.DataFrame(flat_cases)
        return flat_cases


class KibanaHandler:
    def __init__(self, base_url="https://kibana.lan", username="elastic", password="yourpassword", api_key = 'No API Key Found', cases = pd.DataFrame()):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.cookies = {}
        self.api_key = api_key
        self.cases=cases

