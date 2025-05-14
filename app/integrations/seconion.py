from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import requests

class OnionHandler:
    def __init__(self, base_url="https://security-onion.local", username="soadmin", password="yourpassword", api_key = 'No API Key Found'):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.cookies = {}
        self.api_key = api_key

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
