import time
import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# Setting up logger for the OnionHandler class
logger = logging.getLogger("OnionHandler")
logging.basicConfig(level=logging.INFO)

class OnionHandler:
    
    def __init__(self, base_url="http://security-onion.local"):
        self.base_url = base_url  # security onion base url for the code to send requests to

    def get_csrf_token(self):
        base_url = self.base_url
        options = Options()
        options.headless = True
        driver = webdriver.Remote(
            command_executor="http://selenium:4444/wd/hub",
            options=options
        )
        driver.get(f"https://{base_url}")
        csrf_input = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "csrf_token"))
        )
        token = csrf_input.get_attribute("value")
        driver.quit()
        return token