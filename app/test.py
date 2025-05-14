import requests

# Create a session object to handle cookies automatically
session = requests.Session()

# Set the Authorization header and CSRF header
session.headers.update({
    "Authorization": "ApiKey dlRzSnk1WUJIZEFXUlZ4dUdaODM6Q1VicEQzNk5SUHVwYzRWN1RsalNEUQ==",
    "kbn-xsrf": "true",  # This is the CSRF protection header required by Kibana
})

# Make the GET request
response = session.get(
    "http://172.25.7.201:5601/api/cases/_find",
    verify=False  # Disable SSL verification (use cautiously in production)
)

# Print the response
print(response.text)
