"""
This file contains a class to manage tokens
Coded by Tyler Bowers
Github: https://github.com/tylerebowers/Schwab-API-Python
"""
import os
import json
import time
import pyotp
import random
import base64
import asyncio
import logging
import requests
import datetime
import threading
from playwright.async_api import async_playwright, TimeoutError
from playwright_stealth import stealth_async
from playwright_stealth.stealth import StealthConfig


# Define the user agent template for Chrome with placeholders
USER_AGENT_TEMPLATE = "Mozilla/5.0 ({os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.{build}.{patch} Safari/537.36"

# Randomize Chrome version and build numbers
chrome_major_version = random.randint(120, 130)  # Major version (e.g., 85 to 115)
chrome_build = random.randint(4100, 5300)  # Build number range
chrome_patch = random.randint(0, 200)  # Patch number range

# Select a random recent OS version
os_versions = [
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; WOW64",
    "Windows NT 10.0",
    "Windows NT 6.1; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
    "X11; Linux x86_64",
]

# Generate the user agent string
USER_AGENT = USER_AGENT_TEMPLATE.format(
    os=random.choice(os_versions),
    version=chrome_major_version,
    build=chrome_build,
    patch=chrome_patch
)

# Randomize the viewport
VIEWPORT = {'width': (width := random.randint(1200, 1600)), 'height': round(width * random.uniform(2/3, 3/4))}

class Tokens:
    def __init__(self, client, app_key, app_secret, username, password, totp_secret, callback_url, headless=True, tokens_file="tokens.json", update_tokens_auto=True):
        """
        Initialize a tokens manager
        :param client: client object
        :type client: Client
        :param app_key: app key credentials
        :type app_key: str
        :param app_secret: app secret credentials
        :type app_secret: str
        :param callback_url: url for callback
        :type callback_url: str
        :param tokens_file: path to tokens file
        :type tokens_file: str
        :param update_tokens_auto: update tokens automatically
        :type update_tokens_auto: bool
        """
        if app_key is None:
            raise Exception("[Schwabdev] app_key cannot be None.")
        if app_secret is None:
            raise Exception("[Schwabdev] app_secret cannot be None.")
        if username is None:
            raise Exception("[Schwabdev] username cannot be None.")
        if password is None:
            raise Exception("[Schwabdev] password cannot be None.")
        if totp_secret is None:
            raise Exception("[Schwabdev] totp_secret cannot be None.")
        if callback_url is None:
            raise Exception("[Schwabdev] callback_url cannot be None.")
        if tokens_file is None:
            raise Exception("[Schwabdev] tokens_file cannot be None.")
        if len(app_key) != 32 or len(app_secret) != 16:
            raise Exception("[Schwabdev] App key or app secret invalid length.")
        if callback_url[0:5] != "https":
            raise Exception("[Schwabdev] callback_url must be https.")
        if callback_url[-1] == "/":
            raise Exception("[Schwabdev] callback_url cannot be path (ends with \"/\").")
        if tokens_file[-1] == '/':
            raise Exception("[Schwabdev] Tokens file cannot be path.")

        self._client = client                               # client object
        self._app_key = app_key                             # app key credential
        self._app_secret = app_secret                       # app secret credential
        self._callback_url = callback_url                   # callback url to use

        self.username = username                            # Schwab account username
        self.password = password                            # Schwab account password
        self.totp_secret = totp_secret                      # Schwab account totp_secret

        # Get user agent based on browser version (initialized here)
        self.USER_AGENT = USER_AGENT  # Define it as an instance variable
        self.headless = headless
        self.redirect_url = None

        self.access_token = None                            # access token from auth
        self.refresh_token = None                           # refresh token from auth
        self.id_token = None                                # id token from auth
        self._access_token_issued = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)  # datetime of access token issue
        self._refresh_token_issued = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc) # datetime of refresh token issue
        self._access_token_timeout = 1800                   # in seconds (from schwab)
        self._refresh_token_timeout = 7 * 24 * 60 * 60      # in seconds (from schwab)
        self._tokens_file = tokens_file                     # path to tokens file

        self._logger = logging.getLogger("Schwabdev.Tokens")           # logger for this class

        # Try to load tokens from the tokens file
        if None not in self._read_tokens():
            if update_tokens_auto:
                self.update_tokens()  # check if tokens need to be updated and update if needed
            at_delta = self._access_token_timeout - (datetime.datetime.now(datetime.timezone.utc) - self._access_token_issued).total_seconds()
            self._logger.info(f"Access token expires in {'-' if at_delta < 0 else ''}{int(abs(at_delta) / 3600):02}H:{int((abs(at_delta) % 3600) / 60):02}M:{int((abs(at_delta) % 60)):02}S")
            rt_delta = self._refresh_token_timeout - (datetime.datetime.now(datetime.timezone.utc) - self._refresh_token_issued).total_seconds()
            self._logger.info(f"Refresh token expires in {'-' if rt_delta < 0 else ''}{int(abs(rt_delta) / 3600):02}H:{int((abs(rt_delta) % 3600) / 60):02}M:{int((abs(rt_delta) % 60)):02}S")
        else:
            # The tokens file doesn't exist, so create it.
            self._logger.warning(f"Token file does not exist or invalid formatting, creating \"{str(tokens_file)}\"")
            # Tokens must be updated.
            if update_tokens_auto:
                self.update_refresh_token()

        # Spawns a thread to check the access token and update if necessary
        if update_tokens_auto:
            def checker():
                while True:
                    self.update_tokens()
                    time.sleep(30)

            threading.Thread(target=checker, daemon=True).start()
        else:
            self._logger.warning("Warning: Tokens will not be updated automatically.")

    def _post_oauth_token(self, grant_type: str, code: str):
        """
        Makes API calls for auth code and refresh tokens
        :param grant_type: 'authorization_code' or 'refresh_token'
        :type grant_type: str
        :param code: authorization code
        :type code: str
        :return: response
        :rtype: requests.Response
        """
        headers = {'Authorization': f'Basic {base64.b64encode(bytes(f"{self._app_key}:{self._app_secret}", "utf-8")).decode("utf-8")}',
                   'Content-Type': 'application/x-www-form-urlencoded'}
        if grant_type == 'authorization_code':  # gets access and refresh tokens using authorization code
            data = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': self._callback_url}
        elif grant_type == 'refresh_token':  # refreshes the access token
            data = {'grant_type': 'refresh_token',
                    'refresh_token': code}
        else:
            raise Exception("Invalid grant type; options are 'authorization_code' or 'refresh_token'")
        return requests.post('https://api.schwabapi.com/v1/oauth/token', headers=headers, data=data)

    def _write_tokens(self, at_issued: datetime, rt_issued: datetime, token_dictionary: dict):
        """
        Writes token file and sets variables
        :param at_issued: access token issued
        :type at_issued: datetime.pyi
        :param rt_issued: refresh token issued
        :type rt_issued: datetime.pyi
        :param token_dictionary: token dictionary
        :type token_dictionary: dict
        """
        self.access_token = token_dictionary.get("access_token")
        self.refresh_token = token_dictionary.get("refresh_token")
        self.id_token = token_dictionary.get("id_token")
        self._access_token_issued = at_issued
        self._refresh_token_issued = rt_issued
        try:
            with open(self._tokens_file, 'w') as f:
                to_write = {"access_token_issued": at_issued.isoformat(),
                            "refresh_token_issued": rt_issued.isoformat(),
                            "token_dictionary": token_dictionary}
                json.dump(to_write, f, ensure_ascii=False, indent=4)
        except Exception as e:
            self._logger.error(e)
            self._logger.error("Could not write tokens file")


    def _read_tokens(self):
        """
        Reads token file and sets variables
        :return: access token issued, refresh token issued, token dictionary
        :rtype: datetime.pyi, datetime.pyi, dict
        """
        try:
            with open(self._tokens_file, 'r') as f:
                d = json.load(f)
                token_dictionary = d.get("token_dictionary")
                self.access_token = token_dictionary.get("access_token")
                self.refresh_token = token_dictionary.get("refresh_token")
                self.id_token = token_dictionary.get("id_token")
                self._access_token_issued = datetime.datetime.fromisoformat(d.get("access_token_issued"))
                self._refresh_token_issued = datetime.datetime.fromisoformat(d.get("refresh_token_issued"))
                return self._access_token_issued, self._refresh_token_issued, token_dictionary
        except Exception as e:
            self._logger.error(e)
            return None, None, None

    def update_tokens(self, force=False):
        """
        Checks if tokens need to be updated and updates if needed (only access token is automatically updated)
        :param force: force update of refresh token (also updates access token)
        :type force: bool
        """
        # refresh token notification
        rt_delta = self._refresh_token_timeout - (datetime.datetime.now(datetime.timezone.utc) - self._refresh_token_issued).total_seconds()
        if rt_delta < 43200:  # Start to warn the user that the refresh token will expire in less than 43200 = 12 hours
            self._logger.info(f"The refresh token will expire soon! ({'-' if rt_delta < 0 else ''}{int(abs(rt_delta) / 3600):02}H:{int((abs(rt_delta) % 3600) / 60):02}M:{int((abs(rt_delta) % 60)):02}S remaining)")

        # check if we need to update refresh (and access) token
        if (rt_delta < 3600) or force:
            self._logger.warning("The refresh token has expired!")
            self.update_refresh_token()
        # check if we need to update access token
        elif (self._access_token_timeout - (datetime.datetime.now(datetime.timezone.utc) - self._access_token_issued).total_seconds()) < 61:
            self._logger.info("The access token has expired, updating automatically.")
            self.update_access_token()

    """
        Access Token functions below
    """

    def update_access_token(self):
        """
        "refresh" the access token using the refresh token
        """
        response = self._post_oauth_token('refresh_token', self.refresh_token)
        if response.ok:
            # get and update to the new access token
            at_issued = datetime.datetime.now(datetime.timezone.utc)
            self._write_tokens(at_issued, self._refresh_token_issued, response.json())
            # show user that we have updated the access token
            self._logger.info(f"Access token updated: {self._access_token_issued}")
        else:
            self._logger.error(response.text)
            self._logger.error(f"Could not get new access token; refresh_token likely invalid.")

    """
        Refresh Token functions below
    """

    def _generate_certificate(self, common_name="common_name", key_filepath="localhost.key", cert_filepath="localhost.crt"):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # make folders for cert files
        os.makedirs(os.path.dirname(key_filepath), exist_ok=True)
        os.makedirs(os.path.dirname(cert_filepath), exist_ok=True)

        # create a key pair
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)

        # create a self-signed cert
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Schwabdev"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authentication"),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(key.public_key())
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        builder = builder.sign(key, hashes.SHA256())
        with open(key_filepath, "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=serialization.NoEncryption()))
        with open(cert_filepath, "wb") as f:
            f.write(builder.public_bytes(serialization.Encoding.PEM))
        self._logger.info(f"Certificate generated and saved to {key_filepath} and {cert_filepath}")



    def _update_refresh_token_from_code(self, url_or_code):
        """
        Get new access and refresh tokens using callback url or authorization code.
        :param url_or_code: callback url (full url) or authorization code (the code=... in url)
        :type url_or_code: str
        """
        if url_or_code.startswith("https://"):
            code = f"{url_or_code[url_or_code.index('code=') + 5:url_or_code.index('%40')]}@"
            # session = responseURL[responseURL.index("session=")+8:]
        else:
            code = url_or_code
        # get new access and refresh tokens
        now = datetime.datetime.now(datetime.timezone.utc)
        response = self._post_oauth_token('authorization_code', code)
        if response.ok:
            # update token file and variables
            self._write_tokens(now, now, response.json())
            self._logger.info("Refresh and Access tokens updated")
        else:
            self._logger.error(response.text)
            self._logger.error("Could not get new refresh and access tokens, check these:\n"
                               "1. App status is \"Ready For Use\".\n"
                               "2. App key and app secret are valid.\n"
                               "3. You pasted the whole url within 30 seconds. (it has a quick expiration)")

    async def _async_login(self):
        """ This function runs in async mode to perform login.
        Use with login function. See login function for details.
        """
        """Perform login using Chrome with stealth settings."""

        capture_done = asyncio.Event()  # Event to signal when a URL is captured

        def capture_request(request):
        # Capture the URL if it matches the expected pattern
            if '127.0.0.1' in request.url:
                self.redirect_url = request.url
                capture_done.set()  # Signal that we've captured the desired URL

        async def log_request_headers(request):     
            with open("headers_log.json", "a") as f:
                json.dump({"url": request.url, "headers": request.headers}, f, indent=4)
                f.write(",\n")  # Add a comma for separation in case of multiple headers

        # Intercept and modify headers before sending the request
        async def modify_headers(route, request):
            headers = request.headers.copy()  # Make a copy of the current headers
            # Remove the specific headers
            headers.pop("sec-ch-ua", None)
            headers.pop("sec-ch-ua-mobile", None)
            headers.pop("sec-ch-ua-platform", None)
            # Continue the request with the modified headers
            await route.continue_(headers=headers)
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless
        )
        
        # Create a new browser context
        # Create a new browser context with the custom user agent
        context = await self.browser.new_context(
            user_agent=USER_AGENT,
            viewport = VIEWPORT
        )

        # Create a new page in this context
        self.page = await context.new_page()
                
        # Configure stealth options
        config = StealthConfig()
        config.navigator_languages = False
        config.navigator_user_agent = False
        config.navigator_vendor = False
        await stealth_async(self.page, config)

        # Listen for all outgoing requests
        self.page.on("request", log_request_headers)

        # Set up the request interceptor to modify headers
        await self.page.route("**/*", modify_headers)

        auth_url = f'https://api.schwabapi.com/v1/oauth/authorize?client_id={self._app_key}&redirect_uri={self._callback_url}'        
        await self.page.goto(auth_url)
        await asyncio.sleep(random.uniform(1.4, 1.6))
        await self.page.goto(auth_url)
        
        await asyncio.sleep(3)
        await self.page.screenshot(path="screenshot.png")
        # Wait for the login ID input to be visible before attempting to fill it
        await self.page.wait_for_selector('#loginIdInput', timeout=15000)  # 15-second timeout
        await self.page.wait_for_selector('#passwordInput', timeout=1000)  # 15-second timeout
        await self.page.wait_for_selector('#btnLogin', timeout=1000)  # 15-second timeout
        
        if self.totp_secret is not None:
            totp = pyotp.TOTP(self.totp_secret)
            password = self.password + str(totp.now())

        # Fill in the login ID
        await asyncio.sleep(random.uniform(.5, .8))
        await self.page.fill('#loginIdInput', self.username)
        # Fill in the password
        await asyncio.sleep(random.uniform(1.3, 1.8))
        await self.page.fill('#passwordInput', password)

        await self.page.screenshot(path="screenshot.png")
        
        # Click the login button
        await asyncio.sleep(random.uniform(1.4, 1.6))
        await self.page.click('#btnLogin')

        await asyncio.sleep(3)
        await self.page.screenshot(path="screenshot.png")
        
        # Wait for the "Accept Terms" checkbox and check it
        await self.page.wait_for_selector('#acceptTerms', timeout=8000)  # 8-second timeout for loading
        await asyncio.sleep(random.uniform(1, 1.5))
        await self.page.check('#acceptTerms')
        
        await asyncio.sleep(3)
        await self.page.screenshot(path="screenshot.png")
        
        # Wait for the "Continue" button and click it
        await asyncio.sleep(random.uniform(1.8, 2.8))
        await self.page.wait_for_selector('#submit-btn', timeout=2000)  # 5-second timeout for loading
        await self.page.click('#submit-btn')

        await asyncio.sleep(3)
        await self.page.screenshot(path="screenshot.png")
        
        await self.page.wait_for_selector('#agree-modal-btn-', timeout=2000)  # 5-second timeout for loading
        await asyncio.sleep(random.uniform(1.2, 2.8))
        await self.page.click('#agree-modal-btn-')    

        # Ensure all checkboxes within the "Your current Schwab accounts" form group are checked
        await self.page.wait_for_selector('.form-group', timeout=5000)  # Wait for the form group to load
        # Wait before starting interaction
        await asyncio.sleep(1)
    
        # Get all checkboxes in the form group (dynamic, in case there are different checkboxes)
        checkboxes = await self.page.query_selector_all('.form-group input[type="checkbox"]')
    
        # Iterate through all checkboxes and check them
        await asyncio.sleep(random.uniform(0.4, 0.7))
        for checkbox in checkboxes:
            if await checkbox.is_visible():
                await asyncio.sleep(random.uniform(0.4, 0.7))
                await checkbox.check()

        await asyncio.sleep(random.uniform(1.8, 2.8))
        await self.page.wait_for_selector('#submit-btn', timeout=2000)  # 2-second timeout for loading
        await self.page.click('#submit-btn')

        await asyncio.sleep(random.uniform(1.8, 2.8))
        await self.page.wait_for_selector('#cancel-btn', timeout=5000)  # 5-second timeout for loading
                
        try:
            # Attach the listener to capture the url
            self.page.on("request", capture_request)
            # Click the cancel button
            await self.page.click('#cancel-btn')
            await asyncio.wait_for(capture_done.wait(), timeout=10)            
        except Exception as e:
            # Handle the ERR_CONNECTION_REFUSED error
            if "net::ERR_CONNECTION_REFUSED" in str(e):
                pass # DO NOTHING
            else:
                # Re-raise unexpected errors
                raise
        
        print(f"Redirected to: {self.redirect_url}")
        await self.page.close()
        await self.browser.close()
        await self.playwright.stop()
        
        return self.redirect_url
    
    def update_refresh_token(self):
        """
        Get new access and refresh tokens using authorization code.
        """

        # get and open the link that the user will authorize with.
        auth_url = f'https://api.schwabapi.com/v1/oauth/authorize?client_id={self._app_key}&redirect_uri={self._callback_url}'
        print(f"[Schwabdev] Open to authenticate: {auth_url}")
        code = None
        try:
            response_url=asyncio.run(self._async_login())
            print(response_url)
            code = f"{response_url[response_url.index('code=') + 5:response_url.index('%40')]}@"
        except Exception as e:
            print('Error:')
            print(e)
            self._logger.error(e)
            self._logger.warning("Could not open browser for authorization")

        if code is not None:
            self._update_refresh_token_from_code(code)
        else:
            self._logger.error("Could not get new refresh token without code.")
