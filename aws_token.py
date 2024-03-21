import getpass
import logging
import sys
import time
import xml

import botocore
import keyring
import pyotp
import requests

import aws
import okta
import okta_saml
from config import Config
from metadata import __desc__, __version__
from http.client import HTTPConnection

LOG = logging.getLogger(__name__)


class NoAWSAccounts(Exception):
    """Some Expected Return Was Received."""


class AwsToken:
    """Main class for handling AWS token management with Okta authentication."""

    def __init__(self, argv):
        """Initialize AwsToken with command line arguments and set up logging."""
        self.okta_client = None
        self.log = LOG
        self.log.info(f"{__desc__} 🔐 v{__version__}")
        self.config = Config(argv)
        self.role = None
        try:
            self.config.get_config()
        except ValueError as err:
            self.log.fatal(err)
            sys.exit(1)
        if self.config.debug:
            self.log.setLevel(logging.DEBUG)
            self.debug_requests_on()

    def main(self):
        """Main execution method. Handles user password input, Okta client initialization, and Okta authentication."""
        password = self.user_password()
        self.init_okta(password)
        self.auth_okta()
        result = self.aws_auth_loop()
        if result is not None:
            sys.exit(result)

    def aws_auth_loop(self):
        """Continuously refresh AWS credentials using the authenticated OktaSaml client object."""

        session = None
        retries = 0
        while True:
            if session and session.is_valid:
                self.log.debug("Credentials are still valid, sleeping")
                time.sleep(60)
                retries = 0
                continue

            try:
                session = self.start_session()
                self.handle_multiple_roles(session)

            except requests.exceptions.ConnectionError:
                self.log.warning("Connection error... will retry")
                time.sleep(5)
                retries += 1
                if retries > 5:
                    self.log.fatal("Too many connection errors")
                    return 3
                continue  # pragma: no cover
            except (okta.UnknownError, aws.InvalidSaml):
                self.log.error("API response invalid. Retrying...")
                time.sleep(1)
                retries += 1
                if retries > 2:
                    self.log.fatal("SAML failure. Please reauthenticate.")
                    return 1
                continue  # pragma: no cover
            except okta.ReauthNeeded as err:
                msg = "Application-level MFA present; re-authenticating Okta"
                self.log.warning(msg)
                self.auth_okta(state_token=err.state_token)
                continue
            except botocore.exceptions.ProfileNotFound as err:
                msg = (
                    "There is likely an issue with your AWS_DEFAULT_PROFILE "
                    "environment variable. An error occurred attempting to "
                    "load the AWS profile specified. "
                    "Error message: {}"
                ).format(err)
                self.log.fatal(msg)
                return 4

            self.log.info("All done! 👍")
            return

    def start_session(self):
        """Initialize AWS session object and handle SAML assertion."""
        self.log.info(
            "Getting SAML Assertion from {org}".format(
                org=self.config.org,
            ),
        )
        assertion = self.okta_client.get_assertion(
            appid=self.config.appid
        )

        try:
            self.log.info(
                "Starting AWS session for {}".format(
                    self.config.region,
                ),
            )
            session = aws.Session(
                assertion,
                profile='default',
                role=self.role,
                region=self.config.region,
                session_duration=self.config.duration,
            )

        except xml.etree.ElementTree.ParseError:
            self.log.error("Could not find any Role in the SAML assertion")
            self.log.error(assertion.__dict__)
            raise aws.InvalidSaml()
        return session

    def auth_okta(self, state_token=None):
        """Authenticate the Okta client. Handles different types of MFA if necessary."""
        self.log.debug("Attempting to authenticate to Okta")
        try:
            self.okta_client.auth(state_token)
        except okta.InvalidPassword:
            self.log.fatal(
                "Invalid Username ({user}) or Password".format(
                    user=self.config.username,
                ),
            )
            if self.config.password_cache:
                msg = (
                    "Password cache is in use; use option -R to reset the "
                    "cached password with a new value"
                )
                self.log.warning(msg)
            sys.exit(1)
        except okta.PasscodeRequired as err:
            self.log.warning(
                "MFA Requirement Detected - Enter your {} code here".format(
                    err.provider,
                ),
            )
            verified = False
            while not verified:
                if self.config.totp_secret != '' and self.config.totp_secret is not None:
                    self.log.info("TOTP secret found,getting the passcode")
                    passcode = pyotp.TOTP(self.config.totp_secret).now()
                    logging.info(passcode)
                else:
                    passcode = self.user_input("MFA Passcode: ")
                verified = self.okta_client.validate_mfa(
                    err.fid,
                    err.state_token,
                    passcode,
                )
        except okta.UnknownError as err:
            self.log.fatal(f"Fatal error: {err}")
            sys.exit(1)

    def init_okta(self, password):
        """Initialize the Okta client or exit if the client received an empty input value."""
        try:
            self.okta_client = okta_saml.OktaSaml(
                self.config.org,
                self.config.username,
                password,
            )

        except okta.EmptyInput:
            self.log.fatal("Cannot enter a blank string for any input")
            sys.exit(1)

    def user_password(self):
        """Handle user password input. Supports password caching and resetting cached password."""
        password = None
        if self.config.password_cache:
            self.log.debug("Password cache enabled")
            try:
                keyring.get_keyring()
                password = keyring.get_password(
                    "aws_okta",
                    self.config.username,
                )
            except keyring.errors.InitError:
                msg = "Password cache enabled but no keyring available."
                self.log.warning(msg)
                password = getpass.getpass()

            if self.config.password_reset or password is None:
                self.log.debug("Password not in cache or reset requested")
                password = getpass.getpass()
                keyring.set_password(
                    "aws_okta",
                    self.config.username,
                    password,
                )
        else:
            password = getpass.getpass()
        return password

    def handle_multiple_roles(self, session):
        """Handle AWS role selection if there are multiple roles available."""

        roles = session.available_roles()

        if len(roles) == 0:
            # if filtering returned nothing fail
            self.log.fatal("Unable to find a matching account or role")
            return False
        elif len(roles) == 1:
            # if filtering returned a single item,
            # do not prompt for selection
            self.role = roles[0]["roleIdx"]
        else:
            for counter, role in enumerate(roles):
                self.role = counter
                session.role = self.role
                session = self.start_session()
                session.assume_role()

        # session.role = self.role
        return True

    def selector_menu(self, data, header_map):
        """Present a menu to the user for selection. Used for multiple role selection."""

        template = self.generate_template(data, header_map)
        selection = -1
        while selection < 0 or selection > len(data):
            self.print_selector_table(template, header_map, data)
            try:
                selection = int(self.user_input("Selection: "))
            except ValueError:
                self.log.warning("Invalid selection, please try again")
                continue
        print("")
        return selection

    @staticmethod
    def print_selector_table(template, header_map, data):
        """Present a menu to the user for selection. Used for multiple role selection."""

        selector_width = len(str(len(data) - 1)) + 2
        pad = " " * (selector_width + 1)
        header_dict = AwsToken.generate_header(header_map)
        print(f"\n{pad}{template.format(**header_dict)}")
        for index, item in enumerate(data):
            sel = f"[{index}]".ljust(selector_width)
            print(f"{sel} {str(template.format(**item))}")

    @staticmethod
    def generate_header(header_map):
        """Generate a table header for the selector menu."""

        header_dict = {}
        for col in header_map:
            header_dict.update(col)
        return header_dict

    @staticmethod
    def generate_template(data, header_map):
        """Generate a string template for printing a table using the data and header."""

        widths = []
        for col in header_map:
            col_key = list(col.keys())[0]
            values = [row[col_key] for row in data]
            col_wid = max(len(value) + 2 for value in values)
            if len(col[col_key]) + 2 > col_wid:
                col_wid = len(col[col_key]) + 2
            widths.append([col_key, col_wid])
        template = ""
        for col in widths:
            if template == "":
                template = "{}{}:{}{}".format("{", col[0], col[1], "}")
            else:
                template = "{}{}{}:{}{}".format(
                    template,
                    "{",
                    col[0],
                    col[1],
                    "}",
                )
        return template

    @staticmethod
    def user_input(text):
        """Wrap input() for easier testing."""
        return input(text).strip()

    def debug_requests_on(self):
        """Switches on logging of the requests module."""
        HTTPConnection.debuglevel = 1

        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
