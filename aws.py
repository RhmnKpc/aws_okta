"""
AWS Session and Credential classes; how we record the creds and how we talk
to AWS to get them.
"""
import configparser
import datetime
import logging
import os
import re

import boto3
import botocore
import bs4
import requests

from aws_saml import SamlAssertion

LOG = logging.getLogger(__name__)


class InvalidSaml(BaseException):
    """Exception raised when the SAML Assertion is invalid."""


class Credentials:
    """Handles AWS Credentials Profile.

    This class reads an Amazon ~/.aws/credentials file, and allows
    to write out credentials into different Profile sections.
    """

    def __init__(self, filename):
        self.filename = filename

    def _add_profile(self, name, profile):
        """Writes the profile to disk."""
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read_file(open(self.filename))
        except OSError:
            LOG.debug(f"Unable to open {self.filename}")

        if not config.has_section(name):
            config.add_section(name)

        [(config.set(name, k, v)) for k, v in profile.items()]
        with open(self.filename, "w+") as configfile:
            os.chmod(self.filename, 0o600)
            config.write(configfile)

    def add_profile(self, name, region, creds):
        """Writes a set of AWS Credentials to disk."""

        name = str(name)
        self._add_profile(
            name,
            {
                "output": "json",
                "region": str(region),
                "aws_access_key_id": str(creds["AccessKeyId"]),
                "aws_secret_access_key": str(creds["SecretAccessKey"]),
                "aws_security_token": str(creds["SessionToken"]),
                "aws_session_token": str(creds["SessionToken"]),
            },
        )

        LOG.info(
            'Wrote profile "{name}" to {file} 💾'.format(
                name=name,
                file=self.filename,
            ),
        )


class Session:
    """Handles Amazon Federated Session.

    This class is used to contact Amazon with a specific SAML Assertion and
    get back a set of temporary Federated credentials. These credentials are
    written to disk.
    """

    def __init__(
            self,
            assertion,
            credential_path="~/.aws",
            profile="default",
            region="eu-west-1",
            role=None,
            session_duration=None,
    ):
        cred_dir = os.path.expanduser(credential_path)
        cred_file = os.path.join(cred_dir, "credentials")

        boto_logger = logging.getLogger("botocore")
        boto_logger.setLevel(logging.WARNING)

        if not os.path.exists(cred_dir):
            LOG.info(
                "Creating missing AWS Credentials dir {dir} 📁".format(
                    dir=cred_dir,
                ),
            )
            os.makedirs(cred_dir)

        self.profile = profile
        self.region = region
        boto3.setup_default_session()
        self.sts = boto3.client("sts", region_name=self.region)
        self.assertion = SamlAssertion(assertion)
        self.writer = Credentials(cred_file)

        # Populated by self.assume_role()
        self.creds = {
            "AccessKeyId": None,
            "SecretAccessKey": None,
            "SessionToken": None,
            "Expiration": None,
        }
        self.session_token = None
        self.role = role
        if session_duration:
            self.duration = session_duration
        else:
            self.duration = 3600
        self.available_roles()

    @property
    def is_valid(self):
        """Checks if the Session is still valid."""
        try:
            msg = "Session Expiration: {}  // Now: {}".format(
                self.creds["Expiration"],
                datetime.datetime.utcnow(),
            )
            LOG.debug(msg)
            offset = datetime.timedelta(seconds=600)
            now = datetime.datetime.utcnow()
            expir = datetime.datetime.strptime(
                str(self.creds["Expiration"]),
                "%Y-%m-%d %H:%M:%S+00:00",
            )

            return (now + offset) < expir
        except (ValueError, TypeError):
            return False

    def available_roles(self):
        """Returns the roles available from AWS."""

        multiple_accounts = False
        first_account = ""
        formatted_roles = []
        for role in self.assertion.roles():
            account = role["role"].split(":")[4]
            role_name = role["role"].split(":")[5].split("/")[1]
            formatted_roles.append(
                {
                    "account": account,
                    "role_name": role_name,
                    "arn": role["role"],
                    "principle": role["principle"],
                },
            )
            if first_account == "":
                first_account = account
            elif first_account != account:
                multiple_accounts = True

        if multiple_accounts:
            formatted_roles = self.account_ids_to_names(formatted_roles)

        formatted_roles = sorted(
            formatted_roles,
            key=lambda k: (k["account"], k["role_name"]),
        )

        # set the role role index after sorting
        i = 0
        for role in formatted_roles:
            role["roleIdx"] = i
            i = i + 1

        self.roles = formatted_roles

        return self.roles

    def assume_role(self):
        """Uses the SAML Assertion to get the credentials."""

        self.role = 0 if self.role is None else self.role
        role_arn = self.roles[self.role]["arn"]
        LOG.info(f"Assuming role: {role_arn}")

        self.profile = self.roles[self.role]["role_name"]
        principal_arn = self.roles[self.role]["principle"]
        saml_assertion = self.assertion.encode()

        try:
            session = self._assume_role_with_saml(role_arn, principal_arn, saml_assertion, self.duration)
            max_session_duration = self._get_max_session_duration(session)
            session = self._assume_role_with_saml(role_arn, principal_arn, saml_assertion, max_session_duration)
        except botocore.exceptions.ClientError:
            LOG.warning(f"Error assuming session with duration {self.duration}. Retrying with 3600.")
            session = self._assume_role_with_saml(role_arn, principal_arn, saml_assertion, 3600)

        self.creds = session["Credentials"]
        self._write()

    def _assume_role_with_saml(self, role_arn, principal_arn, saml_assertion, duration):
        """Assumes role with SAML."""
        return self.sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=saml_assertion,
            DurationSeconds=duration,
        )

    def _get_max_session_duration(self, session):
        """Gets the maximum session duration."""
        boto_session = boto3.Session(
            aws_access_key_id=session["Credentials"]["AccessKeyId"],
            aws_secret_access_key=session["Credentials"]["SecretAccessKey"],
            aws_session_token=session["Credentials"]["SessionToken"]
        )
        client = boto_session.client('iam')
        response = client.get_role(RoleName=self.profile)
        return int(response['Role']['MaxSessionDuration'])

    def _write(self):
        """Writes out our secrets to the Credentials object."""
        self.writer.add_profile(
            name="role/" + self.profile,
            region=self.region,
            creds=self.creds,
        )
        LOG.info(
            "Current time is {time}".format(
                time=datetime.datetime.utcnow(),
            ),
        )
        LOG.info(
            "Session expires at {time} ⏳".format(
                time=self.creds["Expiration"],
            ),
        )

    def account_ids_to_names(self, roles):
        """Turns account IDs into user-friendly names."""

        try:
            accounts = self.get_account_name_map()
        except Exception:
            msg = (
                "Error retrieving AWS account name/ID map. "
                "Falling back to just account IDs"
            )
            LOG.warning(msg)
            return roles
        for role in roles:
            role["account"] = accounts[role["account"]]
        LOG.debug(f"AWS roles with friendly names: {accounts}")
        return roles

    def get_account_name_map(self):
        """Gets the friendly to ID mappings from AWS."""

        url = "https://signin.aws.amazon.com/saml"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"SAMLResponse": self.assertion.encode()}
        resp = requests.post(url=url, headers=headers, data=data)
        resp.raise_for_status()
        return self.account_names_from_html(resp.text)

    @staticmethod
    def account_names_from_html(html):
        """Parses the AWS SAML login page HTML for account numbers and names."""

        accounts = {}
        soup = bs4.BeautifulSoup(html, "html.parser")
        for account in soup.find_all("div", {"class": "saml-account-name"}):
            name_string = account.text
            a_id = re.match(r".*\((\d+)\)", name_string).group(1)
            a_name = re.match(r"\S+\s(\S+)", name_string).group(1)
            accounts[a_id] = a_name
        LOG.debug(f"AWS account map: {accounts}")
        return accounts
