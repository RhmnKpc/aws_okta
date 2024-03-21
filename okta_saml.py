import base64
import logging
import re

import requests
from bs4 import BeautifulSoup

import okta
from metadata import __version__

LOG = logging.getLogger(__name__)


class OktaSaml(okta.Okta):
    """Handles SAML authentication with Okta."""

    @staticmethod
    def assertion(html):
        """Extracts the SAML assertion from the HTML response.

        Args:
        html: HTML content from AWS response

        Returns: Decoded SAML assertion
        """
        assertion = ""
        soup = BeautifulSoup(html, "html.parser")
        for inputtag in soup.find_all("input"):
            if inputtag.get("name") == "SAMLResponse":
                assertion = inputtag.get("value")
        return base64.b64decode(assertion)

    @staticmethod
    def get_okta_error_from_response(resp):
        """Extracts the error message from Okta's HTML response.

        Args:
        resp: Response object from requests

        Returns: Error message from the HTML
        """
        err = ""
        soup = BeautifulSoup(resp.text, "html.parser")
        for err_div in soup.find_all("div", {"class": "error-content"}):
            err = err_div.select("h1")[0].text.strip()
        if err == "":
            err = "Unknown error"
        return err

    @staticmethod
    def get_state_token_from_html(html):
        """Extracts the state token from Okta's HTML response.

        Args:
        html: HTML content from requests

        Returns: State token
        """
        # Find the token
        match = re.search("var stateToken = \\'(.{,50})\\'", str(html))

        token = match.group(1).replace("\\\\x2D", "-")
        token = token.replace("\\x2D", "-")
        return token

    def get_assertion(self, appid):
        """Requests Okta for the SAML assertion.

        Args:
        appid: Application ID

        Returns: SAML response
        """
        path = "{url}/home/amazon_aws/{appid}".format(
            url=self.base_url,
            appid=appid,
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": f"aws_okta/{__version__}",
            "Content-Type": "application/json",
        }
        resp = self.session.get(
            path,
            cookies={"sid": self.session_token},
            headers=headers,
        )

        if "second-factor" in resp.url:
            try:
                state_token = self.get_state_token_from_html(resp.text)
                LOG.debug("Redirected; reuathing with new token")
                raise okta.ReauthNeeded(state_token)
            except AttributeError:
                LOG.debug("Error finding state token in response")
                raise okta.ReauthNeeded()

        try:
            resp.raise_for_status()
        except (
                requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError,
        ) as err:
            if err.response.status_code == 404:
                LOG.fatal(f"Provided App ID {appid} not found")
                LOG.fatal("404 calling ")
            else:
                LOG.error(
                    "Unknown error: {msg}".format(
                        msg=str(err.response.__dict__),
                    ),
                )
            raise okta.UnknownError()

        assertion = self.assertion(resp.text)
        if assertion == b"":
            error = self.get_okta_error_from_response(resp)
            LOG.fatal(error)
            raise okta.UnknownError()
        return assertion
