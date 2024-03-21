import logging
import time

import requests

from metadata import __version__

LOG = logging.getLogger(__name__)

BASE_URL = "https://{organization}.okta.com"


class UnknownError(Exception):
    """Some Expected Return Was Received."""


class EmptyInput(BaseException):
    """Invalid Input - Empty String Detected."""


class InvalidPassword(BaseException):
    """Invalid Password."""


class ReauthNeeded(BaseException):
    """Raised when the SAML Assertion is invalid and we need to reauth."""

    def __init__(self, state_token=None):
        self.state_token = state_token
        super().__init__()


class PasscodeRequired(BaseException):
    """A 2FA Passcode Must Be Entered."""

    def __init__(self, fid, state_token, provider):
        self.fid = fid
        self.state_token = state_token
        self.provider = provider
        super().__init__()


class AnswerRequired(BaseException):
    """A 2FA Passcode Must Be Entered."""

    def __init__(self, factor, state_token):
        self.factor = factor
        self.state_token = state_token
        super().__init__()


class OktaVerifyRequired(BaseException):
    """OktaVerify Authentication Is Required."""


class Okta:
    """Handles Okta authentication and MFA."""

    def __init__(
            self,
            organization,
            username,
            password):
        if organization and "https://" not in organization:
            self.base_url = BASE_URL.format(organization=organization)
        else:
            self.base_url = organization

        LOG.debug(f"Base URL Set to: {self.base_url}")

        # Validate the inputs are reasonably sane
        for input_value in (organization, username, password):
            if input_value == "" or input_value is None:
                raise EmptyInput()

        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session_token = None
        self.long_token = True

    def _request(self, path, data=None):
        """Make Okta API calls and return the response as a dictionary."""

        headers = {
            "Accept": "application/json",
            "User-Agent": f"aws_okta/{__version__}",
            "Content-Type": "application/json",
        }

        if path.startswith("http"):
            url = path
        else:
            url = f"{self.base_url}/api/v1{path}"

        resp = self.session.post(
            url=url,
            headers=headers,
            json=data,
            allow_redirects=False,
            cookies={"sid": self.session_token},
        )

        resp.raise_for_status()
        resp_obj = resp.json()
        LOG.debug(resp_obj)
        return resp_obj

    def set_token(self, ret):
        """Parse an authentication response, get a long-lived token, store it."""

        if self.session_token:
            # We have a session token already
            return
        first_name = ret["_embedded"]["user"]["profile"]["firstName"]
        last_name = ret["_embedded"]["user"]["profile"]["lastName"]
        LOG.info(
            "Successfully authed {first_name} {last_name}".format(
                first_name=first_name,
                last_name=last_name,
            ),
        )

        LOG.debug("Long-lived token needed; requesting Okta API token")
        resp = self._request(
            "/sessions",
            {"sessionToken": ret["sessionToken"]},
        )
        self.session_token = resp["id"]

    def validate_mfa(self, fid, state_token, passcode):
        """Validate an Okta user with Passcode-based MFA."""

        if len(passcode) > 6 or len(passcode) < 5:
            LOG.error("Passcodes must be 5 or 6 digits")
            return None

        valid = self.send_user_response(fid, state_token, passcode, "passCode")
        if valid:
            self.set_token(valid)
            return True
        return None

    def validate_answer(self, fid, state_token, answer):
        """Validate an Okta user with Question-based MFA."""

        if not answer:
            LOG.error("Answer cannot be blank")
            return None

        valid = self.send_user_response(fid, state_token, answer, "answer")
        if valid:
            self.set_token(valid)
            return True
        return None

    def send_user_response(self, fid, state_token, user_response, resp_type):
        """Call Okta with a factor response and verify it."""

        path = f"/authn/factors/{fid}/verify"
        data = {
            "fid": fid,
            "stateToken": state_token,
            resp_type: user_response,
        }
        try:
            return self._request(path, data)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 403:
                LOG.error("Invalid Passcode Detected")
                return None
            if err.response.status_code == 401:
                LOG.error("Invalid Passcode Retries Exceeded")
                raise UnknownError("Retries exceeded")

            raise UnknownError(err.response.body)

    def okta_verify(self, fid, state_token):
        """Trigger an Okta Push Verification and waits."""

        LOG.warning("Okta Verify Push being sent...")
        path = f"/authn/factors/{fid}/verify"
        data = {
            "fid": fid,
            "stateToken": state_token,
        }
        ret = self._request(path, data)

        ret = self.mfa_wait_loop(ret, data)
        if ret:
            self.set_token(ret)
            return True
        return None

    def mfa_wait_loop(self, ret, data, sleep=2):
        """Wait loop that keeps checking Okta for MFA status."""

        try:
            while ret["status"] != "SUCCESS":
                LOG.info("Waiting for MFA success...")
                time.sleep(sleep)

                links = ret.get("_links")
                ret = self._request(links["next"]["href"], data)
            return ret
        except KeyboardInterrupt:
            LOG.info("User canceled waiting for MFA success.")
            raise

    def auth(self, state_token=None):
        """Perform an initial authentication against Okta."""

        path = "/authn"
        data = {
            "username": self.username,
            "password": self.password,
        }
        if state_token:
            data = {"stateToken": state_token}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 401:
                raise InvalidPassword()
            raise

        status = ret.get("status", None)

        if status == "SUCCESS":
            self.set_token(ret)
            return None

        if status in ("MFA_ENROLL", "MFA_ENROLL_ACTIVATE"):
            LOG.warning(
                "User {u} needs to enroll in 2FA first".format(
                    u=self.username,
                ),
            )

        if status in ("MFA_REQUIRED", "MFA_CHALLENGE"):
            return self.handle_mfa_response(ret)

        raise UnknownError(status)

    def handle_mfa_response(self, ret):
        """In the case of an MFA response evaluate the response and handle accordingly based on available MFA
        factors."""

        response_types = ["sms", "question", "call", "token:software:totp"]
        response_factors = []
        for factor in ret["_embedded"]["factors"]:
            if factor["factorType"] in response_types:
                LOG.debug("{} factor found".format(factor["factorType"]))
                response_factors.append(factor)

        if len(response_factors) == 0:
            LOG.debug(
                "Factors from Okta: {}".format(
                    ret["_embedded"]["factors"],
                ),
            )
            LOG.fatal("No supported MFA types found")
            raise UnknownError("No supported MFA types found")

        self.handle_response_factors(response_factors, ret["stateToken"])
        return None

    def handle_response_factors(self, factors, state_token):
        """Handle any OTP-type factors."""

        otp_provider = None
        otp_factor = None
        for factor in factors:
            if factor["factorType"] == "sms":
                self.request_otp(factor["id"], state_token, "SMS")
                phone = factor["profile"]["phoneNumber"]
                otp_provider = f"SMS ({phone})"
                otp_factor = factor["id"]
                break
            if factor["factorType"] == "call":
                self.request_otp(factor["id"], state_token, "phone call")
                phone = factor["profile"]["phoneNumber"]
                otp_provider = f"call ({phone})"
                otp_factor = factor["id"]
                break
            if factor["factorType"] == "question":
                raise AnswerRequired(factor, state_token)
            if factor["factorType"] == "token:software:totp":
                otp_provider = factor["provider"]
                otp_factor = factor["id"]

        if otp_provider:
            raise PasscodeRequired(
                fid=otp_factor,
                state_token=state_token,
                provider=otp_provider,
            )

    def request_otp(self, fid, state_token, otp_type):
        """Trigger an OTP call, SMS, or other and return."""

        LOG.warning(f"Okta {otp_type} being requested...")
        path = f"/authn/factors/{fid}/verify"
        data = {
            "fid": fid,
            "stateToken": state_token,
        }
        self._request(path, data)

    def get_aws_apps(self):
        """Call Okta to get a list of the AWS apps that a user is able to access."""

        path = "/users/me/appLinks"
        headers = {
            "Accept": "application/json",
            "User-Agent": f"aws_okta/{__version__}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/api/v1{path}"
        cookies = {"sid": self.session_token}

        resp = self.session.get(
            url=url,
            headers=headers,
            allow_redirects=False,
            cookies=cookies,
        )
        resp_obj = resp.json()

        resp.raise_for_status()

        aws_list = {
            i["label"]: i["linkUrl"] for i in resp_obj if i["appName"] == "amazon_aws"
        }

        accounts = []
        for key, val in aws_list.items():
            appid = val.split("/", 5)[5]
            accounts.append({"name": key, "appid": appid})
        return accounts

    def mfa_callback(self, auth, verification, state_token):
        """Do callback to Okta with the info from the MFA provider."""

        app = verification["signature"].split(":")[1]
        response_sig = f"{auth}:{app}"
        callback_params = "stateToken={}&sig_response={}".format(
            state_token,
            response_sig,
        )

        url = "{}?{}".format(
            verification["_links"]["complete"]["href"],
            callback_params,
        )
        ret = self.session.post(url)
        if ret.status_code != 200:
            raise Exception(
                "Bad status from Okta callback {}".format(
                    ret.status_code,
                ),
            )
