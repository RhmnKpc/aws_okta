"""AWS SAML assertion parser."""
import base64
import xml.etree.ElementTree as ET


class SamlAssertion:
    """Handles parsing and encoding of AWS SAML assertion."""

    def __init__(self, assertion):
        self.assertion = assertion

    @staticmethod
    def split_roles(roles):
        """Splits the roles from the string response into a list."""
        return [(y.strip()) for y in roles.text.split(",")]

    @staticmethod
    def sort_roles(roles):
        """Sorts the AWS roles based on whether 'saml-provider' is in the role."""
        return sorted(roles, key=lambda role: "saml-provider" in role)

    def roles(self):
        """Extracts and returns role information from the SAML assertion."""
        attributes = ET.fromstring(self.assertion).iter(
            "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
        )

        name = "https://aws.amazon.com/SAML/Attributes/Role"
        roles_attributes = [x for x in attributes if x.get("Name") == name]

        roles_values = [
            (x.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"))
            for x in roles_attributes
        ]

        return [
            (dict(zip(["role", "principle"], self.sort_roles(self.split_roles(x)))))
            for x in roles_values[0]
        ]

    def encode(self):
        """Encodes the SAML assertion using base64 encoding."""
        return base64.b64encode(self.assertion).decode()
