import argparse
import getpass
import logging
import os
import sys

import yaml

from metadata import __version__

LOG = logging.getLogger(__name__)


class Config:
    """Handles the configuration for AWS Okta."""

    def __init__(self, argv):
        self.argv = argv
        self.writepath = "~/.config/aws_okta.yml"
        self.password_cache = None
        self.password_reset = None
        self.org = None
        self.appid = None
        self.region = None
        self.username = None
        self.duration = 3600
        self.totp_secret = None
        self.debug = False

        if len(argv) > 1:
            if argv[1] == "config":
                self.interactive_config()
                sys.exit(0)

    @staticmethod
    def user_input(text):
        """Prompts the user for input and returns the stripped result."""
        return input(text).strip()

    def interactive_config(self):
        """Prompts the user for configuration values and writes them to the configuration file."""
        try:
            self.org = self.user_input("Organization: ")
            self.username = self.user_input("Username: ")
            self.appid = self.user_input("App ID: ")
            self.region = self.user_input("Region: ")
            self.password_cache = self.user_input("Password Cache: ")
            self.password_reset = self.user_input("Password Reset: ")
            self.totp_secret = self.user_input("TOTP Secret: ")
            self.write_config()
            print("")
            LOG.info("Config file written. Please rerun Aws Okta")
        except KeyboardInterrupt:
            print("")
            LOG.warning("User cancelled configuration; exiting")

    def write_config(self):
        """Writes the current configuration to the configuration file."""

        file_path = os.path.expanduser(self.writepath)
        logging.info(file_path)
        config = self.read_yaml()

        args_dict = dict(vars(self))

        # Combine file data and user args with user args overwriting
        for key, value in config.items():
            setattr(self, key, value)
        for key in args_dict:
            if args_dict[key] is not None:
                setattr(self, key, args_dict[key])

        config_out = self.clean_config_for_write(dict(vars(self)))

        LOG.debug(f"YAML being saved: {config_out}")

        file_folder = os.path.dirname(os.path.abspath(file_path))
        if not os.path.exists(file_folder):
            LOG.debug(
                f"Creating missing config file folder : {file_folder}",
            )
            os.makedirs(file_folder)

        with open(file_path, "w") as outfile:
            yaml.safe_dump(config_out, outfile, default_flow_style=False)

    # Rest of your code
    @staticmethod
    def clean_config_for_write(config):
        """Removes unnecessary keys from the configuration before writing it to a file."""
        ignore = [
            "name",
            # "appid",
            "argv",
            "writepath",
            "config",
            "debug",
            "password_reset",
            "update",
        ]
        for var in ignore:
            if var in config:
                del config[var]
        return config

    def get_config(self):
        """Loads the configuration from the command-line arguments and/or the configuration file."""

        config_file = os.path.expanduser(self.writepath)
        if "-w" in self.argv[1:] or "--writepath" in self.argv[1:]:
            self.parse_args(main_required=False)
            self.write_config()
        elif "-c" in self.argv[1:] or "--config" in self.argv[1:]:
            self.parse_args(main_required=False)
            self.parse_config()
        elif os.path.isfile(config_file):
            # If we haven't been told to write out the args and no filename is
            # given just use the default path
            self.parse_args(main_required=False)
            self.parse_config()
        else:
            # No default file, none specified; operate on args only
            self.parse_args()
        self.validate()

    def parse_args(self, main_required=True):
        """Parses command-line arguments and stores the values in the Config object."""
        arg_parser = argparse.ArgumentParser(
            prog=self.argv[0],
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self.usage_epilog(),
            description=f"AWS Okta  v{__version__}",
        )

        arg_parser._action_groups.pop()

        optional_args = arg_parser.add_argument_group("Optional arguments")

        if main_required:
            required_args = arg_parser.add_argument_group(
                "Required arguments " "or settings",
            )
            self.main_args(required_args, main_required)
        else:
            self.main_args(optional_args)

        self.optional_args(optional_args)

        config = arg_parser.parse_args(args=self.argv[1:])
        config_dict = vars(config)

        for key in config_dict:
            setattr(self, key, config_dict[key])

    @staticmethod
    def main_args(arg_group, required=False):
        """Adds the main command-line arguments to the argument parser."""

        arg_group.add_argument(
            "-o",
            "--org",
            type=str,
            help=(
                "Okta Organization Name - ie, if your "
                "login URL is https://example.okta.com, "
                "enter in foobar here or you may use"
                "the complete URL."
            ),
            required=required,
        )

    @staticmethod
    def usage_epilog():
        """Returns the epilog text for the argument parser."""
        epilog = (
            "** Application ID **\n"
            "The Application ID is a component of the redirect URL used by Okta when you're logged into the Web UI. "
            "For instance, if you hover over the appropriate Application and see a URL like this:\n"
            "\n"
            "\thttps://example.okta.com/home/amazon_aws/0oa1okvmwx7JTBo5r1d8/123?...\n"
            "\n"
            'You would use "0oa1okvmwx7JTBo5r1d8/123" as your Application ID.\n'
            "\n"
            "** Configuration File **\n"
            "AWS Okta can utilize a configuration file to pre-set most of the execution settings. The default file "
            "location is '~/.config/aws_okta.yml' on Linux/Mac, and '$USERPROFILE\\.config\\aws_okta.yml' on "
            "Windows.\n\n"
            "To create a basic configuration, you can start AWS Okta with 'config' as the sole argument. This will "
            "prompt you to enter the basic configuration settings needed to get started.\n"
        )
        return epilog

    def parse_config(self):
        """Loads the configuration from the configuration file and stores the values in the Config object."""
        config = self.read_yaml(raise_on_error=True)

        for key, value in config.items():
            if not getattr(self, key):  # Only overwrite None not args
                setattr(self, key, value)

    def validate(self):
        """Validates the configuration values."""
        if getattr(self, "org", None) is None:
            err = (
                "The parameter org must be provided in the config file "
                "or as an argument"
            )
            raise ValueError(err)

        if self.region is None:
            self.region = "eu-west-1"

        if self.username is None:
            user = getpass.getuser()
            LOG.info(
                "No username provided; defaulting to current user '{}'".format(
                    user,
                ),
            )
            self.username = user
        elif "automatic-username" in self.username:
            self.username = self.username.replace(
                "automatic-username",
                getpass.getuser(),
            )

    def read_yaml(self, raise_on_error=False):
        """Reads the configuration from a YAML file."""
        config = {}
        try:
            with open(os.path.expanduser(self.writepath)) as file:
                config = yaml.load(file, Loader=yaml.FullLoader)
            LOG.info(f"YAML loaded config: {config}")
        except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
            LOG.error(f"Error parsing config file; invalid YAML. Error: {e}")
            if raise_on_error:
                raise
        return config

    @staticmethod
    def optional_args(optional_args):
        """Adds the optional command-line arguments to the argument parser."""
        optional_args.add_argument(
            "-u",
            "--username",
            type=str,
            help=(
                "Okta Login Name - either "
                "bob@foobar.com, or just bob works too,"
                " depending on your organization "
                "settings. Will use the current user if "
                "not specified."
            ),
        )
        optional_args.add_argument(
            "-a",
            "--appid",
            type=str,
            help=(
                'The "redirect link" Application ID  - '
                "this can be found by mousing over the "
                "application in Okta's Web UI. See "
                "details below for more help."
            ),
        )
        optional_args.add_argument(
            "-V",
            "--version",
            action="version",
            version=__version__,
        )
        optional_args.add_argument(
            "-D",
            "--debug",
            action="store_true",
            help=(
                "Enable DEBUG logging - note, this is "
                "extremely verbose and exposes "
                "credentials on the screen so be "
                "careful here!"
            ),
            default=False,
        )
        optional_args.add_argument(
            "-c",
            "--config",
            type=str,
            help="Config File path",
        )
        optional_args.add_argument(
            "-w",
            "--writepath",
            type=str,
            help="Full config file path to write to",
            default="~/.config/aws_okta.yml",
        )
        optional_args.add_argument(
            "-P",
            "--password_cache",
            action="store_true",
            help="Use OS keyring to cache your password.",
            default=False,
        )
        optional_args.add_argument(
            "-R",
            "--password_reset",
            action="store_true",
            help=(
                "Reset your password in the cache. "
                "Use this to update the cached password"
                " if it has changed or is incorrect."
            ),
            default=False,
        )
        optional_args.add_argument(
            "-T",
            "--totp_secret",
            action="store_true",
            help="Use this to get passcode automatically ",
            default='',
        )

        optional_args.add_argument(
            "-re",
            "--region",
            type=str,
            help="AWS region to use for calls.Required for GovCloud.",
        )
