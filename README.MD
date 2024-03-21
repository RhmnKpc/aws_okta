
# AWS Okta Integration Tool

## Description

The AWS Okta Integration Tool (`aws_okta`) facilitates secure access to AWS resources by leveraging Okta for authentication. This Python-based utility enables users to obtain temporary AWS credentials and tokens through Okta, streamlining the process of accessing AWS services in a secure manner.

## Setup

Before you can use `aws_okta`, ensure you have Python 3 installed on your system. You may also need to install any dependencies, typically by running:

```sh
pip install -r requirements.txt
```

## Configuration

The tool supports an interactive configuration mode that prompts the user for necessary details such as Organization, Username, App ID, Region, among others. To enter the interactive configuration mode, run:

```sh
python3 main.py config
```

This will guide you through setting up your initial configuration, which will be saved in `~/.config/aws_okta.yml` by default.

## Usage

To use the tool for obtaining AWS temporary credentials and tokens, the command structure is as follows:

```sh
python3 main.py -u <username> -o <organization> -P
```

### Command-Line Arguments

- `-u, --username`: Specifies the username for Okta authentication. Example: `email@example.com`.
- `-o, --org`: Specifies the Okta organization. Example: `trial-123131`.
- `-P, --password_cache`: Enables the use of the OS keyring to cache your password for convenience.
- `-R, --password_reset`: Resets your password in the cache. Use this to update the cached password if it has changed or is incorrect.
- `-T, --totp_secret`: Automatically use a TOTP secret for passcode generation (if applicable).
- `-c, --config`: Specifies a custom config file path.
- `-w, --writepath`: Specifies a full config file path to write to.
- `-D, --debug`: Enables DEBUG logging. Be cautious as this may expose credentials on the screen.
- `-V, --version`: Displays the version of the tool.
- `-re, --region`: Specifies the AWS region to use for calls. This is required for GovCloud.

Ensure to replace `<username>` and `<organization>` with your actual Okta username and organization values when running the tool.

For further help and options, you can always run:

```sh
python3 main.py --help
```

## Security

Remember to keep your configuration file secure, especially if it contains sensitive information like passwords or TOTP secrets. Use the password caching feature responsibly and be aware of the risks involved in enabling debug logging.
