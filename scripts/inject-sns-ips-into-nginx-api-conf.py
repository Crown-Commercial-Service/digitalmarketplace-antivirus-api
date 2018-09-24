#!/usr/bin/env python
import logging
import subprocess
import sys

import jinja2
from jinja2.runtime import StrictUndefined
import requests

logger = logging.getLogger("antivirus-api-callback-ip-update")


def get_filtered_ip_ranges():
    try:
        response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Error: failed to get IP ranges - {e}")
        sys.exit(1)

    all_ip_ranges = response.json()['prefixes']

    # Currently AWS does not provide specific IP ranges for the SNS service. They will in future though.
    filtered_ip_ranges = [
        i['ip_prefix'] for i in all_ip_ranges if i['service'] == 'AMAZON' and i['region'] == 'eu-west-1'
    ]

    if not filtered_ip_ranges:
        print("No IP ranges found after filtering")
        sys.exit(1)

    return filtered_ip_ranges


def template_conf(sns_ip_ranges):
    jinja_env = jinja2.Environment(
        trim_blocks=True,
        loader=jinja2.FileSystemLoader('/etc/nginx/templates'),
        undefined=StrictUndefined,
    )

    template = jinja_env.get_template('api.j2')
    template.stream(sns_ips=sns_ip_ranges).dump('/etc/nginx/sites-enabled/api')


def reload_nginx():
    try:
        subprocess.run(["/usr/sbin/nginx", "-s", "reload"], check=True)
        logger.info("SNS IP whitelist updated")
    except subprocess.CalledProcessError as e:
        logger.error("Error: failed to reload nginx")
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s:%(name)s:%(levelname)s:%(message)s",
        handlers=[
            logging.FileHandler('/var/log/amazon_ip_update.log'),
            logging.StreamHandler(),
        ]
    )

    template_conf(sns_ip_ranges=get_filtered_ip_ranges())
    reload_nginx()
