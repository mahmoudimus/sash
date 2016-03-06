#!/usr/bin/env python
from __future__ import unicode_literals
import argparse
import logging
import os
import subprocess
import sys
from collections import defaultdict

logger = logging.getLogger(__name__)


def aws_cmd_prefix(aws_profile):
    cmd = ['aws', 'ec2', 'describe-instances']
    if aws_profile:
        cmd.insert(1, '--profile=' + aws_profile)
    return cmd


def private_dns_to_name(args, dns):
    if not dns:
        raise ValueError("please enter private dns (ip-10-0-0-XX)")
    instance_id = subprocess.check_output(
        aws_cmd_prefix(args.profile) + [
        '--filter', 'Name=private-dns-name,Values={}.*'.format(dns),
        '--query', 'Reservations[*].Instances[*].InstanceId',
        '--output', 'text'])
    if not instance_id:
        instance_id = subprocess.check_output(
            aws_cmd_prefix(args.profile) + [
            '--filter', 'Name=private-dns-name,Values={}*'.format(dns),
            '--query', 'Reservations[*].Instances[*].InstanceId',
            '--output', 'text'])

    if not instance_id:
        logger.info("No machine found with private dns %s", dns)
        return

    instance_name = subprocess.check_output(
        aws_cmd_prefix(args.profile) + [
        '--filter', 'Name=key,Values=Name', 'Name=resource-id,Values={}'.format(instance_id),
        '--query', 'Tags[].Value',
        '--output', 'text'])
    return instance_name


def connect(args):
    host = args.target
    if not host:
        raise ValueError("Machine name or host name not set: %s" % host)

    query = ("Reservations[*].Instances[]"
             ".[KeyName,PublicIpAddress,Tags[?Key==`Name`].Value"
             " | [0],InstanceId,Tags[?Key==`SashUserName`].Value"
             " | [0],PrivateIpAddress]")

    for filtr in ["tag:Name", "private-ip-address", "instance-id"]:
        proc = subprocess.Popen(aws_cmd_prefix(args.profile) + [
                '--filter',
                    'Name={0},Values={1}'.format(filtr, host),
                    'Name=instance-state-name,Values=running',
                '--query', query,
                '--output', 'text'],
                stdout=subprocess.PIPE)
        instance = subprocess.check_output(['sort', '-n'], stdin=proc.stdout)
        if instance:
            break
    else:
        logger.debug("Could not find an instance named: %s", host)
        return

    instance_data = defaultdict(list)
    for line in instance.split("\n"):
        if not line:
            continue
        pems, ips, hosts, resource_ids, users, private_ips = line.split()
        instance_data['pems'].append(pems)
        instance_data['ips'].append(ips)
        instance_data['hosts'].append(hosts)
        instance_data['resource_ids'].append(resource_ids)
        instance_data['users'].append(users)
        instance_data['private_ips'].append(private_ips)

    # if there is no public IPs, then we will use the private ip
    for i, v in enumerate(list(instance_data['ips'])):
        if v == 'None':
            instance_data['ips'][i] = instance_data['private_ips'][i]

    # which one do we want to connect w/ from the instance?
    idx = args.index
    pem = instance_data['pems'][idx]
    ip = instance_data['ips'][idx]
    user = args.ssh_user or pem
    identity_file = args.ssh_identity_file
    if not identity_file:
        identity_file = args.ssh_identity_file_fmt.format(filename=pem)
    identity_file = os.path.abspath(os.path.expanduser(identity_file))

    msg = 'Connecting to %s (%s)'
    if len(instance_data['pems']) > 1:
        msg += ' (out of ' + repr(len(instance_data['pems'])) + ' instances)'
    host = instance_data['hosts'][idx]
    if host == 'None':
        host = 'Unknown host'

    logger.info(msg, host, ip)
    sys.stdout.write(
        "ssh -i {identity_file} {user}@{ip} {ssh_args}".format(
            identity_file=identity_file,
            user=user,
            ip=ip,
            ssh_args='' if args.ssh_args is None else args.ssh_args
        ))


def execute(args):
    # private_dns_to_name(args, 'ip-10.0.0.11')
    connect(args)


class SetLoggingLevel(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        level = logging.getLevelName(values)
        setattr(namespace, self.dest, level)
        logger.setLevel(level)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--logging-level',
        action=SetLoggingLevel,
        help='Set the logging level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'],
        )
    parser.add_argument('--profile', help='The AWS profile to use')
    parser.add_argument('--ssh-user', help='The SSH user to connect with')
    parser.add_argument('--ssh-identity-file',
        help='The path to the SSH identity file to connect via SSH. This will '
        'override the --ssh-identity-file-fmt argument.')
    parser.add_argument('--ssh-identity-file-fmt',
        help='A string format expr as a path to the SSH identity file',
        default=os.path.expanduser("~/.aws/{filename}.pem"))
    parser.add_argument('--ssh-args', help='Optional args to pass to SSH cmd')

    parser.add_argument('target',
        help='Query Tags[Name], Private IP Addr, or an Instance ID for target')
    parser.add_argument('index', default=0, nargs='?', type=int,
        help='The index to use from the instance list. Defaults to 0')
    args = parser.parse_args()
    execute(args)


if __name__ == '__main__':
    logging.basicConfig(
            level='INFO',
            format='%(asctime)s : %(levelname)s : %(name)s : %(message)s',
            stream=sys.stderr)
    main()
