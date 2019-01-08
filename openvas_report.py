#!/usr/bin/python3

import pprint
import configparser
from openvas_lib import VulnscanManager, VulnscanException
from xml.etree import ElementTree as ET

# OpenStack dependencies
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as keystone_client

import ipaddress
import json
import os.path

from jinja2 import Environment, FileSystemLoader, BaseLoader
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

pp = pprint.PrettyPrinter()

CONFIG_FILE = 'openvas_report_settings.ini'
DEBUG_OPENSTACK_DATA = '.tmp_openstack_data,json'
DEBUG_OPENVAS_DATA = '.tmp_openvas_data.xml'

DEBUG = False

THREAT_MAP = {'Low': 0, 'Medium': 1, 'High': 2}

def populate_openstack_data(data):
    """ Fetch all openstack data needed """
    data['os'] = {}
    if DEBUG and os.path.isfile(DEBUG_OPENSTACK_DATA):
        print("Warning: DEBUG is enabled, reading openstack data from %s" % DEBUG_OPENSTACK_DATA)
        file = open(DEBUG_OPENSTACK_DATA, "r")
        data['os'] = json.load(file)
    else:
        os_conf = data['config']['openstack']
        os_auth = v3.Password(auth_url=os_conf['url'], username=os_conf['user'],
                              password=os_conf['password'],
                              project_name=os_conf['project'],
                              user_domain_name=os_conf['domain'],
                              project_domain_name=os_conf['domain'])
        os_sess = session.Session(auth=os_auth)
        headers = {'Accept': 'application/json'}
        keystone = keystone_client.Client(session=os_sess, connection_pool=True)

        # We need the ID of the domain.
        domains = {key.name: key.id for key in keystone.domains.list()}
        # We need all role ID:s
        roles = {key.id: key.name for key in keystone.roles.list()}
        # We need all users
        users = {key.id: {'name': key.name, 'email': key.email}
                 for key in keystone.users.list(domain=domains[os_conf['user_domain']]) if hasattr(key, 'email')}

        # Find the neutron url
        services = {service.name+'_'+service.type: service.id for service in keystone.services.list()}
        endpoints = {endpoint.service_id+'_'+endpoint.interface: endpoint.url for endpoint in keystone.endpoints.list()}
        neutron_url = endpoints[services['neutron_network']+'_public']

        # Fetch project list, ID to project name
        data['os']['projects'] = {prj.id: {'name': prj.name, 'emails': {}} for prj in keystone.projects.list()}

        # Fetch all role assignments and use that to figure out which users belong to which project
        response = keystone.session.get(os_conf['url'] + '/role_assignments?scope.domain.id' +
                                        domains[data['config']['openstack']['user_domain']],
                                        headers=headers, authenticated=os_auth)
        if response.status_code != 200:
            print("Failed to list role_assignments!")
            exit(1)
        roles = response.json()
        for entry in roles['role_assignments']:
            if 'scope' in entry and 'user' in entry:
                user_id = entry['user']['id']
                project_id = entry['scope']['project']['id']
                if user_id in users:
                    entry = {users[user_id]['email']: users[user_id]['name']}
                    data['os']['projects'][project_id]['emails'].update(entry)

        data['os']['hosts'] = {}

        # We need to know the networks to look for
        networks = []
        for netname in data['config']['networks']:
            networks.append(ipaddress.IPv4Network(data['config']['networks'][netname]))

        # Get floatingips list
        response = keystone.session.get(neutron_url + '/v2.0/floatingips',
                                        headers=headers, authenticated=os_auth)
        if response.status_code != 200:
            print("Failed to get floating IPs list!")
            exit(1)
        floatingips = response.json()['floatingips']

        # Get port list
        response = keystone.session.get(neutron_url + '/v2.0/ports',
                                        headers=headers, authenticated=os_auth)
        if response.status_code != 200:
            print("Failed to get the port list!")
            exit(1)

        # Combine them to one list.... Needs some work below though
        ports = response.json()['ports'] + floatingips
        for port in ports:
            if 'device_owner' in port:
                owner = port['device_owner']
                # Skip system IP:s, they are of no use to us
                if owner == 'network:floatingip' or owner == 'network:router_gateway':
                    continue
            project = port['project_id']
            if project == '':
                print('Project id is unknown, this should never happen!')
                pp.pprint(port)
                exit(1)
            if 'floating_ip_address' in port:
                address = ipaddress.ip_address(port['floating_ip_address'])
                for network in networks:
                    if address in network:
                        data['os']['hosts'][port['floating_ip_address']] = project
            else:
                for ip in port['fixed_ips']:
                    address = ipaddress.ip_address(ip['ip_address'])
                    for network in networks:
                        if address in network:
                            data['os']['hosts'][ip['ip_address']] = project

        if DEBUG:
            file = open(DEBUG_OPENSTACK_DATA, "w")
            json.dump(data['os'], file)

def populate_openvas_data(data):
    """ Fetch OpenVAS data """
    try:
        data['ovs'] = {}
        data['ovs']['host'] = {}
        data['ovs']['project'] = {}
        data['ovs']['data'] = {}
        ovc = data['config']['openvas']
        ovs_report = None

        if DEBUG and os.path.isfile(DEBUG_OPENVAS_DATA):
            print("Warning: DEBUG is enabled, reading opemvas data from %s" % DEBUG_OPENVAS_DATA)
            ovs_report = ET.ElementTree().parse(DEBUG_OPENVAS_DATA)
        else:
            scanner = VulnscanManager(ovc['host'], ovc['user'],
                                      ovc['password'],
                                      int(ovc['port']), 30)

            finished_scans = scanner.get_finished_scans
            for entry in finished_scans:
                if ovc['scan'] is None or entry == ovc['scan']:
                    report_id = scanner.get_report_id(finished_scans[entry])
                    ovs_report = ET.ElementTree(scanner.get_report_xml(report_id))
                    if DEBUG:
                        ovs_report.write(DEBUG_OPENVAS_DATA)

    except VulnscanException as e:
        print(e)

    if ovs_report:
        for results in ovs_report.iter('results'):
            for result in results:
                ret = {}
                host = result.find('host').text
                details = result.findall('./detection/result/details/detail')
                for detail in details:
                    # typically product, location, source_oid and source_name
                    label = detail.find('name').text
                    value = detail.find('value').text
                    ret[label] = value

                if host not in data['os']['hosts']:
                    print("IP '%s' is unknown" % host)
                else:
                    project_id = data['os']['hosts'][host]
                    project = data['os']['projects'][project_id]['name']

                    projects = data['ovs']['project']
                    if project not in projects:
                        projects[project] = {}
                        projects[project].update({'host': {}, 'emails': {}})

                    projects[project]['emails'].update(data['os']['projects'][project_id]['emails'])

                    hosts = projects[project]['host']
                    if host not in hosts:
                        hosts[host] = {}
                        hosts[host]['ports'] = {}
                        hosts[host]['threat'] = ''
                        hosts[host]['severity'] = ''
                    if ret['location'] not in hosts[host]['ports']:
                        hosts[host]['ports'].update({ret['location']: []})

                    ret['severity'] = result.find('severity').text
                    ret['threat'] = result.find('threat').text
                    ret['description'] = result.find('description').text

                    hosts[host]['ports'][ret['location']].append(ret)


def look_for_templates(data):
    """ Verify that the templates are available """
    # Verify that the templates are there early
    for template in data['config']['templates']:
        if not os.path.isfile(data['config']['templates'][template]):
            print("Could not find template for %s at %s" %
                  (template, data['config']['templates'][template]))
            exit(1)

def process_data(data):
    """ Process the data and send out any emails """
    server = None
    if data['config']['smtp']['send'] == 'yes' and not DEBUG:
        smtp = data['config']['smtp']
        server = smtplib.SMTP(smtp['server'], smtp['port'])
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp['user'], smtp['password'])

    no_recipients = {}

    for project in data['ovs']['project']:
        all_cves = {}
        if project in data['config']['recipients']:
            data['ovs']['project'][project]['emails'].update(
                {entry: {} for entry in data['config']['recipients'][project].split()}
            )
        recipients = data['ovs']['project'][project]['emails']

        subject = 'Results from security scan of ' + project

        if len(recipients) < 1:
            no_recipients[project] = ''
            continue

        host_data = []

        hosts = data['ovs']['project'][project]['host']
        for host in sorted(hosts):

            ports = hosts[host]['ports']
            for port in sorted(ports):
                product = ''
                cves = {}
                threat = None
                severity = None
                for entry in ports[port]:
                    product = entry['product']
                    cves[entry['source_name']] = {'description': entry['description'],
                                                  'threat': entry['threat'],
                                                  'severity': entry['severity']}
                    if not threat or THREAT_MAP[threat] < THREAT_MAP[entry['threat']]:
                        threat = entry['threat']
                    if not severity or severity < entry['severity']:
                        severity = entry['severity']
                all_cves.update(cves)

                host_data.append([host, severity, threat, product, cves])

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = data['config']['smtp']['from']
        msg['To'] = ", ".join(sorted(recipients))

        for template in data['config']['templates']:
            env = Environment(loader=FileSystemLoader(searchpath='.'))
            env.add_extension('jinja2.ext.do')
            msg.attach(MIMEText(
                env.from_string(open(data['config']['templates'][template], 'r').read()).render(
                    project=project, cves=all_cves, hosts=host_data), template))

        if server:
            server.send_message(msg)
        else:
            print(msg)
    if data['config']['missing']['users'] and len(no_recipients) > 0:
        projects = "\t" + ', '.join(sorted(no_recipients.keys()))
        contents = "Projects missing users with email addresses:\n" + projects
        if server:
            msg = MIMEText(contents)
            msg['Subject'] = data['config']['missing']['subject']
            msg['From'] = data['config']['smtp']['from']
            msg['To'] = ", ".join(data['config']['recipients']['__missing__'].split())
            server.send_message(msg)
        else:
            print(contents)
    if server:
        server.quit()

def main():
    """ The main function """
    data = {}
    data['config'] = configparser.ConfigParser()
    data['config'].read(CONFIG_FILE)

    look_for_templates(data)
    populate_openstack_data(data)
    populate_openvas_data(data)
    process_data(data)

if __name__ == "__main__":
    main()
