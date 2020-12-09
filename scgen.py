import os
import sys

bin_path = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)
lib_path = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "lib"))
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

from splunklib.searchcommands import GeneratingCommand, Configuration, Option, validators
import splunklib.results as results
import splunklib.data as data
import re
import ipaddress


@Configuration(type='reporting')
class SCGenCommand(GeneratingCommand):
    def generate(self):

        # get details about recent forwarders
        reader = results.ResultsReader(self.service.jobs.export(
            "rest /services/deployment/server/clients | fields hostname ip utsname | rename utsname AS os",
            earliest_time="-24h"
        ))
        # "search index=_internal Metrics group=tcpin_connections sourcetype=splunkd | stats first(sourceIp) as ip values(os) as os  by hostname",
        forwarders = [row for row in reader if isinstance(row, dict)]

        # get deployment apps
        response = self.service.get(
            "/services/deployment/server/applications",
        )
        application_entries = data.load(response.body.read().decode('utf-8', 'xmlcharrefreplace'))["feed"]["entry"]
        applications = dict()
        for app in application_entries:
            name = app["title"]
            serverclasses = set(app["content"]["serverclasses"])
            applications[name] = serverclasses

        # get already existing server classes
        response = self.service.get(
            "/services/deployment/server/serverclasses",
        )
        existing_serverclasses = data.load(response.body.read().decode('utf-8', 'xmlcharrefreplace'))["feed"]["entry"]
        existing_serverclass_names = set()
        for serverclass in existing_serverclasses:
            if serverclass["title"].endswith("_gen"):
                existing_serverclass_names.add(serverclass["title"])

        # get serverclass rules
        reader = results.ResultsReader(self.service.jobs.export(
            "inputlookup serverclass_rules.csv"
        ))
        serverclass_rules = [row for row in reader if isinstance(row, dict)]

        # iterate rules and update serverclasses appropriately
        for rule in serverclass_rules:

            # get rule details
            serverclass_name = "%s_gen" % rule["serverclass"]
            active = str(rule["active"]).lower() in ['1', 't', 'true', 'y', 'yes', 'enable', 'enabled']
            hostname_pattern = "%s" % rule["hostname"]
            os_pattern = "%s" % rule["os"] if "os" in rule else None
            app_pattern = "%s" % rule["apps"] if "apps" in rule else None
            ip_pattern = "%s" % rule["cidr"] if "cidr" in rule else ""
            ip_network = ipaddress.ip_network(ip_pattern) if ip_pattern else None

            # get matching forwarders
            whitelist = set()
            for forwarder in forwarders:
                forwarder_os = forwarder["os"]
                os_match = True if not os_pattern or re.match(os_pattern, forwarder_os) else False
                forwarder_hostname = forwarder["hostname"]
                forwarder_ip = ipaddress.IPv4Address(forwarder["ip"]) if forwarder["ip"] else None
                hostname_match = True if re.match(hostname_pattern, forwarder_hostname) else False
                network_match = ip_network is None or forwarder_ip is None or forwarder_ip in ip_network
                if hostname_match and network_match and os_match:
                    whitelist.add(forwarder_hostname)

            # generate whilelist attribute based on matching forwarders
            attributes = dict()
            whitelist_index = 0
            for name in whitelist:
                attributes["whitelist.%s" % whitelist_index] = name
                whitelist_index += 1

            # create or update serverclass
            if active:
                if serverclass_name in existing_serverclass_names:
                    existing_serverclass_names.remove(serverclass_name)
                    self.service.post(
                        "/servicesNS/nobody/scgen/deployment/server/serverclasses/%s" % serverclass_name,
                        **attributes
                    )
                else:
                    self.service.post(
                        "/servicesNS/nobody/scgen/deployment/server/serverclasses",
                        name=serverclass_name,
                        **attributes
                    )

            # iterate available apps and map to serverclass accordingly
            assigned_apps = []
            for app_name, serverclasse_names in applications.items():
                app_match = True if app_pattern and re.match(app_pattern, app_name) else False
                if active:
                    if app_match and serverclass_name not in serverclasse_names:
                        self.service.post(
                            "/servicesNS/nobody/scgen/deployment/server/applications/%s" % (app_name),
                            **{
                                "serverclass": serverclass_name,
                            }
                        )
                    if not app_match and serverclass_name in serverclasse_names:
                        self.service.post(
                            "/servicesNS/nobody/scgen/deployment/server/applications/%s" % (app_name),
                            **{
                                "serverclass": serverclass_name,
                                "unmap": True,
                            }
                        )
                if app_match:
                    assigned_apps.append(app_name)

            # return search command result (just for information)
            yield {
                "serverclass": serverclass_name,
                "forwarders": list(whitelist),
                "apps": assigned_apps,
                "active": active,
            }

        # delete already server classes that are not required anymore
        for name in existing_serverclass_names:
            self.service.delete(
                "/services/deployment/server/serverclasses/%s" % name,
            )


if __name__ == "__main__":
    from splunklib.searchcommands import dispatch
    dispatch(SCGenCommand, sys.argv, sys.stdin, sys.stdout, __name__)
