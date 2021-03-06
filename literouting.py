import dns.resolver
import os
import os.path
import sys
import re
import traceback
import subprocess
import json
import logging
import logging.handlers
import urllib2
import time


class VpnClientDisconnected(Exception):
    pass

def flush_routes():
    cmd = ["ip", "route", "flush", "cache"]
    subprocess.call(cmd)
    logging.debug(" ".join(cmd))


def notify_send_pushover(msg):
    """ send a notification via pushover
    """
    global config
    payload = {"message": msg, "token": config["pushover"]["apitoken"], "user": config["pushover"]["userkey"]}
    req = urllib2.Request("https://api.pushover.net/1/messages.json")
    req.add_header("Content-Type", "application/json")
    
    urllib2.urlopen(req, json.dumps(payload))
    

def load_config(config_files):
    """ loads json configuration files
    the latter configs overwrite the previous configs
    """

    config = dict()

    for f in config_files:
        with open(f, 'rt') as cfg:
            config.update(json.load(cfg))

    return config


def lookup_ips(address):
    """ gets all ip addresses for a dns entry """
    global config

    r = dns.resolver.Resolver()

    if config["custom_dns_servers"]:
        r.nameservers = config["custom_dns_servers"]
    for address_type in ['A', 'AAAA']:
        try:
            answers = r.query(address, address_type)
            for rdata in answers:
                yield str(rdata)
        except:
            pass


def ip_version(address):
    """ returns the ip version, can be either 4 or 6 """
    m = re.match("[0-9a-fA-F:]{5}", address)
    if m is not None:
        return 6
    elif re.match("[0-9.]{3}", address):
        return 4
    else:
        raise Exception("Unknown IP-Address format")

    return None


def get_domainlist(url, timeout):
    """ loads the domainlist from the provided url and returns as string """

    try:
        response = urllib2.urlopen(url, timeout=timeout)
        return [domain.strip() for domain in response.read().split() if domain.strip()]
    except urllib2.URLError:
        logging.warning("Domainlist could not be fetched.")
        return []


def lookup_ipaddresses(domains):
    """ looks up the provided domain list and returns a list of all
    corresponding IP addresses """

    global config

    ip_addresses_lists = [lookup_ips(domain) for domain in domains]
    n = list(set([ip for address_list in ip_addresses_lists for ip in address_list])) 

    # filter ipv6 and ipv4, respectively, if the appropriate command is not set
    if not config["ip6tables_cmd"]:
        n = filter(lambda x: ip_version(x) == 4, n)

    if not config["ip4tables_cmd"]:
        n = filter(lambda x: ip_version(x) == 6, n)


    return n


def get_ipaddresses():
    """ provides the caller with a list of lookedup ipaddresses that
    are either cached or just retrieved."""
    global config

    if (config["cache_path"] and
        os.path.exists(config["cache_path"]) and 
        time.time() - os.path.getmtime(config["cache_path"]) < (60 * config["max_cache_duration_in_minutes"])
       ):
        with open(config["cache_path"], "r") as f:
            return [addr.strip() for addr in f.readlines()]
    else:
        domains = get_domainlist(config["domainlist_url"], config["timeout"])

        if config["prepend_www"]:
            domains.extend(["www.{}".format(domain) for domain in domains])
        addresses = lookup_ipaddresses(domains)
        if config["cache_path"]:
            with open(config["cache_path"], "w") as f:
                for addr in addresses:
                    f.write("{address}\n".format(address = addr))

        return addresses
    

def insert_blacklist_rules(ip_addresses):
    """ inserts the iptables rules to block the provided ip_addresses """
    global config

    block_action = config["block_action"]
    
    for addr in ip_addresses:

        insert_cmd = get_routing_command('insert', addr, block_action)
        check_cmd = get_routing_command('check', addr, block_action)
        delete_cmd = get_routing_command('delete', addr, block_action)
        if config["prevent_duplicates"]:
            if not config["iptables_compatability_mode"]:
                try:
                    # Check if the rule is already existing
                    logging.debug(" ".join(check_cmd))
                    subprocess.check_output(check_cmd)
                except:
                    # Add the rule as it does not exist yet
                    logging.debug(" ".join(insert_cmd))
                    subprocess.check_output(insert_cmd)
            else:
                # remove the rule
                logging.debug(" ".join(delete_cmd))
                subprocess.call(delete_cmd)

        if config["iptables_compatability_mode"]:
            # add the rule (in normal mode this already happened)
            logging.debug(" ".join(insert_cmd))
            subprocess.check_output(insert_cmd)


def get_routing_command(routing_operation, address, block_action):
    """ Creates the shell command for the specified address and routing_operation. """
    global config
    iptables = config["ip4tables_cmd"] if ip_version(address) == 4 else config["ip6tables_cmd"]
    out_interface = config["out_interface"]
    routing_action = ["-j", block_action]

    if routing_operation == 'insert':
        return ([iptables, "-I", config["iptables_chain"], "1", "-d", address, "-o", out_interface] 
                                    + routing_action)
    elif routing_operation == 'check':
        return ([iptables, "-C", config["iptables_chain"], "-d", address, "-o", out_interface] 
                                    + routing_action)
    elif routing_operation == 'delete':
        return ([iptables, "-D", config["iptables_chain"], "-d", address, "-o", out_interface] 
                                    + routing_action)
    else:
        logging.error("Unknown routing_operation provided for get_routing_command.")
        return ""


def insert_routing_rules(ipaddresses):
    global config, __location__

    for address in ipaddresses:
        cmd = ["ip", "-4" if ip_version(address) == 4 else "-6", "rule", "add", "to", address, "table", config["vpn_table"]]
        logging.debug(" ".join(cmd))
        subprocess.call(cmd)
    
    # Parse the endpoint ip-address of the vpn tunnel from ifconfig
    vpnaddress = subprocess.check_output(["ifconfig {dev} | sed -n '/inet /{{s/.*P-t-P://;s/ .*//;p}}'".format(dev=config["tunnel_name"])], shell=True).strip()
    flag_file = "/tmp/{}.last_failed".format(os.path.basename(__file__))

    if len(vpnaddress) > 0:
        cmd = (["ip", "route", "add", "default", "via", vpnaddress, "dev", config["tunnel_name"], "table", config["vpn_table"]])
        logging.debug(" ".join(cmd))
        subprocess.call(cmd)
        msg = "{} - routing over vpn resumed".format(os.path.basename(__file__))
 
        if config["pushover"]["enabled"] and os.path.exists(flag_file):
            notify_send_pushover(msg)

            try:                                                                                                            
                os.remove(flag_file)                                                                                        
            except OSError:                                                                                                 
                pass  

    else:
        msg = "{} - all specified domains are blocked".format(os.path.basename(__file__))
        if config["pushover"]["enabled"] and not os.path.exists(flag_file):
            with open(flag_file, 'wt'):
                notify_send_pushover(msg)
        
        raise VpnClientDisconnected(msg)

    flush_routes()


def excepthook(excType, excValue, tb):
    """ this function is called whenever an exception is not catched """
    global config
    err = "Uncaught exception:\n{}\n{}\n{}".format(str(excType), excValue, "".join(traceback.format_exception(excType, excValue, tb)))
    logging.error(err)

    # always flush the toilet ;) 
    try:
        flush_routes() 
    except:
        pass

    # try to notify the sysadmin about this
    if len(config["notification_cmd"]) > 0:
        try:
            subprocess.call(config["notification_cmd"].format(msg="Error: " + err), shell=true)

        except Exception as inst:
            logging.error("could not notify admin, {}".format(inst))

def main():
    """ Retrieve the domains to route """
    ipaddresses = get_ipaddresses()
    insert_blacklist_rules(ipaddresses)
    insert_routing_rules(ipaddresses)


if __name__ == "__main__":
    # configuration
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    sys.excepthook = excepthook
    config = load_config([os.path.join(__location__,"config.json")])
    log_path = config["log_path"]

    # init logging
    rot_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=1000000, backupCount=5)
    rot_handler.setFormatter(logging.Formatter('%(levelname)s\t | %(asctime)s | %(message)s'))
    logging.getLogger().addHandler(rot_handler)
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG if config["verbose"] else logging.INFO)

    # run main procedure
    main()


