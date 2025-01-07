import nmap

def Basic_port_scan(target, ports):
    result = {}
    print(f"Performing basic port scan on {target} for ports: {ports}...")
    nm = nmap.PortScanner()
    nm.scan(target, arguments=f'-p {ports}')  # Scanning specified ports

    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        result.append(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        result.append(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            result.append(f'Protocol: {proto}')
            for port in nm[host][proto].keys():
                print(f'Port: {port}, State: {nm[host][proto][port]["state"]}')
                result.append(f'Port: {port}, State: {nm[host][proto][port]["state"]}')
    return result

def Advanced_port_scan(target, ports):
    result = {}
    print(f"Performing advanced scan on {target} for ports: {ports}...")
    nm = nmap.PortScanner()
    options = f"-sS -sV -O -A -p {ports}"  # Advanced scan options
    nm.scan(target, arguments=options)

    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        result.append(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        result.append(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            result.append(f'Protocol: {proto}')
            for port in nm[host][proto].keys():
                print(f'Port: {port}, State: {nm[host][proto][port]["state"]}')
                result.append(f'Port: {port}, State: {nm[host][proto][port]["state"]}')
    return result