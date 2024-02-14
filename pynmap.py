import nmap
import argparse
from tabulate import tabulate


nm = nmap.PortScanner()


parser = argparse.ArgumentParser(description='Escanear una red utilizando nmap')


parser.add_argument('ip_range', metavar='Rango-IP', type=str, help='Rango de dirección IP a escanear')

parser.add_argument('-v', '--verbose', action='store_true', help='Mostrar resultados detallados')


args = parser.parse_args()


common_ports = '1-1023'


nm.scan(args.ip_range, arguments=f'-sS -sU -T4 -O -p {common_ports} -vv -f -D RND:10 -sV')


host_data = []


for host in nm.all_hosts():
    host_services = []
    
    for protocol in nm[host].all_protocols():
        ports = sorted(nm[host][protocol].keys())
        for port in ports:
           
            if port <= 1023:
                service_name = nm[host][protocol][port]['name']
                service_version = nm[host][protocol][port]['version'] if 'version' in nm[host][protocol][port] else ''
                # Almacenar el puerto, protocolo y servicio en una lista
                host_services.append([f'{port}/{protocol}', service_name, service_version])
    
    os_name = nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] else 'Desconocido'
    
    host_data.append([host, nm[host]['status']['state'], os_name, '', '', ''])
    for service in host_services:
        host_data.append(['', '', '', service[0], service[1], service[2]])

if args.verbose:
    print(tabulate(host_data, headers=['Dirección IP', 'Estado', 'Sistema operativo', 'Puerto/Protocolo', 'Servicios', 'Versión']))
else:
    print(tabulate(host_data, headers=['Dirección IP', 'Estado', 'Sistema operativo', 'Puerto/Protocolo', 'Servicios']))
