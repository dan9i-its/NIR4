import subprocess
import os
from .models import FullScan 
subprocess.run("mkdir amass", shell=True)
subprocess.run("mkdir subfinder", shell=True)
subprocess.run("mkdir assetfinder", shell=True)
def run_subs_enum(ID):
    scan = FullScan.objects.filter(id=ID)
    print("I find id ")
    print(scan)
    print(scan[0].domains)
    domains = scan[0].domains.split('\r\n')
    print(domains)
    subfinder_result=[]
    assetfinder_result=[]
    # for d in domains:
    #     subprocess.run(f'subfinder -d {d} -o ./subfinder/{d}', shell=True)
    # subfinder_result = subprocess.check_output(f'cat ./subfinder/*', shell=True)
    # subfinder_result = str(subfinder_result).split('\\')
    # subfinder_result = subfinder_result[:-1]

    # for d in domains:
    #     subprocess.run(f'assetfinder -subs-only {d} >> ./assetfinder/{d}', shell=True)
    # assetfinder_result = subprocess.check_output(f'cat ./assetfinder/*', shell=True)
    # assetfinder_result = str(assetfinder_result).split('\\')
    # assetfinder_result = assetfinder_result[:-1]

    amass_result = []
    # Потом раскоментить чтобы пока так для дебага.
    # for d in domains:
    #     result = subprocess.run(f'amass enum -d {d} -o ./amass/{d}', shell=True)

    # amass_result = subprocess.check_output(f'cat ./amass/*', shell=True)
    # amass_result = str(assetfinder_result).split('\\')
    # amass_result = assetfinder_result[:-1]

    dedup_domains = []

    for d in subfinder_result:
        if d not in dedup_domains:
            dedup_domains.append(d)

    for d in assetfinder_result:
        if d not in dedup_domains:
            dedup_domains.append(d)

    for d in amass_result:
        if d not in dedup_domains:
            dedup_domains.append(d)
    domains_text = ''
    dedup_domains = ['aaaaaa', 'bbbbbbb']
    for d in dedup_domains:
        domains_text+= str(d) + '\n'
    FullScan.objects.filter(id=ID).update(domains=domains_text, status='Поиск поддоменов завершен')