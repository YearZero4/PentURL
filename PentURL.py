from colorama import init, Fore, Style
import os, time, pyfiglet, whois
import requests, json, re
S='  '

init(autoreset=True)
GREEN=f'{Fore.GREEN}{Style.BRIGHT}'
WHITE=f'{Fore.WHITE}{Style.BRIGHT}'
RED=f'{Fore.RED}{Style.BRIGHT}'
RST=f'{Fore.RESET}'

def vtotal(url):
 api_key = "5ccc5ed7c1decdfc3b81dbf8a844d62ac71bebc348e83806d1898583412b16c7"
 params = {'apikey': api_key, 'resource': url}
 response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
 n=1
 number=[]

 if response.status_code == 200:
  result = response.json()
  i=result
  i=str(i)
  res=i.replace(',', '\n').replace('{', '').replace('}', '').replace('\'', '')
  ss=res.splitlines()
  for d in ss:
   d=d.strip()
   find1=re.search('positives:', d)
   find2=re.search('True', d)
   if find1 != None:
    result=d.split()[1]
    result=int(result)
    if result == 0:
     print(f"{S}{GREEN}[+]{WHITE} Analisis Virus Total -> {GREEN}SEGURO")
    else:
     print(f"{S}{RED}[-]{WHITE} Analisis Virus Total -> {RED}INSEGURO")
   if find2 != None:
    print(f"{WHITE}{S}{d}")
    number.append(n)
   if number:
    linea=number[0]+1
    if n == linea:
     print(f"{WHITE}{S}{d}")
     number.clear()
   n=n+1

def whoX(domain):
 try:
  w = whois.whois(domain)
  for key, value in w.items():
   if key == 'status':
    pass
   else:
    if value is not None:
     if isinstance(value, list) and len(value) > 1:
      print(f"{S}{GREEN}[+]{WHITE} {key} ->")
      for item in value:
       print(f"{S}{GREEN}[+] - {WHITE}{item}")
     else:
      print(f"{S}{GREEN}[+]{WHITE} {key} -> {GREEN}{value}")
 except Exception as e:
  print(f"{S}{RED}Error: {e}")


def start(url):
 from bs4 import BeautifulSoup as b
 import requests, os, subprocess, re, sys, socket, pyfiglet
 S='  '
 so=os.name
 ur=url[-1]
 if ur == '/':
  url=url[:-1]

 ssl=url.replace("http://", "https://")
 ssl_not=url.replace("https://", "http://")
 domain=[] ; url=[] ; ip1=[] ;  headers=[]

 array=[ssl, ssl_not]

 def get_ip_from_domain(domain):
  try:
   ip = socket.gethostbyname(domain)
   return ip
  except socket.error:
   return None

 for i in array:
  try:
   head=requests.get(i).headers
   if i == ssl:
    domain1=ssl.split('://')[1]
    domain1 = domain1.split('/')[0]
    print(f"{S}{GREEN}[+]{WHITE} URL -> {GREEN}{ssl}\n{S}{GREEN}[+] {WHITE}DOMINIO -> {GREEN}{domain1}\n{S}{GREEN}[+]{WHITE} CERTICADO SSL -> {GREEN}True [HTTPS]")
    domain.append(domain1)
    url.append(ssl)
  except:
   if i == ssl_not:
    domain1=ssl_not.split('://')[1]
    domain1 = domain1.split('/')[0]
    print(f"{S}{RED}[-]{WHITE} URL -> {GREEN}{ssl_not}\n{S}{GREEN}[+] {WHITE}DOMINIO -> {GREEN}{domain1}\n{S}{RED}[-]{WHITE} CERTIFICADO SSL ->{RED} False [HTTP]")
    domain.append(domain1)
    url.append(ssl_not)

 count=len(domain)
 if count == 0:
  print(f"{S}URL INVALIDA")
  sys.exit()

 domain=domain[0]
 url=url[0]
 url1=url

 if so == 'nt':
  ip = get_ip_from_domain(domain)
  if ip:
   print(f'{S}{GREEN}[+]{WHITE} DIRECCION IP PRINCIPAL -> {GREEN}' + ip)
   ip1.append(ip)
  else:
   print("No se pudo obtener la IP del dominio.")
   n=n+1
  cmd2=f'nslookup {domain}'
  e = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  r=e.stdout.splitlines()
  n=1
  for k in r:
   if n > 3:
    if k:
     arr=k.split()
     first=arr[0]
     oip=first.count('.')
     oadd=first.count(':')
     if first == 'Addresses:':
      second=arr[1]
      print(f"{S}{GREEN}[+] {WHITE}{first[:-1].upper()} -> {GREEN}{second}")
     elif first == 'Address:':
      second=arr[1]
     elif oadd > 3:
      print(f"{S}{GREEN}[+] {WHITE}ADDRESSES -> {GREEN}{first}")
     if oip > 2:
      if first != ip1[0]:
       print(f"{S}{GREEN}[+] {WHITE}OTRAS IP -> {GREEN}{first}")
       ip1.append(first)
   n=n+1
 vtotal(url)
 try:
  import socket
  import ssl

  def get_certificates(host, port):
   context = ssl.create_default_context()
   with socket.create_connection((host, port)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
     cert = ssock.getpeercert()
     return cert

  if __name__ == "__main__":
   host = domain
   port = 443
   certs = get_certificates(host, port)
   for key, value in certs.items():
    V=str(value).replace('(', '').replace(')', '').replace("'", "")
    v0=V[-1]
    if v0 == ',':
     V=V[:-1]
    elif v0 == ',,':
     V=V[:-2]
    V=V.replace(',', ':').replace('::', f',\n{S}{GREEN}[+]{WHITE}')
    print(f"{S}{GREEN}[+]{WHITE} {key} ->{GREEN} {V}")
 except:
  pass


 whoX(domain)

 print("")
 for ip in ip1:
  url = f"http://ip-api.com/json/{ip}"
  response = requests.get(url)
  if response.status_code == 200:
   data = response.json()
   for key, value in data.items():
    print(f"{S}{GREEN}[+] {WHITE}{key} -> {GREEN}{value}")
  print("")

def first():
 banner=pyfiglet.figlet_format("   PentURL")
 os.system('cls' if os.name == 'nt' else 'clear')
 print(f'{WHITE}{banner}')
 print(f"""
   {WHITE}[1]{GREEN} DICCIONARIO CON VARIAS URL
   {WHITE}[2]{GREEN} URL ESPECIFICA (1)
 """)

 opc=int(input(f"{S} ---> "))

 if opc == 1:
  wordlist=input(f"{S}RUTA DEL DICCIONARIO -> ")
  print("")
  if os.path.exists(wordlist):
   with open(wordlist, 'r') as f:
    v=f.readlines()
    for i in v:
     r=i.replace("\n", "")
     start(r)
  else:
   print(f"\n{S}DICCIONARIO NO EXISTE...")
   time.sleep(3)
   first()
   input()
 elif opc == 2:
  url=input(f"\n{S}INTRODUZCA LA URL -> ")
  print("")
  start(url)

 input("")
if __name__ == '__main__':
 try:
  first()
 except KeyboardInterrupt:
  print(f"\n\n{S}HASTA LA PROXIMA AMIGO...")
