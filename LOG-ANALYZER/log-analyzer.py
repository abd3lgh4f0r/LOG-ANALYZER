from flask import Flask, render_template , render_template_string , send_file
import manage_logfiles
import analyze_vulns
import pandas  as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re 
import pdfkit
from collections import Counter
from flask import send_file

#create the flask application
app = Flask(__name__)
 
#initialize  variables
IP, TIME, method, REQUEST, STATUS, USER_AGENT, ATTACK = [], [], [], [], [], [], []
#Black_list_variables
IP_LIST=[]
ATTACK_LIST=[]
#statistic_variables
MOST_ATTACK_ATTEMPS=[]
MOST_REQUESTED_ENDPOINT=[]


#statistic 
    
def top_requested_endpoints(requests):
    global MOST_REQUESTED_ENDPOINT
    # Count the occurrences of each page
    page_counts = Counter(requests)
    
    # Get the top 4 most requested pages
    top_pages = page_counts.most_common(4)
    
    # Convert the results into the required format
    MOST_REQUESTED_ENDPOINT = [[page, count] for page, count in top_pages]
    
    return MOST_REQUESTED_ENDPOINT


#the result of this function will be like this : 
   #[['/', 2236], ['/test.php', 184], ['/1.php', 137], ['/index.php', 132]]



def top_attack_attemps(attacks):
    global MOST_ATTACK_ATTEMPS
    filtered_attacks = [attack for attack in attacks if attack != "NONE"]
    # Count the occurrences of each page
    attack_counts = Counter(filtered_attacks)
    
    # Get the top 4 most requested pages
    top_pages = attack_counts.most_common(4)
    
    # Convert the results into the required format
    MOST_ATTACK_ATTEMPS = [[page, count] for page, count in top_pages]
    
    return MOST_ATTACK_ATTEMPS


#Real-time Monitoring

class CustomHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global  IP, TIME, method, REQUEST, STATUS, USER_AGENT, ATTACK
        global df 
        global ATTACK_LIST , IP_LIST
        global MOST_REQUESTED_ENDPOINT
        global MOST_ATTACK_ATTEMPS

        df=manage_logfiles.parse_log_file('C:\\project_Cybersec\\LOG-ANALYZER\\data\\logs.txt')
        
        IP, TIME, method, REQUEST, STATUS, USER_AGENT, ATTACK = [], [], [], [], [], [], []
        ATTACK_LIST , IP_LIST =[],[]
        ATTACK=[]
        

        IP = df['ip'].tolist()
        TIME = df['timestamp'].tolist()
        method = df['method'].tolist()
        REQUEST = df['url'].tolist()
        STATUS = df['status'].tolist()
        USER_AGENT = df['user_agent'].tolist()
        
        
        for request in  df['url']:
            attack=analyze_vulns.detect_vulerabilities(request)
            ATTACK.append(attack)
        
        for  ip in IP:
          if ATTACK[IP.index(ip)]!="NONE":
            IP_LIST.append(ip)
            ATTACK_LIST.append(ATTACK[IP.index(ip)])

        MOST_REQUESTED_ENDPOINT=[]
        MOST_REQUESTED_ENDPOINT=top_requested_endpoints(REQUEST)
        MOST_ATTACK_ATTEMPS=[]
        MOST_ATTACK_ATTEMPS=top_attack_attemps(ATTACK)

def start_observer():
    observer = Observer()
    observer.schedule(CustomHandler(), path='./data')
    observer.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

#start analyzing

df=manage_logfiles.parse_log_file('C:\\project_Cybersec\\LOG-ANALYZER\\data\\logs.txt')

  
# Update global variables
IP = df['ip'].tolist()
TIME = df['timestamp'].tolist()
method = df['method'].tolist()
REQUEST = df['url'].tolist()
STATUS = df['status'].tolist()
USER_AGENT = df['user_agent'].tolist()

#generate ATTACK LIST
for request in  df['url']:
        attack=analyze_vulns.detect_vulerabilities(request)
        ATTACK.append(attack)

#black list 
for  i in range(len(IP)):
    if ATTACK[i]!='NONE':
        ATTACK_LIST.append(ATTACK[i])
        IP_LIST.append(IP[i])

MOST_REQUESTED_ENDPOINT=top_requested_endpoints(REQUEST)
MOST_ATTACK_ATTEMPS=top_attack_attemps(ATTACK)




#DASHBOARD 
@app.route("/")
def dashboard():
    return render_template('index.html', list1=IP, list2=method, list3=REQUEST, list4=STATUS, list5=TIME, list6=USER_AGENT, list7=ATTACK,MOST_REQUESTED_ENDPOINT=MOST_REQUESTED_ENDPOINT,MOST_ATTACK_ATTEMPS=MOST_ATTACK_ATTEMPS)

#black_list route 
@app.route("/blacklist")
def blacklist():
    return render_template('blacklist.html',IP_LIST=IP_LIST,ATTACK_LIST=ATTACK_LIST)

#report_route
from flask import send_file

@app.route("/report")
def report():
    # Define path to wkhtmltopdf.exe
    path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'

    rendered_html = render_template_string(open('C:\\project_Cybersec\\LOG-ANALYZER\\templates\\report.html', 'r').read(), MOST_REQUESTED_ENDPOINT=MOST_REQUESTED_ENDPOINT, MOST_ATTACK_ATTEMPS=MOST_ATTACK_ATTEMPS
                                           ,ATTACK_LIST=ATTACK_LIST,IP_LIST=IP_LIST)

    pdf_name = "report.pdf"
    output_pdf = f'C:\\project_Cybersec\\LOG-ANALYZER\\report\\{pdf_name}'

    config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

    # Generate PDF
    pdfkit.from_string(rendered_html, output_pdf, options={"enable-local-file-access": ""}, configuration=config)

    # Return the PDF file as response
    return send_file(output_pdf, as_attachment=True)


if __name__ == '__main__':

    observer = Observer()
    observer.schedule(CustomHandler(), path='./data')
    observer.start()
    
    app.run(debug=True)

