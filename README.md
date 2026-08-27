This DDoS detection framework is based on a thesis work I did on my computer science MSC program at HiLCoE school of computer science in Addis Ababa, Ethiopia.
All development and testing took place on a virtual machine running Ubuntu 24.04.3 LTS (64-bit) hosted within VMware® Workstation 17 Pro on version 17.6.0 build-24238078.
The machine hosting the virtual machine was equipped with an Intel® Core™ Ultra 9 275HX × 16, 32 GB RAM, and 1TB SSD storage, while the virtual machine was allocated 16 GB RAM,
16 CPU cores and 50GB storage.
Python 3.12.3 served as the primary runtime environment. This isolated environment prevented dependency conflicts and ensured consistent behavior across development and evaluation phases.
All Python packages were installed via pip within this virtual environment, with versions explicitly pinned in a requirements.txt file to support exact reproduction. 
The key software components and libraries used are to be found in the requirement.txt file. 

## 🚀 Installation & Setup

### 1. Clone the Repository
git clone [https://github.com/Zekiman23/hybrid-sdn-ddos-detection.git](https://github.com/Zekiman23/hybrid-sdn-ddos-detection.git)
cd hybrid-sdn-ddos-detection
2. Set Up Virtual Environment
Bash
# On Linux / macOS / WSL
python3 -m venv venv
source venv/bin/activate

# On Windows (PowerShell)
python -m venv venv
.\venv\Scripts\activate
3. Install Python Dependencies
Bash
pip install --upgrade pip
pip install -r requirement.txt


instruction steps:
A. Preparing dataset:(this step is already done on the repository but to recreate the whole experiment starting from the training do steps from A -C )

download and insert the following selected csv data from CIC-DDoS2019 and CIC-IDS2017 into: hybrid-sdn-ddos-detection/data/raw
CIC-DDoS2019 sourced:
DrDoS_DNS.csv
DrDoS_LDAP.csv
DrDoS_MSSQL.csv
DrDoS_NTP.csv
DrDoS_NetBIOS.csv
DrDoS_SNMP.csv
DrDoS_SSDP.csv
DrDoS_UDP.csv
Monday-WorkingHours.pcap_ISCX.csv(CIC-IDS2017)
Syn.csv
UDPLag.csv
CIC-IDS2017 sourced:
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

B. preprocess dataset:

step1: on terminal 1: /src/data_prep$ source ~/ryu_project/ryu_env39/bin/activate
step2: on terminal 1: /src/data_prep$ python3 prepare_dataset.py

C. Train the model:

step1: on terminal 1: /src/model$ python3 RF_trainer.py

D. Run offline evaluation of the framework: 

step1: on terminal 1: /src/model$ python3 offline_evaluation.py

E. Run online evaluation of the framework

step2: on terminal 1: 

step1: on terminal 2: /src/sdn$ source ~/ryu_project/ryu_env39/bin/activate
step2: on terminal 2: /src/sdn$ uvicorn detection_service:app --host 0.0.0.0 --port 9000
step3: on terminal 3: source ~/ryu_project/ryu_env39/bin/activate
step4: on terminal 3: /src/sdn$ ryu-manager ddos_controller.py
step5: on terminal 4: /src/utils$ sudo python3 traffic_generator.py
        then choose scenarios on terminal 3 to see the DDoS controller in action
step6: on terminal 5: source ~/ryu_project/ryu_env39/bin/activate
step7: on terminal 5: /src/utils$ sudo python3 analyze_results.py


