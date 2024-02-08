# LOG-ANALYZER
This project is a Command and Control (C2) server implemented in Python, featuring a web interface developed with Flask. This  server is used  to manage  multiple agents, executing commands, and maintaining control through efficient multithreading.

# Key Features
- **Web Interface**: User-friendly Flask-based interface for seamless monitoring and interaction with the C2 server.

- **Multithreading**: Ensures optimal performance by adeptly handling multiple agents concurrently.

- **Command Execution**: Facilitates secure and controlled execution of commands on connected agents.


## How to Run

Follow these steps to set up and run the C2 server on your local machine:

1. **Clone the Repository:** : https://github.com/abd3lgh4f0r/C2_Server.git
2. **Install Dependencies:** :  pip install -r requirements.txt
3. **Run the Server Script:**: python server.py
4. **Access the Web Interface** : Open your web browser and navigate to http://localhost:5000 (or the specified port in your configuration)
5. **Connect Agents** : python client.py

## Screenshots

Here are some screenshots showcasing the C2 server:

- **DASHBOARD:**
  ![Web Interface](static/images/Dashboard.jpg)
  *Screenshot of the Dashboard interface.*

- **Command Line Interface:**
  ![Command Line Interface](static/images/image2.png)
  *Screenshot of the command line interface in the C2 server.*
