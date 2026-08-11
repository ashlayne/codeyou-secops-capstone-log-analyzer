# codeyou-secops-capstone-log-analyzer

Main.py

I decided to use the user's input route so multiple files could be accessed, and will test this sample_log.txt. I also decided to build this script to be OS agnostic, meaning it will run just as well on Linux and Mac as Windows. 

Enum Mapping

AUTH_SUCCESS = "auth_success"
AUTH_FAIL = "auth_fail"
PRIV_CHANGE = "priv_change"

Fields

date
alert_type
username
ip_address
message

Selecting out multiple formats of data, including:
 - all failed logins
 - failed logins by username
 - failed logins by IP
 - successful brute force attempts
 - attempts coming from external IPs
 - privilege escalation events
 - multiple usernames tried from one IP

 The CLI handler asks the user for the filename (in the same directory as the script), and parses it. I did a preview of the file, so I could see its records and the alert types I would be working with. (I commented it out as extraneous data, but wanted to leave it commented.)

 I set up multiple variables for the outputs I would eventually generate, including a text summary, a CSV, and CLI output.

 The CLI confirms the export of all data to the relevant files.