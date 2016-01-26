#Drone Operator

A basic HTTP server with one form to upload any nmap or nessus xml file.  
The server will determin what kind of file it is and correcly parse it and upload the contentes to the lair server.

##Within the form there is: 
* LAIR_PID that needs to be inserted to be imported into lair
* TAGS are comma (',') seperated values to use with imported data
* Input as many files as you'd like

##The server will responde with the following flashes
* alert alert-success for a successful uplaod
* alert alert-danger for a unsuccessful upload and it will tell you what the error is

All flashes can either be closed manually or will fade-out on their own

###Thanks To:

@tomsteele
@djkottmann
