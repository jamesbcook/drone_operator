#Drone Operator

A basic HTTP server with one form to upload any Nmap or Nessus xml file.  
The server will determine what kind of file it is and correctly parse it and upload the contents to the lair server.

##Within the form there is: 
* LAIR_PID that needs to be inserted to be imported into lair
* TAGS are comma (',') separated values to use with imported data
* Input as many files as you'd like

##The server will respond with the following flashes
* alert alert-success for a successful upload
* alert alert-danger for a unsuccessful upload and it will tell you what the error is

All flashes can either be closed manually or will fade-out on their own

###Thanks To:

@tomsteele
@djkottmann
