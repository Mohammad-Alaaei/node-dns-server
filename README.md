# What is this?
this is a simple dns server made on nodejs.  
you can define your custom ip addresses for domains or you can manage domains to resolve by custom dns servers.

## Installation
### 1- install nodeJS
### 2- install required package and dependencies

```
npm install
```

### 3- if you want to route domains to your custom static ip addresses [*optional*]

create a text file (.txt) and rename it to 'domains' (domains.txt) in format like this:

```
sub\.example\.com 1.2.3.4 5.6.7.8
example\.com 1.2.3.4 5.6.7.8
```
each domain should write in new line.  
first part is domain address in regex format.  
after that you can write ip addresses for that domain separated with space.

### 4- if you want to manage domains to resolve with custom dns servers [*optional*]

create a text file (.txt) and rename it to your prefered dns server ip address. for example:

```
8.8.8.8.txt
```

inside this file, write each domain in new line and with regex format. for example:

```
example\.com
.*\.example\.com
```

### 5- run server
##### in windows:
just execute 'run.bat' file
or
1. open a command-prompt (cmd)
2. change directory to where this server files are in
3. run 'main.js':

```
cd YOUR/SERVER/DIRECTORY
node main.js
```
##### in linux:

just go to where is server files located in and run 'main.js':

```
node main.js
```
