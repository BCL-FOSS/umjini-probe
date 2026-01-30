# umjiniti-probe
Open source tool to turn your favorite LLM into a bonafide network administrator.

### Initial Configuration
```bash

# If running on Ubuntu host with 2GB of RAM or less, run the following command
$ sudo sysctl vm.overcommit_memory=1

# Set app scripts as executable
$ sudo chmod +x init.sh
$ sudo chmod +x restart.sh

# Run init script
$ sudo ./init.sh

# NOTE: restart.sh reloads the probe and necessary containers 
$ sudo ./restart.sh
```

### To adopt to umjiniti-cloud
```bash

# Visit /docs for GUI or send POST request to /api/init to adopt probe to umjiniti-cloud
```
