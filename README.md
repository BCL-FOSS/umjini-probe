# umjiniti-probe
Open source tool to turn your favorite LLM into a bonafide network administrator.

### Initial Configuration
```bash
# Assign A record for probe

# Change url in Caddyfile to url assigned to A record

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
# Shut down the probe, the export the umjiniti-cloud and probe API keys
$ export X-UMJ-WFLW-API-KEY="umjiniti_api_key"
$ export PRB-API-KEY="probe_api_key"

# Add the following environment variables to the umj_probe service in docker-compose file ()
- X-UMJ-WFLW-API-KEY=${X-UMJ-WFLW-API-KEY}
- PRB-API-KEY=${PRB-API-KEY}
- UMJ-URL=
- UMJ-USR=
- UMJ-SITE=

# Restart the probe
$ sudo ./restart.sh

# Visit /docs for GUI or send GET request to /api/init to adopt probe to umjiniti-cloud
```
