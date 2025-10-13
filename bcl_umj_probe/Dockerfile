FROM python:3.12

RUN adduser quart --disabled-password 

RUN apt-get update -y

RUN apt-get upgrade -y

#RUN apt-get install sshpass

# Update system and install Ruby, build tools, and sshpass
RUN apt-get install -y \
    tshark \
    tcpdump \
    iputils-ping \
    iperf3 \
    aircrack-ng \
    libpcap-dev \
    p0f \
    traceroute \
    sshpass \
    dnsdiag \
    nmap

WORKDIR /home/quart

RUN mkdir /home/quart/probedata

COPY bcl_umj_probe/requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt --upgrade 

COPY bcl_umj_probe/ /home/quart/

RUN chmod +x boot.sh

ENTRYPOINT ["sh", "./boot.sh"]