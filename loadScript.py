import requests
import json
import networkx as nx
import os
from subprocess import Popen, PIPE
from sys import exit

# Global variables initialization
switch = {}
deviceMAC = {}
hostPorts = {}
path = {}
switchLinks = {}
linkPorts = {}
finalcost = {}
pathlat = {}
linklat = {}
portKey = ""
cost = 0
G = nx.Graph()
h1 = ""
h2 = ""
bestPath = []
shortestPath = ""

# Method to fetch data from URL based on choice
def fetchResponse(url, choice):
    response = requests.get(url)
    
    if response.ok:
        jData = json.loads(response.content)
        if choice == "deviceInfo":
            deviceInformation(jData)
        elif choice == "Switchlinkinfo":
            Switchlinkinfo(jData, switch[h2])
        elif choice == "costcompute":
            costcompute(jData, portKey)
        elif choice == "getswitchlatency":
            getswitchlatency(jData)
    else:
        response.raise_for_status()

# Method to extract device information
def deviceInformation(data):
    global switch, deviceMAC, hostPorts
    switchDPID = ""
    for i in data['devices']:
        if i['ipv4']:
            ip = i['ipv4'][0].encode('ascii', 'ignore')
            mac = i['mac'][0].encode('ascii', 'ignore')
            deviceMAC[ip] = mac
            
            for j in i['attachmentPoint']:
                for key in j:
                    temp = key.encode('ascii', 'ignore')
                    if temp == "switch":
                        switchDPID = j[key].encode('ascii', 'ignore')
                        switch[ip] = switchDPID
                    elif temp == "port":
                        portNumber = j[key]
                        switchShort = switchDPID.split(":")[7]
                        hostPorts[ip + "::" + switchShort] = str(portNumber)

# Method to extract switch link information
def Switchlinkinfo(data, s):
    global switchLinks, linkPorts, G, linklat
    links = []
    for i in data:
        source = i['src-switch'].encode('ascii', 'ignore')
        destination = i['dst-switch'].encode('ascii', 'ignore')
        sourcePort = str(i['src-port'])
        destinationPort = str(i['dst-port'])
        sourceTemp = source.split(":")[7]
        destinationTemp = destination.split(":")[7]
        latency = str(i['latency'])
        
        G.add_edge(int(sourceTemp, 16), int(destinationTemp, 16))
        
        tempSourceToDestination = sourceTemp + "::" + destinationTemp
        tempDestinationToSource = destinationTemp + "::" + sourceTemp
        
        portSourceToDestination = str(sourcePort) + "::" + str(destinationPort)
        portDestinationToSource = str(destinationPort) + "::" + str(sourcePort)
        
        linkPorts[tempSourceToDestination] = portSourceToDestination
        linkPorts[tempDestinationToSource] = portDestinationToSource
        
        linklat[tempSourceToDestination] = latency
        linklat[tempDestinationToSource] = latency
        
        if source == s:
            links.append(destination)
        elif destination == s:
            links.append(source)
    
    switchID = s.split(":")[7]
    switchLinks[switchID] = links

# Method to compute all shortest paths from source to destination
def computeRoute():
    global path, switch, h1, h2, G
    pathKey = ""
    nodeList = []
    src = int(switch[h2].split(":")[7], 16)
    dst = int(switch[h1].split(":")[7], 16)
    
    for currentPath in nx.all_shortest_paths(G, source=src, target=dst, weight=None):
        for node in currentPath:
            tmp = ""
            if node < 17:
                pathKey = pathKey + "0" + str(hex(node)).split("x", 1)[1] + "::"
                tmp = "00:00:00:00:00:00:00:0" + str(hex(node)).split("x", 1)[1]
            else:
                pathKey = pathKey + str(hex(node)).split("x", 1)[1] + "::"
                tmp = "00:00:00:00:00:00:00:" + str(hex(node)).split("x", 1)[1]
            nodeList.append(tmp)
        
        pathKey = pathKey.strip("::")
        path[pathKey] = nodeList
        pathKey = ""
        nodeList = []

# Method to compute cost for given link key
def costcompute(data, key):
    global cost, linkPorts
    port = linkPorts[key]
    port = port.split("::")[0]
    for i in data:
        if i['port'] == port:
            cost += int(i['bits-per-second-tx'])

# Method to fetch switch latency
def fetchLinkCost():
    global finalcost, portKey, cost, path
    for key in path:
        start = switch[h2]
        src = switch[h2]
        srcShortID = src.split(":")[7]
        mid = path[key][1].split(":")[7]
        
        for link in path[key]:
            temp = link.split(":")[7]
            if srcShortID == temp:
                continue
            else:
                portKey = srcShortID + "::" + temp
                portNumber = linkPorts[portKey].split("::")[0]
                stats = "http://localhost:8080/wm/statistics/bandwidth/" + src + "/" + portNumber + "/json"
                fetchResponse(stats, "costcompute")
                srcShortID = temp
                src = link
        
        portKey = start.split(":")[7] + "::" + mid + "::" + switch[h1].split(":")[7]
        finalcost[portKey] = cost
        cost = 0
        portKey = ""

# Method to execute system command
def systemCommand(cmd):
    terminalProcess = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    terminalOutput, stderr = terminalProcess.communicate()

# Method to add flow rules
def flowRule(currentNode, flowCount, inPort, outPort, staticFlowURL):
    global h1, h2, deviceMAC
    flow = {
        'switch': "00:00:00:00:00:00:00:" + currentNode,
        "name": "flow" + str(flowCount),
        "cookie": "0",
        "priority": "32768",
        "in_port": inPort,
        "eth_type": "0x0800",
        "ipv4_src": h2,
        "ipv4_dst": h1,
        "eth_src": deviceMAC[h2],
        "eth_dst": deviceMAC[h1],
        "active": "true",
        "actions": "output=" + outPort
    }
    
    jsonData = json.dumps(flow)
    cmd = "curl -X POST -d '" + jsonData + "' " + staticFlowURL
    systemCommand(cmd)
    
    flowCount += 1
    
    flow = {
        'switch': "00:00:00:00:00:00:00:" + currentNode,
        "name": "flow" + str(flowCount),
        "cookie": "0",
        "priority": "32768",
        "in_port": outPort,
        "eth_type": "0x0800",
        "ipv4_src": h1,
        "ipv4_dst": h2,
        "eth_src": deviceMAC[h1],
        "eth_dst": deviceMAC[h2],
        "active": "true",
        "actions": "output=" + inPort
    }
    
    jsonData = json.dumps(flow)
    cmd = "curl -X POST -d '" + jsonData + "' " + staticFlowURL
    systemCommand(cmd)

    flowCount += 1

# Method to add flow rules based on computed costs
def addFlow():
    global bestPath, shortestPath, finalcost, path, h2, h1
    flowCount = 1
    staticFlowURL = "http://127.0.0.1:8080/wm/staticflowpusher/json"
    
    shortestPath = min(finalcost, key=finalcost.get)
    currentNode = shortestPath.split("::", 2)[0]
    nextNode = shortestPath.split("::")[1]
    
    # Port Computation
    port = linkPorts[currentNode + "::" + nextNode]
    outPort = port.split("::")[0]
    inPort = hostPorts[h2 + "::" + switch[h2].split(":")[7]]
    
    flowRule(currentNode, flowCount, inPort, outPort, staticFlowURL)
    flowCount += 2
    
    bestPath = path[shortestPath]
    previousNode = currentNode
    
    for currentNode in range(0, len(bestPath)):
        if previousNode == bestPath[currentNode].split(":")[7]:
            continue
        else:
            port = linkPorts[bestPath[currentNode].split(":")[7] + "::" + previousNode]
            inPort = port.split("::")[0]
            outPort = ""
            if currentNode + 1 < len(bestPath) and bestPath[currentNode] == bestPath[currentNode + 1]:
                currentNode += 1
                continue
            elif currentNode + 1 < len(bestPath):
                port = linkPorts[bestPath[currentNode].split(":")[7] + "::" + bestPath[currentNode + 1].split(":")[7]]
                outPort = port.split("::")[0]
            elif bestPath[currentNode] == bestPath[-1]:
                outPort = str(hostPorts[h1 + "::" + switch[h1].split(":")[7]])
            
            flowRule(bestPath[currentNode].split(":")[7], flowCount, str(inPort), str(outPort), staticFlowURL)
            flowCount += 2
            previousNode = bestPath[currentNode].split(":")[7]

# Method to compute total latency for each path
def getlinkLatency():
    global linklat, pathlat
    for key in pathlat:
        temp1 = key.split('::')
        length = len(temp1)
        count = 1
        for i in temp1:
            temp2 = i + '::' + temp1[count]
            pathlat[key] = int(pathlat[key]) + int(linklat[temp2])
            count += 1
            if count == length:
                break

# Method to compute latency of every switch
def getswitchlatency(jData):
    global path, pathlat
    temp = 0
    for key in path:
        for switch in path[key]:
            duration = int(jData[switch]['flows'][0]['duration_sec'])
            bytecount = int(jData[switch]['flows'][0]['byte_count'])
            if bytecount == 0:
                bytecount = 1
            temp += 100 * (duration / bytecount)
        pathlat[key] = temp
        temp = 0

# Load Balancer Function
def loadbalance():
    global h1, h2
    linkURL = "http://localhost:8080/wm/topology/links/json"
    fetchResponse(linkURL, "Switchlinkinfo")
    computeRoute()
    url = ('http://localhost:8080/wm/core/switch/all/flow/json')
    fetchResponse(url, "getswitchlatency")
    getlinkLatency()
    fetchLinkCost()
    addFlow()

# Driver function
if __name__ == "__main__":
    try:
        print("\n\n****************************Enter SOURCE and DESTINATION Hosts on which you want to do LOAD BALANCING************************************")
        print("\n\nEnter SOURCE Host:")
        h1 = int(input())
        print("\n\nEnter DESTINATION Host:")
        h2 = int(input())
        
        h1 = "10.0.0." + str(h1)
        h2 = "10.0.0." + str(h2)
        
        # Enable statistics like bandwidth, etc
        enableStats = "http://localhost:8080/wm/statistics/config/enable/json"
        requests.put(enableStats)
        
        # Device Info (Switch to which the device is connected & the MAC address of each device)
        deviceInfo = "http://localhost:8080/wm/device/"
        fetchResponse(deviceInfo, "deviceInfo")
        
        loadbalance()
        os.system('clear')
        
        print("\t\n\n############################################################FINAL OUTPUT############################################\n\n")
        
        print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Switch connected to HOST 1~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\t\t\t\t\t", switch[h1])
        
        # IP & MAC
        print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~IP and Mac addresses of all Devices in Topology~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n", deviceMAC)
        
        # Host Switch Ports
        print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Hosts and connected SwitchPorts~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n", hostPorts)
        
        print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FINAL LINK COSTS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\t\t\t\t", finalcost)
        
        print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Available Paths for routing~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", path)
        
        print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~SHORTEST PATH for routing~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\t\t\t\t\t\t ", shortestPath)
        
        print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Best path for routing~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\t\t\t", bestPath)
        
        print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~LATENCY~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\t\t\t\t", pathlat)
    
    except KeyboardInterrupt:
        exit()
