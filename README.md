# CSC 249 - Project 4 - ICMP Ping and Traceroute

_Attribution: this assignment is based on ICMP Pinger Lab and ICMP Traceroute Lab from Computer Networking: a Top-Down Approach by Jim Kurose and Keith Ross. It was modified for use in CSC249: Networks at Smith College by R. Jordan Crouser in Fall 2022, and further modified by B. Cheikes for use in Fall 2023._

**IMPORTANT: Due to a still-mysterious OS incompatibility, the traceroute code provided in this assignment does not seem to behave correctly when run under native Windows. The code _does_ behave properly when run under MacOS or Linux. [Update: this was an issue with the Windows firewall blocking ICMP Time Exceeded Messages. It works properly if you make a loophole for them: Control Panel > System & Security > Windows Defender Firewall > Advanced Settings > Inbound Rules > New Rule > Custom. Select all programs, protocol ICMPv4 Time Exceeded Messages]**

In this assignment, you will gain a better understanding of Internet Control Message Protocol (ICMP) by implementing your own **`ping`** and **`traceroute`** applications using ICMP request and reply messages. After building these tools you will use them to carry out some basic network performance analysis.

The network utility `ping` is a computer application used to test whether a particular host is reachable across an IP network. It is also used to self-test the network interface card of the computer or as a latency test. It works by sending ICMP `echo` packets to the target host and listening for ICMP `echo reply` packets in response (the return `echo reply` is sometimes called a _pong_). As written, `ping` measures the round-trip time (RTT), records packet loss, and prints a statistical summary of the echo reply packets received (min, max, and the mean of the round-trip times and in some versions the standard deviation of the mean).

Your first programming task is to develop your own `ping` application in Python. This application will use ICMP echo and echo reply messages as described in the official ICMP protocol specification [RFC 792](https://www.rfc-editor.org/rfc/rfc792). Your second task will be to build a `traceroute` application that builds on your `ping` development experience. Read on for more details.

_Note: You will only need to write the client side of these programs, as the functionality needed on the server side is built into nearly all operating systems._

## Part 0: Build a Spreadsheet for Testing and Analysis
Set up a spreadsheet as follows:

* Column headers should be: Domain, IP, Location, Distance, Ping Date, Avg RTT, Trace Date, Trace RTT, # Hops
* Select five domain names of sites located in various places around the US. Hint: Using university domain names, cultural institutions and names of state and local government sites is a good way to get a reasonable geographic distribution. Using a similar strategy, select five domain names of sites located outside the United States. Get creative! Load the 10 domain names as rows in your spreadsheet. Use `nslookup` to determine the IP address of each domain in your list, and add that to your spreadsheet.
* Use an IP-to-geolocation service (e.g., [https://tools.keycdn.com/geo](https://tools.keycdn.com/geo)) to find the (approximate) geographic coordinates of each domain in your list. Record the location in your spreadsheet.
* Use the same service to find the geographic coordinates of smith.edu, and use a geo-distance service (e.g., [https://www.nhc.noaa.gov/gccalc.shtml](https://www.nhc.noaa.gov/gccalc.shtml)) to compute the **pairwise geographic distance in miles** between Smith College and each domain in your list. Put the result in the appropriate column in your spreadsheet.

At this point your spreadsheet should have ten data rows, and each row should have values populated for Domain, IP, Location, and Distance. You're ready for the next part! 

## Part 1: `ping`
Your `ping` application should send a series of three `ping` requests to a specified host separated by approximately one second. Each message will contain a payload of data that includes a timestamp. After sending each packet, the application should wait up to one second to receive a reply. If one second goes by without a reply from the server, then the client should assume that either the ping packet or the pong packet was lost in the network (or that the server is down). The code should compute and display the RTT for each ping request that yields an associated pong. You'll use this information in later analysis.

### Support Code
The file `ICMPpinger.py` contains starter code for the client-side behavior of your `ping` program. Your task is to fill in code in the area marked with `#Fill in start` and `#Fill in end` in order to get your program to behave as described. You should also study the starter code carefully to make sure you fully understand it. Notice that the code is written to accept a target domain name or IP address from the command line. You can feel free to modify this part of the program to "hard code" the ten domains you plan to test, or write a shell script that repeated calls your pinger with each test argument.

### Details
1.	In the `receiveOnePing(...)` method, you need to receive the structure `ICMP_ECHO_REPLY` and fetch the information you need, such as checksum, sequence number, time to live (TTL), etc. Take a look at the `sendOnePing(...)` method and make sure you understand what it is doing before trying to complete the `receiveOnePing(...)` method.
2.	You do not need to be concerned about the `checksum(...)` method, as it is already given in the code.
3.	This exercise requires the use of raw sockets. In some operating systems, you may need **administrator/root privileges** to be able to run your pinger program. In Windows, that means launching a Command Prompt with administrator privileges, then running your code from that Command Prompt. For MacOS and Linux, you will likely need to launch a Terminal window and then run your program with the command `sudo python3 ICMPpinger.py target`).

### Testing the Pinger
First, test your client by sending packets to localhost, that is, 127.0.0.1. Then, see how your Pinger application communicates across the network by pinging the various servers listed in your spreadsheet. During this process you might discover that one or more of your selected servers appears to be unreachable; i.e., all ping requests are unanswered. This could be due to the server being temporarily offline, or it could be due to a common security configuration on the server which blocks replies to ping requests. Regardless, you should discard and replace any domain/IP selection which does not respond to ping requests.

To build confidence that your pinger is performing correctly, compare its output to that of the standard ping application that is built into most operating systems. If the timing results of your Pinger are significantly different (e.g., more than 10 or 20 percent) from the results of the build-in ping application, then your pinger is most likely not working properly. 

### Ping Performance Data Collection
When you think your pinger is working properly, systematically run it against the ten domains in your spreadsheet. **Capture the output of this activity** as this will be one of your project deliverables. Note the date/time of your run in the "Ping Date" column of your spreadsheet, compute the average RTT for each target and load that in the "Avg RTT" column. That's all for now. Time to turn your attention to the next programming task.

## Part 2: `traceroute`
In this section, we'll expand on the pinger in order to implement a traceroute application using ICMP request and reply messages. For obvious reasons you are strongly encouraged to first do the `ping` section before attempting the `traceroute` section, as it is done with the same approach. The checksum and header making are not reiterated here; refer to the previous `ping` section for that purpose. The naming of most of the variables and socket is also the same.

`traceroute` is a computer networking diagnostic tool which allows a user to trace the route from a host running the `traceroute` program to any other host in the world. As with `ping`, `traceroute` is implemented with ICMP messages. It works by sending ICMP `echo` (ICMP type ‘8’) messages to the same destination with increasing value of the time-to-live (TTL) field. The routers along the traceroute path return ICMP `Time Exceeded` (ICMP type ‘11’ ) when the TTL field become zero. The final destination sends an ICMP `echo reply` (ICMP type ’0’ ) messages on receiving the ICMP `echo` request. The IP addresses of the routers which send replies can be extracted from the received packets. The round-trip time between the sending host and a router is determined by setting a timer at the sending host.

Your task is to develop your own `traceroute` application in Python using ICMP. Your application will use ICMP but again, in order to keep it simple, will not exactly follow the official specification in RFC 1739. As you did with the ping program, you should also modify the code so that it takes an IP address or domain name from the command line.

### Support Code
The file `ICMPtraceroute.py` contains starter code for the client-side behavior of your `traceroute` program. Your task is to fill in code in the areas marked with `#Fill in start` and `#Fill in end` in order to get your program to behave as described. **IMPORTANT: Due to a still-mysterious OS incompatibility, the traceroute code provided in this assignment does not seem to behave correctly when run under native Windows.**

### Details
1. As before, this exercise also requires the use of raw sockets. In most operating systems, you will need to run your program with administrator/root privileges.
2. This will not work for websites that block ICMP traffic. If you can't ping a target you also won't be able to correctly run a traceroute to it.
3. You may have to turn your firewall or antivirus software off to allow the messages to be sent and received.

### Optional Feature
Currently the application only prints out a list of ip addresses of all the routers along the path from source to the destination. Try using the `gethostbyname(...)` method to print out the names of each intermediate route along the route.

### Traceroute Performance Data Collection
When you think your traceroute program is working properly, systematically run it against the ten domains in your spreadsheet. **Capture the output of this activity** as this will be one of your project deliverables. If you are uncertain of whether your program is performing correctly, compare its output to that of the standard traceroute application that is built into most operating systems. If your traceroute implementation returns significantly different results from the built-in application, then your implementation is probably not correct.

Augment your spreadsheet for each target by adding the date/time of your trace, the measured RTT of the final hop in the trace, and the total number of hops needed to reach the target.

## Part 3: Performance Analysis
At this point, you have built your own `ping` and `traceroute` utilities, tested them against the same set of ten target domains, and collected result data in a spreadsheet. Perform the following analyses:

* Using the pinger data, draw or create a scatterplot with the **Average RTT in milliseconds** on the Y-axis, and the **geographic distance in miles** on the X-axis. Save this scatterplot to be uploaded as one of your deliverables.

* Using the scatterplot you generated, answer the following questions:

1. Are RTT and geographic distance correlated positively, negatively, or not at all? If applicable, also comment on the strength of correlation (weak vs. strong).
2. Why do you think you observe this trend (or lack thereof)?

* Using the traceroute data, draw or create a scatterplot with the **# Hops to Target** on the Y-axis, and the **geographic distance in miles** on the X-axis. Save this scatterplot to be uploaded as one of your deliverables.

* Using the scatterplot you generated, answer the following questions:

1. Are # hops and geographic distance correlated positively, negatively, or not at all? If applicable, also comment on the strength of correlation (weak vs. strong).
2. Why do you think you observe this trend (or lack thereof)?

## Deliverables
Your work on this project must be submitted for grading on the last day of classes - **THURSDAY DECEMBER 14th at 11:59PM**. Because this is the last day of the class before finals, **no extensions will be available.** Work submitted after the due date will not be graded and will receive a score of zero. Seriously.

All work must be submitted via Gradescope. This project counts for 15 points towards your final course grade.

You must submit these work products:

1. Source code for your ping and traceroute utilities. Ideally, this will be a link to a public Git code repo you have created for this project.
2. Execution trace of ping output tested against ten (10) different IP addresses. 
3. Execution trace of traceroute output tested against the same ten (10) IP addresses.
4. Ping analysis: scatterplot plus answers to the two associated questions.
5. Traceroute analysis: scatterplot plus answers to the two associated questions.
6. Spreadsheet containing all ping and traceroute performance data.

You are strongly encouraged to combine deliverables 2 through 5 into a single Word / Google Doc / PDF document. Your Python code and your spreadsheet should be submitted as separate files. Ideally, all of these materials will be collected in a single Github repository, and you will supply the repository link to Gradescope when making your submission.

## Teamwork Policy
For this project, students are permitted to team up in pairs and submit joint work. Both partners should fully understand all work products that are submitted. Both team members will receive the same grade for the project.

## Tips for Success

Want to ace this project? Then do these things:

* Read about ICMP in our Network+ text, pp. 189-190.
* Review the RFC (specification) for ICMP at this link: https://www.rfc-editor.org/rfc/rfc792.
* Read this paper about raw sockets: http://sock-raw.org/papers/sock_raw.
* Study the Wireshark captures for ping and traceroute messages included in this Github repository.
* Read the starter code carefully to make sure you fully understand each line. If there is any code whose meaning is unfamiliar to you, look it up in the Python documentation. Also, try running the code under a debugger or from an interactive Python session.
* Don't wait until the last week of classes to start this project.

## What to do if your PING or TRACEROUTE applications do not work

If it's the last week of classes and you haven't been able to get your ping and/or traceroute applications running, and it seems unlikely that you'll be able to complete those portions of thie project, then you may consider `Plan B` as follows:

* If you can't get your `ping` application running, do the ping-related performance analysis described in **Part 3** using the built-in `ping` application that comes with your computer.
* If you can't get your `traceroute` application running, do the traceroute-related performance analysis described in **Part 3** using the built-in `tracert` application that comes with your computer.
* In your final project submission, document clearly whether your ping and traceroute analyses used your own code or the built-in applications.

Plan B submissions will receive lower grades; see the Grading Rubric.

## Grading Rubric

Your work on this project will be graded on 15-point scale. Fractional points may be awarded.

_15/15_ (A) Both `ping` and `traceroute` implementations are fully functional and behave properly when compared to built-in applications. Data collection is complete and accurate. Analyses reflect breadth and depth of understanding of the underlying networking factors that might explain the observations.

_13.5/15_ (A-) Both `ping` and `traceroute` implementations are fully functional and behave properly when compared to built-in applications. There are minor gaps, oversights or weaknesses in data collection and/or analysis.

_13/15_ (B+) Both `ping` and `traceroute` implementations are fully functional and behave properly when compared to built-in applications. There are significant gaps, oversights or weaknesses in data collection and/or analysis.

_12.5/15_ (B) One or both `ping` and `traceroute` implementations are less than fully functional and/or do not behave properly when compared to built-in applications. 

_12/15_ (B-) Only one of `ping` or `traceroute` implementations function and behave properly. Analyses are derived from built-in applications but are otherwise complete and reflect breadth and depth of understanding of the underlying networking factors that might explain the observations.

_11.5/15_ (C+) Neither `ping` nor `traceroute` implementations function. Analyses are derived from built-in applications but are otherwise complete and reflect breadth and depth of understanding of the underlying networking factors that might explain the observations.

_11/15 or less_ (C or lower) Missing deliverables. Code that doesn't run. Analyses that are incomplete, inaccurate, and/or reflect poor or limited understanding of the associated networking factors.
