---
title: Email Investigation Techniques
date: 2023-09-26 14:05:11 GMT+7
categories: [DFIR, SIEM, Security, Email Phishing, Analyst]
tags: [Email Phishing, Security, SOC]     # TAG names should always be lowercase
---
- ![Phishing Email Meme](https://kratikal.com/blog/wp-content/uploads/2019/09/Phishing-image-meme.jpg)

## 1.Email Threat Types.
- Email threats are every threat your environment faces when deciding to use an email service. They are 
not limited to phishing emails only; some attackers also use email for blackmailing, information leakage, 
data exfiltration, and lateral movement. In this section, we will focus on email threats that originate 
from external sources and discuss in detail four common types of email threats that organizations face:

>  • Spearphishing attachments
> 
>  • Spearphishing links
> 
>  • Blackmail emails
> 
>  • Business Email Compromise

## 2.Email flow and header analysis.
- Due to the increase in email threats and the use of spoofing techniques to impersonate known legitimate 
domains, it has become crucial for SOC analysts to understand the email message flow and email 
authentication process, as well as analyze email headers to collect additional artifacts and investigate 
and observe potential spoofing attempts.

- The objective of this chapter is to learn about the email message flow and understand email authentication 
protocols such as Sender Policy Framework (SPF), DomainKeys Identified Mail (DKIM), and 
Domain-Based Message Authentication, Reporting, and Conformance (DMARC) and how they 
work. You will also learn how to analyze an email’s message header and observe any spoofing attempts 
by analyzing it.

### 2.1.Email flow.
- An email flow is the f﻿low path that an email follows and the hops that the email passes when sent from 
the sender until it's delivered to the recipient. The email crosses multiple hops between the sender and 
the recipient before it is delivered. Most of them use SMTP. Let’s take a look at these hops in detail:
  - Mail User Agent (MUA): This refers to the agent is used by the client to send the email. 
Examples include Outlook and browsers such as Google Chrome, Mozilla Firefox, and others.
  - Mail Submission Agent (MSA): The server that receives the email after the client has submitted 
it from its MUA.
Mail Transfer Agent (MTA): Also known as the SMTP relay server, this is the email server that 
receives the message from the MSA and passes it to several MTA servers until it’s delivered to 
the recipient’s mail exchange server.
  - Mail Exchange (MX): The email server that is responsible for receiving messages intended 
for a particular domain that are sent and transferred from MTAs to be delivered to recipients. 
This server is typically identified by an MX record in the DNS records of the recipient domain. 
It is worth noting that a domain may have multiple MX servers for load-balancing purposes.
  - Mail Delivery Agent (MDA): The server responsible for providing the user (recipient) with 
the sent email after successful authentication.
![Email Flow](https://www.seqrite.com/blog/wp-content/uploads/2019/06/basic-email-flow.jpg)

  - The diagram illustrates the path an email follows and the hops it traverses
when it is sent from the sender to the recipient. The sender used Microsoft Outlook as the BUY
Connect to Microsoft Exchange Server, then send email to the MSA server. Afterward,
The MSA forwarded the email to MTA servers, which efficiently routed the email to the appropriate address.
MX server, responsible for receiving emails sent to the recipient's domain. Finally, MX
The server forwarded the email to the recipient's MDA server, allowing the end user to be authenticated
to see messages in his mailbox through his MUA. The purpose of understanding the email flow and
The hops that the email passes should be noted that each hop adds a header to the email message header
contains at least the server name, server IP, and email processing date and time of the email server.

### 2.2.Email Header Analysis.
   - .... Wait