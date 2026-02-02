# OIBSIP-report-on-common-network-security-threats-
Research Report on Common Network Security Threats

# Executive Summary
Network security threats continue to evolve at an alarming rate, with cybercriminals developing increasingly sophisticated methods to exploit vulnerabilities in digital infrastructure. This report examines three prevalent network security threats—Malvertising, Ransomware, and Adware—analyzing their mechanisms, real-world impact, and effective mitigation strategies. Understanding these threats is crucial for organizations and individuals to protect their digital assets and maintain operational security in an increasingly connected world.




# Table of Contents
Introduction
Malvertising
Ransomware
Adware
Comparative Analysis
Conclusion and Recommendations
References




# Introduction
The digital landscape of 2024-2025 has witnessed a significant escalation in cyber threats, with malvertising surging 10% in 2024 and ransomware attacks reaching unprecedented levels. These threats not only compromise individual users but also target critical infrastructure, healthcare systems, and major corporations, resulting in billions of dollars in damages annually.
The interconnected nature of modern networks means that a single vulnerability can cascade into widespread disruption. As organizations increasingly rely on digital services, understanding the mechanics of these threats and implementing robust security measures has become paramount.




# Malvertising
# Definition and Overview
Malvertising, a portmanteau of "malicious advertising," is a sophisticated cyberattack method where threat actors embed malware or malicious code into legitimate online advertisements. Unlike traditional malware distribution methods, malvertising exploits the trust users place in established advertising networks and reputable websites, making it particularly insidious.
How Malvertising Works
The malvertising attack chain typically follows these stages:
1. Creation: Cybercriminals design advertisements that appear legitimate, often mimicking trusted brands and using professional graphics to avoid suspicion.
2. Infiltration: Attackers purchase advertising space through legitimate ad networks or compromise advertising servers to inject malicious code into the ad delivery system.
3. Distribution: The malicious ads are served to users visiting trusted websites, leveraging the reputation of both the publisher and the ad network.
4. Exploitation: The malware activates either through:

Drive-by downloads: Malware automatically downloads without user interaction when the ad loads
Click-triggered attacks: Users clicking on the advertisement are redirected to malicious websites or trigger malware installation
Payload Delivery: Once activated, the malware can perform various malicious activities including data theft, system compromise, or further malware installation.


# Real-World Examples
1. Microsoft December 2024 Campaign
In early December 2024, Microsoft Threat Intelligence detected a large-scale malvertising campaign that impacted nearly one million devices globally through illegal streaming websites. The attackers embedded malvertising redirectors that led users through intermediary websites before redirecting them to GitHub and other platforms hosting malicious payloads. This campaign demonstrated the indiscriminate nature of modern malvertising, affecting both consumer and enterprise devices across multiple industries.

2. ScamClub VAST Campaign
The ScamClub campaign represented a sophisticated evolution in video-based malvertising. This operation specifically targeted mobile users, exploiting their typically weaker security protections compared to desktop environments. The campaign utilized auto-redirects embedded in video advertisements, automatically sending users to malicious landing pages without requiring any interaction.

3. Facebook SYS01stealer Operation
The SYS01stealer campaign leveraged Meta's advertising platform and hijacked Facebook accounts to distribute information-stealing malware. Attackers used trusted brand impersonation to expand their reach, creating fake advertisements for AI-generated media and legitimate software. When users interacted with these ads, they were redirected to deceptive sites hosted on Google Sites that impersonated legitimate applications. The stolen Facebook account data was then used to publish more fraudulent ads, creating a self-perpetuating cycle of infection.

4. WinSCP and PuTTY Malvertising
Beginning in early March 2024, security researchers observed the distribution of trojanized installers for WinSCP and PuTTY via malicious ads on search engines. Users searching for these legitimate open-source utilities encountered sponsored ads that redirected them to clone websites offering trojanized versions. This campaign ultimately led to ransomware deployment on affected systems.

# Impact of Malvertising
The consequences of malvertising extend far beyond individual infections:

1. User Impact:
Identity theft and financial fraud
Data breach and privacy violations
System compromise and performance degradation
Loss of trust in online advertising

2. Business Impact:
Over 70% of users now view at least half of online ads as untrustworthy
Brand reputation damage for publishers hosting malicious ads
Revenue loss from decreased user engagement
Legal liability and regulatory compliance issues

Geographic Distribution: In the United States, one out of every 160 ads was malicious in 2024, while Canada experienced a worse ratio of one malicious ad per 75 impressions. This regional disparity highlights the targeted nature of modern malvertising campaigns.

# Mitigation Strategies

1. For Individual Users:
Use Ad Blockers: Install reputable ad-blocking extensions that filter known malicious ad networks

2. Browser Security: Keep browsers updated and enable built-in security features

3. Avoid Suspicious Ads: Never click on ads for software downloads; instead, navigate directly to official websites

4. Security Software: Maintain updated antivirus and anti-malware solutions

5. Script Blocking: Consider using NoScript or similar extensions to prevent automatic script execution

# For Organizations:

1. Multi-layered Security: Implement defense-in-depth strategies combining network security, endpoint protection, and user awareness

2. Ad Network Vetting: Partner only with reputable advertising networks that maintain strict security standards

3. Content Security Policies: Deploy CSP headers to control which scripts can execute on web pages

4. Regular Security Audits: Conduct periodic reviews of advertising partners and ad delivery infrastructure

5. User Education: Train employees to recognize and report suspicious advertisements

6. Web Application Firewalls: Deploy WAF solutions to filter malicious traffic before it reaches users

# For Publishers and Ad Networks:

1. Ad Verification: Implement real-time ad scanning and verification systems
2. Seller Certification: Work with TAG (Trustworthy Accountability Group) certified partners
3. Monitoring Systems: Deploy continuous monitoring for anomalous ad behavior
4. Rapid Response: Establish incident response procedures for quick malvertising takedown
5. Sandbox Testing: Test advertisements in isolated environments before serving them to users




# Ransomware
# Definition and Overview
Ransomware is a type of malicious software that encrypts a victim's data or locks them out of their systems, demanding payment (typically in cryptocurrency) for restoration of access. Modern ransomware operations have evolved into sophisticated criminal enterprises operating as Ransomware-as-a-Service (RaaS) platforms, where developers lease their malware to affiliates who conduct the actual attacks.

# How Ransomware Works
The typical ransomware attack follows this progression:
1. Initial Access: Attackers gain entry through:
- Phishing emails with malicious attachments
- Exploiting unpatched vulnerabilities
- Compromised Remote Desktop Protocol (RDP) credentials
- Malvertising and drive-by downloads
- Supply chain compromises

2. Reconnaissance: Once inside the network, attackers:
- Map the network topology
- Identify valuable data repositories
- Locate backup systems
- Escalate privileges to administrator level

3. Data Exfiltration: Before encryption, attackers steal sensitive data for "double extortion" tactics
   
4. Encryption: The ransomware encrypts critical files using strong encryption algorithms

5. Ransom Demand: Victims receive a ransom note with payment instructions and threats to:
- Permanently delete data
- Publish sensitive information
- Sell data to competitors
- Report regulatory violations

6. Negotiation: Many ransomware groups operate "customer service" operations to negotiate payments


# Real-World Examples

1. LockBit: The Persistent Threat
Since 2020, LockBit had reportedly carried out 1,700 attacks and extorted $91 million before law enforcement intervention. Despite Operation Cronos in February 2024 seizing their infrastructure, LockBit reemerged with at least a dozen new attacks across Western Europe, the Americas, and Asia since September 2025.

Notable LockBit Attacks:
- University Hospital Center, Zagreb (June 2024): The cyberattack caused significant disruption, taking the hospital "back 50 years—to paper and pencil", affecting critical medical services and patient care.

- London Drugs (April-May 2024): All stores were closed nationwide from April 28 to May 7, 2024, representing a complete operational shutdown of a major retail chain.

- Evolve Bank & Trust (June 2024): This breach affected numerous financial technology companies including Stripe, Mercury, and Affirm, demonstrating the cascading impact of supply chain attacks.

- Federal Reserve Claims: While LockBit threatened to leak Federal Reserve data, the actual breach targeted their partner bank Evolve, showing how threat actors leverage fear and misinformation.


# RansomHub: The Rising Successor
Following LockBit's disruption, RansomHub rose to prominence, becoming one of the most active ransomware operations by offering affiliates generous terms. The group's rapid ascension demonstrated how the ransomware ecosystem quickly adapts to law enforcement actions.

# Qilin: Healthcare Sector Targeting
Qilin became the most active ransomware group in Q3 2025, averaging 75 victims per month and conducting a focused campaign against South Korea's financial sector. In June 2024, Qilin claimed responsibility for an attack that disrupted multiple hospitals across London, declared "critical" by NHS London.


# Evolution and Trends

1. Ransomware Statistics
- 2024 observed the highest volume of annual ransomware cases (5,263) since monitoring began in 2021
- Ransomware victim postings stabilized at an average of 535 victims per month in 2025
- The average ransom payment increased 500% to $2 million in 2024
- 59% of organizations experienced ransomware attacks in 2024

2. Fragmentation of the Threat Landscape
During Q3 2025, more than 85 active data leak sites collectively listed victims, with 14 new groups beginning operations in that quarter alone. This fragmentation indicates that despite law enforcement successes against major operations, the overall threat continues to grow and diversify.

3. Industry Targeting
The Industrials sector experienced 27% of all ransomware attacks in 2024, increasing 15% from 2023. Healthcare remained a consistent target at 8% of total victims, while manufacturing and business services were the most affected sectors.


# Impact of Ransomware

1. Operational Disruption:
- Complete business shutdown (as seen with London Drugs)
- Critical infrastructure compromise
- Healthcare service interruption affecting patient care
- Supply chain disruptions impacting multiple organizations

2. Financial Costs:
- Average data breach cost: $4.45 million (2023)
- Healthcare sector breaches: Over $10 million on average
- Recovery costs reached $2.73 million in 2024, up nearly $1 million from 2023
- 63% of ransom demands exceed $1 million, with 30% exceeding $5 million

3. Long-term Consequences:
- Reputational damage and loss of customer trust
- Regulatory penalties for data breaches
- Increased insurance premiums
- Legal liabilities from compromised customer data



# Mitigation Strategies
# Prevention
1. Access Controls:
- Implement principle of least privilege
- Use multi-factor authentication (MFA) for all remote access
- Regularly review and revoke unnecessary permissions
- Segment networks to limit lateral movement

2. Patch Management:
- Maintain updated systems and applications
- Prioritize patching of internet-facing systems
- Implement vulnerability scanning programs
- Subscribe to security advisories for critical software

3. Email Security:
- Deploy advanced email filtering and anti-phishing solutions
- Implement DMARC, SPF, and DKIM protocols
- Conduct regular phishing simulation training
- Disable macros by default in email attachments

4. Backup Strategy:
- Follow the 3-2-1 backup rule (3 copies, 2 different media, 1 offsite)
- Maintain offline or immutable backups
- Regularly test backup restoration procedures
- Encrypt backup data

5. Endpoint Protection:
- Deploy next-generation antivirus (NGAV) and EDR solutions
- Enable application whitelisting
- Disable unnecessary services and ports
- Implement host-based firewalls

# Detection
1. Monitoring and Analytics:
- Implement Security Information and Event Management (SIEM)
- Monitor for unusual network traffic patterns
- Track failed login attempts and privilege escalations
- Analyze file system changes

2. Threat Intelligence:
- Subscribe to threat intelligence feeds
- Participate in information sharing communities
- Monitor dark web for mentions of your organization
- Track indicators of compromise (IoCs)

3. Behavioral Analysis:
- Deploy User and Entity Behavior Analytics (UEBA)
- Monitor for abnormal data access patterns
- Track encryption activities on endpoints
- Alert on bulk file modifications

# Response
1. Incident Response Plan:
- Develop and regularly test IR procedures
- Define clear roles and responsibilities
- Establish communication protocols
- Maintain contact lists for external experts

2. Containment:
- Isolate infected systems immediately
- Disconnect from the network without powering down
- Preserve evidence for forensic analysis
- Document all actions taken

3. Recovery:
- Restore from verified clean backups
- Rebuild compromised systems from known good images
- Implement additional security controls before restoration
- Conduct post-incident analysis

4. Law Enforcement:
- Report incidents to FBI IC3 or local law enforcement
- Cooperate with investigations
- Share indicators of compromise with the community
- Consider CISA reporting for critical infrastructure

# Policy Considerations
# Payment Debate: Most cybersecurity experts and law enforcement agencies advise against paying ransoms because:
- Payment doesn't guarantee data recovery
- It funds future criminal operations
- Organizations may be targeted again
- It violates sanctions in some cases (e.g., payments to sanctioned entities)
However, each organization must evaluate its specific circumstances, considering:

- Business continuity requirements
- Data sensitivity and regulatory implications
- Availability of backups
- Legal and insurance guidance




# Adware
# Definition and Overview
Adware is software that automatically displays or downloads advertising material when a user is online. While some adware operates legitimately with user consent (often as a trade-off for free software), malicious adware installs without explicit permission, disrupts user experience, and may compromise privacy and security.

# How Adware Works
Adware typically infiltrates systems through several vectors:

1. Software Bundling: Free applications bundle adware with their installers, often hiding disclosure in lengthy terms of service agreements that users rarely read.

2. Deceptive Installation: Users are tricked into installing adware through:
- Fake system warnings or security alerts
- Misleading download buttons on websites
- Disguised installation prompts

3. Malvertising: As previously discussed, malicious advertisements can serve as delivery mechanisms for adware.

4. Browser Extensions: Seemingly useful browser add-ons contain hidden adware functionality.

5. Compromised Websites: Visiting infected websites can trigger automatic adware downloads.

Once installed, adware operates through various mechanisms:
- Pop-up Generation: Displays intrusive advertisements at regular intervals
- Browser Hijacking: Changes homepage, default search engine, or redirects web traffic
- Data Collection: Tracks browsing habits, search queries, and personal information
- Performance Degradation: Consumes system resources, slowing device performance
- Security Compromise: May open backdoors for additional malware




# Real-World Examples
# Necro Android Adware (2024)
The Necro Trojan infected 11 million devices through Google Play apps like Wuta Camera and Max Browser using malicious SDKs such as Coral SDK. The applications hid their payloads through image steganography, making detection difficult. Once active, the adware displayed background ads, managed browser traffic through plugin proxies, and engaged in subscription fraud without user knowledge.

# HotPage Adware (2024)
HotPage adware disguised itself as an ad-blocker and installed a Microsoft-signed kernel driver to inject code at the SYSTEM level, hijacking browser traffic for fake advertisements. This sophisticated attack exploited the Windows driver signing system, demonstrating how adware developers abuse legitimate security features to bypass detection.

# macOS Adload TCC Bypass (2024)
The Adload adware successfully evaded macOS Transparency, Consent, and Control (TCC) protections through an operating system vulnerability, allowing it to hijack Safari browser data without proper authorization. This example shows that even systems with robust security frameworks remain vulnerable to sophisticated adware.

# Stealth Android Campaigns (2023)
More than 60,000 Android applications claiming to be VPNs, game modifications, and utilities installed adware through third-party markets while avoiding detection through a two-day activation delay. These apps masked their icons, used misleading titles, and displayed fake "not available" messages while actually launching ad-filled WebViews in the background.


# Current Trends and Statistics
# Mobile Adware Surge
In the second half of 2025, adware volumes nearly doubled, driven by aggressive families like MobiDash. The holiday season proved particularly lucrative for cybercriminals, with attackers laying groundwork months in advance for successful campaigns.
Current data shows that 47% of Windows users and 58% of Android device users have encountered adware infections in 2025, affecting hundreds of millions of devices globally and making adware one of the most common cybersecurity threats.

# Platform Distribution
Kaspersky noted that 40% of mobile threats in 2023 were adware, often embedded in free apps loaded with intrusive ads. Mobile attacks increased by 52% in 2023, reaching 33.8 million cases, with adware and Trojans representing the majority of these threats.

# Android Dominance
Looking at 2024 as a whole, malware and PUPs together made up almost 90% of Android detections, with adware sliding to around 12%. However, this percentage represents absolute numbers remaining high, as attackers shifted focus toward more sophisticated threats while maintaining adware operations.


# Impact of Adware
1. User Experience:
- Constant interruption from unwanted advertisements
- Slower system and browser performance
- Battery drain on mobile devices
- Data plan consumption from background ad loading

2. Privacy Concerns:
- Collection of browsing history and search queries
- Tracking of personal information
- Location data harvesting
- Cookie and session hijacking

3. Security Risks:
- Gateway for additional malware installation
- Exposure to malicious websites through redirects
- Vulnerability exploitation through ad networks
- Credential theft through fake login prompts

4. Financial Impact:
- Unauthorized premium subscription enrollment
- Click fraud draining advertising budgets
- Identity theft leading to financial losses
- Productivity loss from system slowdowns




# Mitigation Strategies
# For Individual Users
1. Safe Download Practices:
- Only download software from official sources (App Store, Google Play, verified developer sites)
- Read user reviews and check developer reputation before installing
- Scrutinize permission requests, especially for SMS, accessibility, and notifications
- Avoid third-party app stores and APK downloads

2. Careful Installation:
- Always choose "Custom" or "Advanced" installation options
- Carefully review all installation prompts
- Decline additional software offers during installation
- Read end-user license agreements for bundled software disclosure

3. Browser Security:
- Install reputable ad-blocking extensions
- Regularly review and remove suspicious browser extensions
- Clear cookies and cache periodically
- Reset browser settings if behavior seems abnormal
- Disable pop-ups by default

4. System Protection:
- Use comprehensive antivirus/anti-malware software
- Keep operating systems and applications updated
- Enable built-in security features (Windows Defender, Google Play Protect)
- Scan system regularly for potentially unwanted programs

5. Mobile-Specific Measures:
- Regularly review installed applications
- Check app permissions and revoke unnecessary access
- Monitor data usage for abnormal consumption
- Use mobile security applications

# For Organizations
1. Endpoint Management:
- Deploy endpoint detection and response (EDR) solutions
- Implement application whitelisting
- Control software installation through group policies
- Use mobile device management (MDM) for company devices

2. Network Security:
- Filter web traffic through secure web gateways
- Block access to known adware distribution sites
- Monitor network traffic for suspicious patterns
- Implement DNS filtering

3. User Education:
- Conduct regular security awareness training
- Teach employees to recognize adware tactics
- Provide clear BYOD policies
- Create reporting mechanisms for suspicious software

4. Policy Enforcement:
- Prohibit third-party software installation on company devices
- Require IT approval for new applications
- Mandate use of company-approved app stores
- Implement bring-your-own-device (BYOD) security standards

# Removal Procedures
# Windows Systems:
1. Disconnect from the interne
2. tBoot into Safe Mode
3. Uninstall suspicious programs via Control Panel
4. Remove malicious browser extensions
5. Reset browser settings
6. Run full antivirus scan
7. Use specialized adware removal tools (Malwarebytes, AdwCleaner)
8. Check startup programs and scheduled tasks

# macOS Systems:
1. Quit all suspicious applications
2. Remove applications from Applications folder
3. Delete associated files from Library folders
4. Remove malicious browser extensions
5. Reset browser preferences
6. Run malware scanner
7. Check Login Items and LaunchAgents

# Android Devices:
1. Boot into Safe Mode
2. Identify and uninstall recently installed apps
3. Clear browser cache and data
4. Remove suspicious device administrator privileges
5. Run Google Play Protect scan
6. Install and run mobile security software
7. Factory reset if infection persists (after backing up essential data)

# iOS Devices:
1. Delete suspicious apps
2. Clear Safari data and history
3. Reset all settings if needed
4. Update to latest iOS version
5. Restore from clean backup if problems persist




# Attack Vector Overlap
These three threats often work in combination:
1. Malvertising → Ransomware: Malicious ads serve as initial infection vector for ransomware deployment
2. Malvertising → Adware: Ads deliver adware payloads that persist on systems
3. Adware → Malvertising: Adware creates environment for additional malicious ad delivery
4. Adware → Ransomware: Adware opens backdoors that attackers later exploit for ransomware

# Common Defense Principles
Despite their differences, these threats share common mitigation strategies:
1. User Education: All three exploit user trust and lack of awareness
2. System Updates: Keeping software patched prevents exploitation
3. Security Software: Multi-layered protection detects various threat types
4. Network Monitoring: Unusual traffic patterns indicate potential infections
5. Backup Strategy: Regular backups mitigate impact of all three threats
6. Access Control: Limiting privileges reduces attack surface

# Evolution Patterns
All three threats demonstrate similar evolutionary trends:
- Increasing Sophistication: More advanced evasion techniques
- Mobile Migration: Shifting focus to smartphone platforms
- Automation: Using AI and machine learning for targeting
- Commodification: As-a-Service models lowering entry barriers
- Targeting: Moving from opportunistic to targeted attacks
- Multi-Stage: Complex, multi-step attack chains




# Conclusion and Recommendations
# Key Findings
The cybersecurity landscape of 2024-2025 reveals an escalating arms race between threat actors and defenders. Malvertising, ransomware, and adware continue to evolve, exploiting human psychology, technical vulnerabilities, and the complexity of modern digital ecosystems.

# Critical Insights:
1. Persistence Despite Disruption: Law enforcement successes against major operations like LockBit demonstrate temporary setbacks rather than permanent solutions, as threat actors quickly reorganize and adapt.


2. Mobile Vulnerability: Mobile devices account for 56% of malicious ad traffic, highlighting the growing importance of mobile security.


3. Trust Exploitation: All three threats leverage the trust users place in legitimate platforms, whether advertising networks, software downloads, or established brands.


4. Financial Motivation: The profitability of cybercrime continues to drive innovation and persistence in attacks, with ransomware payments reaching $2 million on average.


5. Ecosystem Fragmentation: The ransomware landscape shows increasing decentralization, with 85+ active groups operating simultaneously, making comprehensive enforcement challenging.


# Strategic Recommendations
# For Individuals
1. Adopt a Security-First Mindset: Treat all online interactions with healthy skepticism
2. Maintain Vigilance: Regular system monitoring and security software updates
3. Practice Digital Hygiene: Careful download practices, strong passwords, multi-factor authentication
4. Stay Informed: Follow cybersecurity news and threat alerts
5. Backup Religiously: Maintain offline backups of critical personal data

# For Organizations
1. Implement Zero Trust Architecture: Never trust, always verify for all network access
2. Invest in Security Teams: Skilled cybersecurity professionals are essential
3. Conduct Regular Training: Security awareness must be ongoing, not one-time
4. Test Defenses: Regular penetration testing and red team exercises
5. Develop Comprehensive IR Plans: Prepare for incidents before they occur
6. Collaborate: Share threat intelligence with industry peers and law enforcement
7. Consider Cyber Insurance: But don't rely on it as primary defense

# For the Industry
1. Standardize Security Practices: Develop and enforce industry-wide security standards
2. Improve Ad Network Security: Advertising platforms must implement rigorous vetting
3. Enhance Platform Security: App stores need better malware detection
4. Support Law Enforcement: Cooperation between private sector and authorities
5. Invest in Research: Continued development of detection and prevention technologies
6. Promote Transparency: Clear disclosure of security incidents helps collective defense

# For Policymakers
1. Strengthen Legal Frameworks: Update laws to address modern cyber threats
2. International Cooperation: Cybercrime knows no borders; response must be coordinated
3. Critical Infrastructure Protection: Mandate security standards for essential services
4. Support Victims: Provide resources for incident response and recovery
5. Deterrence: Credible consequences for cybercriminals
6. Privacy Protection: Balance security needs with privacy rights

# Future Outlook
The threat landscape will continue evolving with several anticipated trends:
1. AI-Powered Attacks: Machine learning enabling more sophisticated and personalized attacks
2. IoT Exploitation: Expanding attack surface as more devices connect to networks
3. Supply Chain Focus: Increasing targeting of software and hardware supply chains
4. Cryptocurrency Evolution: New payment methods enabling and complicating cybercrime
5. Quantum Computing: Potential disruption of current encryption standards
6. 5G Security: New vulnerabilities in next-generation networks

# Final Thoughts
Cybersecurity is not a destination but a continuous journey. The threats posed by malvertising, ransomware, and adware will persist and evolve, requiring constant vigilance, adaptation, and investment in security measures. Organizations and individuals must recognize that perfect security is impossible, but resilience—the ability to prevent, detect, respond to, and recover from attacks—is achievable.
The human element remains both the weakest link and the strongest defense. Technical controls provide necessary protection, but educated, aware users make the crucial difference between successful attacks and foiled attempts. As technology advances, maintaining this human firewall through ongoing education and awareness becomes increasingly critical.
Success in cybersecurity requires a balanced approach: robust technical defenses, comprehensive policies and procedures, continuous monitoring and improvement, and a culture that prioritizes security at all levels. Only through this holistic approach can we hope to stay ahead of increasingly sophisticated cyber threats.




# References
# Malvertising Sources
1. AdMonsters. (2025). "Digital Advertising Malware in 2024: Lessons for 2025 and Beyond." Retrieved from https://admonsters.com/digital-advertising-malware-in-2024-lessons-for-2025-and-beyond/

2. Microsoft Security Blog. (2025). "Malvertising campaign leads to info stealers hosted on GitHub." Retrieved from https://www.microsoft.com/en-us/security/blog/2025/03/06/malvertising-campaign-leads-to-info-stealers-hosted-on-github/

3. GeoEdge. (2024). "How AdTech Fared Against Malvertising in Early 2024." Retrieved from https://www.geoedge.com/q1-malvertising-adtech/

4. SentinelOne. (2024). "What is Malvertising?: Examples, Risks, and Prevention." Retrieved from https://www.sentinelone.com/cybersecurity-101/cybersecurity/malvertising/

5. VMRay. (2025). "Malware & Phishing Threat Landscape Report - 2024/2." Retrieved from https://www.vmray.com/malware-phishing-threat-landscape-report-2024-2/

6. LastPass Blog. (2025). "How to Protect Yourself from Malvertising in 2025." Retrieved from https://blog.lastpass.com/posts/malvertising

7. Rapid7. (2024). "Ongoing Malvertising Campaign leads to Ransomware." Retrieved from https://www.rapid7.com/blog/post/2024/05/13/ongoing-malvertising-campaign-leads-to-ransomware/

8. SecureWorld. (2024). "Evolving Malvertising Threats: How Cybercriminals Are Exploiting Online Ads in 2024." Retrieved from https://www.secureworld.io/industry-news/evolving-malvertising-threats-online-ads

9. eSecurity Planet. (2025). "When Ads Attack: Inside the Growing Malvertising Threat." Retrieved from https://www.esecurityplanet.com/threats/when-ads-attack-inside-the-growing-malvertising-threat/

10. The Hacker News. (2024). "Malvertising Campaign Hijacks Facebook Accounts to Spread SYS01stealer Malware." Retrieved from https://thehackernews.com/2024/10/malvertising-campaign-hijacks-facebook.html


# Ransomware Sources
11. Wikipedia. (2025). "LockBit." Retrieved from https://en.wikipedia.org/wiki/LockBit
12. BlackF




